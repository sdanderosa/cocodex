import { createPublicKey, randomUUID, sign, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  agentDispatchSigningTranscript,
  agentRequestSigningTranscript,
  type AgentDefinition,
  type AgentTask,
  type ChatEvent,
} from "@cocodex/protocol";
import type { ServerIdentity } from "./identity";
import { appendChatEventResult, requireProjectMembership } from "./shared-state";

const MAX_CLOCK_SKEW_MS = 60_000;
const MAX_TASK_LIFETIME_MS = 5 * 60_000;
const MAX_PENDING_TASKS_PER_REQUESTER = 8;

export interface RegisterAgentInput {
  id: string;
  projectId: string;
  hostDeviceId: string;
  name: string;
}

export function registerAgent(db: Database, input: RegisterAgentInput, now = new Date()): AgentDefinition {
  requireProjectMembership(db, input.projectId, input.hostDeviceId);
  const agent: AgentDefinition = {
    id: input.id,
    projectId: input.projectId,
    name: input.name.trim(),
    hostDeviceId: input.hostDeviceId,
    enabled: true,
  };
  if (!agent.name) throw new Error("Agent name is required");
  db.query(`INSERT INTO agents (id, project_id, host_device_id, name, enabled, created_at)
    VALUES (?, ?, ?, ?, 1, ?)`)
    .run(agent.id, agent.projectId, agent.hostDeviceId, agent.name, now.toISOString());
  return agent;
}

export interface CreateAgentTaskInput {
  id: string;
  projectId: string;
  requesterDeviceId: string;
  agentId: string;
  prompt: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  dependencies?: string[];
  requesterSignature: string;
}

interface AgentRow {
  id: string;
  projectId: string;
  hostDeviceId: string;
  enabled: number;
}

interface DeviceKeyRow { publicKeyPem: string; status: string }
interface TaskRow extends Omit<AgentTask, "status"> { status: AgentTask["status"]; dependenciesJson?: string }

function parseDependencies(value: string | undefined): string[] {
  if (!value) return [];
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== "string")) throw new Error("Stored task dependencies are invalid");
  return parsed as string[];
}

function taskById(db: Database, id: string): AgentTask | null {
  const row = db.query(`SELECT t.id, t.project_id AS projectId, t.requester_device_id AS requesterDeviceId,
    t.target_device_id AS targetDeviceId, t.agent_id AS agentId, t.prompt, t.nonce,
    t.issued_at AS issuedAt, t.expires_at AS expiresAt, t.requester_signature AS requesterSignature,
    t.server_signature AS serverSignature, d.public_key_pem AS requesterPublicKeyPem,
    t.status, t.accepted_at AS acceptedAt, t.dependencies_json AS dependenciesJson
    FROM agent_tasks t JOIN devices d ON d.id = t.requester_device_id WHERE t.id = ?`).get(id) as TaskRow | null;
  if (!row) return null;
  const { dependenciesJson, ...task } = row;
  return { ...task, dependencies: parseDependencies(dependenciesJson) };
}

function sameRequest(task: AgentTask, input: CreateAgentTaskInput): boolean {
  return task.projectId === input.projectId && task.requesterDeviceId === input.requesterDeviceId
    && task.agentId === input.agentId && task.prompt === input.prompt && task.nonce === input.nonce
    && task.issuedAt === input.issuedAt && task.expiresAt === input.expiresAt
    && JSON.stringify(task.dependencies) === JSON.stringify(input.dependencies ?? [])
    && task.requesterSignature === input.requesterSignature;
}

export function createAgentTask(
  db: Database,
  identity: ServerIdentity,
  input: CreateAgentTaskInput,
  now = new Date(),
): { task: AgentTask; created: boolean } {
  requireProjectMembership(db, input.projectId, input.requesterDeviceId);
  const existing = taskById(db, input.id);
  if (existing) {
    if (!sameRequest(existing, input)) throw new Error("Task ID was already used for a different request");
    return { task: existing, created: false };
  }
  const issued = Date.parse(input.issuedAt);
  const expires = Date.parse(input.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) throw new Error("Invalid task lifetime");
  if (issued > now.getTime() + MAX_CLOCK_SKEW_MS) throw new Error("Task issue time is too far in the future");
  if (expires <= now.getTime() || expires - issued > MAX_TASK_LIFETIME_MS) throw new Error("Task is expired or lives too long");
  const agent = db.query(`SELECT id, project_id AS projectId, host_device_id AS hostDeviceId, enabled
    FROM agents WHERE id = ?`).get(input.agentId) as AgentRow | null;
  if (!agent || agent.projectId !== input.projectId || agent.enabled !== 1) throw new Error("Agent is not available in this project");
  const dependencies = [...new Set(input.dependencies ?? [])];
  if (dependencies.includes(input.id)) throw new Error("Task cannot depend on itself");
  if (dependencies.length > 16) throw new Error("Too many task dependencies");
  for (const dependencyId of dependencies) {
    const dependency = db.query("SELECT project_id AS projectId FROM agent_tasks WHERE id = ?")
      .get(dependencyId) as { projectId: string } | null;
    if (!dependency || dependency.projectId !== input.projectId) throw new Error("Task dependency was not found in this project");
  }
  requireProjectMembership(db, input.projectId, agent.hostDeviceId);
  if (agent.hostDeviceId === input.requesterDeviceId) throw new Error("Remote agent must be hosted by another device");
  const requester = db.query(`SELECT public_key_pem AS publicKeyPem, status FROM devices WHERE id = ?`)
    .get(input.requesterDeviceId) as DeviceKeyRow | null;
  if (!requester || requester.status !== "approved") throw new Error("Requester device is not approved");
  const pending = db.query(`SELECT COUNT(*) AS count FROM agent_tasks
    WHERE requester_device_id = ?
      AND (status = 'running' OR (status = 'queued' AND expires_at > ?))`)
    .get(input.requesterDeviceId, now.toISOString()) as { count: number };
  if (pending.count >= MAX_PENDING_TASKS_PER_REQUESTER) {
    throw new Error("Requester has too many pending agent tasks");
  }
  const requestValid = verify(null, agentRequestSigningTranscript({
    taskId: input.id,
    projectId: input.projectId,
    agentId: input.agentId,
    prompt: input.prompt,
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    dependencies,
  }), createPublicKey(requester.publicKeyPem), Buffer.from(input.requesterSignature, "base64url"));
  if (!requestValid) throw new Error("Invalid agent request signature");
  const acceptedAt = now.toISOString();
  const unsigned = {
    taskId: input.id,
    projectId: input.projectId,
    agentId: input.agentId,
    prompt: input.prompt,
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    requesterDeviceId: input.requesterDeviceId,
    targetDeviceId: agent.hostDeviceId,
    requesterSignature: input.requesterSignature,
    requesterPublicKeyPem: requester.publicKeyPem,
    dependencies,
  };
  const serverSignature = sign(null, agentDispatchSigningTranscript(unsigned), identity.privateKeyPem).toString("base64url");
  const { taskId: _signedTaskId, ...dispatch } = unsigned;
  const task: AgentTask = { ...dispatch, id: input.id, status: "queued", acceptedAt, serverSignature, dependencies };
  db.query(`INSERT INTO agent_tasks (
    id, project_id, requester_device_id, target_device_id, agent_id, prompt, nonce,
    issued_at, expires_at, requester_signature, server_signature, status, accepted_at, dependencies_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`).run(
    task.id, task.projectId, task.requesterDeviceId, task.targetDeviceId, task.agentId,
    task.prompt, task.nonce, task.issuedAt, task.expiresAt, task.requesterSignature,
    task.serverSignature, task.acceptedAt, JSON.stringify(dependencies),
  );
  return { task, created: true };
}

export function expireQueuedAgentTasks(db: Database, now = new Date()): Array<{
  task: AgentTask;
  event: ChatEvent;
}> {
  const expired = db.query(`SELECT id, target_device_id AS targetDeviceId
    FROM agent_tasks WHERE status = 'queued' AND expires_at <= ?
    ORDER BY accepted_at, id`).all(now.toISOString()) as Array<{ id: string; targetDeviceId: string }>;
  return expired.map(item => {
    const result = appendAgentResult(
      db,
      item.targetDeviceId,
      item.id,
      randomUUID(),
      "Agent request expired before the host client accepted it.",
      true,
      "failed",
      now,
    );
    return { task: result.task, event: result.event };
  });
}

export function cancelAgentTask(
  db: Database,
  actorDeviceId: string,
  taskId: string,
  reason: string,
  now = new Date(),
): { task: AgentTask; event: ChatEvent; created: boolean } {
  const task = taskById(db, taskId);
  if (!task) throw new Error("Agent task was not found");
  if (task.requesterDeviceId !== actorDeviceId && task.targetDeviceId !== actorDeviceId) {
    throw new Error("Only the requester or host device can cancel this task");
  }
  requireProjectMembership(db, task.projectId, actorDeviceId);
  if (task.status === "completed" || task.status === "failed") {
    throw new Error("Agent task is already final");
  }
  const normalizedReason = reason.trim().slice(0, 512) || "Cancelled by a trusted device.";
  return appendAgentResult(
    db,
    task.targetDeviceId,
    task.id,
    randomUUID(),
    `Agent task cancelled: ${normalizedReason}`,
    true,
    "failed",
    now,
  );
}

export function pendingAgentTasks(db: Database, targetDeviceId: string, now = new Date()): AgentTask[] {
  const rows = db.query(`SELECT t.id, t.project_id AS projectId, t.requester_device_id AS requesterDeviceId,
    t.target_device_id AS targetDeviceId, t.agent_id AS agentId, t.prompt, t.nonce,
    t.issued_at AS issuedAt, t.expires_at AS expiresAt, t.requester_signature AS requesterSignature,
    t.server_signature AS serverSignature, d.public_key_pem AS requesterPublicKeyPem,
    t.status, t.accepted_at AS acceptedAt, t.dependencies_json AS dependenciesJson
    FROM agent_tasks t JOIN devices d ON d.id = t.requester_device_id
    WHERE t.target_device_id = ?
      AND (t.status = 'running' OR (t.status = 'queued' AND t.expires_at > ?))
    ORDER BY t.accepted_at, t.id`).all(targetDeviceId, now.toISOString()) as TaskRow[];
  return rows.map(row => {
    const { dependenciesJson, ...task } = row;
    return { ...task, dependencies: parseDependencies(dependenciesJson) };
  })
    .filter(task => task.dependencies.every(dependencyId => {
      const dependency = db.query("SELECT status FROM agent_tasks WHERE id = ?").get(dependencyId) as { status: string } | null;
      return dependency?.status === "completed";
    }));
}

export function appendAgentResult(
  db: Database,
  targetDeviceId: string,
  taskId: string,
  eventId: string,
  content: string,
  final: boolean,
  status: "running" | "completed" | "failed",
  now = new Date(),
): { task: AgentTask; event: ChatEvent; created: boolean } {
  return db.transaction(() => {
    const task = taskById(db, taskId);
    if (!task || task.targetDeviceId !== targetDeviceId) throw new Error("Agent task is not assigned to this device");
    requireProjectMembership(db, task.projectId, targetDeviceId);
    const existing = db.query(`SELECT c.sequence, c.project_id AS projectId, c.event_id AS eventId,
      c.sender_device_id AS senderDeviceId, c.content, c.client_created_at AS clientCreatedAt,
      c.accepted_at AS acceptedAt, e.task_id AS taskId, e.final, e.status
      FROM chat_events c JOIN agent_task_events e ON e.chat_sequence = c.sequence
      WHERE c.event_id = ?`).get(eventId) as (ChatEvent & {
        taskId: string; final: number; status: string;
      }) | null;
    if (existing) {
      if (existing.taskId !== taskId || existing.senderDeviceId !== targetDeviceId
        || existing.content !== content || Boolean(existing.final) !== final || existing.status !== status) {
        throw new Error("Agent result event ID was reused with different content");
      }
      return { task: { ...task, status: status }, event: existing, created: false };
    }
    if (task.status === "completed" || task.status === "failed") throw new Error("Agent task is already final");
    if (final !== (status === "completed" || status === "failed")) throw new Error("Agent result final flag and status disagree");
    const appended = appendChatEventResult(db, {
      projectId: task.projectId, eventId, senderDeviceId: targetDeviceId, content,
      clientCreatedAt: now.toISOString(),
    }, now);
    const event = appended.event;
    db.query(`INSERT INTO agent_task_events (task_id, chat_sequence, final, status) VALUES (?, ?, ?, ?)`)
      .run(task.id, event.sequence, final ? 1 : 0, status);
    db.query(`UPDATE agent_tasks SET status = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END WHERE id = ?`)
      .run(status, final ? 1 : 0, now.toISOString(), task.id);
    return { task: { ...task, status }, event, created: true };
  }).immediate();
}

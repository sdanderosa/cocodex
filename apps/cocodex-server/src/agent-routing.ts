import { createPublicKey, randomUUID, sign, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  agentDefinitionSigningTranscript,
  agentDispatchSigningTranscript,
  agentRequestSigningTranscript,
  type AgentDefinition,
  type AgentTaskView,
  type AgentView,
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

export function createAgentForHost(
  db: Database,
  input: RegisterAgentInput & { signature: string },
  now = new Date(),
): { agent: AgentDefinition; created: boolean } {
  requireProjectMembership(db, input.projectId, input.hostDeviceId);
  const agent: AgentDefinition = {
    id: input.id.trim(),
    projectId: input.projectId,
    name: input.name.trim(),
    hostDeviceId: input.hostDeviceId,
    enabled: true,
  };
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(agent.id)) {
    throw new Error("Agent ID must be a UUID");
  }
  if (!agent.name || agent.name.length > 120) throw new Error("Agent name must be 1-120 characters");
  const host = db.query(`
    SELECT public_key_pem AS publicKeyPem, status FROM devices WHERE id = ?
  `).get(agent.hostDeviceId) as DeviceKeyRow | null;
  if (!host || host.status !== "approved") throw new Error("Agent host device is not approved");
  const valid = verify(
    null,
    agentDefinitionSigningTranscript({
      projectId: agent.projectId,
      agentId: agent.id,
      name: agent.name,
      hostDeviceId: agent.hostDeviceId,
    }),
    createPublicKey(host.publicKeyPem),
    Buffer.from(input.signature, "base64url"),
  );
  if (!valid) throw new Error("Invalid agent definition signature");
  return db.transaction(() => {
    const existing = db.query(`
      SELECT id, project_id AS projectId, name, host_device_id AS hostDeviceId, enabled
      FROM agents WHERE id = ?
    `).get(agent.id) as (Omit<AgentDefinition, "enabled"> & { enabled: number }) | null;
    if (existing) {
      if (existing.projectId !== agent.projectId || existing.hostDeviceId !== agent.hostDeviceId
        || existing.name !== agent.name || existing.enabled !== 1) {
        throw new Error("Agent ID was already used for a different definition");
      }
      return { agent, created: false };
    }
    const hostCount = db.query(`
      SELECT COUNT(*) AS count FROM agents
      WHERE project_id = ? AND host_device_id = ? AND enabled = 1
    `).get(agent.projectId, agent.hostDeviceId) as { count: number };
    if (Number(hostCount.count) >= 1) {
      throw new Error("This client currently supports one enabled agent per project");
    }
    const projectCount = db.query(`
      SELECT COUNT(*) AS count FROM agents WHERE project_id = ?
    `).get(agent.projectId) as { count: number };
    if (Number(projectCount.count) >= 128) throw new Error("Project agent limit reached");
    db.query(`INSERT INTO agents (id, project_id, host_device_id, name, enabled, created_at)
      VALUES (?, ?, ?, ?, 1, ?)`)
      .run(agent.id, agent.projectId, agent.hostDeviceId, agent.name, now.toISOString());
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES ('agent.created', ?, ?, ?, ?)
    `).run(agent.hostDeviceId, agent.id, now.toISOString(), JSON.stringify({
      projectId: agent.projectId,
      name: agent.name,
      hostDeviceId: agent.hostDeviceId,
    }));
    return { agent, created: true };
  }).immediate();
}

export function listAgents(
  db: Database,
  projectId: string,
  requesterDeviceId: string,
  isHostReady: (hostDeviceId: string, agentId: string) => boolean = () => true,
): AgentView[] {
  requireProjectMembership(db, projectId, requesterDeviceId);
  const rows = db.query(`
    SELECT a.id, a.project_id AS projectId, a.name, a.host_device_id AS hostDeviceId,
      a.enabled, d.display_name AS hostDisplayName, d.status AS hostStatus,
      pm.device_id AS hostMemberDeviceId
    FROM agents a
    JOIN devices d ON d.id = a.host_device_id
    LEFT JOIN project_members pm ON pm.project_id = a.project_id AND pm.device_id = a.host_device_id
    WHERE a.project_id = ?
    ORDER BY a.created_at ASC, a.id ASC
  `).all(projectId) as Array<{
    id: string;
    projectId: string;
    name: string;
    hostDeviceId: string;
    enabled: number;
    hostDisplayName: string;
    hostStatus: string;
    hostMemberDeviceId: string | null;
  }>;
  return rows.map(row => {
    const counts = db.query(`
      SELECT
        SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS activeTasks,
        SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queuedTasks,
        MAX(COALESCE(completed_at, accepted_at)) AS lastTaskAt
      FROM agent_tasks WHERE agent_id = ?
    `).get(row.id) as { activeTasks: number | null; queuedTasks: number | null; lastTaskAt: string | null };
    const activeTasks = Math.max(0, Number(counts.activeTasks ?? 0));
    const queuedTasks = Math.max(0, Number(counts.queuedTasks ?? 0));
    const hostReady = row.hostMemberDeviceId !== null
      && row.hostStatus === "approved" && isHostReady(row.hostDeviceId, row.id);
    const latest = counts.lastTaskAt
      ? db.query(`SELECT status FROM agent_tasks WHERE agent_id = ?
          ORDER BY COALESCE(completed_at, accepted_at) DESC, id DESC LIMIT 1`).get(row.id) as { status: string } | null
      : null;
    const status: AgentView["status"] = row.enabled !== 1 || !hostReady
      ? "offline"
      : activeTasks > 0
        ? "working"
        : queuedTasks > 0
          ? "queued"
          : latest?.status === "completed"
            ? "completed"
            : latest?.status === "failed"
              ? "failed"
              : "available";
    return {
      id: row.id,
      projectId: row.projectId,
      name: row.name,
      hostDeviceId: row.hostDeviceId,
      hostDisplayName: row.hostDisplayName,
      enabled: row.enabled === 1,
      status,
      activeTasks,
      queuedTasks,
      lastTaskAt: counts.lastTaskAt ?? null,
    } satisfies AgentView;
  });
}

export function listAgentTasks(
  db: Database,
  projectId: string,
  requesterDeviceId: string,
  limit = 128,
): AgentTaskView[] {
  requireProjectMembership(db, projectId, requesterDeviceId);
  const boundedLimit = Math.max(1, Math.min(256, Math.trunc(limit)));
  const rows = db.query(`
    SELECT t.id, t.project_id AS projectId, t.agent_id AS agentId,
      a.name AS agentName, t.requester_device_id AS requesterDeviceId,
      t.target_device_id AS targetDeviceId, t.status,
      t.dependencies_json AS dependenciesJson, t.input_artifact_ids_json AS inputArtifactIdsJson,
      t.workspace_mode AS workspaceMode, t.workspace_ref AS workspaceRef,
      t.worktree_branch AS branch, t.base_commit AS baseCommit,
      t.merge_target AS mergeTarget,
      t.accepted_at AS acceptedAt,
      t.completed_at AS completedAt,
      CASE WHEN t.prompt_envelope_json IS NOT NULL THEN 1 ELSE 0 END AS encrypted,
      COALESCE(t.execution_started_at, (SELECT MIN(c.accepted_at)
        FROM agent_task_events e JOIN chat_events c ON c.sequence = e.chat_sequence
        WHERE e.task_id = t.id AND e.status = 'running'),
        (SELECT MIN(c.accepted_at)
        FROM project_chat_events c
        WHERE c.task_id = t.id AND c.status = 'running')) AS startedAt,
      (SELECT COUNT(*) FROM agent_task_events e WHERE e.task_id = t.id)
        + (SELECT COUNT(*) FROM project_chat_events c WHERE c.task_id = t.id) AS eventCount,
      COALESCE(
        (SELECT MAX(c.accepted_at)
          FROM agent_task_events e JOIN chat_events c ON c.sequence = e.chat_sequence
          WHERE e.task_id = t.id),
        (SELECT MAX(c.accepted_at) FROM project_chat_events c WHERE c.task_id = t.id),
        t.accepted_at
      ) AS lastActivityAt
    FROM agent_tasks t
    JOIN agents a ON a.id = t.agent_id
    WHERE t.project_id = ?
    ORDER BY lastActivityAt DESC, t.id ASC
    LIMIT ?
  `).all(projectId, boundedLimit) as Array<{
    id: string;
    projectId: string;
    agentId: string;
    agentName: string;
    requesterDeviceId: string;
    targetDeviceId: string;
    status: AgentTaskView["status"];
    dependenciesJson: string;
    inputArtifactIdsJson: string;
    workspaceMode: AgentTaskView["workspaceMode"];
    workspaceRef: string | null;
    branch: string | null;
    baseCommit: string | null;
    mergeTarget: string | null;
    acceptedAt: string;
    startedAt: string | null;
    completedAt: string | null;
    encrypted: number;
    eventCount: number;
    lastActivityAt: string;
  }>;
  return rows.map(row => ({
    id: row.id,
    projectId: row.projectId,
    agentId: row.agentId,
    agentName: row.agentName,
    requesterDeviceId: row.requesterDeviceId,
    targetDeviceId: row.targetDeviceId,
    status: row.status,
    dependencies: parseDependencies(row.dependenciesJson),
    inputArtifactIds: parseDependencies(row.inputArtifactIdsJson),
    workspaceMode: row.workspaceMode,
    workspaceRef: row.workspaceRef,
    branch: row.branch,
    baseCommit: row.baseCommit,
    mergeTarget: row.mergeTarget,
    acceptedAt: row.acceptedAt,
    startedAt: row.startedAt,
    completedAt: row.completedAt,
    lastActivityAt: row.lastActivityAt,
    eventCount: Math.max(0, Number(row.eventCount ?? 0)),
    encrypted: row.encrypted === 1,
  } satisfies AgentTaskView));
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
  inputArtifactIds?: string[];
  privateShareMessageId?: string;
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

function normalizeDependencies(value: string[] | undefined, taskId: string): string[] {
  const dependencies = [...new Set(value ?? [])];
  if (dependencies.some(dependencyId => dependencyId === taskId)) {
    throw new Error("Task cannot depend on itself");
  }
  if (dependencies.length > 16) throw new Error("Too many task dependencies");
  return dependencies;
}

function rejectDependencyCycle(db: Database, projectId: string, taskId: string, dependencies: string[]): void {
  const pending = [...dependencies];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const dependencyId = pending.pop()!;
    if (dependencyId === taskId) throw new Error("Task dependency would create a cycle");
    if (visited.has(dependencyId)) continue;
    visited.add(dependencyId);
    if (visited.size > 4_096) throw new Error("Task dependency graph is too large");
    const row = db.query(`
      SELECT project_id AS projectId, dependencies_json AS dependenciesJson
      FROM agent_tasks WHERE id = ?
    `).get(dependencyId) as { projectId: string; dependenciesJson: string } | null;
    if (!row || row.projectId !== projectId) continue;
    pending.push(...parseDependencies(row.dependenciesJson));
  }
}

function taskById(db: Database, id: string): AgentTask | null {
  const row = db.query(`SELECT t.id, t.project_id AS projectId, t.requester_device_id AS requesterDeviceId,
    t.target_device_id AS targetDeviceId, t.agent_id AS agentId, t.prompt, t.nonce,
    t.issued_at AS issuedAt, t.expires_at AS expiresAt, t.requester_signature AS requesterSignature,
    t.server_signature AS serverSignature, d.public_key_pem AS requesterPublicKeyPem,
    t.status, t.accepted_at AS acceptedAt, t.dependencies_json AS dependenciesJson,
    t.private_share_message_id AS privateShareMessageId
    FROM agent_tasks t JOIN devices d ON d.id = t.requester_device_id WHERE t.id = ?`).get(id) as TaskRow | null;
  if (!row) return null;
  const { dependenciesJson, ...task } = row;
  return { ...task, dependencies: parseDependencies(dependenciesJson), inputArtifactIds: [] };
}

function sameRequest(task: AgentTask, input: CreateAgentTaskInput, dependencies: string[]): boolean {
  return task.projectId === input.projectId && task.requesterDeviceId === input.requesterDeviceId
    && task.agentId === input.agentId && task.prompt === input.prompt && task.nonce === input.nonce
    && task.issuedAt === input.issuedAt && task.expiresAt === input.expiresAt
    && JSON.stringify(task.dependencies) === JSON.stringify(dependencies)
    && (task.privateShareMessageId ?? undefined) === input.privateShareMessageId
    && task.requesterSignature === input.requesterSignature;
}

export function createAgentTask(
  db: Database,
  identity: ServerIdentity,
  input: CreateAgentTaskInput,
  now = new Date(),
): { task: AgentTask; created: boolean } {
  requireProjectMembership(db, input.projectId, input.requesterDeviceId);
  const dependencies = normalizeDependencies(input.dependencies, input.id);
  if ((input.inputArtifactIds?.length ?? 0) > 0) {
    throw new Error("Task input artifacts require project encryption");
  }
  const existing = taskById(db, input.id);
  if (existing) {
    if (!sameRequest(existing, input, dependencies)) throw new Error("Task ID was already used for a different request");
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
  for (const dependencyId of dependencies) {
    const dependency = db.query("SELECT project_id AS projectId FROM agent_tasks WHERE id = ?")
      .get(dependencyId) as { projectId: string } | null;
    if (!dependency || dependency.projectId !== input.projectId) throw new Error("Task dependency was not found in this project");
  }
  rejectDependencyCycle(db, input.projectId, input.id, dependencies);
  requireProjectMembership(db, input.projectId, agent.hostDeviceId);
  if (agent.hostDeviceId === input.requesterDeviceId && !input.privateShareMessageId) {
    throw new Error("Remote agent must be hosted by another device");
  }
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
    inputArtifactIds: [],
    privateShareMessageId: input.privateShareMessageId,
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
    inputArtifactIds: [],
    ...(input.privateShareMessageId ? { privateShareMessageId: input.privateShareMessageId } : {}),
  };
  const serverSignature = sign(null, agentDispatchSigningTranscript(unsigned), identity.privateKeyPem).toString("base64url");
  const { taskId: _signedTaskId, ...dispatch } = unsigned;
  const task: AgentTask = { ...dispatch, id: input.id, status: "queued", acceptedAt, serverSignature, dependencies, inputArtifactIds: [] };
  db.query(`INSERT INTO agent_tasks (
    id, project_id, requester_device_id, target_device_id, agent_id, prompt, nonce,
    issued_at, expires_at, requester_signature, server_signature, status, accepted_at, dependencies_json,
    private_share_message_id
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`).run(
    task.id, task.projectId, task.requesterDeviceId, task.targetDeviceId, task.agentId,
    task.prompt, task.nonce, task.issuedAt, task.expiresAt, task.requesterSignature,
    task.serverSignature, task.acceptedAt, JSON.stringify(dependencies), input.privateShareMessageId ?? null,
  );
  return { task, created: true };
}

export function expireQueuedAgentTasks(db: Database, now = new Date()): Array<{
  task: AgentTask;
  event: ChatEvent;
}> {
  const expired = db.query(`SELECT id, target_device_id AS targetDeviceId
    FROM agent_tasks WHERE status = 'queued' AND prompt_envelope_json IS NULL AND expires_at <= ?
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

export function pendingAgentTasks(db: Database, targetDeviceId: string, now = new Date(), agentId?: string): AgentTask[] {
  const agentFilter = agentId ? " AND t.agent_id = ?" : "";
  const rows = db.query(`SELECT t.id, t.project_id AS projectId, t.requester_device_id AS requesterDeviceId,
    t.target_device_id AS targetDeviceId, t.agent_id AS agentId, t.prompt, t.nonce,
    t.issued_at AS issuedAt, t.expires_at AS expiresAt, t.requester_signature AS requesterSignature,
    t.server_signature AS serverSignature, d.public_key_pem AS requesterPublicKeyPem,
    t.status, t.accepted_at AS acceptedAt, t.dependencies_json AS dependenciesJson
    FROM agent_tasks t
    JOIN devices d ON d.id = t.requester_device_id
    JOIN agents a ON a.id = t.agent_id
      AND a.project_id = t.project_id
      AND a.host_device_id = t.target_device_id
      AND a.enabled = 1
    WHERE t.target_device_id = ? AND t.prompt_envelope_json IS NULL
      AND EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = t.project_id AND pm.device_id = t.target_device_id)
      AND (t.status = 'running' OR (t.status = 'queued' AND t.expires_at > ?))
      ${agentFilter}
    ORDER BY t.accepted_at, t.id`).all(targetDeviceId, now.toISOString(), ...(agentId ? [agentId] : [])) as TaskRow[];
  return rows.map(row => {
    const { dependenciesJson, ...task } = row;
    return { ...task, dependencies: parseDependencies(dependenciesJson), inputArtifactIds: [] };
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

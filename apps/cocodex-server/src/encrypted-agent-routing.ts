import { createPublicKey, sign, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  agentEncryptedDispatchSigningTranscript,
  canonicalEd25519PublicKey,
  encryptedAgentResultEventSchema,
  encryptedAgentTaskSchema,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  type EncryptedAgentResultEvent,
  type EncryptedAgentTask,
  type ProjectContentEnvelope,
} from "../../../packages/cocodex-protocol/src/index.ts";
import type { ServerIdentity } from "./identity";
import { currentProjectKeyEpochForWrite } from "./project-encryption-storage";
import { encryptedArtifactsByIds } from "./encrypted-artifacts";
import { requireSharedChat } from "./shared-chats";
import { assertProjectUnlocked } from "./project-locks";

const MAX_CLOCK_SKEW_MS = 60_000;
const MAX_TASK_LIFETIME_MS = 5 * 60_000;
const MAX_PENDING_TASKS_PER_REQUESTER = 8;
const ENCRYPTED_PROMPT_PLACEHOLDER = "[encrypted]" as const;

export interface CreateEncryptedAgentTaskInput {
  id: string;
  projectId: string;
  chatId?: string;
  requesterDeviceId: string;
  agentId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  dependencies?: string[];
  inputArtifactIds?: string[];
  privateShareMessageId?: string;
  envelope: unknown;
}

export interface AppendEncryptedAgentResultInput {
  taskId: string;
  chatId?: string;
  eventId: string;
  targetDeviceId: string;
  envelope: unknown;
  final: boolean;
  status: "running" | "completed" | "failed";
}

export interface AppendEncryptedAgentResultOutput {
  task: EncryptedAgentTask;
  event: EncryptedAgentResultEvent;
  created: boolean;
}

export interface CancelEncryptedAgentTaskOutput {
  task: EncryptedAgentTask;
}

interface AgentRow { id: string; projectId: string; hostDeviceId: string; enabled: number; }
interface DeviceKeyRow { publicKeyPem: string; status: string; }
interface TaskRow {
  id: string;
  projectId: string;
  chatId: string;
  requesterDeviceId: string;
  targetDeviceId: string;
  agentId: string;
  prompt: string;
  promptEnvelopeJson: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  requesterSignature: string;
  requesterPublicKeyPem: string;
  serverSignature: string;
  status: EncryptedAgentTask["status"];
  acceptedAt: string;
  dependenciesJson: string;
  inputArtifactIdsJson: string;
  privateShareMessageId?: string;
}
interface EventRow {
  sequence: number;
  projectId: string;
  chatId: string;
  taskId: string;
  eventId: string;
  senderDeviceId: string;
  envelopeJson: string;
  final: number;
  status: "running" | "completed" | "failed";
  clientCreatedAt: string;
  acceptedAt: string;
}

function parseDependencies(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== "string")) {
    throw new Error("Stored encrypted task dependencies are invalid");
  }
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

function normalizeArtifactIds(value: string[] | undefined): string[] {
  const artifactIds = [...new Set(value ?? [])];
  if (artifactIds.length > 16) throw new Error("Too many task input artifacts");
  return artifactIds;
}

function rejectDependencyCycle(
  db: Database,
  projectId: string,
  chatId: string,
  taskId: string,
  dependencies: string[],
): void {
  const pending = [...dependencies];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const dependencyId = pending.pop()!;
    if (dependencyId === taskId) throw new Error("Task dependency would create a cycle");
    if (visited.has(dependencyId)) continue;
    visited.add(dependencyId);
    if (visited.size > 4_096) throw new Error("Task dependency graph is too large");
    const row = db.query(`
      SELECT project_id AS projectId, chat_id AS chatId, dependencies_json AS dependenciesJson
      FROM agent_tasks WHERE id = ?
    `).get(dependencyId) as { projectId: string; chatId: string; dependenciesJson: string } | null;
    if (!row) continue;
    if (row.projectId !== projectId || row.chatId !== chatId) {
      throw new Error("Task dependency graph crosses a shared-chat boundary");
    }
    pending.push(...parseDependencies(row.dependenciesJson));
  }
}

function envelopeJson(value: ProjectContentEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function parseEnvelope(value: string, projectId: string, chatId: string): ProjectContentEnvelope {
  try {
    const envelope = projectContentEnvelopeSchema.parse(JSON.parse(value));
    if (envelope.projectId !== projectId
      || (envelope.version === 1 ? chatId !== projectId : envelope.chatId !== chatId)) {
      throw new Error("Stored encrypted agent envelope is not bound to its shared chat");
    }
    return envelope;
  }
  catch { throw new Error("Stored encrypted agent envelope is invalid"); }
}

function verifyEnvelopeSender(db: Database, senderDeviceId: string, envelope: ProjectContentEnvelope): string {
  const device = db.query(`
    SELECT public_key_pem AS publicKeyPem FROM devices
    WHERE id = ? AND status = 'approved'
  `).get(senderDeviceId) as DeviceKeyRow | null;
  if (!device) throw new Error("Approved encrypted agent sender key was not found");
  let expected: string;
  let embedded: string;
  try {
    expected = canonicalEd25519PublicKey(device.publicKeyPem);
    embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem);
  } catch { throw new Error("Encrypted agent sender key is invalid"); }
  if (expected !== embedded) throw new Error("Encrypted agent sender key does not match the enrolled device");
  let valid = false;
  try {
    valid = verify(null, projectContentSigningTranscript({ ...envelope, senderPublicKeyPem: embedded }),
      createPublicKey(expected), Buffer.from(envelope.signature, "base64url"));
  } catch { valid = false; }
  if (!valid) throw new Error("Encrypted agent envelope signature is invalid");
  return expected;
}

function taskFromRow(db: Database, row: TaskRow): EncryptedAgentTask {
  const inputArtifactIds = parseDependencies(row.inputArtifactIdsJson);
  return encryptedAgentTaskSchema.parse({
    id: row.id,
    projectId: row.projectId,
    chatId: row.chatId,
    requesterDeviceId: row.requesterDeviceId,
    targetDeviceId: row.targetDeviceId,
    agentId: row.agentId,
    prompt: ENCRYPTED_PROMPT_PLACEHOLDER,
    promptEnvelope: parseEnvelope(row.promptEnvelopeJson, row.projectId, row.chatId),
    nonce: row.nonce,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
    dependencies: parseDependencies(row.dependenciesJson),
    inputArtifactIds,
    inputArtifacts: encryptedArtifactsByIds(db, row.projectId, row.chatId, inputArtifactIds),
    ...(row.privateShareMessageId ? { privateShareMessageId: row.privateShareMessageId } : {}),
    requesterSignature: row.requesterSignature,
    requesterPublicKeyPem: row.requesterPublicKeyPem,
    serverSignature: row.serverSignature,
    status: row.status,
    acceptedAt: row.acceptedAt,
  });
}

function readTask(db: Database, id: string): TaskRow | null {
  return db.query(`
    SELECT t.id, t.project_id AS projectId, t.chat_id AS chatId,
      t.requester_device_id AS requesterDeviceId,
      t.target_device_id AS targetDeviceId, t.agent_id AS agentId, t.prompt,
      t.prompt_envelope_json AS promptEnvelopeJson, t.nonce, t.issued_at AS issuedAt,
      t.expires_at AS expiresAt, t.requester_signature AS requesterSignature,
      t.server_signature AS serverSignature, d.public_key_pem AS requesterPublicKeyPem,
      t.status, t.accepted_at AS acceptedAt, t.dependencies_json AS dependenciesJson,
      t.input_artifact_ids_json AS inputArtifactIdsJson,
      t.private_share_message_id AS privateShareMessageId
    FROM agent_tasks t JOIN devices d ON d.id = t.requester_device_id
    WHERE t.id = ? AND t.prompt_envelope_json IS NOT NULL
  `).get(id) as TaskRow | null;
}

function sameTaskRequest(task: EncryptedAgentTask, input: CreateEncryptedAgentTaskInput, envelope: ProjectContentEnvelope, dependencies: string[], inputArtifactIds: string[]): boolean {
  return task.projectId === input.projectId && task.requesterDeviceId === input.requesterDeviceId
    && task.chatId === (input.chatId ?? input.projectId)
    && task.agentId === input.agentId && task.nonce === input.nonce
    && task.issuedAt === input.issuedAt && task.expiresAt === input.expiresAt
    && JSON.stringify(task.dependencies) === JSON.stringify(dependencies)
    && JSON.stringify(task.inputArtifactIds) === JSON.stringify(inputArtifactIds)
    && task.privateShareMessageId === input.privateShareMessageId
    && task.promptEnvelope && envelopeJson(task.promptEnvelope) === envelopeJson(envelope);
}

export function createEncryptedAgentTask(
  db: Database,
  identity: ServerIdentity,
  input: CreateEncryptedAgentTaskInput,
  now = new Date(),
): { task: EncryptedAgentTask; created: boolean } {
  assertProjectUnlocked(db, input.projectId);
  const chatId = input.chatId ?? input.projectId;
  requireSharedChat(db, input.projectId, chatId, input.requesterDeviceId);
  const dependencies = normalizeDependencies(input.dependencies, input.id);
  const inputArtifactIds = normalizeArtifactIds(input.inputArtifactIds);
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (input.chatId !== undefined && envelope.version !== 2) throw new Error("Encrypted agent prompt must use a chat-bound v2 envelope");
  if (envelope.projectId !== input.projectId) throw new Error("Encrypted agent prompt belongs to another project");
  if (envelope.version === 2 && envelope.chatId !== chatId) throw new Error("Encrypted agent prompt belongs to another shared chat");
  if (envelope.recordType !== "task") throw new Error("Encrypted agent prompt must use the task record type");
  if (envelope.recordId !== input.id) throw new Error("Encrypted agent prompt record ID must match the task ID");
  if (envelope.senderDeviceId !== input.requesterDeviceId) throw new Error("Encrypted agent prompt sender does not match the requester");
  if (envelope.keyEpoch !== currentProjectKeyEpochForWrite(db, input.projectId)) {
    throw new Error("Encrypted agent prompt must use the current project key epoch");
  }
  verifyEnvelopeSender(db, input.requesterDeviceId, envelope);

  const existing = readTask(db, input.id);
  if (existing) {
    const task = taskFromRow(db, existing);
    if (!sameTaskRequest(task, input, envelope, dependencies, inputArtifactIds)) throw new Error("Task ID was already used for a different request");
    return { task, created: false };
  }
  if (db.query("SELECT 1 FROM agent_tasks WHERE id = ?").get(input.id)) {
    throw new Error("Task ID was already used for a different request");
  }
  const issued = Date.parse(input.issuedAt);
  const expires = Date.parse(input.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) throw new Error("Invalid task lifetime");
  if (issued > now.getTime() + MAX_CLOCK_SKEW_MS) throw new Error("Task issue time is too far in the future");
  if (expires <= now.getTime() || expires - issued > MAX_TASK_LIFETIME_MS) throw new Error("Task is expired or lives too long");
  const agent = db.query("SELECT id, project_id AS projectId, host_device_id AS hostDeviceId, enabled FROM agents WHERE id = ?")
    .get(input.agentId) as AgentRow | null;
  if (!agent || agent.projectId !== input.projectId || agent.enabled !== 1) throw new Error("Agent is not available in this project");
  for (const dependencyId of dependencies) {
    const dependency = db.query("SELECT project_id AS projectId, chat_id AS chatId FROM agent_tasks WHERE id = ?")
      .get(dependencyId) as { projectId: string; chatId: string } | null;
    if (!dependency || dependency.projectId !== input.projectId || dependency.chatId !== chatId) {
      throw new Error("Task dependency was not found in this shared chat");
    }
  }
  rejectDependencyCycle(db, input.projectId, chatId, input.id, dependencies);
  encryptedArtifactsByIds(db, input.projectId, chatId, inputArtifactIds);
  requireSharedChat(db, input.projectId, chatId, agent.hostDeviceId);
  if (agent.hostDeviceId === input.requesterDeviceId && !input.privateShareMessageId) {
    throw new Error("Remote agent must be hosted by another device");
  }
  const requester = db.query("SELECT public_key_pem AS publicKeyPem, status FROM devices WHERE id = ?")
    .get(input.requesterDeviceId) as DeviceKeyRow | null;
  if (!requester || requester.status !== "approved") throw new Error("Requester device is not approved");
  const pending = db.query(`SELECT COUNT(*) AS count FROM agent_tasks
    WHERE requester_device_id = ? AND (status = 'running' OR (status = 'queued' AND expires_at > ?))`)
    .get(input.requesterDeviceId, now.toISOString()) as { count: number };
  if (pending.count >= MAX_PENDING_TASKS_PER_REQUESTER) throw new Error("Requester has too many pending agent tasks");

  const unsigned = {
    taskId: input.id,
    projectId: input.projectId,
    chatId,
    agentId: input.agentId,
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    requesterDeviceId: input.requesterDeviceId,
    targetDeviceId: agent.hostDeviceId,
    dependencies,
    inputArtifactIds,
    envelopeProjectId: envelope.projectId,
    envelopeKeyEpoch: envelope.keyEpoch,
    envelopeRecordId: envelope.recordId,
    envelopeNonce: envelope.nonce,
    envelopeCiphertext: envelope.ciphertext,
    envelopeSenderDeviceId: envelope.senderDeviceId,
    envelopeSenderPublicKeyPem: envelope.senderPublicKeyPem,
    envelopeSignature: envelope.signature,
    ...(input.privateShareMessageId ? { privateShareMessageId: input.privateShareMessageId } : {}),
  };
  const serverSignature = signDispatch(identity.privateKeyPem, unsigned);
  const acceptedAt = now.toISOString();
  return db.transaction(() => {
    assertProjectUnlocked(db, input.projectId);
    db.query(`INSERT INTO agent_tasks (
      id, project_id, chat_id, requester_device_id, target_device_id, agent_id, prompt,
      prompt_envelope_json, nonce, issued_at, expires_at, requester_signature,
      server_signature, status, accepted_at, dependencies_json, input_artifact_ids_json, private_share_message_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)`).run(
      input.id, input.projectId, chatId, input.requesterDeviceId, agent.hostDeviceId, input.agentId,
      ENCRYPTED_PROMPT_PLACEHOLDER, envelopeJson(envelope), input.nonce, input.issuedAt,
      input.expiresAt, envelope.signature, serverSignature, acceptedAt, JSON.stringify(dependencies),
      JSON.stringify(inputArtifactIds), input.privateShareMessageId ?? null,
    );
    return { task: taskFromRow(db, readTask(db, input.id)!), created: true };
  }).immediate();
}

function signDispatch(privateKeyPem: string, input: Parameters<typeof agentEncryptedDispatchSigningTranscript>[0]): string {
  return sign(null, agentEncryptedDispatchSigningTranscript(input), privateKeyPem).toString("base64url");
}

export function pendingEncryptedAgentTasks(db: Database, targetDeviceId: string, now = new Date(), agentId?: string): EncryptedAgentTask[] {
  const agentFilter = agentId ? " AND t.agent_id = ?" : "";
  const rows = db.query(`
    SELECT t.id, t.project_id AS projectId, t.chat_id AS chatId,
      t.requester_device_id AS requesterDeviceId,
      t.target_device_id AS targetDeviceId, t.agent_id AS agentId, t.prompt,
      t.prompt_envelope_json AS promptEnvelopeJson, t.nonce, t.issued_at AS issuedAt,
      t.expires_at AS expiresAt, t.requester_signature AS requesterSignature,
      t.server_signature AS serverSignature, d.public_key_pem AS requesterPublicKeyPem,
      t.status, t.accepted_at AS acceptedAt, t.dependencies_json AS dependenciesJson,
      t.input_artifact_ids_json AS inputArtifactIdsJson,
      t.private_share_message_id AS privateShareMessageId
    FROM agent_tasks t
    JOIN devices d ON d.id = t.requester_device_id
    JOIN agents a ON a.id = t.agent_id
      AND a.project_id = t.project_id
      AND a.host_device_id = t.target_device_id
      AND a.enabled = 1
    JOIN project_lock_state pls ON pls.project_id = t.project_id AND pls.state = 'active'
    JOIN shared_chats c ON c.id = t.chat_id
      AND c.project_id = t.project_id
      AND c.state = 'active'
    WHERE t.target_device_id = ? AND t.prompt_envelope_json IS NOT NULL
      AND EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = t.project_id AND pm.device_id = t.target_device_id)
      AND EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = t.project_id AND pm.device_id = t.requester_device_id)
      AND (t.status = 'running' OR (t.status = 'queued' AND t.expires_at > ?))
      ${agentFilter}
    ORDER BY t.accepted_at, t.id
  `).all(targetDeviceId, now.toISOString(), ...(agentId ? [agentId] : [])) as TaskRow[];
  return rows.map(row => taskFromRow(db, row)).filter(task => task.dependencies.every(dependencyId => {
    const dependency = db.query(`
      SELECT status FROM agent_tasks
      WHERE id = ? AND project_id = ? AND chat_id = ?
    `).get(dependencyId, task.projectId, task.chatId) as { status: string } | null;
    return dependency?.status === "completed";
  }));
}

export function isEncryptedAgentTask(db: Database, taskId: string): boolean {
  return Boolean(db.query("SELECT 1 FROM agent_tasks WHERE id = ? AND prompt_envelope_json IS NOT NULL").get(taskId));
}

/**
 * Validate an encrypted-task cancellation without fabricating a plaintext
 * result. The host client must produce the encrypted terminal event so the
 * result remains attributable to the device that owns the local execution.
 */
export function cancelEncryptedAgentTask(
  db: Database,
  actorDeviceId: string,
  taskId: string,
): CancelEncryptedAgentTaskOutput {
  const row = readTask(db, taskId);
  if (!row) throw new Error("Encrypted agent task was not found");
  if (row.requesterDeviceId !== actorDeviceId && row.targetDeviceId !== actorDeviceId) {
    throw new Error("Only the requester or host device can cancel this task");
  }
  requireSharedChat(db, row.projectId, row.chatId, actorDeviceId);
  if (row.status === "completed" || row.status === "failed") {
    throw new Error("Agent task is already final");
  }
  return { task: taskFromRow(db, row) };
}

function resultFromRow(row: EventRow): EncryptedAgentResultEvent {
  return encryptedAgentResultEventSchema.parse({
    sequence: row.sequence,
    projectId: row.projectId,
    chatId: row.chatId,
    taskId: row.taskId,
    eventId: row.eventId,
    senderDeviceId: row.senderDeviceId,
    envelope: parseEnvelope(row.envelopeJson, row.projectId, row.chatId),
    final: Boolean(row.final),
    status: row.status,
    clientCreatedAt: row.clientCreatedAt,
    acceptedAt: row.acceptedAt,
  });
}

export function appendEncryptedAgentResult(
  db: Database,
  input: AppendEncryptedAgentResultInput,
  now = new Date(),
): AppendEncryptedAgentResultOutput {
  const taskRow = readTask(db, input.taskId);
  if (!taskRow || taskRow.targetDeviceId !== input.targetDeviceId) throw new Error("Encrypted agent task is not assigned to this device");
  assertProjectUnlocked(db, taskRow.projectId);
  if (taskRow.chatId !== (input.chatId ?? taskRow.projectId)) throw new Error("Encrypted agent task belongs to another shared chat");
  requireSharedChat(db, taskRow.projectId, taskRow.chatId, input.targetDeviceId);
  if (input.final !== (input.status === "completed" || input.status === "failed")) {
    throw new Error("Encrypted agent result final flag and status disagree");
  }
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (input.chatId !== undefined && envelope.version !== 2) throw new Error("Encrypted agent result must use a chat-bound v2 envelope");
  if (envelope.projectId !== taskRow.projectId) throw new Error("Encrypted agent result belongs to another project");
  if (envelope.version === 2 && envelope.chatId !== taskRow.chatId) throw new Error("Encrypted agent result belongs to another shared chat");
  if (envelope.recordType !== "agent-response") throw new Error("Encrypted agent result must use the agent-response record type");
  if (envelope.recordId !== input.eventId) throw new Error("Encrypted agent result record ID must match the event ID");
  if (envelope.senderDeviceId !== input.targetDeviceId) throw new Error("Encrypted agent result sender does not match the host device");
  if (envelope.keyEpoch !== currentProjectKeyEpochForWrite(db, taskRow.projectId)) throw new Error("Encrypted agent result must use the current project key epoch");
  verifyEnvelopeSender(db, input.targetDeviceId, envelope);
  const serialized = envelopeJson(envelope);
  return db.transaction(() => {
    assertProjectUnlocked(db, taskRow.projectId);
    const existing = db.query(`
      SELECT sequence, project_id AS projectId, chat_id AS chatId,
        task_id AS taskId, event_id AS eventId,
        sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
        final, status, client_created_at AS clientCreatedAt, accepted_at AS acceptedAt
      FROM project_chat_events WHERE event_id = ?
    `).get(input.eventId) as EventRow | null;
    if (existing) {
      if (existing.projectId !== taskRow.projectId || existing.chatId !== taskRow.chatId
        || existing.taskId !== input.taskId
        || existing.senderDeviceId !== input.targetDeviceId || existing.envelopeJson !== serialized
        || Boolean(existing.final) !== input.final || existing.status !== input.status) {
        throw new Error("Encrypted agent result event ID was reused with different content");
      }
      return { task: taskFromRow(db, { ...taskRow, status: input.status }), event: resultFromRow(existing), created: false };
    }
    if (taskRow.status === "completed" || taskRow.status === "failed") throw new Error("Encrypted agent task is already final");
    const acceptedAt = now.toISOString();
    const result = db.query(`INSERT INTO project_chat_events (
      project_id, chat_id, event_id, sender_device_id, envelope_json, client_created_at,
      accepted_at, task_id, final, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      taskRow.projectId, taskRow.chatId, input.eventId, input.targetDeviceId, serialized, acceptedAt,
      acceptedAt, input.taskId, input.final ? 1 : 0, input.status,
    );
    db.query(`UPDATE agent_tasks SET status = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END WHERE id = ?`)
      .run(input.status, input.final ? 1 : 0, acceptedAt, input.taskId);
    const row = db.query(`
      SELECT sequence, project_id AS projectId, chat_id AS chatId,
        task_id AS taskId, event_id AS eventId,
        sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
        final, status, client_created_at AS clientCreatedAt, accepted_at AS acceptedAt
      FROM project_chat_events WHERE sequence = ?
    `).get(Number(result.lastInsertRowid)) as EventRow;
    return { task: taskFromRow(db, { ...taskRow, status: input.status }), event: resultFromRow(row), created: true };
  }).immediate();
}

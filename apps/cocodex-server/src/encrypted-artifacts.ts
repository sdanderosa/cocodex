import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  encryptedArtifactSchema,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  type EncryptedArtifact,
  type ProjectContentEnvelope,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { currentProjectKeyEpochForWrite } from "./project-encryption-storage";
import { requireSharedChat } from "./shared-chats";
import { assertProjectUnlocked } from "./project-locks";

export interface AppendEncryptedArtifactInput {
  artifactId: string;
  projectId: string;
  chatId?: string;
  taskId: string | null;
  authorDeviceId: string;
  envelope: unknown;
}

export interface AppendEncryptedArtifactResult {
  artifact: EncryptedArtifact;
  created: boolean;
}

interface DeviceKeyRow { publicKeyPem: string; }
interface ArtifactRow {
  id: string;
  projectId: string;
  chatId: string;
  taskId: string | null;
  authorDeviceId: string;
  envelopeJson: string;
  createdAt: string;
  updatedAt: string;
}

function envelopeJson(value: ProjectContentEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function parseEnvelope(value: string): ProjectContentEnvelope {
  try { return projectContentEnvelopeSchema.parse(JSON.parse(value)); }
  catch { throw new Error("Stored encrypted artifact envelope is invalid"); }
}

function verifyEnvelopeSender(db: Database, senderDeviceId: string, envelope: ProjectContentEnvelope): void {
  const device = db.query(`
    SELECT public_key_pem AS publicKeyPem FROM devices
    WHERE id = ? AND status = 'approved'
  `).get(senderDeviceId) as DeviceKeyRow | null;
  if (!device) throw new Error("Approved artifact sender key was not found");
  let expected: string;
  let embedded: string;
  try {
    expected = canonicalEd25519PublicKey(device.publicKeyPem);
    embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem);
  } catch { throw new Error("Encrypted artifact sender key is invalid"); }
  if (expected !== embedded) throw new Error("Encrypted artifact sender key does not match the enrolled device");
  let valid = false;
  try {
    valid = verify(null, projectContentSigningTranscript({ ...envelope, senderPublicKeyPem: embedded }),
      createPublicKey(expected), Buffer.from(envelope.signature, "base64url"));
  } catch { valid = false; }
  if (!valid) throw new Error("Encrypted artifact envelope signature is invalid");
}

function artifactFromRow(row: ArtifactRow): EncryptedArtifact {
  return encryptedArtifactSchema.parse({
    artifactId: row.id,
    projectId: row.projectId,
    chatId: row.chatId,
    taskId: row.taskId,
    authorDeviceId: row.authorDeviceId,
    envelope: parseEnvelope(row.envelopeJson),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

export function publishEncryptedArtifact(
  db: Database,
  input: AppendEncryptedArtifactInput,
  now = new Date(),
): AppendEncryptedArtifactResult {
  assertProjectUnlocked(db, input.projectId);
  const chatId = input.chatId ?? input.projectId;
  requireSharedChat(db, input.projectId, chatId, input.authorDeviceId);
  if (input.taskId) {
    const task = db.query("SELECT project_id AS projectId, chat_id AS chatId, target_device_id AS targetDeviceId FROM agent_tasks WHERE id = ?")
      .get(input.taskId) as { projectId: string; chatId: string; targetDeviceId: string } | null;
    if (!task || task.projectId !== input.projectId || task.chatId !== chatId) throw new Error("Artifact task is not in this shared chat");
    if (task.targetDeviceId !== input.authorDeviceId) {
      throw new Error("Task-linked artifact must be published by the task target device");
    }
  }
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (input.chatId !== undefined && envelope.version !== 2) throw new Error("New encrypted artifacts require a chat-bound content envelope");
  if (envelope.projectId !== input.projectId) throw new Error("Encrypted artifact belongs to another project");
  if (envelope.version === 2 && envelope.chatId !== chatId) throw new Error("Encrypted artifact belongs to another shared chat");
  if (envelope.recordType !== "artifact") throw new Error("Encrypted artifact envelope must use the artifact record type");
  if (envelope.recordId !== input.artifactId) throw new Error("Encrypted artifact record ID must match the artifact ID");
  if (envelope.senderDeviceId !== input.authorDeviceId) throw new Error("Encrypted artifact sender does not match the authenticated device");
  if (envelope.keyEpoch !== currentProjectKeyEpochForWrite(db, input.projectId)) {
    throw new Error("Encrypted artifact envelope must use the current project key epoch");
  }
  verifyEnvelopeSender(db, input.authorDeviceId, envelope);
  const serialized = envelopeJson(envelope);
  const existing = db.query(`
    SELECT id, project_id AS projectId, chat_id AS chatId, task_id AS taskId, author_device_id AS authorDeviceId,
      envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
    FROM project_artifacts WHERE id = ?
  `).get(input.artifactId) as ArtifactRow | null;
  if (existing) {
    if (existing.projectId !== input.projectId || existing.chatId !== chatId || existing.taskId !== input.taskId
      || existing.authorDeviceId !== input.authorDeviceId || existing.envelopeJson !== serialized) {
      throw new Error("Encrypted artifact ID was already used for different content");
    }
    return { artifact: artifactFromRow(existing), created: false };
  }
  const timestamp = now.toISOString();
  return db.transaction(() => {
    assertProjectUnlocked(db, input.projectId);
    db.query(`
      INSERT INTO project_artifacts (id, project_id, chat_id, task_id, author_device_id, envelope_json, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(input.artifactId, input.projectId, chatId, input.taskId, input.authorDeviceId, serialized, timestamp, timestamp);
    return {
      artifact: artifactFromRow({
        id: input.artifactId,
        projectId: input.projectId,
        chatId,
        taskId: input.taskId,
        authorDeviceId: input.authorDeviceId,
        envelopeJson: serialized,
        createdAt: timestamp,
        updatedAt: timestamp,
      }),
      created: true,
    };
  }).immediate();
}

export function listEncryptedArtifacts(
  db: Database,
  projectId: string,
  chatIdOrDeviceId: string,
  maybeDeviceId?: string,
): EncryptedArtifact[] {
  const chatId = maybeDeviceId ? chatIdOrDeviceId : projectId;
  const deviceId = maybeDeviceId ?? chatIdOrDeviceId;
  requireSharedChat(db, projectId, chatId, deviceId);
  const rows = db.query(`
    SELECT id, project_id AS projectId, chat_id AS chatId, task_id AS taskId, author_device_id AS authorDeviceId,
      envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
    FROM project_artifacts WHERE project_id = ? AND chat_id = ? ORDER BY created_at, id LIMIT 500
  `).all(projectId, chatId) as ArtifactRow[];
  return rows.map(artifactFromRow);
}

/** Resolve an exact, ordered set of immutable encrypted artifacts for dispatch. */
export function encryptedArtifactsByIds(
  db: Database,
  projectId: string,
  chatIdOrArtifactIds: string | readonly string[],
  maybeArtifactIds?: readonly string[],
): EncryptedArtifact[] {
  const chatId = typeof chatIdOrArtifactIds === "string" ? chatIdOrArtifactIds : projectId;
  const artifactIds = typeof chatIdOrArtifactIds === "string" ? (maybeArtifactIds ?? []) : chatIdOrArtifactIds;
  return artifactIds.map(artifactId => {
    const row = db.query(`
      SELECT id, project_id AS projectId, chat_id AS chatId, task_id AS taskId, author_device_id AS authorDeviceId,
        envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
      FROM project_artifacts WHERE id = ?
    `).get(artifactId) as ArtifactRow | null;
    if (!row || row.projectId !== projectId || row.chatId !== chatId) {
      throw new Error("Task input artifact was not found in this shared chat");
    }
    return artifactFromRow(row);
  });
}

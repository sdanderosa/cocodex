import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  type ProjectContentEnvelope,
} from "@cocodex/protocol";
import { requireProjectMembership } from "./shared-state";
import { currentProjectKeyEpochForWrite } from "./project-encryption-storage";

/**
 * The server-side chat path stores only the signed opaque project envelope.
 * It never parses or decrypts the chat payload; clients with an enrolled
 * project key turn the envelope back into a UI event locally.
 */
export interface EncryptedChatEvent {
  sequence: number;
  projectId: string;
  eventId: string;
  senderDeviceId: string;
  envelope: ProjectContentEnvelope;
  clientCreatedAt: string;
  acceptedAt: string;
  taskId?: string;
  final?: boolean;
  status?: "running" | "completed" | "failed";
}

export interface AppendEncryptedChatInput {
  projectId: string;
  eventId: string;
  senderDeviceId: string;
  envelope: unknown;
  clientCreatedAt: string;
}

export interface AppendEncryptedChatResult {
  event: EncryptedChatEvent;
  created: boolean;
}

interface DeviceKeyRow {
  publicKeyPem: string;
}

interface EventRow {
  sequence: number;
  projectId: string;
  eventId: string;
  senderDeviceId: string;
  envelopeJson: string;
  clientCreatedAt: string;
  acceptedAt: string;
  taskId: string | null;
  final: number;
  status: "chat" | "running" | "completed" | "failed";
}

function envelopeJson(value: ProjectContentEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function parseEnvelope(value: string): ProjectContentEnvelope {
  try {
    return projectContentEnvelopeSchema.parse(JSON.parse(value));
  } catch {
    throw new Error("Stored encrypted chat envelope is invalid");
  }
}

function verifyEnvelopeSender(
  db: Database,
  senderDeviceId: string,
  envelope: ProjectContentEnvelope,
): void {
  const device = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices
    WHERE id = ? AND status = 'approved'
  `).get(senderDeviceId) as DeviceKeyRow | null;
  if (!device) throw new Error("Approved chat sender key was not found");
  let expected: string;
  let embedded: string;
  try {
    expected = canonicalEd25519PublicKey(device.publicKeyPem);
    embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem);
  } catch {
    throw new Error("Encrypted chat sender key is invalid");
  }
  if (expected !== embedded) throw new Error("Encrypted chat sender key does not match the enrolled device");
  let valid = false;
  try {
    valid = verify(
      null,
      projectContentSigningTranscript({ ...envelope, senderPublicKeyPem: embedded }),
      createPublicKey(expected),
      Buffer.from(envelope.signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Encrypted chat envelope signature is invalid");
}

function eventFromRow(row: EventRow): EncryptedChatEvent {
  if (row.taskId && row.status === "chat") throw new Error("Stored encrypted agent result metadata is invalid");
  const taskMetadata: Pick<EncryptedChatEvent, "taskId" | "final" | "status"> = row.taskId
    ? { taskId: row.taskId, final: Boolean(row.final), status: row.status as "running" | "completed" | "failed" }
    : {};
  return {
    sequence: row.sequence,
    projectId: row.projectId,
    eventId: row.eventId,
    senderDeviceId: row.senderDeviceId,
    envelope: parseEnvelope(row.envelopeJson),
    clientCreatedAt: row.clientCreatedAt,
    acceptedAt: row.acceptedAt,
    ...taskMetadata,
  };
}

function assertClientTimestamp(value: string): void {
  if (!Number.isFinite(new Date(value).getTime())) throw new Error("Invalid client creation time");
}

export function appendEncryptedChatEventResult(
  db: Database,
  input: AppendEncryptedChatInput,
  now = new Date(),
): AppendEncryptedChatResult {
  requireProjectMembership(db, input.projectId, input.senderDeviceId);
  assertClientTimestamp(input.clientCreatedAt);
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (envelope.projectId !== input.projectId) throw new Error("Encrypted chat belongs to another project");
  if (envelope.recordType !== "chat") throw new Error("Encrypted chat envelope must use the chat record type");
  if (envelope.recordId !== input.eventId) throw new Error("Encrypted chat record ID must match the event ID");
  if (envelope.senderDeviceId !== input.senderDeviceId) throw new Error("Encrypted chat sender does not match the authenticated device");
  const currentEpoch = currentProjectKeyEpochForWrite(db, input.projectId);
  if (envelope.keyEpoch !== currentEpoch) {
    throw new Error(`Encrypted chat envelope must use the current project key epoch ${currentEpoch}`);
  }
  verifyEnvelopeSender(db, input.senderDeviceId, envelope);
  const serialized = envelopeJson(envelope);
  const existing = db.query(`
    SELECT sequence, project_id AS projectId, event_id AS eventId,
      sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
      client_created_at AS clientCreatedAt, accepted_at AS acceptedAt,
      task_id AS taskId, final, status
    FROM project_chat_events
    WHERE event_id = ?
  `).get(input.eventId) as EventRow | null;
  if (existing) {
    if (existing.projectId !== input.projectId
      || existing.senderDeviceId !== input.senderDeviceId
      || existing.clientCreatedAt !== input.clientCreatedAt
      || existing.envelopeJson !== serialized) {
      throw new Error("Encrypted chat event ID was already used with different content");
    }
    return { event: eventFromRow(existing), created: false };
  }
  const result = db.query(`
    INSERT INTO project_chat_events (
      project_id, event_id, sender_device_id, envelope_json,
      client_created_at, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    input.projectId,
    input.eventId,
    input.senderDeviceId,
    serialized,
    input.clientCreatedAt,
    now.toISOString(),
  );
  const row = db.query(`
    SELECT sequence, project_id AS projectId, event_id AS eventId,
      sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
      client_created_at AS clientCreatedAt, accepted_at AS acceptedAt,
      task_id AS taskId, final, status
    FROM project_chat_events WHERE sequence = ?
  `).get(Number(result.lastInsertRowid)) as EventRow;
  return { event: eventFromRow(row), created: true };
}

export function encryptedChatEventsAfter(
  db: Database,
  projectId: string,
  deviceId: string,
  afterSequence: number,
  limit = 500,
): EncryptedChatEvent[] {
  requireProjectMembership(db, projectId, deviceId);
  const boundedLimit = Math.max(1, Math.min(500, Math.trunc(limit)));
  const rows = db.query(`
    SELECT sequence, project_id AS projectId, event_id AS eventId,
      sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
      client_created_at AS clientCreatedAt, accepted_at AS acceptedAt,
      task_id AS taskId, final, status
    FROM project_chat_events
    WHERE project_id = ? AND sequence > ?
    ORDER BY sequence ASC
    LIMIT ?
  `).all(projectId, afterSequence, boundedLimit) as EventRow[];
  return rows.map(eventFromRow);
}

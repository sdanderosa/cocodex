import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  type ProjectContentEnvelope,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { currentProjectKeyEpochForWrite } from "./project-encryption-storage";
import { requireSharedChat } from "./shared-chats";

/** Opaque, ordered Yjs updates. The server never applies the Yjs payload. */
export interface EncryptedPromptUpdate {
  sequence: number;
  projectId: string;
  chatId: string;
  updateId: string;
  senderDeviceId: string;
  envelope: ProjectContentEnvelope;
  acceptedAt: string;
}

export interface AppendEncryptedPromptInput {
  projectId: string;
  chatId: string;
  updateId: string;
  senderDeviceId: string;
  envelope: unknown;
}

export interface AppendEncryptedPromptResult {
  update: EncryptedPromptUpdate;
  created: boolean;
}

interface DeviceKeyRow { publicKeyPem: string }
interface UpdateRow {
  sequence: number;
  projectId: string;
  chatId: string;
  updateId: string;
  senderDeviceId: string;
  envelopeJson: string;
  acceptedAt: string;
}

function envelopeJson(value: ProjectContentEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function parseEnvelope(value: string): ProjectContentEnvelope {
  try { return projectContentEnvelopeSchema.parse(JSON.parse(value)); }
  catch { throw new Error("Stored encrypted prompt envelope is invalid"); }
}

function verifySender(db: Database, senderDeviceId: string, envelope: ProjectContentEnvelope): void {
  const row = db.query(`
    SELECT public_key_pem AS publicKeyPem FROM devices WHERE id = ? AND status = 'approved'
  `).get(senderDeviceId) as DeviceKeyRow | null;
  if (!row) throw new Error("Approved prompt sender key was not found");
  let expected: string;
  let embedded: string;
  try {
    expected = canonicalEd25519PublicKey(row.publicKeyPem);
    embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem);
  } catch { throw new Error("Encrypted prompt sender key is invalid"); }
  if (expected !== embedded) throw new Error("Encrypted prompt sender key does not match the enrolled device");
  let valid = false;
  try {
    valid = verify(
      null,
      projectContentSigningTranscript({ ...envelope, senderPublicKeyPem: embedded }),
      createPublicKey(expected),
      Buffer.from(envelope.signature, "base64url"),
    );
  } catch { valid = false; }
  if (!valid) throw new Error("Encrypted prompt envelope signature is invalid");
}

function updateFromRow(row: UpdateRow): EncryptedPromptUpdate {
  return {
    sequence: row.sequence,
    projectId: row.projectId,
    chatId: row.chatId,
    updateId: row.updateId,
    senderDeviceId: row.senderDeviceId,
    envelope: parseEnvelope(row.envelopeJson),
    acceptedAt: row.acceptedAt,
  };
}

export function appendEncryptedPromptUpdateResult(
  db: Database,
  input: AppendEncryptedPromptInput,
  now = new Date(),
): AppendEncryptedPromptResult {
  requireSharedChat(db, input.projectId, input.chatId, input.senderDeviceId);
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (envelope.version !== 2) throw new Error("New encrypted prompt updates require a chat-bound content envelope");
  if (envelope.projectId !== input.projectId) throw new Error("Encrypted prompt belongs to another project");
  if (envelope.chatId !== input.chatId) throw new Error("Encrypted prompt belongs to another shared chat");
  if (envelope.recordType !== "shared-prompt") throw new Error("Encrypted prompt envelope must use the shared-prompt record type");
  if (envelope.recordId !== input.updateId) throw new Error("Encrypted prompt record ID must match the update ID");
  if (envelope.senderDeviceId !== input.senderDeviceId) throw new Error("Encrypted prompt sender does not match the authenticated device");
  const currentEpoch = currentProjectKeyEpochForWrite(db, input.projectId);
  if (envelope.keyEpoch !== currentEpoch) throw new Error(`Encrypted prompt envelope must use the current project key epoch ${currentEpoch}`);
  verifySender(db, input.senderDeviceId, envelope);
  const serialized = envelopeJson(envelope);
  const existing = db.query(`
    SELECT sequence, project_id AS projectId, chat_id AS chatId, update_id AS updateId,
      sender_device_id AS senderDeviceId, envelope_json AS envelopeJson, accepted_at AS acceptedAt
    FROM project_prompt_updates WHERE update_id = ?
  `).get(input.updateId) as UpdateRow | null;
  if (existing) {
    if (existing.projectId !== input.projectId || existing.chatId !== input.chatId
      || existing.senderDeviceId !== input.senderDeviceId || existing.envelopeJson !== serialized) {
      throw new Error("Encrypted prompt update ID was already used with different content");
    }
    return { update: updateFromRow(existing), created: false };
  }
  const result = db.query(`
    INSERT INTO project_prompt_updates (
      project_id, chat_id, update_id, sender_device_id, envelope_json, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(input.projectId, input.chatId, input.updateId, input.senderDeviceId, serialized, now.toISOString());
  const row = db.query(`
    SELECT sequence, project_id AS projectId, chat_id AS chatId, update_id AS updateId,
      sender_device_id AS senderDeviceId, envelope_json AS envelopeJson, accepted_at AS acceptedAt
    FROM project_prompt_updates WHERE sequence = ?
  `).get(Number(result.lastInsertRowid)) as UpdateRow;
  return { update: updateFromRow(row), created: true };
}

export function encryptedPromptUpdatesAfter(
  db: Database,
  projectId: string,
  chatId: string,
  deviceId: string,
  afterSequence: number,
  limit = 500,
): EncryptedPromptUpdate[] {
  requireSharedChat(db, projectId, chatId, deviceId);
  const boundedLimit = Math.max(1, Math.min(500, Math.trunc(limit)));
  const rows = db.query(`
    SELECT sequence, project_id AS projectId, chat_id AS chatId, update_id AS updateId,
      sender_device_id AS senderDeviceId, envelope_json AS envelopeJson, accepted_at AS acceptedAt
    FROM project_prompt_updates
    WHERE project_id = ? AND chat_id = ? AND sequence > ?
    ORDER BY sequence ASC LIMIT ?
  `).all(projectId, chatId, afterSequence, boundedLimit) as UpdateRow[];
  return rows.map(updateFromRow);
}

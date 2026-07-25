import { createHash } from "node:crypto";
import type { Database } from "bun:sqlite";
import type { PrivateMessageEnvelope } from "@cocodex/protocol";

interface DeviceStatusRow {
  status: "pending" | "approved" | "revoked";
}

function requireApprovedDevice(db: Database, deviceId: string): void {
  const row = db.query("SELECT status FROM devices WHERE id = ?").get(deviceId) as DeviceStatusRow | null;
  if (!row || row.status !== "approved") throw new Error("Private-message device is not approved");
}

export interface AppendPrivateMessageInput {
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  ciphertext: string;
  clientCreatedAt: string;
}

export function appendPrivateMessage(
  db: Database,
  input: AppendPrivateMessageInput,
  now = new Date(),
): { envelope: PrivateMessageEnvelope; created: boolean } {
  requireApprovedDevice(db, input.senderDeviceId);
  requireApprovedDevice(db, input.recipientDeviceId);
  if (input.senderDeviceId === input.recipientDeviceId) throw new Error("Private message recipient must be another device");
  if (!Number.isFinite(Date.parse(input.clientCreatedAt))) throw new Error("Invalid private-message creation time");
  const existing = db.query(`
    SELECT sequence, message_id AS messageId, sender_device_id AS senderDeviceId,
      recipient_device_id AS recipientDeviceId, ciphertext,
      client_created_at AS clientCreatedAt, accepted_at AS acceptedAt
    FROM private_messages WHERE message_id = ?
  `).get(input.messageId) as PrivateMessageEnvelope | null;
  if (existing) {
    if (
      existing.senderDeviceId !== input.senderDeviceId ||
      existing.recipientDeviceId !== input.recipientDeviceId ||
      existing.ciphertext !== input.ciphertext ||
      existing.clientCreatedAt !== input.clientCreatedAt
    ) {
      throw new Error("Private message ID was already used with different ciphertext");
    }
    return { envelope: existing, created: false };
  }
  const ciphertextHash = createHash("sha256").update(input.ciphertext, "utf8").digest("hex");
  const prior = db.query(`SELECT first_message_id AS messageId FROM private_message_replays
    WHERE sender_device_id = ? AND recipient_device_id = ? AND ciphertext_hash = ?`)
    .get(input.senderDeviceId, input.recipientDeviceId, ciphertextHash) as { messageId: string } | null;
  if (prior) throw new Error("Private message ciphertext was already delivered (replay rejected)");
  const historical = db.query(`SELECT message_id AS messageId FROM private_messages
    WHERE sender_device_id = ? AND recipient_device_id = ? AND ciphertext = ?`)
    .get(input.senderDeviceId, input.recipientDeviceId, input.ciphertext) as { messageId: string } | null;
  if (historical) throw new Error("Private message ciphertext was already delivered (replay rejected)");
  const result = db.query(`
    INSERT INTO private_messages (
      message_id, sender_device_id, recipient_device_id, ciphertext,
      client_created_at, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    input.messageId,
    input.senderDeviceId,
    input.recipientDeviceId,
    input.ciphertext,
    input.clientCreatedAt,
    now.toISOString(),
  );
  db.query(`INSERT INTO private_message_replays
    (sender_device_id, recipient_device_id, ciphertext_hash, first_message_id)
    VALUES (?, ?, ?, ?)`)
    .run(input.senderDeviceId, input.recipientDeviceId, ciphertextHash, input.messageId);
  const envelope = db.query(`
    SELECT sequence, message_id AS messageId, sender_device_id AS senderDeviceId,
      recipient_device_id AS recipientDeviceId, ciphertext,
      client_created_at AS clientCreatedAt, accepted_at AS acceptedAt
    FROM private_messages WHERE sequence = ?
  `).get(Number(result.lastInsertRowid)) as PrivateMessageEnvelope;
  return { envelope, created: true };
}

export function privateMessagesAfter(
  db: Database,
  deviceId: string,
  afterSequence: number,
  limit = 500,
): PrivateMessageEnvelope[] {
  requireApprovedDevice(db, deviceId);
  return db.query(`
    SELECT sequence, message_id AS messageId, sender_device_id AS senderDeviceId,
      recipient_device_id AS recipientDeviceId, ciphertext,
      client_created_at AS clientCreatedAt, accepted_at AS acceptedAt
    FROM private_messages
    WHERE sequence > ? AND (sender_device_id = ? OR recipient_device_id = ?)
    ORDER BY sequence ASC LIMIT ?
  `).all(afterSequence, deviceId, deviceId, Math.max(1, Math.min(500, Math.trunc(limit)))) as PrivateMessageEnvelope[];
}

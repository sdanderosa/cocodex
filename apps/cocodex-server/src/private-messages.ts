import { createHash } from "node:crypto";
import type { Database } from "bun:sqlite";
import type { PrivateMessageEnvelope, PrivateReceiptEnvelope } from "../../../packages/cocodex-protocol/src/index.ts";

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
  const transaction = db.transaction(() => {
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
  });
  return transaction.immediate();
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

export interface AppendPrivateReceiptInput {
  messageId: string;
  recipientDeviceId: string;
  receipt: "delivered" | "read";
}

/**
 * Persist a recipient acknowledgement without ever opening or inspecting the
 * message ciphertext.  The recipient is taken from the authenticated socket
 * by the caller and must match the original private-message envelope.
 */
export function appendPrivateReceipt(
  db: Database,
  input: AppendPrivateReceiptInput,
  now = new Date(),
): { envelope: PrivateReceiptEnvelope; created: boolean } {
  const transaction = db.transaction(() => {
    requireApprovedDevice(db, input.recipientDeviceId);
    const message = db.query(`
      SELECT sender_device_id AS senderDeviceId, recipient_device_id AS recipientDeviceId
      FROM private_messages WHERE message_id = ?
    `).get(input.messageId) as { senderDeviceId: string; recipientDeviceId: string } | null;
    if (!message) throw new Error("Private message was not found");
    if (message.recipientDeviceId !== input.recipientDeviceId) {
      throw new Error("Only the private-message recipient may acknowledge it");
    }
    const delivered = db.query(`
      SELECT sequence FROM private_message_receipts
      WHERE message_id = ? AND recipient_device_id = ? AND receipt = 'delivered'
    `).get(input.messageId, input.recipientDeviceId) as { sequence: number } | null;
    const read = db.query(`
      SELECT sequence FROM private_message_receipts
      WHERE message_id = ? AND recipient_device_id = ? AND receipt = 'read'
    `).get(input.messageId, input.recipientDeviceId) as { sequence: number } | null;
    if (input.receipt === "read" && !delivered) {
      throw new Error("A read receipt requires a delivered receipt");
    }
    if (input.receipt === "delivered" && read) {
      throw new Error("A delivered receipt cannot follow a read receipt");
    }
    const existing = db.query(`
      SELECT sequence, message_id AS messageId, sender_device_id AS senderDeviceId,
        recipient_device_id AS recipientDeviceId, receipt, accepted_at AS acceptedAt
      FROM private_message_receipts
      WHERE message_id = ? AND recipient_device_id = ? AND receipt = ?
    `).get(input.messageId, input.recipientDeviceId, input.receipt) as PrivateReceiptEnvelope | null;
    if (existing) return { envelope: existing, created: false };
    const result = db.query(`
      INSERT INTO private_message_receipts (
        message_id, sender_device_id, recipient_device_id, receipt, accepted_at
      ) VALUES (?, ?, ?, ?, ?)
    `).run(
      input.messageId,
      message.senderDeviceId,
      input.recipientDeviceId,
      input.receipt,
      now.toISOString(),
    );
    const envelope = db.query(`
      SELECT sequence, message_id AS messageId, sender_device_id AS senderDeviceId,
        recipient_device_id AS recipientDeviceId, receipt, accepted_at AS acceptedAt
      FROM private_message_receipts WHERE sequence = ?
    `).get(Number(result.lastInsertRowid)) as PrivateReceiptEnvelope;
    return { envelope, created: true };
  });
  return transaction.immediate();
}

export function privateReceiptsAfter(
  db: Database,
  deviceId: string,
  afterSequence: number,
  limit = 500,
): PrivateReceiptEnvelope[] {
  requireApprovedDevice(db, deviceId);
  return db.query(`
    SELECT sequence, message_id AS messageId, sender_device_id AS senderDeviceId,
      recipient_device_id AS recipientDeviceId, receipt, accepted_at AS acceptedAt
    FROM private_message_receipts
    WHERE sequence > ? AND sender_device_id = ?
    ORDER BY sequence ASC LIMIT ?
  `).all(afterSequence, deviceId, Math.max(1, Math.min(500, Math.trunc(limit)))) as PrivateReceiptEnvelope[];
}

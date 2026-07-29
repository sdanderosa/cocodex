import { createHash } from "node:crypto";
import type { Database } from "bun:sqlite";
import type { PrivateContactView } from "../../../packages/cocodex-protocol/src/index.ts";

const MAX_PRIVATE_CONTACTS = 128;

function requireApprovedDevice(db: Database, deviceId: string): void {
  const row = db.query("SELECT status FROM devices WHERE id = ?").get(deviceId) as {
    status: "pending" | "approved" | "revoked";
  } | null;
  if (!row || row.status !== "approved") {
    throw new Error("Private-contact requester is not approved");
  }
}

export function listPrivateContacts(db: Database, requesterDeviceId: string): PrivateContactView[] {
  requireApprovedDevice(db, requesterDeviceId);
  return db.query(`
    SELECT id AS deviceId, display_name AS displayName, fingerprint,
      device_key_certificate AS deviceKeyCertificate
    FROM devices
    WHERE status = 'approved'
      AND id <> ?
      AND device_key_certificate IS NOT NULL
    ORDER BY enrolled_at ASC, id ASC
    LIMIT ?
  `).all(requesterDeviceId, MAX_PRIVATE_CONTACTS) as PrivateContactView[];
}

export function privateContactDirectoryRevision(db: Database): string {
  const rows = db.query(`
    SELECT id, display_name AS displayName, fingerprint, status,
      COALESCE(device_key_certificate, '') AS deviceKeyCertificate
    FROM devices
    ORDER BY id ASC
  `).all();
  return createHash("sha256").update(JSON.stringify(rows), "utf8").digest("hex");
}

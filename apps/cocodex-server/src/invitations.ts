import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { Database } from "bun:sqlite";
import { decodeInvitation, encodeInvitation } from "@cocodex/protocol";

export { decodeInvitation };
import { randomToken } from "./identity";

export interface CreateInvitationOptions {
  host: string;
  port: number;
  serverFingerprint: string;
  ttlSeconds?: number;
  now?: Date;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function invitationIsUsable(
  db: Database,
  invitationId: string,
  token: string,
  now = new Date(),
): boolean {
  const record = db.query(`
    SELECT token_hash AS tokenHash, expires_at AS expiresAt, consumed_at AS consumedAt
    FROM invitations WHERE id = ?
  `).get(invitationId) as { tokenHash: string; expiresAt: string; consumedAt: string | null } | null;
  if (!record || record.consumedAt || record.expiresAt <= now.toISOString()) return false;
  const expected = Buffer.from(record.tokenHash, "hex");
  const actual = Buffer.from(tokenHash(token), "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function createInvitation(db: Database, options: CreateInvitationOptions): string {
  const now = options.now ?? new Date();
  const ttlSeconds = options.ttlSeconds ?? 900;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86400) {
    throw new Error("Invitation TTL must be between 60 and 86400 seconds");
  }
  const invitationId = randomUUID();
  const token = randomToken();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
  db.query(
    "INSERT INTO invitations (id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
  ).run(invitationId, tokenHash(token), expiresAt.toISOString(), now.toISOString());
  return encodeInvitation({
    version: 1,
    host: options.host,
    port: options.port,
    serverFingerprint: options.serverFingerprint,
    invitationId,
    token,
    expiresAt: expiresAt.toISOString(),
    scope: "device-enrollment",
  });
}

export function consumeInvitation(
  db: Database,
  invitationId: string,
  token: string,
  now = new Date(),
): boolean {
  const result = db.query(`
    UPDATE invitations
    SET consumed_at = ?
    WHERE id = ?
      AND token_hash = ?
      AND consumed_at IS NULL
      AND expires_at > ?
  `).run(now.toISOString(), invitationId, tokenHash(token), now.toISOString());
  return result.changes === 1;
}

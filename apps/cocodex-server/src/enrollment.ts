import { createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  enrollmentSigningTranscript,
  publicKeyFingerprint,
  type InvitationPayload,
} from "@cocodex/protocol";
import { consumeInvitation, invitationIsUsable } from "./invitations";

export interface EnrollmentChallenge {
  id: string;
  challenge: string;
  expiresAt: string;
}

export interface EnrollmentRequest {
  invitation: InvitationPayload;
  challengeId: string;
  challenge: string;
  displayName: string;
  devicePublicKeyPem: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string;
  signature: string;
}

export interface DeviceRecord {
  id: string;
  fingerprint: string;
  displayName: string;
  status: "pending" | "approved" | "revoked";
}

interface ChallengeRow {
  id: string;
  invitationId: string;
  challenge: string;
  publicKeyPem: string;
  expiresAt: string;
  consumedAt: string | null;
}

function validateDisplayName(value: string): string {
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 80) {
    throw new Error("Display name must be 1-80 characters");
  }
  return normalized;
}

function canonicalX25519PublicKey(value: string, label: string): string {
  const key = createPublicKey(value);
  if (key.asymmetricKeyType !== "x25519") throw new Error(`${label} key must be X25519`);
  return key.export({ type: "spki", format: "pem" }).toString();
}

export function createEnrollmentChallenge(
  db: Database,
  invitation: InvitationPayload,
  devicePublicKeyPem: string,
  expectedServerFingerprint: string,
  now = new Date(),
): EnrollmentChallenge {
  if (invitation.serverFingerprint !== expectedServerFingerprint) {
    throw new Error("Invitation does not belong to this server");
  }
  if (!invitationIsUsable(db, invitation.invitationId, invitation.token, now)) {
    throw new Error("Invitation is invalid, expired, or already used");
  }
  db.query(`
    DELETE FROM enrollment_challenges
    WHERE consumed_at IS NOT NULL OR expires_at <= ?
  `).run(now.toISOString());
  const active = db.query(`
    SELECT COUNT(*) AS count
    FROM enrollment_challenges
    WHERE invitation_id = ? AND consumed_at IS NULL AND expires_at > ?
  `).get(invitation.invitationId, now.toISOString()) as { count: number };
  if (active.count >= 8) {
    throw new Error("Too many active enrollment challenges for this invitation");
  }
  const canonicalPublicKey = canonicalEd25519PublicKey(devicePublicKeyPem);
  const result = {
    id: randomUUID(),
    challenge: randomBytes(32).toString("base64url"),
    expiresAt: new Date(now.getTime() + 120_000).toISOString(),
  };
  db.query(`
    INSERT INTO enrollment_challenges (
      id, invitation_id, challenge, public_key_pem, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    result.id,
    invitation.invitationId,
    result.challenge,
    canonicalPublicKey,
    result.expiresAt,
    now.toISOString(),
  );
  return result;
}

export function enrollDevice(db: Database, request: EnrollmentRequest, now = new Date()): DeviceRecord {
  const displayName = validateDisplayName(request.displayName);
  const canonicalPublicKey = canonicalEd25519PublicKey(request.devicePublicKeyPem);
  const messagingPublicKeyPem = canonicalX25519PublicKey(request.messagingPublicKeyPem, "Messaging");
  const projectWrapPublicKeyPem = request.projectWrapPublicKeyPem
    ? canonicalX25519PublicKey(request.projectWrapPublicKeyPem, "Project-wrap")
    : null;
  const transaction = db.transaction(() => {
    const challenge = db.query(`
      SELECT
        id,
        invitation_id AS invitationId,
        challenge,
        public_key_pem AS publicKeyPem,
        expires_at AS expiresAt,
        consumed_at AS consumedAt
      FROM enrollment_challenges WHERE id = ?
    `).get(request.challengeId) as ChallengeRow | null;
    if (
      !challenge ||
      challenge.invitationId !== request.invitation.invitationId ||
      challenge.challenge !== request.challenge ||
      challenge.publicKeyPem !== canonicalPublicKey ||
      challenge.consumedAt ||
      challenge.expiresAt <= now.toISOString()
    ) {
      throw new Error("Enrollment challenge is invalid, expired, or already used");
    }
    const proof = enrollmentSigningTranscript({
      serverFingerprint: request.invitation.serverFingerprint,
      invitationId: request.invitation.invitationId,
      challengeId: challenge.id,
      challenge: challenge.challenge,
      displayName,
      devicePublicKeyPem: canonicalPublicKey,
      messagingPublicKeyPem,
      projectWrapPublicKeyPem: projectWrapPublicKeyPem ?? undefined,
    });
    const signature = Buffer.from(request.signature, "base64url");
    if (!verify(null, proof, canonicalPublicKey, signature)) {
      throw new Error("Invalid enrollment proof");
    }
    if (!consumeInvitation(db, request.invitation.invitationId, request.invitation.token, now)) {
      throw new Error("Invitation is invalid, expired, or already used");
    }
    db.query("UPDATE enrollment_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL")
      .run(now.toISOString(), challenge.id);
    const record: DeviceRecord = {
      id: randomUUID(),
      fingerprint: publicKeyFingerprint(canonicalPublicKey),
      displayName,
      status: "pending",
    };
    db.query(`
      INSERT INTO devices (
        id, public_key_pem, messaging_public_key_pem, project_wrap_public_key_pem, fingerprint, display_name,
        status, invitation_id, enrolled_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    `).run(
      record.id,
      canonicalPublicKey,
      messagingPublicKeyPem,
      projectWrapPublicKeyPem,
      record.fingerprint,
      record.displayName,
      request.invitation.invitationId,
      now.toISOString(),
    );
    db.query(`
      INSERT INTO audit_events (event_type, subject_id, occurred_at, details_json)
      VALUES ('device.enrolled', ?, ?, ?)
    `).run(record.id, now.toISOString(), JSON.stringify({ fingerprint: record.fingerprint }));
    return record;
  });
  return transaction.immediate();
}

export function approveDevice(db: Database, fingerprint: string, now = new Date()): boolean {
  const result = db.query(`
    UPDATE devices
    SET status = 'approved', approved_at = ?
    WHERE fingerprint = ? AND status = 'pending'
  `).run(now.toISOString(), fingerprint);
  if (result.changes === 1) {
    db.query(`
      INSERT INTO audit_events (event_type, subject_id, occurred_at, details_json)
      SELECT 'device.approved', id, ?, '{}' FROM devices WHERE fingerprint = ?
    `).run(now.toISOString(), fingerprint);
  }
  return result.changes === 1;
}

export function revokeDevice(db: Database, fingerprint: string, now = new Date()): boolean {
  const result = db.query(`
    UPDATE devices
    SET status = 'revoked', revoked_at = ?
    WHERE fingerprint = ? AND status = 'approved'
  `).run(now.toISOString(), fingerprint);
  if (result.changes === 1) {
    db.query(`
      INSERT INTO audit_events (event_type, subject_id, occurred_at, details_json)
      SELECT 'device.revoked', id, ?, '{}' FROM devices WHERE fingerprint = ?
    `).run(now.toISOString(), fingerprint);
  }
  return result.changes === 1;
}
export function listDevices(db: Database): DeviceRecord[] {
  return db.query(`
    SELECT id, fingerprint, display_name AS displayName, status
    FROM devices ORDER BY enrolled_at ASC
  `).all() as DeviceRecord[];
}

export function devicePublicKeys(db: Database, deviceId: string): {
  deviceId: string;
  fingerprint: string;
  devicePublicKeyPem: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string;
} {
  const row = db.query(`SELECT id AS deviceId, fingerprint,
    public_key_pem AS devicePublicKeyPem, messaging_public_key_pem AS messagingPublicKeyPem,
    project_wrap_public_key_pem AS projectWrapPublicKeyPem
    FROM devices WHERE id = ? AND status = 'approved'`).get(deviceId) as {
      deviceId: string; fingerprint: string; devicePublicKeyPem: string; messagingPublicKeyPem: string | null;
      projectWrapPublicKeyPem: string | null;
    } | null;
  if (!row || !row.messagingPublicKeyPem) throw new Error("Approved device messaging keys were not found");
  return {
    deviceId: row.deviceId,
    fingerprint: row.fingerprint,
    devicePublicKeyPem: row.devicePublicKeyPem,
    messagingPublicKeyPem: row.messagingPublicKeyPem,
    ...(row.projectWrapPublicKeyPem ? { projectWrapPublicKeyPem: row.projectWrapPublicKeyPem } : {}),
  };
}

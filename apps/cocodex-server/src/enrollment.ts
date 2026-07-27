import { createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import { expirePendingProjectInvitationsForDevice } from "./project-invitations";
import {
  canonicalEd25519PublicKey,
  deviceEnrollmentDigest,
  deviceVerificationPhrase,
  enrollmentSigningTranscript,
  publicKeyFingerprint,
  type InvitationPayload,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { consumeInvitation, invitationIsUsable } from "./invitations";
import { quarantineEncryptedProjectsForRevokedDevice } from "./project-encryption-storage";
import { requireActiveServerAuthority } from "./server-state";

const PENDING_APPROVAL_TTL_MS = 15 * 60_000;

export interface EnrollmentChallenge {
  id: string;
  challenge: string;
  expiresAt: string;
}

export interface EnrollmentRequest {
  invitation: InvitationPayload;
  expectedServerFingerprint: string;
  serverIdentityFingerprint: string;
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

export interface PendingEnrollmentRecord extends DeviceRecord {
  enrollmentDigest: string;
  enrolledAt: string;
  approvalExpiresAt: string;
  verificationPhrase: string;
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

export function enrollDevice(db: Database, request: EnrollmentRequest, now = new Date()): PendingEnrollmentRecord {
  if (request.invitation.serverFingerprint !== request.expectedServerFingerprint) {
    throw new Error("Invitation does not belong to this server");
  }
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
    const invitation = db.query(`
      SELECT token_hash AS tokenHash, expires_at AS expiresAt
      FROM invitations WHERE id = ?
    `).get(request.invitation.invitationId) as { tokenHash: string; expiresAt: string } | null;
    if (!invitation || invitation.expiresAt !== request.invitation.expiresAt) {
      throw new Error("Invitation authority metadata is invalid");
    }
    const id = randomUUID();
    const enrolledAt = now.toISOString();
    const approvalExpiresAt = new Date(now.getTime() + PENDING_APPROVAL_TTL_MS).toISOString();
    const fingerprint = publicKeyFingerprint(canonicalPublicKey);
    const digest = deviceEnrollmentDigest({
      serverTlsFingerprint: request.invitation.serverFingerprint,
      serverIdentityFingerprint: request.serverIdentityFingerprint,
      invitationId: request.invitation.invitationId,
      invitationTokenHash: invitation.tokenHash,
      invitationExpiresAt: invitation.expiresAt,
      deviceId: id,
      displayName,
      fingerprint,
      devicePublicKeyPem: canonicalPublicKey,
      messagingPublicKeyPem,
      projectWrapPublicKeyPem,
      enrolledAt,
      approvalExpiresAt,
      approvalRevision: 0,
    });
    const record: PendingEnrollmentRecord = {
      id,
      fingerprint,
      displayName,
      status: "pending",
      enrollmentDigest: digest,
      enrolledAt,
      approvalExpiresAt,
      verificationPhrase: deviceVerificationPhrase(
        request.serverIdentityFingerprint,
        id,
        fingerprint,
      ),
    };
    db.query(`
      INSERT INTO devices (
        id, public_key_pem, messaging_public_key_pem, project_wrap_public_key_pem, fingerprint, display_name,
        status, invitation_id, enrolled_at, enrollment_digest, enrollment_signature,
        approval_expires_at, approval_revision
      ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, 0)
    `).run(
      record.id,
      canonicalPublicKey,
      messagingPublicKeyPem,
      projectWrapPublicKeyPem,
      record.fingerprint,
      record.displayName,
      request.invitation.invitationId,
      enrolledAt,
      digest,
      request.signature,
      approvalExpiresAt,
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
  return bootstrapApproveDevice(db, fingerprint, now);
}

export function bootstrapApproveDevice(db: Database, fingerprint: string, now = new Date()): boolean {
  return db.transaction(() => {
    requireActiveServerAuthority(db);
    const marker = db.query(`
      SELECT value FROM server_state WHERE key = 'device_bootstrap_consumed'
    `).get() as { value: string } | null;
    if (!marker || marker.value !== "0") {
      throw new Error("First-device bootstrap approval has already been consumed");
    }
    const approved = db.query(`
      SELECT COUNT(*) AS count FROM devices WHERE status = 'approved'
    `).get() as { count: number };
    if (approved.count !== 0) {
      throw new Error("First-device bootstrap requires zero approved devices");
    }
    const pending = db.query(`
      SELECT COUNT(*) AS count FROM devices
      WHERE status = 'pending' AND approval_expires_at > ?
    `).get(now.toISOString()) as { count: number };
    if (pending.count !== 1) {
      throw new Error("First-device bootstrap requires exactly one unexpired pending device");
    }
    const result = db.query(`
      UPDATE devices
      SET status = 'approved', approved_at = ?, approval_revision = 1
      WHERE fingerprint = ? AND status = 'pending' AND approval_expires_at > ?
    `).run(now.toISOString(), fingerprint, now.toISOString());
    if (result.changes !== 1) return false;
    const consumed = db.query(`
      UPDATE server_state SET value = '1'
      WHERE key = 'device_bootstrap_consumed' AND value = '0'
    `).run();
    if (consumed.changes !== 1) throw new Error("First-device bootstrap state changed concurrently");
    db.query(`
      INSERT INTO audit_events (event_type, subject_id, occurred_at, details_json)
      SELECT 'device.bootstrap-approved', id, ?, '{"bootstrap":true}'
      FROM devices WHERE fingerprint = ?
    `).run(now.toISOString(), fingerprint);
    return true;
  }).immediate();
}

export function revokeDevice(db: Database, fingerprint: string, now = new Date()): boolean {
  return db.transaction(() => {
    const device = db.query(`
      SELECT id FROM devices WHERE fingerprint = ? AND status = 'approved'
    `).get(fingerprint) as { id: string } | null;
    if (!device) return false;
    const result = db.query(`
      UPDATE devices
      SET status = 'revoked', revoked_at = ?
      WHERE id = ? AND status = 'approved'
    `).run(now.toISOString(), device.id);
    if (result.changes !== 1) return false;
    expirePendingProjectInvitationsForDevice(db, device.id, now);
    quarantineEncryptedProjectsForRevokedDevice(db, device.id, now);
    db.query(`
      INSERT INTO audit_events (event_type, subject_id, occurred_at, details_json)
      VALUES ('device.revoked', ?, ?, '{}')
    `).run(device.id, now.toISOString());
    return true;
  }).immediate();
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

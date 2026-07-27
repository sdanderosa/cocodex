import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  deviceApprovalSigningTranscript,
  deviceApprovalUpdateFrameSchema,
  deviceEnrollmentDigest,
  type DeviceApprovalUpdateFrame,
  type PendingDeviceApproval,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { requireActiveServerAuthority } from "./server-state";

interface PendingDeviceRow {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  devicePublicKeyPem: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem: string | null;
  invitationId: string;
  invitationTokenHash: string;
  invitationExpiresAt: string;
  enrolledAt: string;
  approvalExpiresAt: string;
  approvalRevision: number;
  enrollmentDigest: string | null;
}

interface PriorOperationRow {
  operationId: string;
  targetDeviceId: string;
  approverDeviceId: string;
  decision: "approve" | "reject";
  targetFingerprint: string;
  targetEnrollmentDigest: string;
  expectedRevision: number;
  resultingRevision: number;
  resultingStatus: "approved" | "rejected";
  serverIdentityFingerprint: string;
  serverEpoch: number;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
  decidedAt: string;
}

export interface DeviceApprovalResult {
  operationId: string;
  targetDeviceId: string;
  targetFingerprint: string;
  decision: "approve" | "reject";
  status: "approved" | "rejected";
  approverDeviceId: string;
  resultingRevision: 1;
  decidedAt: string;
  created: boolean;
}

function approvedDeviceKey(db: Database, deviceId: string): string {
  const row = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices WHERE id = ? AND status = 'approved'
  `).get(deviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Only an approved device can review pending enrollment");
  try {
    return canonicalEd25519PublicKey(row.publicKeyPem);
  } catch {
    throw new Error("Approver device signing key is invalid");
  }
}

function pendingRows(db: Database): PendingDeviceRow[] {
  return db.query(`
    SELECT d.id AS deviceId, d.display_name AS displayName,
      d.fingerprint, d.public_key_pem AS devicePublicKeyPem,
      d.messaging_public_key_pem AS messagingPublicKeyPem,
      d.project_wrap_public_key_pem AS projectWrapPublicKeyPem,
      d.invitation_id AS invitationId, i.token_hash AS invitationTokenHash,
      i.expires_at AS invitationExpiresAt, d.enrolled_at AS enrolledAt,
      d.approval_expires_at AS approvalExpiresAt,
      d.approval_revision AS approvalRevision,
      d.enrollment_digest AS enrollmentDigest
    FROM devices d
    JOIN invitations i ON i.id = d.invitation_id
    WHERE d.status = 'pending'
    ORDER BY d.enrolled_at, d.id
    LIMIT 256
  `).all() as PendingDeviceRow[];
}

function validatedPendingDevice(
  row: PendingDeviceRow,
  serverTlsFingerprint: string,
  serverIdentityFingerprint: string,
): PendingDeviceApproval {
  if (row.approvalRevision !== 0 || !row.enrollmentDigest) {
    throw new Error("Pending device enrollment attestation is incomplete");
  }
  const value: PendingDeviceApproval = {
    ...row,
    approvalRevision: 0,
    enrollmentDigest: row.enrollmentDigest,
  };
  const recomputed = deviceEnrollmentDigest({
    serverTlsFingerprint,
    serverIdentityFingerprint,
    invitationId: row.invitationId,
    invitationTokenHash: row.invitationTokenHash,
    invitationExpiresAt: row.invitationExpiresAt,
    deviceId: row.deviceId,
    displayName: row.displayName,
    fingerprint: row.fingerprint,
    devicePublicKeyPem: row.devicePublicKeyPem,
    messagingPublicKeyPem: row.messagingPublicKeyPem,
    projectWrapPublicKeyPem: row.projectWrapPublicKeyPem,
    enrolledAt: row.enrolledAt,
    approvalExpiresAt: row.approvalExpiresAt,
    approvalRevision: 0,
  });
  if (recomputed !== row.enrollmentDigest) {
    throw new Error("Pending device enrollment attestation is invalid");
  }
  return value;
}

function expirePendingDevices(db: Database, now: Date): string[] {
  const timestamp = now.toISOString();
  const expired = db.query(`
    SELECT id FROM devices
    WHERE status = 'pending' AND approval_expires_at <= ?
    ORDER BY enrolled_at, id
  `).all(timestamp) as Array<{ id: string }>;
  const update = db.query(`
    UPDATE devices
    SET status = 'revoked', revoked_at = ?, approval_revision = 1
    WHERE id = ? AND status = 'pending' AND approval_expires_at <= ?
  `);
  const audit = db.query(`
    INSERT INTO audit_events (event_type, subject_id, occurred_at, details_json)
    VALUES ('device.approval-expired', ?, ?, '{"reason":"pending-approval-expired"}')
  `);
  const changed: string[] = [];
  for (const target of expired) {
    if (update.run(timestamp, target.id, timestamp).changes !== 1) continue;
    audit.run(target.id, timestamp);
    changed.push(target.id);
  }
  return changed;
}

export function expirePendingDeviceApprovals(db: Database, now = new Date()): string[] {
  return db.transaction(() => {
    requireActiveServerAuthority(db);
    return expirePendingDevices(db, now);
  }).immediate();
}

export function listPendingDeviceApprovals(
  db: Database,
  requesterDeviceId: string,
  serverTlsFingerprint: string,
  serverIdentityFingerprint: string,
  now = new Date(),
): PendingDeviceApproval[] {
  return db.transaction(() => {
    requireActiveServerAuthority(db);
    approvedDeviceKey(db, requesterDeviceId);
    expirePendingDevices(db, now);
    return pendingRows(db).map(row =>
      validatedPendingDevice(row, serverTlsFingerprint, serverIdentityFingerprint));
  }).immediate();
}

function verifyApprovalAuthority(
  db: Database,
  approverDeviceId: string,
  frame: DeviceApprovalUpdateFrame,
  expectedIdentityFingerprint: string,
  expectedServerEpoch: number,
): void {
  if (frame.serverIdentityFingerprint !== expectedIdentityFingerprint
    || frame.serverEpoch !== expectedServerEpoch) {
    throw new Error("Device approval targets a different server authority");
  }
  const key = approvedDeviceKey(db, approverDeviceId);
  const valid = verify(
    null,
    deviceApprovalSigningTranscript({
      version: 1,
      operationId: frame.operationId,
      targetDeviceId: frame.targetDeviceId,
      targetFingerprint: frame.targetFingerprint,
      targetEnrollmentDigest: frame.targetEnrollmentDigest,
      expectedRevision: frame.expectedRevision,
      decision: frame.decision,
      serverIdentityFingerprint: frame.serverIdentityFingerprint,
      serverEpoch: frame.serverEpoch,
      issuedAt: frame.issuedAt,
      expiresAt: frame.expiresAt,
      nonce: frame.nonce,
    }),
    createPublicKey(key),
    Buffer.from(frame.signature, "base64url"),
  );
  if (!valid) throw new Error("Device approval signature is invalid");
}

function verifyValidity(frame: DeviceApprovalUpdateFrame, now: Date): void {
  const nowMs = now.getTime();
  const issuedMs = Date.parse(frame.issuedAt);
  const expiresMs = Date.parse(frame.expiresAt);
  if (issuedMs > nowMs + 60_000 || expiresMs <= nowMs || expiresMs - issuedMs > 5 * 60_000) {
    throw new Error("Device approval request is outside its validity window");
  }
}

function replayResult(frame: DeviceApprovalUpdateFrame, prior: PriorOperationRow): DeviceApprovalResult {
  if (prior.targetDeviceId !== frame.targetDeviceId
    || prior.decision !== frame.decision
    || prior.targetFingerprint !== frame.targetFingerprint
    || prior.targetEnrollmentDigest !== frame.targetEnrollmentDigest
    || prior.expectedRevision !== frame.expectedRevision
    || prior.serverIdentityFingerprint !== frame.serverIdentityFingerprint
    || prior.serverEpoch !== frame.serverEpoch
    || prior.nonce !== frame.nonce
    || prior.issuedAt !== frame.issuedAt
    || prior.expiresAt !== frame.expiresAt
    || prior.signature !== frame.signature) {
    throw new Error("Device approval operation replay conflict");
  }
  return {
    operationId: prior.operationId,
    targetDeviceId: prior.targetDeviceId,
    targetFingerprint: prior.targetFingerprint,
    decision: prior.decision,
    status: prior.resultingStatus,
    approverDeviceId: prior.approverDeviceId,
    resultingRevision: 1,
    decidedAt: prior.decidedAt,
    created: false,
  };
}

export function updateDeviceApproval(
  db: Database,
  approverDeviceId: string,
  value: unknown,
  serverTlsFingerprint: string,
  expectedIdentityFingerprint: string,
  expectedServerEpoch: number,
  now = new Date(),
): DeviceApprovalResult {
  const frame = deviceApprovalUpdateFrameSchema.parse(value);
  verifyApprovalAuthority(
    db,
    approverDeviceId,
    frame,
    expectedIdentityFingerprint,
    expectedServerEpoch,
  );
  return db.transaction((): DeviceApprovalResult => {
    requireActiveServerAuthority(db);
    approvedDeviceKey(db, approverDeviceId);
    if (approverDeviceId === frame.targetDeviceId) {
      throw new Error("A device cannot approve its own enrollment");
    }
    const prior = db.query(`
      SELECT operation_id AS operationId, target_device_id AS targetDeviceId,
        approver_device_id AS approverDeviceId, decision,
        target_fingerprint AS targetFingerprint,
        target_enrollment_digest AS targetEnrollmentDigest,
        expected_revision AS expectedRevision,
        resulting_revision AS resultingRevision,
        resulting_status AS resultingStatus,
        server_identity_fingerprint AS serverIdentityFingerprint,
        server_epoch AS serverEpoch, nonce, issued_at AS issuedAt,
        expires_at AS expiresAt, signature, decided_at AS decidedAt
      FROM device_approval_operations WHERE operation_id = ?
    `).get(frame.operationId) as PriorOperationRow | null;
    if (prior) {
      if (prior.approverDeviceId !== approverDeviceId) {
        throw new Error("Device approval operation belongs to another approver");
      }
      return replayResult(frame, prior);
    }
    verifyValidity(frame, now);
    const row = db.query(`
      SELECT d.id AS deviceId, d.display_name AS displayName,
        d.fingerprint, d.public_key_pem AS devicePublicKeyPem,
        d.messaging_public_key_pem AS messagingPublicKeyPem,
        d.project_wrap_public_key_pem AS projectWrapPublicKeyPem,
        d.invitation_id AS invitationId, i.token_hash AS invitationTokenHash,
        i.expires_at AS invitationExpiresAt, d.enrolled_at AS enrolledAt,
        d.approval_expires_at AS approvalExpiresAt,
        d.approval_revision AS approvalRevision,
        d.enrollment_digest AS enrollmentDigest
      FROM devices d
      JOIN invitations i ON i.id = d.invitation_id
      WHERE d.id = ? AND d.status = 'pending'
    `).get(frame.targetDeviceId) as PendingDeviceRow | null;
    if (!row) throw new Error("Pending device approval target was not found");
    if (row.approvalExpiresAt <= now.toISOString()) {
      throw new Error("Pending device approval has expired");
    }
    const target = validatedPendingDevice(row, serverTlsFingerprint, expectedIdentityFingerprint);
    if (target.fingerprint !== frame.targetFingerprint
      || target.enrollmentDigest !== frame.targetEnrollmentDigest
      || target.approvalRevision !== frame.expectedRevision) {
      throw new Error("Pending device approval target changed");
    }
    const decidedAt = now.toISOString();
    const status: DeviceApprovalResult["status"] =
      frame.decision === "approve" ? "approved" : "rejected";
    db.query(`
      INSERT INTO device_approval_operations (
        operation_id, target_device_id, approver_device_id, decision,
        target_fingerprint, target_enrollment_digest, expected_revision,
        resulting_revision, resulting_status, server_identity_fingerprint,
        server_epoch, nonce, issued_at, expires_at, signature, decided_at
      ) VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      frame.operationId,
      frame.targetDeviceId,
      approverDeviceId,
      frame.decision,
      frame.targetFingerprint,
      frame.targetEnrollmentDigest,
      status,
      frame.serverIdentityFingerprint,
      frame.serverEpoch,
      frame.nonce,
      frame.issuedAt,
      frame.expiresAt,
      frame.signature,
      decidedAt,
    );
    const updated = frame.decision === "approve"
      ? db.query(`
          UPDATE devices SET status = 'approved', approved_at = ?,
            approval_revision = 1, approved_by_device_id = ?,
            approval_operation_id = ?
          WHERE id = ? AND status = 'pending' AND approval_revision = 0
            AND approval_expires_at > ?
        `).run(
          decidedAt,
          approverDeviceId,
          frame.operationId,
          frame.targetDeviceId,
          decidedAt,
        )
      : db.query(`
          UPDATE devices SET status = 'revoked', revoked_at = ?,
            approval_revision = 1, approved_by_device_id = ?,
            approval_operation_id = ?
          WHERE id = ? AND status = 'pending' AND approval_revision = 0
            AND approval_expires_at > ?
        `).run(
          decidedAt,
          approverDeviceId,
          frame.operationId,
          frame.targetDeviceId,
          decidedAt,
        );
    if (updated.changes !== 1) throw new Error("Pending device approval changed concurrently");
    db.query(`
      UPDATE enrollment_challenges SET consumed_at = COALESCE(consumed_at, ?)
      WHERE invitation_id = ?
    `).run(decidedAt, target.invitationId);
    db.query(`
      INSERT INTO audit_events (
        event_type, actor_device_id, subject_id, occurred_at, details_json
      ) VALUES (?, ?, ?, ?, ?)
    `).run(
      frame.decision === "approve" ? "device.approved" : "device.enrollment-rejected",
      approverDeviceId,
      frame.targetDeviceId,
      decidedAt,
      JSON.stringify({
        operationId: frame.operationId,
        targetFingerprint: frame.targetFingerprint,
        enrollmentDigest: frame.targetEnrollmentDigest,
        resultingRevision: 1,
      }),
    );
    return {
      operationId: frame.operationId,
      targetDeviceId: frame.targetDeviceId,
      targetFingerprint: frame.targetFingerprint,
      decision: frame.decision,
      status,
      approverDeviceId,
      resultingRevision: 1,
      decidedAt,
      created: true,
    };
  }).immediate();
}

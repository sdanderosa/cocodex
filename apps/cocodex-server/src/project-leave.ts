import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectMemberLeaveFrameSchema,
  projectMemberLeaveSigningTranscript,
  type ProjectMemberLeaveFrame,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { expirePendingProjectInvitationsForProject } from "./project-invitations";

interface LeaveRequestRow {
  requestId: string;
  projectId: string;
  deviceId: string;
  serverFingerprint: string;
  serverEpoch: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  signature: string;
  state: "pending" | "completed";
  requestedAt: string;
}

export interface ProjectLeaveRequestResult {
  requestId: string;
  projectId: string;
  deviceId: string;
  requestedAt: string;
  created: boolean;
  cancelledTasks: Array<{ taskId: string; targetDeviceId: string }>;
}

function priorRequest(db: Database, requestId: string): LeaveRequestRow | null {
  return db.query(`
    SELECT request_id AS requestId, project_id AS projectId,
      device_id AS deviceId, server_fingerprint AS serverFingerprint,
      server_epoch AS serverEpoch, issued_at AS issuedAt,
      expires_at AS expiresAt, nonce, signature, state,
      requested_at AS requestedAt
    FROM project_member_leave_requests WHERE request_id = ?
  `).get(requestId) as LeaveRequestRow | null;
}

function approvedSigningKey(db: Database, deviceId: string): string {
  const row = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices WHERE id = ? AND status = 'approved'
  `).get(deviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Project-leave actor is not an approved device");
  try { return canonicalEd25519PublicKey(row.publicKeyPem); }
  catch { throw new Error("Project-leave actor signing key is invalid"); }
}

function verifyRequest(
  frame: ProjectMemberLeaveFrame,
  actorDeviceId: string,
  publicKeyPem: string,
  expectedServerFingerprint: string,
  expectedServerEpoch: number,
): void {
  if (frame.serverFingerprint !== expectedServerFingerprint || frame.serverEpoch !== expectedServerEpoch) {
    throw new Error("Project-leave request targets a different server authority");
  }
  const valid = verify(null, projectMemberLeaveSigningTranscript({
    version: 1,
    requestId: frame.requestId,
    projectId: frame.projectId,
    serverFingerprint: frame.serverFingerprint,
    serverEpoch: frame.serverEpoch,
    issuedAt: frame.issuedAt,
    expiresAt: frame.expiresAt,
    nonce: frame.nonce,
  }), createPublicKey(publicKeyPem), Buffer.from(frame.signature, "base64url"));
  if (!valid) throw new Error("Project-leave signature is invalid");
  if (!actorDeviceId) throw new Error("Project-leave actor is missing");
}

function verifyReplay(frame: ProjectMemberLeaveFrame, actorDeviceId: string, prior: LeaveRequestRow): void {
  if (prior.projectId !== frame.projectId
    || prior.deviceId !== actorDeviceId
    || prior.serverFingerprint !== frame.serverFingerprint
    || prior.serverEpoch !== frame.serverEpoch
    || prior.issuedAt !== frame.issuedAt
    || prior.expiresAt !== frame.expiresAt
    || prior.nonce !== frame.nonce
    || prior.signature !== frame.signature) {
    throw new Error("Project-leave request replay conflict");
  }
}

function verifyValidity(frame: ProjectMemberLeaveFrame, now: Date): void {
  const nowMs = now.getTime();
  const issuedMs = Date.parse(frame.issuedAt);
  const expiresMs = Date.parse(frame.expiresAt);
  if (issuedMs > nowMs + 60_000 || expiresMs <= nowMs || expiresMs - issuedMs > 5 * 60_000) {
    throw new Error("Project-leave request is outside its validity window");
  }
}

export function requestProjectLeave(
  db: Database,
  actorDeviceId: string,
  value: unknown,
  expectedServerFingerprint: string,
  expectedServerEpoch: number,
  now = new Date(),
): ProjectLeaveRequestResult {
  const frame = projectMemberLeaveFrameSchema.parse(value);
  const publicKeyPem = approvedSigningKey(db, actorDeviceId);
  verifyRequest(frame, actorDeviceId, publicKeyPem, expectedServerFingerprint, expectedServerEpoch);
  const existing = priorRequest(db, frame.requestId);
  if (existing) {
    verifyReplay(frame, actorDeviceId, existing);
    return {
      requestId: existing.requestId,
      projectId: existing.projectId,
      deviceId: existing.deviceId,
      requestedAt: existing.requestedAt,
      created: false,
      cancelledTasks: [],
    };
  }
  verifyValidity(frame, now);

  return db.transaction(() => {
    const raced = priorRequest(db, frame.requestId);
    if (raced) {
      verifyReplay(frame, actorDeviceId, raced);
      return {
        requestId: raced.requestId,
        projectId: raced.projectId,
        deviceId: raced.deviceId,
        requestedAt: raced.requestedAt,
        created: false,
        cancelledTasks: [],
      };
    }
    const membership = db.query(`
      SELECT pm.role
      FROM project_members pm
      JOIN devices d ON d.id = pm.device_id
      WHERE pm.project_id = ? AND pm.device_id = ? AND d.status = 'approved'
    `).get(frame.projectId, actorDeviceId) as { role: "owner" | "member" } | null;
    if (!membership) throw new Error("Device is not an approved project member");
    if (membership.role === "owner") {
      throw new Error("A project owner cannot leave until ownership transfer is available; archive or delete the project instead");
    }
    const epoch = db.query(`
      SELECT current_epoch AS currentEpoch
      FROM project_key_epochs WHERE project_id = ?
    `).get(frame.projectId) as { currentEpoch: number } | null;
    if (!epoch || epoch.currentEpoch < 1) {
      throw new Error("Project leave requires initialized project encryption");
    }
    const pending = db.query(`
      SELECT request_id AS requestId
      FROM project_member_leave_requests
      WHERE project_id = ? AND device_id = ? AND state = 'pending'
    `).get(frame.projectId, actorDeviceId) as { requestId: string } | null;
    if (pending) throw new Error("A different project-leave request is already pending");

    const timestamp = now.toISOString();
    db.query(`
      INSERT INTO project_member_leave_requests (
        request_id, project_id, device_id, server_fingerprint, server_epoch,
        issued_at, expires_at, nonce, signature, state, requested_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
    `).run(
      frame.requestId,
      frame.projectId,
      actorDeviceId,
      frame.serverFingerprint,
      frame.serverEpoch,
      frame.issuedAt,
      frame.expiresAt,
      frame.nonce,
      frame.signature,
      timestamp,
    );
    db.query(`
      UPDATE agents SET enabled = 0
      WHERE project_id = ? AND host_device_id = ?
    `).run(frame.projectId, actorDeviceId);
    const cancelledTasks = db.query(`
      SELECT id AS taskId, target_device_id AS targetDeviceId
      FROM agent_tasks
      WHERE project_id = ? AND (requester_device_id = ? OR target_device_id = ?)
        AND status IN ('queued', 'running')
      ORDER BY accepted_at ASC, id ASC
    `).all(frame.projectId, actorDeviceId, actorDeviceId) as
      Array<{ taskId: string; targetDeviceId: string }>;
    if (cancelledTasks.length > 0) {
      db.query(`
        UPDATE agent_tasks SET status = 'failed', completed_at = ?
        WHERE project_id = ? AND (requester_device_id = ? OR target_device_id = ?)
          AND status IN ('queued', 'running')
      `).run(timestamp, frame.projectId, actorDeviceId, actorDeviceId);
    }
    db.query(`
      UPDATE project_key_epochs
      SET rotation_required = 1, updated_at = ?
      WHERE project_id = ? AND current_epoch = ?
    `).run(timestamp, frame.projectId, epoch.currentEpoch);
    expirePendingProjectInvitationsForProject(db, frame.projectId, "member-leave-pending", now);
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES ('project.member.leave-requested', ?, ?, ?, ?)
    `).run(actorDeviceId, actorDeviceId, timestamp, JSON.stringify({
      projectId: frame.projectId,
      requestId: frame.requestId,
      currentEpoch: epoch.currentEpoch,
      cancelledTasks,
    }));
    return {
      requestId: frame.requestId,
      projectId: frame.projectId,
      deviceId: actorDeviceId,
      requestedAt: timestamp,
      created: true,
      cancelledTasks,
    };
  }).immediate();
}

export function completePendingProjectLeave(
  db: Database,
  projectId: string,
  removedDeviceId: string,
  ownerDeviceId: string,
  keyEpoch: number,
  rotationId: string,
  now = new Date(),
): string | null {
  const pending = db.query(`
    SELECT request_id AS requestId
    FROM project_member_leave_requests
    WHERE project_id = ? AND device_id = ? AND state = 'pending'
  `).get(projectId, removedDeviceId) as { requestId: string } | null;
  if (!pending) return null;
  const timestamp = now.toISOString();
  const completed = db.query(`
    UPDATE project_member_leave_requests
    SET state = 'completed', completed_at = ?, completed_by_device_id = ?,
      completion_rotation_id = ?
    WHERE request_id = ? AND state = 'pending'
  `).run(timestamp, ownerDeviceId, rotationId, pending.requestId);
  if (completed.changes !== 1) throw new Error("Project-leave completion changed concurrently");
  db.query(`
    INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
    VALUES ('project.member.leave-completed', ?, ?, ?, ?)
  `).run(ownerDeviceId, removedDeviceId, timestamp, JSON.stringify({
    projectId,
    requestId: pending.requestId,
    rotationId,
    keyEpoch,
  }));
  return pending.requestId;
}

import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectLockSigningTranscript,
  projectLockUpdateFrameSchema,
  type ProjectLockState,
  type ProjectLockTransition,
  type ProjectLockUpdateFrame,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { expirePendingProjectInvitationsForProject } from "./project-invitation-lifecycle";

interface LockRow {
  state: "active" | "locked";
  revision: number;
  lockedAt: string | null;
  lockedByDeviceId: string | null;
  reason: string | null;
}

interface PriorTransitionRow {
  projectId: string;
  actorDeviceId: string;
  action: "lock" | "unlock";
  expectedRevision: number;
  resultingRevision: number;
  reason: string;
  serverFingerprint: string;
  serverEpoch: number;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
  cancelledTasksJson: string;
  createdAt: string;
}

export interface ProjectLockUpdateResult {
  transition: ProjectLockTransition;
  created: boolean;
  cancelledTasks: Array<{ taskId: string; targetDeviceId: string }>;
}

function readLockRow(db: Database, projectId: string): LockRow {
  const row = db.query(`
    SELECT state, revision, locked_at AS lockedAt,
      locked_by_device_id AS lockedByDeviceId, reason
    FROM project_lock_state WHERE project_id = ?
  `).get(projectId) as LockRow | null;
  if (!row) throw new Error("Project lock state was not found");
  return row;
}

function stateFromRow(row: LockRow): ProjectLockState {
  return {
    state: row.state,
    revision: row.revision,
    lockedAt: row.lockedAt,
    lockedByDeviceId: row.lockedByDeviceId,
    reason: row.reason,
  };
}

export function projectLockState(db: Database, projectId: string): ProjectLockState {
  return stateFromRow(readLockRow(db, projectId));
}

export function assertProjectUnlocked(db: Database, projectId: string): void {
  const state = readLockRow(db, projectId);
  if (state.state === "locked") {
    throw new Error(`PROJECT_LOCKED:${projectId}:${state.revision}`);
  }
}

function enrolledOwnerKey(db: Database, projectId: string, actorDeviceId: string): string {
  const row = db.query(`
    SELECT d.public_key_pem AS publicKeyPem
    FROM project_members pm
    JOIN devices d ON d.id = pm.device_id
    WHERE pm.project_id = ? AND pm.device_id = ?
      AND pm.role = 'owner' AND d.status = 'approved'
  `).get(projectId, actorDeviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Only an approved project owner can change the project lock");
  try {
    return canonicalEd25519PublicKey(row.publicKeyPem);
  } catch {
    throw new Error("Project owner signing key is invalid");
  }
}

function verifyUpdateAuthority(
  db: Database,
  actorDeviceId: string,
  frame: ProjectLockUpdateFrame,
  expectedServerFingerprint: string,
  expectedServerEpoch: number,
): void {
  if (frame.serverFingerprint !== expectedServerFingerprint || frame.serverEpoch !== expectedServerEpoch) {
    throw new Error("Project lock request targets a different server authority");
  }
  const publicKeyPem = enrolledOwnerKey(db, frame.projectId, actorDeviceId);
  const valid = verify(
    null,
    projectLockSigningTranscript({
      version: 1,
      operationId: frame.operationId,
      projectId: frame.projectId,
      action: frame.action,
      expectedRevision: frame.expectedRevision,
      reason: frame.reason,
      serverFingerprint: frame.serverFingerprint,
      serverEpoch: frame.serverEpoch,
      issuedAt: frame.issuedAt,
      expiresAt: frame.expiresAt,
      nonce: frame.nonce,
    }),
    createPublicKey(publicKeyPem),
    Buffer.from(frame.signature, "base64url"),
  );
  if (!valid) throw new Error("Project lock signature is invalid");
}

function verifyUpdateValidity(frame: ProjectLockUpdateFrame, now: Date): void {
  const nowMs = now.getTime();
  const issuedMs = Date.parse(frame.issuedAt);
  const expiresMs = Date.parse(frame.expiresAt);
  if (issuedMs > nowMs + 60_000 || expiresMs <= nowMs || expiresMs - issuedMs > 5 * 60_000) {
    throw new Error("Project lock request is outside its validity window");
  }
}

function parseCancelledTasks(value: string): Array<{ taskId: string; targetDeviceId: string }> {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some(item =>
    !item || typeof item !== "object"
    || typeof (item as { taskId?: unknown }).taskId !== "string"
    || typeof (item as { targetDeviceId?: unknown }).targetDeviceId !== "string")) {
    throw new Error("Stored project lock cancellation evidence is invalid");
  }
  return parsed as Array<{ taskId: string; targetDeviceId: string }>;
}

function replayResult(
  frame: ProjectLockUpdateFrame,
  prior: PriorTransitionRow,
): ProjectLockUpdateResult {
  if (prior.projectId !== frame.projectId
    || prior.action !== frame.action
    || prior.expectedRevision !== frame.expectedRevision
    || prior.reason !== frame.reason.trim()
    || prior.serverFingerprint !== frame.serverFingerprint
    || prior.serverEpoch !== frame.serverEpoch
    || prior.nonce !== frame.nonce
    || prior.issuedAt !== frame.issuedAt
    || prior.expiresAt !== frame.expiresAt
    || prior.signature !== frame.signature) {
    throw new Error("Project lock operation replay conflict");
  }
  const state: ProjectLockState = prior.action === "lock" ? {
    state: "locked",
    revision: prior.resultingRevision,
    lockedAt: prior.createdAt,
    lockedByDeviceId: prior.actorDeviceId,
    reason: prior.reason,
  } : {
    state: "active",
    revision: prior.resultingRevision,
    lockedAt: null,
    lockedByDeviceId: null,
    reason: null,
  };
  return {
    transition: {
      operationId: frame.operationId,
      projectId: frame.projectId,
      action: frame.action,
      actorDeviceId: prior.actorDeviceId,
      reason: prior.reason,
      state,
      createdAt: prior.createdAt,
    },
    created: false,
    cancelledTasks: parseCancelledTasks(prior.cancelledTasksJson),
  };
}

export function updateProjectLock(
  db: Database,
  actorDeviceId: string,
  value: unknown,
  expectedServerFingerprint: string,
  expectedServerEpoch: number,
  now = new Date(),
): ProjectLockUpdateResult {
  const frame = projectLockUpdateFrameSchema.parse(value);
  verifyUpdateAuthority(db, actorDeviceId, frame, expectedServerFingerprint, expectedServerEpoch);
  return db.transaction(() => {
    // Recheck mutable authorization after the immediate write lock is held.
    // A concurrent revocation or ownership change must invalidate this write
    // even when its signature was valid immediately before the transaction.
    enrolledOwnerKey(db, frame.projectId, actorDeviceId);
    const prior = db.query(`
      SELECT project_id AS projectId, actor_device_id AS actorDeviceId, action,
        expected_revision AS expectedRevision, resulting_revision AS resultingRevision,
        reason, server_fingerprint AS serverFingerprint, server_epoch AS serverEpoch,
        nonce, issued_at AS issuedAt, expires_at AS expiresAt, signature,
        cancelled_tasks_json AS cancelledTasksJson, created_at AS createdAt
      FROM project_lock_transitions WHERE operation_id = ?
    `).get(frame.operationId) as PriorTransitionRow | null;
    const current = readLockRow(db, frame.projectId);
    if (prior) {
      if (current.revision !== prior.resultingRevision) {
        throw new Error("Project lock operation was superseded");
      }
      return replayResult(frame, prior);
    }
    verifyUpdateValidity(frame, now);
    if (current.revision !== frame.expectedRevision) {
      throw new Error("Project lock revision is stale");
    }
    const desired = frame.action === "lock" ? "locked" : "active";
    if (current.state === desired) throw new Error(`Project is already ${desired}`);
    const timestamp = now.toISOString();
    const cancelledTasks = frame.action === "lock"
      ? db.query(`
          SELECT id AS taskId, target_device_id AS targetDeviceId
          FROM agent_tasks
          WHERE project_id = ? AND status IN ('queued', 'running')
          ORDER BY accepted_at, id
        `).all(frame.projectId) as Array<{ taskId: string; targetDeviceId: string }>
      : [];
    if (frame.action === "lock") {
      db.query(`
        UPDATE agent_tasks SET status = 'failed', completed_at = ?
        WHERE project_id = ? AND status IN ('queued', 'running')
      `).run(timestamp, frame.projectId);
      expirePendingProjectInvitationsForProject(db, frame.projectId, "project-locked", now);
    }
    const resultingRevision = current.revision + 1;
    db.query(`
      UPDATE project_lock_state
      SET state = ?, revision = ?, locked_at = ?, locked_by_device_id = ?,
        reason = ?, updated_at = ?
      WHERE project_id = ?
    `).run(
      desired,
      resultingRevision,
      frame.action === "lock" ? timestamp : null,
      frame.action === "lock" ? actorDeviceId : null,
      frame.action === "lock" ? frame.reason.trim() : null,
      timestamp,
      frame.projectId,
    );
    db.query(`
      INSERT INTO project_lock_transitions (
        operation_id, project_id, actor_device_id, action, expected_revision,
        resulting_revision, reason, server_fingerprint, server_epoch, nonce,
        issued_at, expires_at, signature, cancelled_tasks_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      frame.operationId,
      frame.projectId,
      actorDeviceId,
      frame.action,
      frame.expectedRevision,
      resultingRevision,
      frame.reason.trim(),
      frame.serverFingerprint,
      frame.serverEpoch,
      frame.nonce,
      frame.issuedAt,
      frame.expiresAt,
      frame.signature,
      JSON.stringify(cancelledTasks),
      timestamp,
    );
    if (frame.action === "lock") {
      const insertCancellation = db.query(`
        INSERT INTO project_lock_task_cancellations (
          operation_id, task_id, project_id, target_device_id, reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const task of cancelledTasks) {
        insertCancellation.run(
          frame.operationId,
          task.taskId,
          frame.projectId,
          task.targetDeviceId,
          "The authoritative project owner locked this project.",
          timestamp,
        );
      }
    }
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      frame.action === "lock" ? "project.locked" : "project.unlocked",
      actorDeviceId,
      frame.projectId,
      timestamp,
      JSON.stringify({
        operationId: frame.operationId,
        revision: resultingRevision,
        reason: frame.reason.trim(),
        cancelledTaskCount: cancelledTasks.length,
      }),
    );
    const state = stateFromRow(readLockRow(db, frame.projectId));
    return {
      transition: {
        operationId: frame.operationId,
        projectId: frame.projectId,
        action: frame.action,
        actorDeviceId,
        reason: frame.reason.trim(),
        state,
        createdAt: timestamp,
      },
      created: true,
      cancelledTasks,
    };
  }).immediate();
}

export function pendingProjectLockCancellations(
  db: Database,
  targetDeviceId: string,
): Array<{ operationId: string; taskId: string; reason: string }> {
  return db.query(`
    SELECT operation_id AS operationId, task_id AS taskId, reason
    FROM project_lock_task_cancellations
    WHERE target_device_id = ?
    ORDER BY created_at DESC, operation_id DESC, task_id DESC
    LIMIT 512
  `).all(targetDeviceId) as Array<{ operationId: string; taskId: string; reason: string }>;
}

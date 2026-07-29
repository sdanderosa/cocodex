import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectLifecycleSigningTranscript,
  projectLifecycleTransitionSchema,
  projectLifecycleUpdateFrameSchema,
  type ProjectLifecycleTransition,
  type ProjectLifecycleUpdateFrame,
  type SharedProject,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { listProjects } from "./shared-state";

interface ProjectRow {
  name: string;
  state: "active" | "archived";
  lifecycleRevision: number;
  lockState: "active" | "locked";
}

interface PriorOperationRow {
  actorDeviceId: string;
  action: ProjectLifecycleUpdateFrame["action"];
  expectedRevision: number;
  requestedName: string | null;
  confirmationName: string | null;
  serverFingerprint: string;
  serverEpoch: number;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
  transitionJson: string;
}

export interface ProjectLifecycleUpdateResult {
  transition: ProjectLifecycleTransition;
  project: SharedProject | null;
  memberDeviceIds: string[];
  created: boolean;
}

function projectRow(db: Database, projectId: string): ProjectRow {
  const row = db.query(`
    SELECT p.name, p.state, p.lifecycle_revision AS lifecycleRevision,
      pls.state AS lockState
    FROM projects p
    JOIN project_lock_state pls ON pls.project_id = p.id
    WHERE p.id = ?
  `).get(projectId) as ProjectRow | null;
  if (!row) throw new Error("Project was not found");
  return row;
}

function devicePublicKey(db: Database, deviceId: string): string {
  const row = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices WHERE id = ? AND status = 'approved'
  `).get(deviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Project lifecycle actor is not an approved device");
  try { return canonicalEd25519PublicKey(row.publicKeyPem); }
  catch { throw new Error("Project lifecycle actor signing key is invalid"); }
}

function ownerPublicKey(db: Database, projectId: string, actorDeviceId: string): string {
  const row = db.query(`
    SELECT d.public_key_pem AS publicKeyPem
    FROM project_members pm
    JOIN devices d ON d.id = pm.device_id
    WHERE pm.project_id = ? AND pm.device_id = ?
      AND pm.role = 'owner' AND d.status = 'approved'
  `).get(projectId, actorDeviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Only an approved project owner can change project lifecycle state");
  try { return canonicalEd25519PublicKey(row.publicKeyPem); }
  catch { throw new Error("Project owner signing key is invalid"); }
}

function verifyAuthority(
  frame: ProjectLifecycleUpdateFrame,
  publicKeyPem: string,
  expectedServerFingerprint: string,
  expectedServerEpoch: number,
): void {
  if (frame.serverFingerprint !== expectedServerFingerprint || frame.serverEpoch !== expectedServerEpoch) {
    throw new Error("Project lifecycle request targets a different server authority");
  }
  const valid = verify(null, projectLifecycleSigningTranscript({
    version: 1,
    operationId: frame.operationId,
    projectId: frame.projectId,
    action: frame.action,
    expectedRevision: frame.expectedRevision,
    ...(frame.name !== undefined ? { name: frame.name } : {}),
    ...(frame.confirmationName !== undefined ? { confirmationName: frame.confirmationName } : {}),
    serverFingerprint: frame.serverFingerprint,
    serverEpoch: frame.serverEpoch,
    issuedAt: frame.issuedAt,
    expiresAt: frame.expiresAt,
    nonce: frame.nonce,
  }), createPublicKey(publicKeyPem), Buffer.from(frame.signature, "base64url"));
  if (!valid) throw new Error("Project lifecycle signature is invalid");
}

function verifyValidity(frame: ProjectLifecycleUpdateFrame, now: Date): void {
  const nowMs = now.getTime();
  const issuedMs = Date.parse(frame.issuedAt);
  const expiresMs = Date.parse(frame.expiresAt);
  if (issuedMs > nowMs + 60_000 || expiresMs <= nowMs || expiresMs - issuedMs > 5 * 60_000) {
    throw new Error("Project lifecycle request is outside its validity window");
  }
}

function priorOperation(db: Database, operationId: string): PriorOperationRow | null {
  return db.query(`
    SELECT actor_device_id AS actorDeviceId, action,
      expected_revision AS expectedRevision, requested_name AS requestedName,
      confirmation_name AS confirmationName, server_fingerprint AS serverFingerprint,
      server_epoch AS serverEpoch, nonce, issued_at AS issuedAt,
      expires_at AS expiresAt, signature, transition_json AS transitionJson
    FROM project_lifecycle_operations WHERE operation_id = ?
  `).get(operationId) as PriorOperationRow | null;
}

function replayResult(
  frame: ProjectLifecycleUpdateFrame,
  actorDeviceId: string,
  prior: PriorOperationRow,
  db: Database,
): ProjectLifecycleUpdateResult {
  if (prior.actorDeviceId !== actorDeviceId
    || prior.action !== frame.action
    || prior.expectedRevision !== frame.expectedRevision
    || prior.requestedName !== (frame.name?.trim() ?? null)
    || prior.confirmationName !== (frame.confirmationName ?? null)
    || prior.serverFingerprint !== frame.serverFingerprint
    || prior.serverEpoch !== frame.serverEpoch
    || prior.nonce !== frame.nonce
    || prior.issuedAt !== frame.issuedAt
    || prior.expiresAt !== frame.expiresAt
    || prior.signature !== frame.signature) {
    throw new Error("Project lifecycle operation replay conflict");
  }
  const transition = projectLifecycleTransitionSchema.parse(JSON.parse(prior.transitionJson));
  const project = transition.action === "delete"
    ? null
    : listProjects(db, actorDeviceId).find(candidate => candidate.id === frame.projectId) ?? null;
  if (transition.action !== "delete" && !project) {
    throw new Error("Project lifecycle operation was superseded");
  }
  return { transition, project, memberDeviceIds: [], created: false };
}

export function updateProjectLifecycle(
  db: Database,
  actorDeviceId: string,
  value: unknown,
  expectedServerFingerprint: string,
  expectedServerEpoch: number,
  now = new Date(),
): ProjectLifecycleUpdateResult {
  const frame = projectLifecycleUpdateFrameSchema.parse(value);
  const existing = priorOperation(db, frame.operationId);
  verifyAuthority(
    frame,
    existing ? devicePublicKey(db, actorDeviceId) : ownerPublicKey(db, frame.projectId, actorDeviceId),
    expectedServerFingerprint,
    expectedServerEpoch,
  );
  if (existing) return replayResult(frame, actorDeviceId, existing, db);
  verifyValidity(frame, now);

  return db.transaction(() => {
    const raced = priorOperation(db, frame.operationId);
    if (raced) return replayResult(frame, actorDeviceId, raced, db);
    ownerPublicKey(db, frame.projectId, actorDeviceId);
    const current = projectRow(db, frame.projectId);
    if (current.lifecycleRevision !== frame.expectedRevision) {
      throw new Error("Project lifecycle revision is stale");
    }
    if (frame.action === "rename") {
      if (current.state !== "active" || current.lockState !== "active") {
        throw new Error("Only an active unlocked project can be renamed");
      }
      if (frame.name!.trim() === current.name) throw new Error("Project already has that name");
    } else if (frame.action === "archive") {
      if (current.state !== "active") throw new Error("Project is already archived");
      if (current.lockState !== "locked") throw new Error("Lock the project before archiving it");
    } else if (frame.action === "restore") {
      if (current.state !== "archived") throw new Error("Project is not archived");
    } else {
      if (current.state !== "archived") throw new Error("Archive the project before deleting it");
      if (frame.confirmationName !== current.name) {
        throw new Error("Project deletion confirmation must exactly match the current project name");
      }
    }

    const timestamp = now.toISOString();
    const resultingRevision = current.lifecycleRevision + 1;
    const resultingName = frame.action === "rename" ? frame.name!.trim() : current.name;
    const resultingState = frame.action === "delete"
      ? null
      : frame.action === "archive" ? "archived"
      : frame.action === "restore" ? "active"
      : current.state;
    const memberDeviceIds = (db.query(`
      SELECT device_id AS deviceId FROM project_members
      WHERE project_id = ?
      ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END, joined_at, device_id
    `).all(frame.projectId) as Array<{ deviceId: string }>).map(row => row.deviceId);
    const transition = projectLifecycleTransitionSchema.parse({
      operationId: frame.operationId,
      projectId: frame.projectId,
      action: frame.action,
      actorDeviceId,
      previousName: current.name,
      resultingName,
      previousState: current.state,
      resultingState,
      resultingRevision,
      createdAt: timestamp,
    });

    if (frame.action === "delete") {
      db.query("DELETE FROM projects WHERE id = ?").run(frame.projectId);
    } else {
      db.query(`
        UPDATE projects SET name = ?, state = ?, lifecycle_revision = ?,
          updated_at = ?, archived_at = ? WHERE id = ?
      `).run(
        resultingName,
        resultingState,
        resultingRevision,
        timestamp,
        resultingState === "archived" ? timestamp : null,
        frame.projectId,
      );
    }
    db.query(`
      INSERT INTO project_lifecycle_operations (
        operation_id, project_id, actor_device_id, action, expected_revision,
        resulting_revision, requested_name, confirmation_name, server_fingerprint,
        server_epoch, nonce, issued_at, expires_at, signature, transition_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      frame.operationId, frame.projectId, actorDeviceId, frame.action,
      frame.expectedRevision, resultingRevision, frame.name?.trim() ?? null,
      frame.confirmationName ?? null, frame.serverFingerprint, frame.serverEpoch,
      frame.nonce, frame.issuedAt, frame.expiresAt, frame.signature,
      JSON.stringify(transition), timestamp,
    );
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(`project.${frame.action}d`, actorDeviceId, frame.projectId, timestamp, JSON.stringify({
      operationId: frame.operationId,
      previousName: current.name,
      resultingName,
      previousState: current.state,
      resultingState,
      lifecycleRevision: resultingRevision,
    }));
    const project = frame.action === "delete"
      ? null
      : listProjects(db, actorDeviceId).find(candidate => candidate.id === frame.projectId) ?? null;
    if (frame.action !== "delete" && !project) throw new Error("Updated project could not be reloaded");
    return { transition, project, memberDeviceIds, created: true };
  }).immediate();
}

import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectInvitationDecisionTranscript,
  projectInvitationSigningTranscript,
  projectInvitationViewSchema,
  projectKeyEnvelopeSchema,
  projectKeyEnvelopeSigningTranscript,
  type ProjectInvitationCreateFrame,
  type ProjectInvitationDecision,
  type ProjectInvitationView,
  type ProjectKeyEnvelope,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { requireProjectMembership } from "./shared-state";

const MAX_INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1_000;
const MAX_PENDING_INVITATIONS_PER_OWNER = 128;

interface InvitationRow {
  invitationId: string;
  projectId: string;
  projectName: string;
  serverFingerprint: string;
  ownerDeviceId: string;
  ownerDisplayName: string;
  ownerFingerprint: string;
  ownerDeviceKeyCertificate: string | null;
  recipientDeviceId: string;
  recipientDisplayName: string;
  recipientFingerprint: string;
  keyEpoch: number;
  envelopeJson: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  ownerSignature: string;
  status: ProjectInvitationView["status"];
  responseSignature: string | null;
}

export interface ProjectInvitationWriteResult {
  invitation: ProjectInvitationView;
  created: boolean;
}

function canonicalEnvelopeJson(envelope: ProjectKeyEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(projectKeyEnvelopeSchema.parse(envelope))
      .sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function approvedSigningKey(db: Database, deviceId: string): string {
  const row = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices WHERE id = ? AND status = 'approved'
  `).get(deviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Approved invitation device was not found");
  try { return canonicalEd25519PublicKey(row.publicKeyPem); }
  catch { throw new Error("Approved invitation device signing key is invalid"); }
}

function verifySignature(db: Database, deviceId: string, transcript: Buffer, signature: string): void {
  const key = approvedSigningKey(db, deviceId);
  let valid = false;
  try {
    valid = verify(null, transcript, createPublicKey(key), Buffer.from(signature, "base64url"));
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Project invitation signature is invalid");
}

function verifyOwnerEnvelope(
  db: Database,
  ownerDeviceId: string,
  projectId: string,
  recipientDeviceId: string,
  keyEpoch: number,
  value: unknown,
): ProjectKeyEnvelope {
  const envelope = projectKeyEnvelopeSchema.parse(value);
  if (envelope.projectId !== projectId
    || envelope.recipientDeviceId !== recipientDeviceId
    || envelope.senderDeviceId !== ownerDeviceId
    || envelope.keyEpoch !== keyEpoch) {
    throw new Error("Project invitation key envelope does not match its routing metadata");
  }
  const enrolled = approvedSigningKey(db, ownerDeviceId);
  let embedded: string;
  try { embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem); }
  catch { throw new Error("Project invitation envelope sender key is invalid"); }
  if (embedded !== enrolled) {
    throw new Error("Project invitation envelope sender key does not match the owner device");
  }
  let valid = false;
  try {
    valid = verify(
      null,
      projectKeyEnvelopeSigningTranscript(envelope),
      createPublicKey(enrolled),
      Buffer.from(envelope.signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Project invitation key envelope signature is invalid");
  return envelope;
}

function invitationRow(db: Database, invitationId: string): InvitationRow | null {
  return db.query(`
    SELECT
      pi.invitation_id AS invitationId,
      pi.project_id AS projectId,
      p.name AS projectName,
      pi.server_fingerprint AS serverFingerprint,
      pi.owner_device_id AS ownerDeviceId,
      owner.display_name AS ownerDisplayName,
      owner.fingerprint AS ownerFingerprint,
      owner.device_key_certificate AS ownerDeviceKeyCertificate,
      pi.recipient_device_id AS recipientDeviceId,
      recipient.display_name AS recipientDisplayName,
      recipient.fingerprint AS recipientFingerprint,
      pi.key_epoch AS keyEpoch,
      pi.envelope_json AS envelopeJson,
      pi.issued_at AS issuedAt,
      pi.expires_at AS expiresAt,
      pi.nonce,
      pi.owner_signature AS ownerSignature,
      pi.status,
      pi.response_signature AS responseSignature
    FROM project_invitations pi
    JOIN projects p ON p.id = pi.project_id
    JOIN devices owner ON owner.id = pi.owner_device_id
    JOIN devices recipient ON recipient.id = pi.recipient_device_id
    WHERE pi.invitation_id = ?
  `).get(invitationId) as InvitationRow | null;
}

function rowView(row: InvitationRow): ProjectInvitationView {
  if (!row.ownerDeviceKeyCertificate) {
    throw new Error("Project invitation owner has no device key certificate");
  }
  let envelope: ProjectKeyEnvelope;
  try { envelope = projectKeyEnvelopeSchema.parse(JSON.parse(row.envelopeJson)); }
  catch { throw new Error("Stored project invitation envelope is invalid"); }
  return projectInvitationViewSchema.parse({
    invitationId: row.invitationId,
    projectId: row.projectId,
    projectName: row.projectName,
    serverFingerprint: row.serverFingerprint,
    ownerDeviceId: row.ownerDeviceId,
    ownerDisplayName: row.ownerDisplayName,
    ownerFingerprint: row.ownerFingerprint,
    ownerDeviceKeyCertificate: row.ownerDeviceKeyCertificate,
    recipientDeviceId: row.recipientDeviceId,
    recipientDisplayName: row.recipientDisplayName,
    recipientFingerprint: row.recipientFingerprint,
    keyEpoch: row.keyEpoch,
    envelope,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
    nonce: row.nonce,
    ownerSignature: row.ownerSignature,
    status: row.status,
  });
}

function signingInput(row: InvitationRow, envelope: ProjectKeyEnvelope) {
  return {
    invitationId: row.invitationId,
    projectId: row.projectId,
    serverFingerprint: row.serverFingerprint,
    ownerDeviceId: row.ownerDeviceId,
    recipientDeviceId: row.recipientDeviceId,
    keyEpoch: row.keyEpoch,
    envelope,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
    nonce: row.nonce,
  };
}

function expirePending(db: Database, now: Date): void {
  const expired = db.query(`
    SELECT invitation_id AS invitationId, project_id AS projectId
    FROM project_invitations
    WHERE status = 'pending' AND expires_at <= ?
  `).all(now.toISOString()) as Array<{ invitationId: string; projectId: string }>;
  if (expired.length === 0) return;
  db.query(`
    UPDATE project_invitations
    SET status = 'expired', updated_at = ?
    WHERE status = 'pending' AND expires_at <= ?
  `).run(now.toISOString(), now.toISOString());
  const audit = db.query(`
    INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
    VALUES ('project.invite.expired', NULL, ?, ?, ?)
  `);
  for (const invitation of expired) {
    audit.run(
      invitation.invitationId,
      now.toISOString(),
      JSON.stringify({ projectId: invitation.projectId, reason: "time-window" }),
    );
  }
}

export function listProjectInvitations(
  db: Database,
  deviceId: string,
  now = new Date(),
): ProjectInvitationView[] {
  approvedSigningKey(db, deviceId);
  expirePending(db, now);
  const rows = db.query(`
    SELECT
      pi.invitation_id AS invitationId,
      pi.project_id AS projectId,
      p.name AS projectName,
      pi.server_fingerprint AS serverFingerprint,
      pi.owner_device_id AS ownerDeviceId,
      owner.display_name AS ownerDisplayName,
      owner.fingerprint AS ownerFingerprint,
      owner.device_key_certificate AS ownerDeviceKeyCertificate,
      pi.recipient_device_id AS recipientDeviceId,
      recipient.display_name AS recipientDisplayName,
      recipient.fingerprint AS recipientFingerprint,
      pi.key_epoch AS keyEpoch,
      pi.envelope_json AS envelopeJson,
      pi.issued_at AS issuedAt,
      pi.expires_at AS expiresAt,
      pi.nonce,
      pi.owner_signature AS ownerSignature,
      pi.status,
      pi.response_signature AS responseSignature
    FROM project_invitations pi
    JOIN projects p ON p.id = pi.project_id
    JOIN devices owner ON owner.id = pi.owner_device_id
    JOIN devices recipient ON recipient.id = pi.recipient_device_id
    WHERE (pi.owner_device_id = ? OR pi.recipient_device_id = ?)
      AND pi.status IN ('pending', 'accepted', 'declined', 'cancelled', 'expired')
    ORDER BY pi.created_at DESC, pi.invitation_id ASC
    LIMIT 256
  `).all(deviceId, deviceId) as InvitationRow[];
  return rows.map(rowView);
}

export function createProjectInvitation(
  db: Database,
  ownerDeviceId: string,
  serverFingerprint: string,
  frame: ProjectInvitationCreateFrame,
  now = new Date(),
): ProjectInvitationWriteResult {
  if (frame.serverFingerprint !== serverFingerprint) {
    throw new Error("Project invitation belongs to another Server authority");
  }
  if (ownerDeviceId === frame.recipientDeviceId) throw new Error("A project owner cannot invite itself");
  const issuedAt = new Date(frame.issuedAt);
  const expiresAt = new Date(frame.expiresAt);
  if (!Number.isFinite(issuedAt.getTime()) || !Number.isFinite(expiresAt.getTime())
    || issuedAt.getTime() > now.getTime() + MAX_CLOCK_SKEW_MS
    || issuedAt.getTime() < now.getTime() - MAX_CLOCK_SKEW_MS
    || expiresAt.getTime() <= issuedAt.getTime()
    || expiresAt.getTime() <= now.getTime()
    || expiresAt.getTime() - issuedAt.getTime() > MAX_INVITATION_LIFETIME_MS) {
    throw new Error("Project invitation time window is invalid");
  }
  return db.transaction(() => {
    const owner = requireProjectMembership(db, frame.projectId, ownerDeviceId);
    if (owner.role !== "owner") throw new Error("Only a project owner can invite members");
    const ownerCertificate = db.query(`
      SELECT device_key_certificate AS deviceKeyCertificate
      FROM devices WHERE id = ? AND status = 'approved'
    `).get(ownerDeviceId) as { deviceKeyCertificate: string | null } | null;
    if (!ownerCertificate?.deviceKeyCertificate) {
      throw new Error("Project invitation owner has no device key certificate");
    }
    const envelope = verifyOwnerEnvelope(
      db,
      ownerDeviceId,
      frame.projectId,
      frame.recipientDeviceId,
      frame.keyEpoch,
      frame.envelope,
    );
    verifySignature(db, ownerDeviceId, projectInvitationSigningTranscript({
      invitationId: frame.invitationId,
      projectId: frame.projectId,
      serverFingerprint,
      ownerDeviceId,
      recipientDeviceId: frame.recipientDeviceId,
      keyEpoch: frame.keyEpoch,
      envelope,
      issuedAt: frame.issuedAt,
      expiresAt: frame.expiresAt,
      nonce: frame.nonce,
    }), frame.signature);

    expirePending(db, now);
    const prior = invitationRow(db, frame.invitationId);
    if (prior) {
      if (prior.projectId !== frame.projectId
        || prior.ownerDeviceId !== ownerDeviceId
        || prior.serverFingerprint !== serverFingerprint
        || prior.recipientDeviceId !== frame.recipientDeviceId
        || prior.keyEpoch !== frame.keyEpoch
        || prior.envelopeJson !== canonicalEnvelopeJson(envelope)
        || prior.issuedAt !== frame.issuedAt
        || prior.expiresAt !== frame.expiresAt
        || prior.nonce !== frame.nonce
        || prior.ownerSignature !== frame.signature) {
        throw new Error("Project invitation replay conflict");
      }
      return { invitation: rowView(prior), created: false };
    }

    const recipient = db.query(`
      SELECT status, project_wrap_public_key_pem AS projectWrapPublicKeyPem,
        device_key_certificate AS deviceKeyCertificate
      FROM devices WHERE id = ?
    `).get(frame.recipientDeviceId) as {
      status: string;
      projectWrapPublicKeyPem: string | null;
      deviceKeyCertificate: string | null;
    } | null;
    if (!recipient || recipient.status !== "approved"
      || !recipient.projectWrapPublicKeyPem || !recipient.deviceKeyCertificate) {
      throw new Error("Project invitation recipient is not an approved project-capable device");
    }
    if (db.query(`
      SELECT 1 FROM project_members WHERE project_id = ? AND device_id = ?
    `).get(frame.projectId, frame.recipientDeviceId)) {
      throw new Error("Project invitation recipient is already a member");
    }
    const epoch = db.query(`
      SELECT current_epoch AS currentEpoch, rotation_required AS rotationRequired
      FROM project_key_epochs WHERE project_id = ?
    `).get(frame.projectId) as { currentEpoch: number; rotationRequired: number | boolean } | null;
    if (!epoch || epoch.rotationRequired === 1 || epoch.rotationRequired === true
      || epoch.currentEpoch !== frame.keyEpoch) {
      throw new Error("Project invitation must use the active project key epoch");
    }
    const pendingCount = db.query(`
      SELECT COUNT(*) AS count FROM project_invitations
      WHERE owner_device_id = ? AND status = 'pending'
    `).get(ownerDeviceId) as { count: number };
    if (pendingCount.count >= MAX_PENDING_INVITATIONS_PER_OWNER) {
      throw new Error("Project invitation pending limit reached");
    }
    const timestamp = now.toISOString();
    db.query(`
      INSERT INTO project_invitations (
        invitation_id, project_id, server_fingerprint, owner_device_id, recipient_device_id,
        key_epoch, envelope_json, issued_at, expires_at, nonce, owner_signature,
        status, response_signature, responded_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)
    `).run(
      frame.invitationId,
      frame.projectId,
      serverFingerprint,
      ownerDeviceId,
      frame.recipientDeviceId,
      frame.keyEpoch,
      canonicalEnvelopeJson(envelope),
      frame.issuedAt,
      frame.expiresAt,
      frame.nonce,
      frame.signature,
      timestamp,
      timestamp,
    );
    return { invitation: rowView(invitationRow(db, frame.invitationId)!), created: true };
  }).immediate();
}

export function respondToProjectInvitation(
  db: Database,
  recipientDeviceId: string,
  serverFingerprint: string,
  invitationId: string,
  decision: "accept" | "decline",
  signature: string,
  now = new Date(),
): ProjectInvitationWriteResult {
  approvedSigningKey(db, recipientDeviceId);
  expirePending(db, now);
  const row = invitationRow(db, invitationId);
  if (!row || row.recipientDeviceId !== recipientDeviceId) {
    throw new Error("Project invitation was not addressed to this device");
  }
  if (row.serverFingerprint !== serverFingerprint) {
    throw new Error("Project invitation belongs to another Server authority");
  }
  const envelope = verifyOwnerEnvelope(
    db,
    row.ownerDeviceId,
    row.projectId,
    row.recipientDeviceId,
    row.keyEpoch,
    JSON.parse(row.envelopeJson),
  );
  const targetStatus = decision === "accept" ? "accepted" : "declined";
  verifySignature(
    db,
    recipientDeviceId,
    projectInvitationDecisionTranscript(signingInput(row, envelope), decision),
    signature,
  );
  return db.transaction(() => {
    const current = invitationRow(db, invitationId);
    if (!current || current.recipientDeviceId !== recipientDeviceId) {
      throw new Error("Project invitation was not addressed to this device");
    }
    if (current.status === targetStatus && current.responseSignature === signature) {
      return { invitation: rowView(current), created: false };
    }
    if (current.status !== "pending") throw new Error(`Project invitation is ${current.status}`);
    if (new Date(current.expiresAt).getTime() <= now.getTime()) {
      throw new Error("Project invitation is expired");
    }
    const recipient = db.query(`
      SELECT status FROM devices WHERE id = ?
    `).get(recipientDeviceId) as { status: string } | null;
    if (recipient?.status !== "approved") {
      throw new Error("Project invitation recipient is no longer approved");
    }
    if (decision === "accept") {
      approvedSigningKey(db, current.ownerDeviceId);
      const owner = requireProjectMembership(db, current.projectId, current.ownerDeviceId);
      if (owner.role !== "owner") throw new Error("Project invitation owner is no longer authorized");
      const epoch = db.query(`
        SELECT current_epoch AS currentEpoch, rotation_required AS rotationRequired
        FROM project_key_epochs WHERE project_id = ?
      `).get(current.projectId) as { currentEpoch: number; rotationRequired: number | boolean } | null;
      if (!epoch || epoch.rotationRequired === 1 || epoch.rotationRequired === true
        || epoch.currentEpoch !== current.keyEpoch) {
        throw new Error("Project invitation key epoch is stale");
      }
      const memberCount = db.query(`
        SELECT COUNT(*) AS count FROM project_members WHERE project_id = ?
      `).get(current.projectId) as { count: number };
      if (memberCount.count >= 128) throw new Error("Project member limit reached");
      if (db.query(`
        SELECT 1 FROM project_members WHERE project_id = ? AND device_id = ?
      `).get(current.projectId, recipientDeviceId)) {
        throw new Error("Project invitation recipient is already a member");
      }
      db.query(`
        INSERT INTO project_members (project_id, device_id, role, joined_at)
        VALUES (?, ?, 'member', ?)
      `).run(current.projectId, recipientDeviceId, now.toISOString());
      db.query(`
        INSERT INTO project_key_envelopes (
          project_id, key_epoch, recipient_device_id, sender_device_id,
          envelope_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        current.projectId,
        current.keyEpoch,
        recipientDeviceId,
        current.ownerDeviceId,
        current.envelopeJson,
        now.toISOString(),
        now.toISOString(),
      );
    }
    const claimed = db.query(`
      UPDATE project_invitations
      SET status = ?, response_signature = ?, responded_at = ?, updated_at = ?
      WHERE invitation_id = ? AND status = 'pending'
    `).run(targetStatus, signature, now.toISOString(), now.toISOString(), invitationId);
    if (claimed.changes !== 1) throw new Error("Project invitation response lost an authority race");
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      decision === "accept" ? "project.invite.accepted" : "project.invite.declined",
      recipientDeviceId,
      invitationId,
      now.toISOString(),
      JSON.stringify({ projectId: current.projectId, ownerDeviceId: current.ownerDeviceId }),
    );
    return {
      invitation: rowView(invitationRow(db, invitationId)!),
      created: true,
    };
  }).immediate();
}

export function cancelProjectInvitation(
  db: Database,
  ownerDeviceId: string,
  serverFingerprint: string,
  invitationId: string,
  signature: string,
  now = new Date(),
): ProjectInvitationWriteResult {
  expirePending(db, now);
  const row = invitationRow(db, invitationId);
  if (!row || row.ownerDeviceId !== ownerDeviceId) {
    throw new Error("Project invitation is not owned by this device");
  }
  if (row.serverFingerprint !== serverFingerprint) {
    throw new Error("Project invitation belongs to another Server authority");
  }
  const envelope = projectKeyEnvelopeSchema.parse(JSON.parse(row.envelopeJson));
  verifySignature(
    db,
    ownerDeviceId,
    projectInvitationDecisionTranscript(signingInput(row, envelope), "cancel"),
    signature,
  );
  return db.transaction(() => {
    const current = invitationRow(db, invitationId);
    if (!current || current.ownerDeviceId !== ownerDeviceId) {
      throw new Error("Project invitation is not owned by this device");
    }
    if (current.status === "cancelled" && current.responseSignature === signature) {
      return { invitation: rowView(current), created: false };
    }
    if (current.status !== "pending") throw new Error(`Project invitation is ${current.status}`);
    const owner = requireProjectMembership(db, current.projectId, ownerDeviceId);
    if (owner.role !== "owner") throw new Error("Only a project owner can cancel invitations");
    const claimed = db.query(`
      UPDATE project_invitations
      SET status = 'cancelled', response_signature = ?, responded_at = ?, updated_at = ?
      WHERE invitation_id = ? AND status = 'pending'
    `).run(signature, now.toISOString(), now.toISOString(), invitationId);
    if (claimed.changes !== 1) throw new Error("Project invitation cancellation lost an authority race");
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES ('project.invite.cancelled', ?, ?, ?, ?)
    `).run(
      ownerDeviceId,
      invitationId,
      now.toISOString(),
      JSON.stringify({ projectId: current.projectId, recipientDeviceId: current.recipientDeviceId }),
    );
    return { invitation: rowView(invitationRow(db, invitationId)!), created: true };
  }).immediate();
}

export function expirePendingProjectInvitationsBeforeEpoch(
  db: Database,
  projectId: string,
  minimumEpoch: number,
  now = new Date(),
): void {
  const expired = db.query(`
    SELECT invitation_id AS invitationId
    FROM project_invitations
    WHERE project_id = ? AND status = 'pending' AND key_epoch < ?
  `).all(projectId, minimumEpoch) as Array<{ invitationId: string }>;
  if (expired.length === 0) return;
  db.query(`
    UPDATE project_invitations
    SET status = 'expired', updated_at = ?
    WHERE project_id = ? AND status = 'pending' AND key_epoch < ?
  `).run(now.toISOString(), projectId, minimumEpoch);
  const audit = db.query(`
    INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
    VALUES ('project.invite.expired', NULL, ?, ?, ?)
  `);
  for (const invitation of expired) {
    audit.run(
      invitation.invitationId,
      now.toISOString(),
      JSON.stringify({ projectId, reason: "key-epoch", minimumEpoch }),
    );
  }
}

export function expirePendingProjectInvitationsForProject(
  db: Database,
  projectId: string,
  reason: "key-rotation-required" | "project-locked",
  now = new Date(),
): void {
  const expired = db.query(`
    SELECT invitation_id AS invitationId
    FROM project_invitations
    WHERE project_id = ? AND status = 'pending'
  `).all(projectId) as Array<{ invitationId: string }>;
  if (expired.length === 0) return;
  db.query(`
    UPDATE project_invitations
    SET status = 'expired', updated_at = ?
    WHERE project_id = ? AND status = 'pending'
  `).run(now.toISOString(), projectId);
  const audit = db.query(`
    INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
    VALUES ('project.invite.expired', NULL, ?, ?, ?)
  `);
  for (const invitation of expired) {
    audit.run(
      invitation.invitationId,
      now.toISOString(),
      JSON.stringify({ projectId, reason }),
    );
  }
}

export function expirePendingProjectInvitationsForDevice(
  db: Database,
  deviceId: string,
  now = new Date(),
): void {
  const expired = db.query(`
    SELECT invitation_id AS invitationId, project_id AS projectId
    FROM project_invitations
    WHERE status = 'pending' AND (owner_device_id = ? OR recipient_device_id = ?)
  `).all(deviceId, deviceId) as Array<{ invitationId: string; projectId: string }>;
  if (expired.length === 0) return;
  db.query(`
    UPDATE project_invitations
    SET status = 'expired', updated_at = ?
    WHERE status = 'pending' AND (owner_device_id = ? OR recipient_device_id = ?)
  `).run(now.toISOString(), deviceId, deviceId);
  const audit = db.query(`
    INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
    VALUES ('project.invite.expired', NULL, ?, ?, ?)
  `);
  for (const invitation of expired) {
    audit.run(
      invitation.invitationId,
      now.toISOString(),
      JSON.stringify({ projectId: invitation.projectId, reason: "device-revoked", deviceId }),
    );
  }
}

import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  projectKeyEnvelopeSchema,
  projectKeyEnvelopeSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectKeyEnvelope,
} from "@cocodex/protocol";
import { removeProjectMember as removeMembership, requireProjectMembership } from "./shared-state";

interface DeviceSigningKeyRow {
  publicKeyPem: string;
}

interface KeyEnvelopeRow {
  envelopeJson: string;
}

interface ContextRow {
  envelopeJson: string;
  revision: number;
  updatedAt: string;
}

interface ProjectKeyEpochRow {
  currentEpoch: number;
  lastRotationId: string | null;
  updatedAt: string;
}

export interface ProjectKeyEnvelopeWriteResult {
  envelope: ProjectKeyEnvelope;
  created: boolean;
}

export interface EncryptedProjectContextRecord {
  projectId: string;
  envelope: ProjectContentEnvelope;
  revision: number;
  updatedAt: string;
}

export interface EncryptedProjectContextWriteResult extends EncryptedProjectContextRecord {
  created: boolean;
}

export interface ProjectKeyEpochRecord {
  projectId: string;
  currentEpoch: number;
  lastRotationId: string | null;
  updatedAt: string | null;
}

export interface ProjectKeyRotationResult extends ProjectKeyEpochRecord {
  keyEpoch: number;
  envelopes: ProjectKeyEnvelope[];
  created: boolean;
}

function enrolledSigningKey(db: Database, deviceId: string): string {
  const row = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices
    WHERE id = ? AND status = 'approved'
  `).get(deviceId) as DeviceSigningKeyRow | null;
  if (!row) throw new Error("Approved device signing key was not found");
  try {
    return canonicalEd25519PublicKey(row.publicKeyPem);
  } catch {
    throw new Error("Approved device signing key is invalid");
  }
}

function verifyEnvelopeSender(
  db: Database,
  senderDeviceId: string,
  senderPublicKeyPem: string,
  transcript: Buffer,
  signature: string,
): void {
  const expectedPublicKeyPem = enrolledSigningKey(db, senderDeviceId);
  let envelopePublicKeyPem: string;
  try {
    envelopePublicKeyPem = canonicalEd25519PublicKey(senderPublicKeyPem);
  } catch {
    throw new Error("Project envelope sender key is not a valid Ed25519 key");
  }
  if (envelopePublicKeyPem !== expectedPublicKeyPem) {
    throw new Error("Project envelope sender key does not match the enrolled device");
  }
  let valid = false;
  try {
    valid = verify(
      null,
      transcript,
      createPublicKey(expectedPublicKeyPem),
      Buffer.from(signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Project envelope signature is invalid");
}

function parseKeyEnvelope(envelopeJson: string): ProjectKeyEnvelope {
  try {
    return projectKeyEnvelopeSchema.parse(JSON.parse(envelopeJson));
  } catch {
    throw new Error("Stored project key envelope is invalid");
  }
}

function parseContextEnvelope(envelopeJson: string): ProjectContentEnvelope {
  try {
    return projectContentEnvelopeSchema.parse(JSON.parse(envelopeJson));
  } catch {
    throw new Error("Stored encrypted project context is invalid");
  }
}

function envelopeJson(value: object): string {
  // The protocol schemas only admit JSON values. Keeping the server storage
  // as one opaque JSON value makes it impossible for this layer to persist
  // plaintext project content accidentally.
  // Sort the flat envelope fields so a retry with a different wire key order
  // is still recognized as the same idempotent envelope.
  return JSON.stringify(Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right))));
}

function readProjectKeyEpoch(db: Database, projectId: string): ProjectKeyEpochRow | null {
  const row = db.query(`
    SELECT current_epoch AS currentEpoch,
      last_rotation_id AS lastRotationId,
      updated_at AS updatedAt
    FROM project_key_epochs
    WHERE project_id = ?
  `).get(projectId) as ProjectKeyEpochRow | null;
  if (row) return row;
  const legacy = db.query(`
    SELECT MAX(key_epoch) AS currentEpoch, MAX(updated_at) AS updatedAt
    FROM project_key_envelopes
    WHERE project_id = ?
  `).get(projectId) as { currentEpoch: number | null; updatedAt: string | null };
  if (!legacy.currentEpoch) return null;
  return { currentEpoch: legacy.currentEpoch, lastRotationId: null, updatedAt: legacy.updatedAt ?? "" };
}

function ensureProjectKeyEpochRow(
  db: Database,
  projectId: string,
  senderDeviceId: string,
  envelopeEpoch: number,
  now: Date,
): ProjectKeyEpochRow {
  const existing = readProjectKeyEpoch(db, projectId);
  if (existing) return existing;
  if (envelopeEpoch !== 1) throw new Error("Project key epoch must start at 1");
  const timestamp = now.toISOString();
  db.query(`
    INSERT INTO project_key_epochs (
      project_id, current_epoch, last_rotation_id, updated_by_device_id,
      created_at, updated_at
    ) VALUES (?, 1, NULL, ?, ?, ?)
  `).run(projectId, senderDeviceId, timestamp, timestamp);
  return { currentEpoch: 1, lastRotationId: null, updatedAt: timestamp };
}

export function getProjectKeyEpoch(
  db: Database,
  projectId: string,
  deviceId: string,
): ProjectKeyEpochRecord {
  requireProjectMembership(db, projectId, deviceId);
  const state = readProjectKeyEpoch(db, projectId);
  return {
    projectId,
    currentEpoch: state?.currentEpoch ?? 0,
    lastRotationId: state?.lastRotationId ?? null,
    updatedAt: state?.updatedAt || null,
  };
}

function approvedProjectMembers(db: Database, projectId: string): string[] {
  const rows = db.query(`
    SELECT pm.device_id AS deviceId
    FROM project_members pm
    JOIN devices d ON d.id = pm.device_id
    WHERE pm.project_id = ? AND d.status = 'approved'
    ORDER BY pm.device_id ASC
  `).all(projectId) as Array<{ deviceId: string }>;
  return rows.map(row => row.deviceId);
}

function sameEnvelopeSet(left: ProjectKeyEnvelope[], right: ProjectKeyEnvelope[]): boolean {
  if (left.length !== right.length) return false;
  const leftByRecipient = new Map(left.map(envelope => [envelope.recipientDeviceId, envelopeJson(envelope)]));
  const rightByRecipient = new Map(right.map(envelope => [envelope.recipientDeviceId, envelopeJson(envelope)]));
  if (leftByRecipient.size !== rightByRecipient.size) return false;
  for (const [recipient, value] of leftByRecipient) {
    if (rightByRecipient.get(recipient) !== value) return false;
  }
  return true;
}

export function shareProjectKeyEnvelope(
  db: Database,
  projectId: string,
  senderDeviceId: string,
  value: unknown,
  now = new Date(),
): ProjectKeyEnvelopeWriteResult {
  const envelope = projectKeyEnvelopeSchema.parse(value);
  if (envelope.projectId !== projectId) throw new Error("Project key envelope belongs to another project");
  const senderMembership = requireProjectMembership(db, projectId, senderDeviceId);
  if (senderMembership.role !== "owner") throw new Error("Only a project owner can share project keys");
  if (envelope.senderDeviceId !== senderDeviceId) throw new Error("Project key envelope sender device does not match the authenticated device");
  requireProjectMembership(db, projectId, envelope.recipientDeviceId);
  verifyEnvelopeSender(
    db,
    senderDeviceId,
    envelope.senderPublicKeyPem,
    projectKeyEnvelopeSigningTranscript(envelope),
    envelope.signature,
  );
  const serialized = envelopeJson(envelope);
  return db.transaction(() => {
    const epoch = ensureProjectKeyEpochRow(db, projectId, senderDeviceId, envelope.keyEpoch, now);
    if (envelope.keyEpoch < epoch.currentEpoch) {
      throw new Error(`Project key envelope epoch ${envelope.keyEpoch} is stale; current epoch is ${epoch.currentEpoch}`);
    }
    if (envelope.keyEpoch > epoch.currentEpoch) {
      throw new Error(`Project key envelope epoch ${envelope.keyEpoch} requires a project key rotation`);
    }
    const existing = db.query(`
      SELECT envelope_json AS envelopeJson
      FROM project_key_envelopes
      WHERE project_id = ? AND key_epoch = ? AND recipient_device_id = ?
    `).get(projectId, envelope.keyEpoch, envelope.recipientDeviceId) as KeyEnvelopeRow | null;
    if (existing) {
      const prior = parseKeyEnvelope(existing.envelopeJson);
      if (existing.envelopeJson === serialized) return { envelope: prior, created: false };
      throw new Error("Project key envelope replay conflict");
    }
    db.query(`
      INSERT INTO project_key_envelopes (
        project_id, key_epoch, recipient_device_id, sender_device_id,
        envelope_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      projectId,
      envelope.keyEpoch,
      envelope.recipientDeviceId,
      envelope.senderDeviceId,
      serialized,
      now.toISOString(),
      now.toISOString(),
    );
    return { envelope, created: true };
  }).immediate();
}

export function rotateProjectKeyEpoch(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  expectedEpoch: number,
  rotationId: string,
  values: unknown,
  now = new Date(),
): ProjectKeyRotationResult {
  if (!Number.isSafeInteger(expectedEpoch) || expectedEpoch < 0) {
    throw new Error("Invalid expected project key epoch");
  }
  if (!rotationId || rotationId.length > 128) throw new Error("Invalid project key rotation ID");
  if (!Array.isArray(values) || values.length < 1 || values.length > 128) {
    throw new Error("Project key rotation requires 1-128 envelopes");
  }
  const envelopes = values.map(value => projectKeyEnvelopeSchema.parse(value));
  if (envelopes.some(envelope => envelope.projectId !== projectId)) {
    throw new Error("Project key rotation contains an envelope for another project");
  }
  const ownerMembership = requireProjectMembership(db, projectId, ownerDeviceId);
  if (ownerMembership.role !== "owner") throw new Error("Only a project owner can rotate project keys");
  const members = approvedProjectMembers(db, projectId);
  const memberSet = new Set(members);
  const recipients = new Set<string>();
  for (const envelope of envelopes) {
    if (envelope.senderDeviceId !== ownerDeviceId) {
      throw new Error("Project key rotation envelopes must be signed by the owner");
    }
    if (recipients.has(envelope.recipientDeviceId)) {
      throw new Error("Project key rotation contains duplicate recipients");
    }
    recipients.add(envelope.recipientDeviceId);
    if (!memberSet.has(envelope.recipientDeviceId)) {
      throw new Error("Project key rotation recipient is not an approved project member");
    }
  }
  if (recipients.size !== memberSet.size || members.some(memberId => !recipients.has(memberId))) {
    throw new Error("Project key rotation must include every approved project member");
  }
  const serialized = envelopes.map(envelope => envelopeJson(envelope));
  for (let index = 0; index < envelopes.length; index += 1) {
    verifyEnvelopeSender(
      db,
      ownerDeviceId,
      envelopes[index]!.senderPublicKeyPem,
      projectKeyEnvelopeSigningTranscript(envelopes[index]!),
      envelopes[index]!.signature,
    );
  }
  return db.transaction(() => {
    const state = readProjectKeyEpoch(db, projectId);
    const currentEpoch = state?.currentEpoch ?? 0;
    if (state?.lastRotationId === rotationId) {
      const priorRows = db.query(`
        SELECT envelope_json AS envelopeJson
        FROM project_key_envelopes
        WHERE project_id = ? AND key_epoch = ?
        ORDER BY recipient_device_id ASC
      `).all(projectId, currentEpoch) as KeyEnvelopeRow[];
      const prior = priorRows.map(row => parseKeyEnvelope(row.envelopeJson));
      if (!sameEnvelopeSet(prior, envelopes)) throw new Error("Project key rotation replay conflict");
      return {
        projectId,
        currentEpoch,
        lastRotationId: state.lastRotationId,
        updatedAt: state.updatedAt || null,
        keyEpoch: currentEpoch,
        envelopes: prior,
        created: false,
      };
    }
    if (currentEpoch !== expectedEpoch) {
      throw new Error(`Project key rotation conflict (expected ${expectedEpoch}, current ${currentEpoch})`);
    }
    const keyEpoch = currentEpoch + 1;
    if (keyEpoch > 0x7fffffff) throw new Error("Project key epoch limit reached");
    if (envelopes.some(envelope => envelope.keyEpoch !== keyEpoch)) {
      throw new Error(`Project key rotation envelopes must use epoch ${keyEpoch}`);
    }
    const timestamp = now.toISOString();
    for (let index = 0; index < envelopes.length; index += 1) {
      const envelope = envelopes[index]!;
      db.query(`
        INSERT INTO project_key_envelopes (
          project_id, key_epoch, recipient_device_id, sender_device_id,
          envelope_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        projectId,
        keyEpoch,
        envelope.recipientDeviceId,
        envelope.senderDeviceId,
        serialized[index],
        timestamp,
        timestamp,
      );
    }
    if (state) {
      db.query(`
        UPDATE project_key_epochs
        SET current_epoch = ?, last_rotation_id = ?, updated_by_device_id = ?, updated_at = ?
        WHERE project_id = ?
      `).run(keyEpoch, rotationId, ownerDeviceId, timestamp, projectId);
    } else {
      db.query(`
        INSERT INTO project_key_epochs (
          project_id, current_epoch, last_rotation_id, updated_by_device_id,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(projectId, keyEpoch, rotationId, ownerDeviceId, timestamp, timestamp);
    }
    return {
      projectId,
      currentEpoch: keyEpoch,
      lastRotationId: rotationId,
      updatedAt: timestamp,
      keyEpoch,
      envelopes,
      created: true,
    };
  }).immediate();
}

export function removeProjectMemberAndInvalidateKeys(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  memberDeviceId: string,
  now = new Date(),
): void {
  removeMembership(db, projectId, ownerDeviceId, memberDeviceId, now);
  db.query(`
    DELETE FROM project_key_envelopes
    WHERE project_id = ? AND (recipient_device_id = ? OR sender_device_id = ?)
  `).run(projectId, memberDeviceId, memberDeviceId);
}

export function listProjectKeyEnvelopes(
  db: Database,
  projectId: string,
  recipientDeviceId: string,
  keyEpoch?: number,
): ProjectKeyEnvelope[] {
  requireProjectMembership(db, projectId, recipientDeviceId);
  const rows = keyEpoch === undefined
    ? db.query(`
      SELECT envelope_json AS envelopeJson
      FROM project_key_envelopes
      WHERE project_id = ? AND recipient_device_id = ?
      ORDER BY key_epoch ASC
      LIMIT 128
    `).all(projectId, recipientDeviceId) as KeyEnvelopeRow[]
    : db.query(`
      SELECT envelope_json AS envelopeJson
      FROM project_key_envelopes
      WHERE project_id = ? AND recipient_device_id = ? AND key_epoch = ?
      ORDER BY key_epoch ASC
      LIMIT 1
    `).all(projectId, recipientDeviceId, keyEpoch) as KeyEnvelopeRow[];
  return rows.map(row => parseKeyEnvelope(row.envelopeJson));
}

export function getEncryptedProjectContext(
  db: Database,
  projectId: string,
  deviceId: string,
): EncryptedProjectContextRecord | null {
  requireProjectMembership(db, projectId, deviceId);
  const row = db.query(`
    SELECT envelope_json AS envelopeJson, revision, updated_at AS updatedAt
    FROM encrypted_project_context
    WHERE project_id = ?
  `).get(projectId) as ContextRow | null;
  if (!row) return null;
  return {
    projectId,
    envelope: parseContextEnvelope(row.envelopeJson),
    revision: row.revision,
    updatedAt: row.updatedAt,
  };
}

export function updateEncryptedProjectContext(
  db: Database,
  projectId: string,
  senderDeviceId: string,
  expectedRevision: number,
  value: unknown,
  now = new Date(),
): EncryptedProjectContextWriteResult {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new Error("Invalid encrypted project context revision");
  }
  const envelope = projectContentEnvelopeSchema.parse(value);
  if (envelope.projectId !== projectId) throw new Error("Encrypted project context belongs to another project");
  if (envelope.recordType !== "shared-context") throw new Error("Project context envelope must use the shared-context record type");
  requireProjectMembership(db, projectId, senderDeviceId);
  if (envelope.senderDeviceId !== senderDeviceId) throw new Error("Project context sender device does not match the authenticated device");
  verifyEnvelopeSender(
    db,
    senderDeviceId,
    envelope.senderPublicKeyPem,
    projectContentSigningTranscript(envelope),
    envelope.signature,
  );
  const serialized = envelopeJson(envelope);
  return db.transaction(() => {
    const existing = db.query(`
      SELECT envelope_json AS envelopeJson, revision, updated_at AS updatedAt
      FROM encrypted_project_context
      WHERE project_id = ?
    `).get(projectId) as ContextRow | null;
    if (existing) {
      const prior = parseContextEnvelope(existing.envelopeJson);
      if (prior.recordId === envelope.recordId) {
        if (existing.envelopeJson === serialized) {
          return {
            projectId,
            envelope: prior,
            revision: existing.revision,
            updatedAt: existing.updatedAt,
            created: false,
          };
        }
        throw new Error("Encrypted project context replay conflict");
      }
      if (existing.revision !== expectedRevision) {
        throw new Error(`Encrypted project context revision conflict (expected ${expectedRevision}, current ${existing.revision})`);
      }
    } else if (expectedRevision !== 0) {
      throw new Error(`Encrypted project context revision conflict (expected ${expectedRevision}, current 0)`);
    }
    const revision = (existing?.revision ?? 0) + 1;
    const updatedAt = now.toISOString();
    db.query(`
      INSERT INTO encrypted_project_context (
        project_id, key_epoch, record_id, sender_device_id, envelope_json,
        revision, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id) DO UPDATE SET
        key_epoch = excluded.key_epoch,
        record_id = excluded.record_id,
        sender_device_id = excluded.sender_device_id,
        envelope_json = excluded.envelope_json,
        revision = excluded.revision,
        updated_at = excluded.updated_at
    `).run(
      projectId,
      envelope.keyEpoch,
      envelope.recordId,
      envelope.senderDeviceId,
      serialized,
      revision,
      updatedAt,
      updatedAt,
    );
    return { projectId, envelope, revision, updatedAt, created: true };
  }).immediate();
}

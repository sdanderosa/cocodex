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
import { requireProjectMembership } from "./shared-state";

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

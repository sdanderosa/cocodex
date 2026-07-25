import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  encryptedArtifactSchema,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  type EncryptedArtifact,
  type ProjectContentEnvelope,
} from "@cocodex/protocol";
import { requireProjectMembership } from "./shared-state";

export interface AppendEncryptedArtifactInput {
  artifactId: string;
  projectId: string;
  taskId: string | null;
  authorDeviceId: string;
  envelope: unknown;
}

export interface AppendEncryptedArtifactResult {
  artifact: EncryptedArtifact;
  created: boolean;
}

interface DeviceKeyRow { publicKeyPem: string; }
interface ArtifactRow {
  id: string;
  projectId: string;
  taskId: string | null;
  authorDeviceId: string;
  envelopeJson: string;
  createdAt: string;
  updatedAt: string;
}

function envelopeJson(value: ProjectContentEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function parseEnvelope(value: string): ProjectContentEnvelope {
  try { return projectContentEnvelopeSchema.parse(JSON.parse(value)); }
  catch { throw new Error("Stored encrypted artifact envelope is invalid"); }
}

function currentProjectKeyEpoch(db: Database, projectId: string): number {
  const current = db.query("SELECT current_epoch AS currentEpoch FROM project_key_epochs WHERE project_id = ?")
    .get(projectId) as { currentEpoch: number } | null;
  if (current) return current.currentEpoch;
  const legacy = db.query("SELECT MAX(key_epoch) AS currentEpoch FROM project_key_envelopes WHERE project_id = ?")
    .get(projectId) as { currentEpoch: number | null };
  if (!legacy.currentEpoch) throw new Error("Project encryption key has not been initialized");
  return legacy.currentEpoch;
}

function verifyEnvelopeSender(db: Database, senderDeviceId: string, envelope: ProjectContentEnvelope): void {
  const device = db.query(`
    SELECT public_key_pem AS publicKeyPem FROM devices
    WHERE id = ? AND status = 'approved'
  `).get(senderDeviceId) as DeviceKeyRow | null;
  if (!device) throw new Error("Approved artifact sender key was not found");
  let expected: string;
  let embedded: string;
  try {
    expected = canonicalEd25519PublicKey(device.publicKeyPem);
    embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem);
  } catch { throw new Error("Encrypted artifact sender key is invalid"); }
  if (expected !== embedded) throw new Error("Encrypted artifact sender key does not match the enrolled device");
  let valid = false;
  try {
    valid = verify(null, projectContentSigningTranscript({ ...envelope, senderPublicKeyPem: embedded }),
      createPublicKey(expected), Buffer.from(envelope.signature, "base64url"));
  } catch { valid = false; }
  if (!valid) throw new Error("Encrypted artifact envelope signature is invalid");
}

function artifactFromRow(row: ArtifactRow): EncryptedArtifact {
  return encryptedArtifactSchema.parse({
    artifactId: row.id,
    projectId: row.projectId,
    taskId: row.taskId,
    authorDeviceId: row.authorDeviceId,
    envelope: parseEnvelope(row.envelopeJson),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

export function publishEncryptedArtifact(
  db: Database,
  input: AppendEncryptedArtifactInput,
  now = new Date(),
): AppendEncryptedArtifactResult {
  requireProjectMembership(db, input.projectId, input.authorDeviceId);
  if (input.taskId) {
    const task = db.query("SELECT project_id AS projectId FROM agent_tasks WHERE id = ?")
      .get(input.taskId) as { projectId: string } | null;
    if (!task || task.projectId !== input.projectId) throw new Error("Artifact task is not in this project");
  }
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (envelope.projectId !== input.projectId) throw new Error("Encrypted artifact belongs to another project");
  if (envelope.recordType !== "artifact") throw new Error("Encrypted artifact envelope must use the artifact record type");
  if (envelope.recordId !== input.artifactId) throw new Error("Encrypted artifact record ID must match the artifact ID");
  if (envelope.senderDeviceId !== input.authorDeviceId) throw new Error("Encrypted artifact sender does not match the authenticated device");
  if (envelope.keyEpoch !== currentProjectKeyEpoch(db, input.projectId)) {
    throw new Error("Encrypted artifact envelope must use the current project key epoch");
  }
  verifyEnvelopeSender(db, input.authorDeviceId, envelope);
  const serialized = envelopeJson(envelope);
  const existing = db.query(`
    SELECT id, project_id AS projectId, task_id AS taskId, author_device_id AS authorDeviceId,
      envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
    FROM project_artifacts WHERE id = ?
  `).get(input.artifactId) as ArtifactRow | null;
  if (existing) {
    if (existing.projectId !== input.projectId || existing.taskId !== input.taskId
      || existing.authorDeviceId !== input.authorDeviceId || existing.envelopeJson !== serialized) {
      throw new Error("Encrypted artifact ID was already used for different content");
    }
    return { artifact: artifactFromRow(existing), created: false };
  }
  const timestamp = now.toISOString();
  db.query(`
    INSERT INTO project_artifacts (id, project_id, task_id, author_device_id, envelope_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(input.artifactId, input.projectId, input.taskId, input.authorDeviceId, serialized, timestamp, timestamp);
  return {
    artifact: artifactFromRow({
      id: input.artifactId,
      projectId: input.projectId,
      taskId: input.taskId,
      authorDeviceId: input.authorDeviceId,
      envelopeJson: serialized,
      createdAt: timestamp,
      updatedAt: timestamp,
    }),
    created: true,
  };
}

export function listEncryptedArtifacts(db: Database, projectId: string, deviceId: string): EncryptedArtifact[] {
  requireProjectMembership(db, projectId, deviceId);
  const rows = db.query(`
    SELECT id, project_id AS projectId, task_id AS taskId, author_device_id AS authorDeviceId,
      envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
    FROM project_artifacts WHERE project_id = ? ORDER BY created_at, id LIMIT 500
  `).all(projectId) as ArtifactRow[];
  return rows.map(artifactFromRow);
}

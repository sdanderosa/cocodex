import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  encryptedFileReferenceSchema,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  type EncryptedFileReference,
  type ProjectContentEnvelope,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { currentProjectKeyEpochForWrite } from "./project-encryption-storage";
import { requireSharedChat } from "./shared-chats";
import { assertProjectUnlocked } from "./project-locks";

export interface PublishEncryptedFileReferenceInput {
  referenceId: string;
  projectId: string;
  chatId?: string;
  artifactId: string;
  authorDeviceId: string;
  envelope: unknown;
}

interface DeviceKeyRow { publicKeyPem: string; }
interface ArtifactOwnerRow { projectId: string; chatId: string; authorDeviceId: string; }
interface FileReferenceRow {
  id: string;
  projectId: string;
  chatId: string;
  artifactId: string;
  hostDeviceId: string;
  authorDeviceId: string;
  envelopeJson: string;
  createdAt: string;
  updatedAt: string;
}

function canonicalEnvelopeJson(value: ProjectContentEnvelope): string {
  return JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function parseEnvelope(value: string): ProjectContentEnvelope {
  try { return projectContentEnvelopeSchema.parse(JSON.parse(value)); }
  catch { throw new Error("Stored encrypted file-reference envelope is invalid"); }
}

function verifyEnvelopeSender(db: Database, senderDeviceId: string, envelope: ProjectContentEnvelope): void {
  const device = db.query(`
    SELECT public_key_pem AS publicKeyPem FROM devices
    WHERE id = ? AND status = 'approved'
  `).get(senderDeviceId) as DeviceKeyRow | null;
  if (!device) throw new Error("Approved file-reference sender key was not found");
  let expected: string;
  let embedded: string;
  try {
    expected = canonicalEd25519PublicKey(device.publicKeyPem);
    embedded = canonicalEd25519PublicKey(envelope.senderPublicKeyPem);
  } catch { throw new Error("Encrypted file-reference sender key is invalid"); }
  if (expected !== embedded) {
    throw new Error("Encrypted file-reference sender key does not match the enrolled device");
  }
  let valid = false;
  try {
    valid = verify(
      null,
      projectContentSigningTranscript({ ...envelope, senderPublicKeyPem: embedded }),
      createPublicKey(expected),
      Buffer.from(envelope.signature, "base64url"),
    );
  } catch { valid = false; }
  if (!valid) throw new Error("Encrypted file-reference envelope signature is invalid");
}

function fromRow(row: FileReferenceRow): EncryptedFileReference {
  return encryptedFileReferenceSchema.parse({
    referenceId: row.id,
    projectId: row.projectId,
    chatId: row.chatId,
    artifactId: row.artifactId,
    hostDeviceId: row.hostDeviceId,
    authorDeviceId: row.authorDeviceId,
    envelope: parseEnvelope(row.envelopeJson),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

export function publishEncryptedFileReference(
  db: Database,
  input: PublishEncryptedFileReferenceInput,
  now = new Date(),
): { reference: EncryptedFileReference; created: boolean } {
  assertProjectUnlocked(db, input.projectId);
  const chatId = input.chatId ?? input.projectId;
  requireSharedChat(db, input.projectId, chatId, input.authorDeviceId);
  const artifact = db.query(`
    SELECT project_id AS projectId, chat_id AS chatId, author_device_id AS authorDeviceId
    FROM project_artifacts WHERE id = ?
  `).get(input.artifactId) as ArtifactOwnerRow | null;
  if (!artifact || artifact.projectId !== input.projectId || artifact.chatId !== chatId) {
    throw new Error("File-reference artifact is not in this shared chat");
  }
  if (artifact.authorDeviceId !== input.authorDeviceId) {
    throw new Error("Only the artifact host may publish its local file reference");
  }
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (input.chatId !== undefined && envelope.version !== 2) {
    throw new Error("New encrypted file references require a chat-bound content envelope");
  }
  if (envelope.projectId !== input.projectId) throw new Error("Encrypted file reference belongs to another project");
  if (envelope.version === 2 && envelope.chatId !== chatId) {
    throw new Error("Encrypted file reference belongs to another shared chat");
  }
  if (envelope.recordType !== "file-reference") {
    throw new Error("Encrypted file-reference envelope must use the file-reference record type");
  }
  if (envelope.recordId !== input.referenceId) {
    throw new Error("Encrypted file-reference record ID must match the reference ID");
  }
  if (envelope.senderDeviceId !== input.authorDeviceId) {
    throw new Error("Encrypted file-reference sender does not match the authenticated device");
  }
  if (envelope.keyEpoch !== currentProjectKeyEpochForWrite(db, input.projectId)) {
    throw new Error("Encrypted file-reference envelope must use the current project key epoch");
  }
  verifyEnvelopeSender(db, input.authorDeviceId, envelope);
  const serialized = canonicalEnvelopeJson(envelope);
  const existing = db.query(`
    SELECT id, project_id AS projectId, chat_id AS chatId, artifact_id AS artifactId,
      host_device_id AS hostDeviceId, author_device_id AS authorDeviceId,
      envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
    FROM project_file_references WHERE id = ?
  `).get(input.referenceId) as FileReferenceRow | null;
  if (existing) {
    if (existing.projectId !== input.projectId || existing.chatId !== chatId
      || existing.artifactId !== input.artifactId
      || existing.hostDeviceId !== input.authorDeviceId || existing.authorDeviceId !== input.authorDeviceId
      || existing.envelopeJson !== serialized) {
      throw new Error("Encrypted file-reference ID was already used for different content");
    }
    return { reference: fromRow(existing), created: false };
  }
  const count = db.query(
    "SELECT COUNT(*) AS count FROM project_file_references WHERE project_id = ? AND chat_id = ?",
  ).get(input.projectId, chatId) as { count: number };
  if (count.count >= 500) {
    throw new Error("Encrypted file-reference shared-chat limit of 500 was reached");
  }
  const timestamp = now.toISOString();
  return db.transaction(() => {
    assertProjectUnlocked(db, input.projectId);
    const currentCount = db.query(
      "SELECT COUNT(*) AS count FROM project_file_references WHERE project_id = ? AND chat_id = ?",
    ).get(input.projectId, chatId) as { count: number };
    if (currentCount.count >= 500) {
      throw new Error("Encrypted file-reference shared-chat limit of 500 was reached");
    }
    db.query(`
      INSERT INTO project_file_references
        (id, project_id, chat_id, artifact_id, host_device_id, author_device_id, envelope_json, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.referenceId,
      input.projectId,
      chatId,
      input.artifactId,
      input.authorDeviceId,
      input.authorDeviceId,
      serialized,
      timestamp,
      timestamp,
    );
    return {
      reference: fromRow({
        id: input.referenceId,
        projectId: input.projectId,
        chatId,
        artifactId: input.artifactId,
        hostDeviceId: input.authorDeviceId,
        authorDeviceId: input.authorDeviceId,
        envelopeJson: serialized,
        createdAt: timestamp,
        updatedAt: timestamp,
      }),
      created: true,
    };
  }).immediate();
}

export function listEncryptedFileReferences(
  db: Database,
  projectId: string,
  chatIdOrDeviceId: string,
  maybeDeviceId?: string,
): EncryptedFileReference[] {
  const chatId = maybeDeviceId ? chatIdOrDeviceId : projectId;
  const deviceId = maybeDeviceId ?? chatIdOrDeviceId;
  requireSharedChat(db, projectId, chatId, deviceId);
  const rows = db.query(`
    SELECT id, project_id AS projectId, chat_id AS chatId, artifact_id AS artifactId,
      host_device_id AS hostDeviceId, author_device_id AS authorDeviceId,
      envelope_json AS envelopeJson, created_at AS createdAt, updated_at AS updatedAt
    FROM project_file_references
    WHERE project_id = ? AND chat_id = ?
    ORDER BY created_at, id LIMIT 500
  `).all(projectId, chatId) as FileReferenceRow[];
  return rows.map(fromRow);
}

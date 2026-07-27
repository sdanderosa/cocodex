import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  projectCreationSigningTranscript,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  projectKeyEnvelopeSchema,
  projectKeyEnvelopeSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectKeyEnvelope,
  type SharedChat,
  type SharedProject,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { PROJECT_CONTENT_ENCRYPTION_VERSION } from "../../../packages/cocodex-protocol/src/project-encryption.ts";
import { removeProjectMember as removeMembership, requireProjectMembership } from "./shared-state";
import {
  expirePendingProjectInvitationsBeforeEpoch,
  expirePendingProjectInvitationsForProject,
} from "./project-invitations";
import { generalSharedChat, insertGeneralSharedChat, requireSharedChat } from "./shared-chats";

interface DeviceSigningKeyRow {
  publicKeyPem: string;
}

interface KeyEnvelopeRow {
  envelopeJson: string;
}

interface ContextRow {
  chatId: string;
  envelopeJson: string;
  revision: number;
  updatedAt: string;
}

interface ProjectKeyEpochRow {
  currentEpoch: number;
  lastRotationId: string | null;
  updatedAt: string;
  rotationRequired: boolean;
}

export interface ProjectKeyEnvelopeWriteResult {
  envelope: ProjectKeyEnvelope;
  created: boolean;
}

export interface EncryptedProjectContextRecord {
  projectId: string;
  chatId: string;
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
  rotationRequired: boolean;
}

export interface ProjectKeyRotationResult extends ProjectKeyEpochRecord {
  keyEpoch: number;
  envelopes: ProjectKeyEnvelope[];
  created: boolean;
}

export interface ProjectKeyInitializationResult extends ProjectKeyEpochRecord {
  keyEpoch: 1;
  envelopes: ProjectKeyEnvelope[];
  created: boolean;
}

export interface EncryptedProjectCreationResult {
  project: SharedProject;
  defaultChat: SharedChat;
  keyEpoch: 1;
  envelopes: ProjectKeyEnvelope[];
  created: boolean;
}

export interface ProjectMemberRemovalRotationResult extends ProjectKeyRotationResult {
  removedDeviceId: string;
  cancelledTasks: Array<{ taskId: string; targetDeviceId: string }>;
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

function verifyDeviceSignature(
  db: Database,
  deviceId: string,
  transcript: Buffer,
  signature: string,
): void {
  const publicKeyPem = enrolledSigningKey(db, deviceId);
  let valid = false;
  try {
    valid = verify(null, transcript, createPublicKey(publicKeyPem), Buffer.from(signature, "base64url"));
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Project creation signature is invalid");
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
      updated_at AS updatedAt,
      rotation_required AS rotationRequired
    FROM project_key_epochs
    WHERE project_id = ?
  `).get(projectId) as (Omit<ProjectKeyEpochRow, "rotationRequired"> & { rotationRequired: boolean | number }) | null;
  if (row) return { ...row, rotationRequired: row.rotationRequired === true || row.rotationRequired === 1 };
  const legacy = db.query(`
    SELECT MAX(key_epoch) AS currentEpoch, MAX(updated_at) AS updatedAt
    FROM project_key_envelopes
    WHERE project_id = ?
  `).get(projectId) as { currentEpoch: number | null; updatedAt: string | null };
  if (!legacy.currentEpoch) return null;
  return { currentEpoch: legacy.currentEpoch, lastRotationId: null, updatedAt: legacy.updatedAt ?? "", rotationRequired: false };
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
      created_at, updated_at, rotation_required
    ) VALUES (?, 1, NULL, ?, ?, ?, 0)
  `).run(projectId, senderDeviceId, timestamp, timestamp);
  return { currentEpoch: 1, lastRotationId: null, updatedAt: timestamp, rotationRequired: false };
}

/** Return the active epoch and fail closed while membership-key rotation is pending. */
export function currentProjectKeyEpochForWrite(db: Database, projectId: string): number {
  const state = readProjectKeyEpoch(db, projectId);
  if (!state?.currentEpoch) throw new Error("Project encryption key has not been initialized");
  if (state.rotationRequired) {
    throw new Error("Project key rotation is required before encrypted writes are accepted");
  }
  return state.currentEpoch;
}

/** Reject legacy plaintext project routes once a project has entered encrypted mode. */
export function assertLegacyProjectWriteAllowed(db: Database, projectId: string): void {
  const epoch = db.query(`
    SELECT current_epoch AS currentEpoch, rotation_required AS rotationRequired
    FROM project_key_epochs WHERE project_id = ?
  `).get(projectId) as { currentEpoch: number; rotationRequired: boolean | number } | null;
  const legacy = db.query(`
    SELECT 1 AS initialized FROM project_key_envelopes WHERE project_id = ? LIMIT 1
  `).get(projectId) as { initialized: number } | null;
  if (!epoch && !legacy) return;
  if (epoch?.rotationRequired === true || epoch?.rotationRequired === 1) {
    throw new Error("Project key rotation is required before encrypted writes are accepted");
  }
  throw new Error("Project requires encrypted content frames");
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
    rotationRequired: state?.rotationRequired ?? false,
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
    if (epoch.rotationRequired) {
      throw new Error("Project key rotation is required before sharing project keys");
    }
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

/**
 * Initialize a project key in one transaction.  Initialization is deliberately
 * stricter than the legacy single-envelope share route: the owner must submit
 * one signed envelope for every currently approved project member, and the
 * epoch row is created only if every envelope validates.  This prevents a
 * client from entering encrypted mode locally while the server has only a
 * partial recipient set.
 */
export function initializeProjectKeyEpoch(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  initializationId: string,
  values: unknown,
  now = new Date(),
): ProjectKeyInitializationResult {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(initializationId)) {
    throw new Error("Invalid project key initialization ID");
  }
  if (!Array.isArray(values) || values.length < 1 || values.length > 128) {
    throw new Error("Project key initialization requires 1-128 envelopes");
  }
  const envelopes = values.map(value => projectKeyEnvelopeSchema.parse(value));
  if (envelopes.some(envelope => envelope.projectId !== projectId)) {
    throw new Error("Project key initialization contains an envelope for another project");
  }
  if (envelopes.some(envelope => envelope.keyEpoch !== 1)) {
    throw new Error("Project key initialization envelopes must use epoch 1");
  }
  const ownerMembership = requireProjectMembership(db, projectId, ownerDeviceId);
  if (ownerMembership.role !== "owner") throw new Error("Only a project owner can initialize project keys");
  const members = approvedProjectMembers(db, projectId);
  const memberSet = new Set(members);
  const recipients = new Set<string>();
  for (const envelope of envelopes) {
    if (envelope.senderDeviceId !== ownerDeviceId) {
      throw new Error("Project key initialization envelopes must be signed by the owner");
    }
    if (recipients.has(envelope.recipientDeviceId)) {
      throw new Error("Project key initialization contains duplicate recipients");
    }
    recipients.add(envelope.recipientDeviceId);
    if (!memberSet.has(envelope.recipientDeviceId)) {
      throw new Error("Project key initialization recipient is not an approved project member");
    }
  }
  if (recipients.size !== memberSet.size || members.some(memberId => !recipients.has(memberId))) {
    throw new Error("Project key initialization must include every approved project member");
  }
  for (const envelope of envelopes) {
    verifyEnvelopeSender(
      db,
      ownerDeviceId,
      envelope.senderPublicKeyPem,
      projectKeyEnvelopeSigningTranscript(envelope),
      envelope.signature,
    );
  }
  const serialized = envelopes.map(envelope => envelopeJson(envelope));
  // `last_rotation_id` is globally unique in the current SQLite schema, so
  // scope the idempotency marker by project as well as request id.
  const initRotationId = `init:${projectId}:${initializationId}`;
  return db.transaction(() => {
    const state = readProjectKeyEpoch(db, projectId);
    if (state) {
      if (state.currentEpoch !== 1 || state.rotationRequired) {
        throw new Error("Project key initialization is only allowed before encrypted mode");
      }
      if (state.lastRotationId !== initRotationId) {
        throw new Error("Project encryption key has already been initialized");
      }
      const priorRows = db.query(`
        SELECT envelope_json AS envelopeJson
        FROM project_key_envelopes
        WHERE project_id = ? AND key_epoch = 1
        ORDER BY recipient_device_id ASC
      `).all(projectId) as KeyEnvelopeRow[];
      const prior = priorRows.map(row => parseKeyEnvelope(row.envelopeJson));
      if (!sameEnvelopeSet(prior, envelopes)) throw new Error("Project key initialization replay conflict");
      return {
        projectId,
        currentEpoch: state.currentEpoch,
        lastRotationId: state.lastRotationId,
        updatedAt: state.updatedAt || null,
        rotationRequired: state.rotationRequired,
        keyEpoch: 1 as const,
        envelopes: prior,
        created: false,
      };
    }
    const existing = db.query(`
      SELECT 1 AS present FROM project_key_envelopes WHERE project_id = ? LIMIT 1
    `).get(projectId) as { present: number } | null;
    if (existing) throw new Error("Project key envelopes already exist without an atomic initialization record");
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
        1,
        envelope.recipientDeviceId,
        ownerDeviceId,
        serialized[index],
        timestamp,
        timestamp,
      );
    }
    db.query(`
      INSERT INTO project_key_epochs (
        project_id, current_epoch, last_rotation_id, updated_by_device_id,
        created_at, updated_at, rotation_required
      ) VALUES (?, 1, ?, ?, ?, ?, 0)
    `).run(projectId, initRotationId, ownerDeviceId, timestamp, timestamp);
    return {
      projectId,
      currentEpoch: 1,
      lastRotationId: initRotationId,
      updatedAt: timestamp,
      rotationRequired: false,
      keyEpoch: 1 as const,
      envelopes,
      created: true,
    };
  }).immediate();
}

/**
 * Create a Co-Project, its complete initial membership, and epoch-1 key
 * envelopes as one SQLite transaction. A successful project is therefore
 * never observable without its encryption state.
 */
export function createEncryptedProject(
  db: Database,
  projectId: string,
  name: string,
  ownerDeviceId: string,
  creationId: string,
  values: unknown,
  signature: string,
  now = new Date(),
): EncryptedProjectCreationResult {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(projectId)) {
    throw new Error("Invalid project ID");
  }
  const normalizedName = name.trim();
  if (normalizedName.length < 1 || normalizedName.length > 120) {
    throw new Error("Project name must be 1-120 characters");
  }
  if (!Array.isArray(values) || values.length !== 1) {
    throw new Error("Project creation requires exactly the owner key envelope");
  }
  const envelopes = values.map(value => projectKeyEnvelopeSchema.parse(value));
  const recipientIds = envelopes.map(envelope => envelope.recipientDeviceId);
  if (recipientIds[0] !== ownerDeviceId) {
    throw new Error("Project creation may include only the owner device");
  }
  if (envelopes.some(envelope =>
    envelope.projectId !== projectId
    || envelope.keyEpoch !== 1
    || envelope.senderDeviceId !== ownerDeviceId)) {
    throw new Error("Project creation contains an invalid epoch-1 owner envelope");
  }
  verifyDeviceSignature(
    db,
    ownerDeviceId,
    projectCreationSigningTranscript({
      projectId,
      name: normalizedName,
      ownerDeviceId,
      envelopes,
    }),
    signature,
  );
  const approved = db.query(`
    SELECT id FROM devices
    WHERE id IN (${recipientIds.map(() => "?").join(",")}) AND status = 'approved'
    ORDER BY id ASC
  `).all(...recipientIds) as Array<{ id: string }>;
  if (approved.length !== recipientIds.length) {
    throw new Error("Every project member device must be approved");
  }
  const creationEnvelopesJson = JSON.stringify(
    [...envelopes]
      .sort((left, right) => left.recipientDeviceId.localeCompare(right.recipientDeviceId))
      .map(envelope => JSON.parse(envelopeJson(envelope))),
  );

  return db.transaction(() => {
    const priorCreation = db.query(`
      SELECT project_id AS projectId, name, owner_device_id AS ownerDeviceId,
        envelopes_json AS envelopesJson, owner_signature AS ownerSignature
      FROM encrypted_project_creations
      WHERE creation_id = ?
    `).get(creationId) as {
      projectId: string;
      name: string;
      ownerDeviceId: string;
      envelopesJson: string;
      ownerSignature: string;
    } | null;
    if (priorCreation) {
      if (priorCreation.projectId !== projectId
        || priorCreation.name !== normalizedName
        || priorCreation.ownerDeviceId !== ownerDeviceId
        || priorCreation.envelopesJson !== creationEnvelopesJson
        || priorCreation.ownerSignature !== signature) {
        throw new Error("Project creation replay conflict");
      }
      return {
        project: { id: projectId, name: normalizedName, role: "owner" as const },
        defaultChat: generalSharedChat(db, projectId),
        keyEpoch: 1 as const,
        envelopes,
        created: false,
      };
    }
    const existing = db.query(`
      SELECT name, created_by_device_id AS createdByDeviceId
      FROM projects WHERE id = ?
    `).get(projectId) as { name: string; createdByDeviceId: string } | null;
    let created = false;
    if (!existing) {
      const ownedProjectCount = db.query(`
        SELECT COUNT(*) AS count FROM projects WHERE created_by_device_id = ?
      `).get(ownerDeviceId) as { count: number };
      if (ownedProjectCount.count >= 128) {
        throw new Error("Project owner limit reached");
      }
      const timestamp = now.toISOString();
      db.query(`
        INSERT INTO projects (id, name, created_by_device_id, created_at)
        VALUES (?, ?, ?, ?)
      `).run(projectId, normalizedName, ownerDeviceId, timestamp);
      insertGeneralSharedChat(db, projectId, ownerDeviceId, timestamp);
      for (const recipientDeviceId of [...recipientIds].sort()) {
        db.query(`
          INSERT INTO project_members (project_id, device_id, role, joined_at)
          VALUES (?, ?, ?, ?)
        `).run(
          projectId,
          recipientDeviceId,
          recipientDeviceId === ownerDeviceId ? "owner" : "member",
          timestamp,
        );
      }
      created = true;
    } else {
      if (existing.name !== normalizedName || existing.createdByDeviceId !== ownerDeviceId) {
        throw new Error("Project creation replay conflict");
      }
      const priorMembers = (db.query(`
        SELECT device_id AS deviceId FROM project_members
        WHERE project_id = ? ORDER BY device_id ASC
      `).all(projectId) as Array<{ deviceId: string }>).map(row => row.deviceId);
      const expectedMembers = [...recipientIds].sort();
      if (priorMembers.length !== expectedMembers.length
        || priorMembers.some((deviceId, index) => deviceId !== expectedMembers[index])) {
        throw new Error("Project creation replay conflict");
      }
    }
    const initialized = initializeProjectKeyEpoch(
      db,
      projectId,
      ownerDeviceId,
      creationId,
      envelopes,
      now,
    );
    if (created !== initialized.created) {
      throw new Error("Project creation replay state is inconsistent");
    }
    db.query(`
      INSERT INTO encrypted_project_creations (
        creation_id, project_id, name, owner_device_id,
        envelopes_json, owner_signature, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      creationId,
      projectId,
      normalizedName,
      ownerDeviceId,
      creationEnvelopesJson,
      signature,
      now.toISOString(),
    );
    return {
      project: { id: projectId, name: normalizedName, role: "owner" as const },
      defaultChat: generalSharedChat(db, projectId),
      keyEpoch: 1 as const,
      envelopes: initialized.envelopes,
      created,
    };
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
        rotationRequired: state.rotationRequired,
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
        SET current_epoch = ?, last_rotation_id = ?, updated_by_device_id = ?, updated_at = ?, rotation_required = 0
        WHERE project_id = ?
      `).run(keyEpoch, rotationId, ownerDeviceId, timestamp, projectId);
    } else {
      db.query(`
        INSERT INTO project_key_epochs (
          project_id, current_epoch, last_rotation_id, updated_by_device_id,
          created_at, updated_at, rotation_required
        ) VALUES (?, ?, ?, ?, ?, ?, 0)
      `).run(projectId, keyEpoch, rotationId, ownerDeviceId, timestamp, timestamp);
    }
    expirePendingProjectInvitationsBeforeEpoch(db, projectId, keyEpoch, now);
    return {
      projectId,
      currentEpoch: keyEpoch,
      lastRotationId: rotationId,
      updatedAt: timestamp,
      rotationRequired: false,
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
): Array<{ taskId: string; targetDeviceId: string }> {
  let cancelledTasks: Array<{ taskId: string; targetDeviceId: string }> = [];
  removeMembership(db, projectId, ownerDeviceId, memberDeviceId, now, () => {
    db.query(`
      UPDATE agents SET enabled = 0
      WHERE project_id = ? AND host_device_id = ?
    `).run(projectId, memberDeviceId);
    cancelledTasks = db.query(`
      SELECT id AS taskId, target_device_id AS targetDeviceId FROM agent_tasks
      WHERE project_id = ? AND (requester_device_id = ? OR target_device_id = ?)
        AND status IN ('queued', 'running')
      ORDER BY accepted_at ASC, id ASC
    `).all(projectId, memberDeviceId, memberDeviceId) as Array<{ taskId: string; targetDeviceId: string }>;
    if (cancelledTasks.length > 0) {
      db.query(`
        UPDATE agent_tasks
        SET status = 'failed', completed_at = ?
        WHERE project_id = ? AND (requester_device_id = ? OR target_device_id = ?)
          AND status IN ('queued', 'running')
      `).run(now.toISOString(), projectId, memberDeviceId, memberDeviceId);
    }
    db.query(`
      DELETE FROM project_key_envelopes
      WHERE project_id = ? AND (recipient_device_id = ? OR sender_device_id = ?)
    `).run(projectId, memberDeviceId, memberDeviceId);
    db.query(`
      UPDATE project_key_epochs
      SET rotation_required = 1, updated_at = ?
      WHERE project_id = ?
    `).run(now.toISOString(), projectId);
    expirePendingProjectInvitationsForProject(db, projectId, "key-rotation-required", now);
  });
  return cancelledTasks;
}

/**
 * Remove one member and install the next complete key epoch in the same
 * transaction. This closes the revocation window: either membership, active
 * task cancellation, old-envelope invalidation, and the new recipient set all
 * commit, or none of them do.
 */
export function removeProjectMemberAndRotateKeys(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  memberDeviceId: string,
  expectedEpoch: number,
  rotationId: string,
  values: unknown,
  now = new Date(),
): ProjectMemberRemovalRotationResult {
  if (!Number.isSafeInteger(expectedEpoch) || expectedEpoch < 1) {
    throw new Error("Invalid expected project key epoch");
  }
  if (!rotationId || rotationId.length > 128) throw new Error("Invalid project key rotation ID");
  if (!Array.isArray(values) || values.length < 1 || values.length > 127) {
    throw new Error("Project member removal requires 1-127 rotation envelopes");
  }
  const envelopes = values.map(value => projectKeyEnvelopeSchema.parse(value));
  const priorOperation = db.query(`
    SELECT project_id AS projectId, owner_device_id AS ownerDeviceId,
      removed_device_id AS removedDeviceId, key_epoch AS keyEpoch,
      envelopes_json AS envelopesJson, cancelled_tasks_json AS cancelledTasksJson,
      created_at AS createdAt
    FROM project_member_removal_rotations
    WHERE rotation_id = ?
  `).get(rotationId) as {
    projectId: string;
    ownerDeviceId: string;
    removedDeviceId: string;
    keyEpoch: number;
    envelopesJson: string;
    cancelledTasksJson: string;
    createdAt: string;
  } | null;
  if (priorOperation) {
    let priorEnvelopes: ProjectKeyEnvelope[];
    let cancelledTasks: Array<{ taskId: string; targetDeviceId: string }>;
    try {
      const parsedEnvelopes = JSON.parse(priorOperation.envelopesJson) as unknown;
      if (!Array.isArray(parsedEnvelopes)) throw new Error("invalid envelopes");
      priorEnvelopes = parsedEnvelopes.map(value => projectKeyEnvelopeSchema.parse(value));
      const parsedTasks = JSON.parse(priorOperation.cancelledTasksJson) as unknown;
      if (!Array.isArray(parsedTasks)
        || !parsedTasks.every(value =>
          value && typeof value === "object"
          && typeof (value as Record<string, unknown>).taskId === "string"
          && typeof (value as Record<string, unknown>).targetDeviceId === "string")) {
        throw new Error("invalid cancelled tasks");
      }
      cancelledTasks = parsedTasks as Array<{ taskId: string; targetDeviceId: string }>;
    } catch {
      throw new Error("Project member removal replay record is invalid");
    }
    if (priorOperation.projectId !== projectId
      || priorOperation.ownerDeviceId !== ownerDeviceId
      || priorOperation.removedDeviceId !== memberDeviceId
      || priorOperation.keyEpoch !== expectedEpoch + 1
      || !sameEnvelopeSet(priorEnvelopes, envelopes)) {
      throw new Error("Project member removal replay conflict");
    }
    const currentState = readProjectKeyEpoch(db, projectId);
    return {
      projectId,
      currentEpoch: currentState?.currentEpoch ?? priorOperation.keyEpoch,
      lastRotationId: currentState?.lastRotationId ?? rotationId,
      updatedAt: priorOperation.createdAt,
      rotationRequired: currentState?.rotationRequired ?? false,
      keyEpoch: priorOperation.keyEpoch,
      envelopes: priorEnvelopes,
      created: false,
      removedDeviceId: memberDeviceId,
      cancelledTasks,
    };
  }
  const state = readProjectKeyEpoch(db, projectId);
  const ownerMembership = requireProjectMembership(db, projectId, ownerDeviceId);
  if (ownerMembership.role !== "owner") throw new Error("Only a project owner can remove members");
  if (ownerDeviceId === memberDeviceId) throw new Error("A project owner cannot remove itself");
  const member = db.query(`
    SELECT role FROM project_members WHERE project_id = ? AND device_id = ?
  `).get(projectId, memberDeviceId) as { role: "owner" | "member" } | null;
  if (!member) throw new Error("Device is not a project member");
  if (member.role === "owner") throw new Error("A project owner cannot be removed");
  const currentEpoch = state?.currentEpoch ?? 0;
  if (currentEpoch !== expectedEpoch) {
    throw new Error(`Project key rotation conflict (expected ${expectedEpoch}, current ${currentEpoch})`);
  }
  const keyEpoch = currentEpoch + 1;
  if (keyEpoch > 0x7fffffff) throw new Error("Project key epoch limit reached");
  const remainingMembers = approvedProjectMembers(db, projectId).filter(id => id !== memberDeviceId);
  const remainingSet = new Set(remainingMembers);
  const recipients = new Set<string>();
  if (envelopes.some(envelope => envelope.projectId !== projectId || envelope.keyEpoch !== keyEpoch)) {
    throw new Error(`Project member removal envelopes must use project ${projectId} epoch ${keyEpoch}`);
  }
  for (const envelope of envelopes) {
    if (envelope.senderDeviceId !== ownerDeviceId) {
      throw new Error("Project member removal envelopes must be signed by the owner");
    }
    if (recipients.has(envelope.recipientDeviceId)) {
      throw new Error("Project member removal contains duplicate recipients");
    }
    if (!remainingSet.has(envelope.recipientDeviceId)) {
      throw new Error("Project member removal recipient is not a remaining approved project member");
    }
    recipients.add(envelope.recipientDeviceId);
    verifyEnvelopeSender(
      db,
      ownerDeviceId,
      envelope.senderPublicKeyPem,
      projectKeyEnvelopeSigningTranscript(envelope),
      envelope.signature,
    );
  }
  if (recipients.size !== remainingSet.size || remainingMembers.some(id => !recipients.has(id))) {
    throw new Error("Project member removal must rotate to every remaining approved project member");
  }
  const serialized = envelopes.map(envelope => envelopeJson(envelope));
  let cancelledTasks: Array<{ taskId: string; targetDeviceId: string }> = [];
  removeMembership(db, projectId, ownerDeviceId, memberDeviceId, now, () => {
    db.query(`
      UPDATE agents SET enabled = 0
      WHERE project_id = ? AND host_device_id = ?
    `).run(projectId, memberDeviceId);
    cancelledTasks = db.query(`
      SELECT id AS taskId, target_device_id AS targetDeviceId
      FROM agent_tasks
      WHERE project_id = ? AND (requester_device_id = ? OR target_device_id = ?)
        AND status IN ('queued', 'running')
      ORDER BY accepted_at ASC, id ASC
    `).all(projectId, memberDeviceId, memberDeviceId) as Array<{ taskId: string; targetDeviceId: string }>;
    if (cancelledTasks.length > 0) {
      db.query(`
        UPDATE agent_tasks SET status = 'failed', completed_at = ?
        WHERE project_id = ? AND (requester_device_id = ? OR target_device_id = ?)
          AND status IN ('queued', 'running')
      `).run(now.toISOString(), projectId, memberDeviceId, memberDeviceId);
    }
    const removalAuditUpdate = db.query(`
      UPDATE audit_events
      SET details_json = ?
      WHERE rowid = (
        SELECT rowid FROM audit_events
        WHERE event_type = 'project.member.removed' AND actor_device_id = ? AND subject_id = ?
          AND json_extract(details_json, '$.projectId') = ?
          AND json_extract(details_json, '$.rotationId') IS NULL
        ORDER BY rowid DESC LIMIT 1
      )
    `).run(
      JSON.stringify({ projectId, rotationId, keyEpoch, cancelledTasks }),
      ownerDeviceId,
      memberDeviceId,
      projectId,
    );
    if (removalAuditUpdate.changes !== 1) {
      throw new Error("Project member removal audit record was not created");
    }
    db.query(`
      DELETE FROM project_key_envelopes
      WHERE project_id = ? AND (recipient_device_id = ? OR sender_device_id = ?)
    `).run(projectId, memberDeviceId, memberDeviceId);
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
    const advanced = db.query(`
      UPDATE project_key_epochs
      SET current_epoch = ?, last_rotation_id = ?, updated_by_device_id = ?,
        updated_at = ?, rotation_required = 0
      WHERE project_id = ? AND current_epoch = ?
    `).run(keyEpoch, rotationId, ownerDeviceId, timestamp, projectId, expectedEpoch);
    if (advanced.changes !== 1) throw new Error("Project key epoch changed during member removal");
    expirePendingProjectInvitationsBeforeEpoch(db, projectId, keyEpoch, now);
    db.query(`
      INSERT INTO audit_events (event_type, actor_device_id, subject_id, occurred_at, details_json)
      VALUES ('project.key.rotated-after-removal', ?, ?, ?, ?)
    `).run(ownerDeviceId, memberDeviceId, timestamp, JSON.stringify({ projectId, keyEpoch, rotationId }));
    db.query(`
      INSERT INTO project_member_removal_rotations (
        rotation_id, project_id, owner_device_id, removed_device_id,
        key_epoch, envelopes_json, cancelled_tasks_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      rotationId,
      projectId,
      ownerDeviceId,
      memberDeviceId,
      keyEpoch,
      JSON.stringify(envelopes),
      JSON.stringify(cancelledTasks),
      timestamp,
    );
  });
  return {
    projectId,
    currentEpoch: keyEpoch,
    lastRotationId: rotationId,
    updatedAt: now.toISOString(),
    rotationRequired: false,
    keyEpoch,
    envelopes,
    created: true,
    removedDeviceId: memberDeviceId,
    cancelledTasks,
  };
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

/** Return all envelopes currently addressed to an approved device. */
export function listProjectKeyEnvelopesForDevice(
  db: Database,
  deviceId: string,
): ProjectKeyEnvelope[] {
  const rows = db.query(`
    SELECT e.envelope_json AS envelopeJson
    FROM project_key_envelopes e
    JOIN project_members pm ON pm.project_id = e.project_id AND pm.device_id = e.recipient_device_id
    JOIN devices d ON d.id = pm.device_id
    WHERE e.recipient_device_id = ? AND d.status = 'approved'
    ORDER BY e.project_id ASC, e.key_epoch ASC
    LIMIT 4096
  `).all(deviceId) as KeyEnvelopeRow[];
  return rows.map(row => parseKeyEnvelope(row.envelopeJson));
}

export function getEncryptedProjectContext(
  db: Database,
  projectId: string,
  chatIdOrDeviceId: string,
  maybeDeviceId?: string,
): EncryptedProjectContextRecord | null {
  const chatId = maybeDeviceId ? chatIdOrDeviceId : projectId;
  const deviceId = maybeDeviceId ?? chatIdOrDeviceId;
  requireSharedChat(db, projectId, chatId, deviceId);
  const row = db.query(`
    SELECT chat_id AS chatId, envelope_json AS envelopeJson,
      revision, updated_at AS updatedAt
    FROM encrypted_project_context
    WHERE project_id = ? AND chat_id = ?
  `).get(projectId, chatId) as ContextRow | null;
  if (!row) return null;
  const envelope = parseContextEnvelope(row.envelopeJson);
  if (envelope.version === 1) {
    // Version-1 envelopes had no chat binding.  Migration places those
    // records in the project's General chat; never make an unbound record
    // readable from a newly-created chat.
    if (chatId !== projectId || row.chatId !== projectId) {
      throw new Error("Legacy encrypted project context is only supported for the General chat");
    }
  } else if (envelope.chatId !== chatId || row.chatId !== chatId) {
    throw new Error("Stored encrypted project context belongs to another chat");
  }
  return {
    projectId,
    chatId,
    envelope,
    revision: row.revision,
    updatedAt: row.updatedAt,
  };
}

export function updateEncryptedProjectContext(
  db: Database,
  projectId: string,
  chatIdOrSenderDeviceId: string,
  senderDeviceIdOrExpectedRevision: string | number,
  expectedRevisionOrValue: number | unknown,
  valueOrNow?: unknown,
  maybeNow?: Date,
): EncryptedProjectContextWriteResult {
  const chatScoped = typeof senderDeviceIdOrExpectedRevision === "string";
  const chatId = chatScoped ? chatIdOrSenderDeviceId : projectId;
  const senderDeviceId = chatScoped ? senderDeviceIdOrExpectedRevision : chatIdOrSenderDeviceId;
  const expectedRevision = chatScoped
    ? expectedRevisionOrValue as number
    : senderDeviceIdOrExpectedRevision;
  const value = chatScoped ? valueOrNow : expectedRevisionOrValue;
  const now = (chatScoped ? maybeNow : valueOrNow instanceof Date ? valueOrNow : undefined) ?? new Date();
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new Error("Invalid encrypted project context revision");
  }
  const envelope = projectContentEnvelopeSchema.parse(value);
  if (envelope.projectId !== projectId) throw new Error("Encrypted project context belongs to another project");
  if (chatScoped && envelope.version !== PROJECT_CONTENT_ENCRYPTION_VERSION) {
    throw new Error("Encrypted project context writes require a chat-bound version 2 envelope");
  }
  if (envelope.version === 2 && envelope.chatId !== chatId) throw new Error("Encrypted project context belongs to another chat");
  if (envelope.recordType !== "shared-context") throw new Error("Project context envelope must use the shared-context record type");
  requireSharedChat(db, projectId, chatId, senderDeviceId);
  const currentEpoch = currentProjectKeyEpochForWrite(db, projectId);
  if (envelope.keyEpoch !== currentEpoch) {
    throw new Error(`Encrypted project context must use the current project key epoch ${currentEpoch}`);
  }
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
      SELECT chat_id AS chatId, envelope_json AS envelopeJson,
        revision, updated_at AS updatedAt
      FROM encrypted_project_context
      WHERE project_id = ? AND chat_id = ?
    `).get(projectId, chatId) as ContextRow | null;
    if (existing) {
      const prior = parseContextEnvelope(existing.envelopeJson);
      if ((prior.version === 2 && prior.chatId !== chatId) || existing.chatId !== chatId) {
        throw new Error("Stored encrypted project context belongs to another chat");
      }
      if (prior.recordId === envelope.recordId) {
        if (existing.envelopeJson === serialized) {
          return {
            projectId,
            chatId,
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
        project_id, chat_id, key_epoch, record_id, sender_device_id, envelope_json,
        revision, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(project_id, chat_id) DO UPDATE SET
        key_epoch = excluded.key_epoch,
        record_id = excluded.record_id,
        sender_device_id = excluded.sender_device_id,
        envelope_json = excluded.envelope_json,
        revision = excluded.revision,
        updated_at = excluded.updated_at
    `).run(
      projectId,
      chatId,
      envelope.keyEpoch,
      envelope.recordId,
      envelope.senderDeviceId,
      serialized,
      revision,
      updatedAt,
      updatedAt,
    );
    // Once an encrypted context revision is accepted, remove any legacy
    // plaintext projection so migration cannot leave a second readable copy.
    db.query("DELETE FROM shared_project_context WHERE project_id = ? AND chat_id = ?")
      .run(projectId, chatId);
    return { projectId, chatId, envelope, revision, updatedAt, created: true };
  }).immediate();
}

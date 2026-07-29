import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import * as Y from "yjs";
import {
  PROJECT_MIGRATION_MAX_ITEMS,
  PROJECT_MIGRATION_PAGE_MAX_ITEMS,
  canonicalEd25519PublicKey,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  projectMigrationEnvelopeDigest,
  projectMigrationInventoryItemSchema,
  projectMigrationManifestSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectMigrationInventoryItem,
  type ProjectMigrationStageItem,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { assertProjectUnlocked } from "./project-locks";
import { requireProjectMembership } from "./shared-state";

interface PreparedMigrationRow {
  migrationId: string;
  projectId: string;
  keyEpoch: number;
  ownerDeviceId: string;
  snapshotDigest: string;
  state: "prepared" | "completed" | "invalidated";
  itemCount: number;
  stagedCount: number;
}

interface MigrationItemRow {
  ordinal: number;
  sourceKind: ProjectMigrationInventoryItem["kind"];
  sourceId: string;
  sourceDigest: string;
  inventoryJson: string;
  envelopeJson: string | null;
  envelopeDigest: string | null;
}

export interface ProjectPlaintextMigrationSummary {
  projectId: string;
  migrationId: string;
  keyEpoch: number;
  snapshotDigest: string;
  itemCount: number;
  stagedCount: number;
}

export interface ProjectPlaintextMigrationPage extends ProjectPlaintextMigrationSummary {
  cursor: number;
  items: ProjectMigrationInventoryItem[];
  nextCursor: number | null;
}

const KIND_ORDER: Record<ProjectMigrationInventoryItem["kind"], number> = {
  "shared-context": 0,
  chat: 1,
  "agent-response": 2,
  "shared-prompt": 3,
  artifact: 4,
  task: 5,
};

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("base64url");
}

function migrationRecordId(kind: ProjectMigrationInventoryItem["kind"], projectId: string, chatId: string, value: string): string {
  const bytes = createHash("sha256")
    .update("CoCodex plaintext migration\u0000", "utf8")
    .update(kind, "utf8")
    .update("\u0000", "utf8")
    .update(projectId, "utf8")
    .update("\u0000", "utf8")
    .update(chatId, "utf8")
    .update("\u0000", "utf8")
    .update(value, "utf8")
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function parseObjectJson(value: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${label} is invalid JSON`); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${label} is invalid`);
  return parsed as Record<string, unknown>;
}

function parseStringArray(value: string, label: string): string[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${label} is invalid JSON`); }
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== "string")) throw new Error(`${label} is invalid`);
  return parsed;
}

function withSourceDigest(
  item: Record<string, unknown>,
  source?: unknown,
): ProjectMigrationInventoryItem {
  return projectMigrationInventoryItemSchema.parse({
    ...item,
    sourceDigest: digest(source ?? item),
    staged: false,
  });
}

function meaningfulLegacyContext(db: Database, projectId: string): boolean {
  return Boolean(db.query(`
    SELECT 1 FROM shared_project_context
    WHERE project_id = ? AND (revision > 0 OR final_goal <> '' OR context_json <> '{}')
    LIMIT 1
  `).get(projectId));
}

export function projectHasLegacyPlaintext(db: Database, projectId: string): boolean {
  if (meaningfulLegacyContext(db, projectId)) return true;
  for (const table of ["chat_events", "shared_prompt_updates", "artifacts"] as const) {
    if (db.query(`SELECT 1 FROM ${table} WHERE project_id = ? LIMIT 1`).get(projectId)) return true;
  }
  if (db.query(`SELECT 1 FROM agent_tasks WHERE project_id = ? AND prompt <> '[encrypted]' LIMIT 1`).get(projectId)) return true;
  return false;
}

function projectKeyState(db: Database, projectId: string): { currentEpoch: number; rotationRequired: boolean } {
  const row = db.query(`
    SELECT current_epoch AS currentEpoch, rotation_required AS rotationRequired
    FROM project_key_epochs WHERE project_id = ?
  `).get(projectId) as { currentEpoch: number; rotationRequired: boolean | number } | null;
  return {
    currentEpoch: row?.currentEpoch ?? 0,
    rotationRequired: row?.rotationRequired === true || row?.rotationRequired === 1,
  };
}
function requireOwner(db: Database, projectId: string, deviceId: string): void {
  if (requireProjectMembership(db, projectId, deviceId).role !== "owner") {
    throw new Error("Only the approved project owner can migrate historical plaintext");
  }
}

function promptItems(db: Database, projectId: string): ProjectMigrationInventoryItem[] {
  const documents = db.query(`
    SELECT chat_id AS chatId, yjs_state AS yjsState, updated_at AS updatedAt
    FROM shared_prompt_documents WHERE project_id = ? ORDER BY chat_id ASC
  `).all(projectId) as Array<{ chatId: string; yjsState: Uint8Array; updatedAt: string }>;
  const result: ProjectMigrationInventoryItem[] = [];
  for (const document of documents) {
    const updates = db.query(`
      SELECT update_id AS updateId, sender_device_id AS senderDeviceId,
        update_blob AS updateBlob, accepted_at AS acceptedAt
      FROM shared_prompt_updates
      WHERE project_id = ? AND chat_id = ?
      ORDER BY accepted_at ASC, update_id ASC
    `).all(projectId, document.chatId) as Array<{
      updateId: string;
      senderDeviceId: string;
      updateBlob: Uint8Array;
      acceptedAt: string;
    }>;
    if (updates.length === 0) continue;
    const stored = new Y.Doc();
    const replayed = new Y.Doc();
    try {
      Y.applyUpdate(stored, new Uint8Array(document.yjsState));
      for (const update of updates) Y.applyUpdate(replayed, new Uint8Array(update.updateBlob));
      if (!Buffer.from(Y.encodeStateVector(stored)).equals(Buffer.from(Y.encodeStateVector(replayed)))) {
        throw new Error("Legacy shared prompt document does not match its update log");
      }
      const canonicalUpdate = Buffer.from(Y.encodeStateAsUpdate(stored)).toString("base64");
      const sourceId = migrationRecordId("shared-prompt", projectId, document.chatId, document.updatedAt);
      result.push(withSourceDigest({
        kind: "shared-prompt",
        sourceId,
        chatId: document.chatId,
        updatedAt: document.updatedAt,
        updateBase64: canonicalUpdate,
      }, {
        document: canonicalUpdate,
        updates: updates.map(update => ({
          updateId: update.updateId,
          senderDeviceId: update.senderDeviceId,
          updateBase64: Buffer.from(update.updateBlob).toString("base64"),
          acceptedAt: update.acceptedAt,
        })),
      }));
    } finally {
      stored.destroy();
      replayed.destroy();
    }
  }
  return result;
}

export function buildProjectPlaintextInventory(db: Database, projectId: string): ProjectMigrationInventoryItem[] {
  const items: ProjectMigrationInventoryItem[] = [];
  const contexts = db.query(`
    SELECT chat_id AS chatId, final_goal AS finalGoal, context_json AS contextJson,
      revision, updated_by_device_id AS updatedByDeviceId, updated_at AS updatedAt
    FROM shared_project_context
    WHERE project_id = ? AND (revision > 0 OR final_goal <> '' OR context_json <> '{}')
    ORDER BY chat_id ASC
  `).all(projectId) as Array<{
    chatId: string;
    finalGoal: string;
    contextJson: string;
    revision: number;
    updatedByDeviceId: string | null;
    updatedAt: string;
  }>;
  for (const row of contexts) {
    const context = parseObjectJson(row.contextJson, "Legacy project context");
    items.push(withSourceDigest({
      kind: "shared-context",
      sourceId: migrationRecordId("shared-context", projectId, row.chatId, String(row.revision)),
      chatId: row.chatId,
      revision: row.revision,
      updatedByDeviceId: row.updatedByDeviceId,
      updatedAt: row.updatedAt,
      finalGoal: row.finalGoal,
      context,
    }, row));
  }

  const chats = db.query(`
    SELECT c.sequence AS sourceSequence, c.chat_id AS chatId, c.event_id AS sourceId,
      c.sender_device_id AS attributedDeviceId, c.content,
      c.client_created_at AS clientCreatedAt, c.accepted_at AS acceptedAt,
      e.task_id AS taskId, e.final, e.status
    FROM chat_events c
    LEFT JOIN agent_task_events e ON e.chat_sequence = c.sequence
    WHERE c.project_id = ?
    ORDER BY c.sequence ASC
  `).all(projectId) as Array<{
    sourceSequence: number;
    chatId: string;
    sourceId: string;
    attributedDeviceId: string;
    content: string;
    clientCreatedAt: string;
    acceptedAt: string;
    taskId: string | null;
    final: boolean | number | null;
    status: "running" | "completed" | "failed" | null;
  }>;
  for (const row of chats) {
    if (row.taskId) {
      items.push(withSourceDigest({
        kind: "agent-response",
        sourceId: row.sourceId,
        chatId: row.chatId,
        sourceSequence: row.sourceSequence,
        attributedDeviceId: row.attributedDeviceId,
        taskId: row.taskId,
        final: row.final === true || row.final === 1,
        status: row.status!,
        clientCreatedAt: row.clientCreatedAt,
        acceptedAt: row.acceptedAt,
        content: row.content,
      }, row));
    } else {
      items.push(withSourceDigest({
        kind: "chat",
        sourceId: row.sourceId,
        chatId: row.chatId,
        sourceSequence: row.sourceSequence,
        attributedDeviceId: row.attributedDeviceId,
        clientCreatedAt: row.clientCreatedAt,
        acceptedAt: row.acceptedAt,
        content: row.content,
      }, row));
    }
  }

  items.push(...promptItems(db, projectId));

  const artifacts = db.query(`
    SELECT id AS sourceId, chat_id AS chatId, task_id AS taskId,
      author_device_id AS attributedDeviceId, type AS artifactType,
      title, summary, content, status, created_at AS createdAt, updated_at AS updatedAt
    FROM artifacts WHERE project_id = ? ORDER BY created_at ASC, id ASC
  `).all(projectId) as Array<Record<string, any>>;
  for (const row of artifacts) items.push(withSourceDigest({ kind: "artifact", ...row }, row));

  const tasks = db.query(`
    SELECT id AS sourceId, chat_id AS chatId, requester_device_id AS attributedDeviceId,
      target_device_id AS targetDeviceId, agent_id AS agentId, prompt,
      dependencies_json AS dependenciesJson, input_artifact_ids_json AS inputArtifactIdsJson,
      private_share_message_id AS privateShareMessageId, status,
      accepted_at AS acceptedAt, completed_at AS completedAt
    FROM agent_tasks WHERE project_id = ? AND prompt <> '[encrypted]'
    ORDER BY accepted_at ASC, id ASC
  `).all(projectId) as Array<Record<string, any>>;
  for (const row of tasks) {
    if (row.status === "queued" || row.status === "running") {
      throw new Error("Historical plaintext migration requires every legacy agent task to be terminal");
    }
    items.push(withSourceDigest({
      kind: "task",
      sourceId: row.sourceId,
      chatId: row.chatId,
      attributedDeviceId: row.attributedDeviceId,
      targetDeviceId: row.targetDeviceId,
      agentId: row.agentId,
      prompt: row.prompt,
      dependencies: parseStringArray(row.dependenciesJson, "Legacy task dependencies"),
      inputArtifactIds: parseStringArray(row.inputArtifactIdsJson, "Legacy task artifact inputs"),
      privateShareMessageId: row.privateShareMessageId,
      status: row.status,
      acceptedAt: row.acceptedAt,
      completedAt: row.completedAt,
    }, row));
  }

  if (items.length > PROJECT_MIGRATION_MAX_ITEMS) throw new Error("Project has too many legacy records for one migration");
  return items.sort((left, right) =>
    KIND_ORDER[left.kind] - KIND_ORDER[right.kind]
    || left.chatId.localeCompare(right.chatId)
    || ("sourceSequence" in left ? left.sourceSequence : 0) - ("sourceSequence" in right ? right.sourceSequence : 0)
    || left.sourceId.localeCompare(right.sourceId));
}

export function projectPlaintextSnapshotDigest(items: readonly ProjectMigrationInventoryItem[]): string {
  return digest(items.map(item => ({ kind: item.kind, sourceId: item.sourceId, sourceDigest: item.sourceDigest })));
}

function migrationFromRow(row: PreparedMigrationRow): ProjectPlaintextMigrationSummary {
  return {
    projectId: row.projectId,
    migrationId: row.migrationId,
    keyEpoch: row.keyEpoch,
    snapshotDigest: row.snapshotDigest,
    itemCount: row.itemCount,
    stagedCount: row.stagedCount,
  };
}

function preparedMigration(db: Database, projectId: string, migrationId?: string): PreparedMigrationRow | null {
  const clauses = migrationId ? "project_id = ? AND migration_id = ?" : "project_id = ? AND state = 'prepared'";
  return db.query(`
    SELECT migration_id AS migrationId, project_id AS projectId, key_epoch AS keyEpoch,
      owner_device_id AS ownerDeviceId, snapshot_digest AS snapshotDigest,
      state, item_count AS itemCount, staged_count AS stagedCount
    FROM project_plaintext_migrations WHERE ${clauses}
  `).get(...(migrationId ? [projectId, migrationId] : [projectId])) as PreparedMigrationRow | null;
}

export function prepareProjectPlaintextMigration(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  now = new Date(),
): ProjectPlaintextMigrationSummary {
  requireOwner(db, projectId, ownerDeviceId);
  assertProjectUnlocked(db, projectId);
  const epoch = projectKeyState(db, projectId);
  if (!epoch.currentEpoch) throw new Error("Project encryption must be initialized before plaintext migration");
  if (epoch.rotationRequired) throw new Error("Project key rotation must finish before plaintext migration");

  const result = db.transaction(() => {
    const items = buildProjectPlaintextInventory(db, projectId);
    const snapshotDigest = projectPlaintextSnapshotDigest(items);
    const existing = preparedMigration(db, projectId);
    if (existing) {
      if (existing.ownerDeviceId !== ownerDeviceId || existing.keyEpoch !== epoch.currentEpoch
        || existing.snapshotDigest !== snapshotDigest || existing.itemCount !== items.length) {
        db.query(`UPDATE project_plaintext_migrations SET state = 'invalidated', updated_at = ? WHERE migration_id = ?`)
          .run(now.toISOString(), existing.migrationId);
        return null;
      }
      return migrationFromRow(existing);
    }
    const migrationId = randomUUID();
    const timestamp = now.toISOString();
    db.query(`
      INSERT INTO project_plaintext_migrations (
        migration_id, project_id, key_epoch, owner_device_id, snapshot_digest,
        state, item_count, staged_count, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, 'prepared', ?, 0, ?, ?)
    `).run(migrationId, projectId, epoch.currentEpoch, ownerDeviceId, snapshotDigest, items.length, timestamp, timestamp);
    const insert = db.query(`
      INSERT INTO project_plaintext_migration_items (
        migration_id, ordinal, source_kind, source_id, chat_id,
        source_digest, inventory_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    items.forEach((item, ordinal) => insert.run(
      migrationId, ordinal, item.kind, item.sourceId, item.chatId,
      item.sourceDigest, JSON.stringify(item),
    ));
    return {
      projectId,
      migrationId,
      keyEpoch: epoch.currentEpoch,
      snapshotDigest,
      itemCount: items.length,
      stagedCount: 0,
    };
  }).immediate();
  if (!result) throw new Error("Legacy project content changed after migration preparation; prepare a new migration");
  return result;
}

function requirePreparedMigration(
  db: Database,
  projectId: string,
  migrationId: string,
  ownerDeviceId: string,
  snapshotDigest: string,
): PreparedMigrationRow {
  requireOwner(db, projectId, ownerDeviceId);
  const row = preparedMigration(db, projectId, migrationId);
  if (!row || row.state !== "prepared") throw new Error("Prepared project migration was not found");
  if (row.ownerDeviceId !== ownerDeviceId) throw new Error("Project migration belongs to another owner");
  if (row.snapshotDigest !== snapshotDigest) throw new Error("Project migration snapshot digest changed");
  return row;
}

export function projectPlaintextMigrationPage(
  db: Database,
  input: {
    projectId: string;
    migrationId: string;
    ownerDeviceId: string;
    snapshotDigest: string;
    cursor: number;
  },
): ProjectPlaintextMigrationPage {
  const migration = requirePreparedMigration(
    db, input.projectId, input.migrationId, input.ownerDeviceId, input.snapshotDigest,
  );
  const rows = db.query(`
    SELECT ordinal, source_kind AS sourceKind, source_id AS sourceId,
      source_digest AS sourceDigest, inventory_json AS inventoryJson,
      envelope_json AS envelopeJson, envelope_digest AS envelopeDigest
    FROM project_plaintext_migration_items
    WHERE migration_id = ? AND ordinal >= ?
    ORDER BY ordinal ASC LIMIT ?
  `).all(input.migrationId, input.cursor, PROJECT_MIGRATION_PAGE_MAX_ITEMS) as MigrationItemRow[];
  const items: ProjectMigrationInventoryItem[] = [];
  let encodedBytes = 0;
  for (const row of rows) {
    const parsed = projectMigrationInventoryItemSchema.parse({
      ...JSON.parse(row.inventoryJson),
      staged: row.envelopeJson !== null,
      ...(row.envelopeDigest ? { envelopeDigest: row.envelopeDigest } : {}),
    });
    const bytes = Buffer.byteLength(JSON.stringify(parsed), "utf8");
    if (items.length > 0 && encodedBytes + bytes > 800_000) break;
    if (bytes > 800_000) throw new Error("One legacy migration item exceeds the supported page size");
    items.push(parsed);
    encodedBytes += bytes;
  }
  const next = input.cursor + items.length;
  return {
    ...migrationFromRow(migration),
    cursor: input.cursor,
    items,
    nextCursor: next < migration.itemCount ? next : null,
  };
}

function expectedRecordType(kind: ProjectMigrationInventoryItem["kind"]): ProjectContentEnvelope["recordType"] {
  if (kind === "shared-context") return "shared-context";
  if (kind === "shared-prompt") return "shared-prompt";
  if (kind === "agent-response") return "agent-response";
  return kind;
}

function enrolledOwnerKey(db: Database, ownerDeviceId: string): string {
  const row = db.query(`SELECT public_key_pem AS publicKeyPem FROM devices WHERE id = ? AND status = 'approved'`)
    .get(ownerDeviceId) as { publicKeyPem: string } | null;
  if (!row) throw new Error("Approved migration owner signing key was not found");
  return canonicalEd25519PublicKey(row.publicKeyPem);
}

export function stageProjectPlaintextMigration(
  db: Database,
  input: {
    projectId: string;
    migrationId: string;
    ownerDeviceId: string;
    snapshotDigest: string;
    items: readonly ProjectMigrationStageItem[];
  },
  now = new Date(),
): ProjectPlaintextMigrationSummary & { accepted: number } {
  const migration = requirePreparedMigration(
    db, input.projectId, input.migrationId, input.ownerDeviceId, input.snapshotDigest,
  );
  const epoch = projectKeyState(db, input.projectId);
  if (epoch.currentEpoch !== migration.keyEpoch || epoch.rotationRequired) {
    throw new Error("Project key state changed during plaintext migration");
  }
  const ownerKey = enrolledOwnerKey(db, input.ownerDeviceId);
  return db.transaction(() => {
    let accepted = 0;
    for (const item of input.items) {
      const source = db.query(`
        SELECT source_kind AS sourceKind, source_id AS sourceId,
          source_digest AS sourceDigest, inventory_json AS inventoryJson,
          envelope_json AS envelopeJson, envelope_digest AS envelopeDigest
        FROM project_plaintext_migration_items
        WHERE migration_id = ? AND source_kind = ? AND source_id = ?
      `).get(input.migrationId, item.kind, item.sourceId) as MigrationItemRow | null;
      if (!source || source.sourceDigest !== item.sourceDigest) {
        throw new Error("Migration stage item does not match the frozen legacy inventory");
      }
      const inventory = projectMigrationInventoryItemSchema.parse(JSON.parse(source.inventoryJson));
      const envelope = projectContentEnvelopeSchema.parse(item.envelope);
      if (envelope.projectId !== input.projectId || envelope.keyEpoch !== migration.keyEpoch
        || envelope.recordType !== expectedRecordType(item.kind) || envelope.recordId !== item.sourceId
        || (envelope.version === 2 && envelope.chatId !== inventory.chatId)
        || envelope.senderDeviceId !== input.ownerDeviceId
        || canonicalEd25519PublicKey(envelope.senderPublicKeyPem) !== ownerKey) {
        throw new Error("Migration envelope does not match its frozen source record");
      }
      if (!verify(null, projectContentSigningTranscript({ ...envelope, signature: undefined } as never), createPublicKey(ownerKey), Buffer.from(envelope.signature, "base64url"))) {
        throw new Error("Migration envelope owner signature is invalid");
      }
      const envelopeDigest = projectMigrationEnvelopeDigest(envelope);
      const serialized = JSON.stringify(Object.fromEntries(
        Object.entries(envelope).sort(([left], [right]) => left.localeCompare(right)),
      ));
      if (source.envelopeJson !== null) {
        if (source.envelopeDigest !== envelopeDigest || source.envelopeJson !== serialized) {
          throw new Error("Migration stage retry changed an already accepted envelope");
        }
        continue;
      }
      db.query(`
        UPDATE project_plaintext_migration_items
        SET envelope_json = ?, envelope_digest = ?, staged_at = ?
        WHERE migration_id = ? AND source_kind = ? AND source_id = ? AND envelope_json IS NULL
      `).run(serialized, envelopeDigest, now.toISOString(), input.migrationId, item.kind, item.sourceId);
      accepted += 1;
    }
    const count = db.query(`
      SELECT COUNT(*) AS count FROM project_plaintext_migration_items
      WHERE migration_id = ? AND envelope_json IS NOT NULL
    `).get(input.migrationId) as { count: number };
    db.query(`UPDATE project_plaintext_migrations SET staged_count = ?, updated_at = ? WHERE migration_id = ? AND state = 'prepared'`)
      .run(count.count, now.toISOString(), input.migrationId);
    return { ...migrationFromRow({ ...migration, stagedCount: count.count }), accepted };
  }).immediate();
}

export interface ProjectPlaintextMigrationCompleted {
  projectId: string;
  migrationId: string;
  keyEpoch: number;
  snapshotDigest: string;
  migratedCount: number;
  resetChatIds: string[];
  completedAt: string;
}

interface ExistingEncryptedChatRow {
  sequence: number;
  chatId: string;
  eventId: string;
  senderDeviceId: string;
  envelopeJson: string;
  clientCreatedAt: string;
  acceptedAt: string;
  taskId: string | null;
  final: number;
  status: string;
  migrationId: string | null;
  attributedDeviceId: string | null;
}

interface ExistingEncryptedPromptRow {
  sequence: number;
  chatId: string;
  updateId: string;
  senderDeviceId: string;
  envelopeJson: string;
  acceptedAt: string;
  migrationId: string | null;
}

function verifyStoredMigrationEnvelope(
  source: MigrationItemRow,
  inventory: ProjectMigrationInventoryItem,
  migration: PreparedMigrationRow,
  ownerKey: string,
): { envelope: ProjectContentEnvelope; envelopeJson: string; envelopeDigest: string } {
  if (!source.envelopeJson || !source.envelopeDigest) throw new Error("Migration inventory is not fully staged");
  const envelope = projectContentEnvelopeSchema.parse(JSON.parse(source.envelopeJson));
  if (envelope.projectId !== migration.projectId || envelope.keyEpoch !== migration.keyEpoch
    || envelope.recordType !== expectedRecordType(inventory.kind) || envelope.recordId !== inventory.sourceId
    || (envelope.version === 2 && envelope.chatId !== inventory.chatId)
    || envelope.senderDeviceId !== migration.ownerDeviceId
    || canonicalEd25519PublicKey(envelope.senderPublicKeyPem) !== ownerKey
    || projectMigrationEnvelopeDigest(envelope) !== source.envelopeDigest) {
    throw new Error("Stored migration envelope no longer matches its frozen source record");
  }
  const { signature, ...unsigned } = envelope;
  if (!verify(null, projectContentSigningTranscript(unsigned), createPublicKey(ownerKey), Buffer.from(signature, "base64url"))) {
    throw new Error("Stored migration envelope owner signature is invalid");
  }
  const canonical = JSON.stringify(Object.fromEntries(
    Object.entries(envelope).sort(([left], [right]) => left.localeCompare(right)),
  ));
  if (canonical !== source.envelopeJson) throw new Error("Stored migration envelope is not canonical");
  return { envelope, envelopeJson: canonical, envelopeDigest: source.envelopeDigest };
}

function compareHistoricalOrder(
  left: { acceptedAt: string; migrated: boolean; order: number; id: string },
  right: { acceptedAt: string; migrated: boolean; order: number; id: string },
): number {
  return left.acceptedAt.localeCompare(right.acceptedAt)
    || Number(right.migrated) - Number(left.migrated)
    || left.order - right.order
    || left.id.localeCompare(right.id);
}

export function commitProjectPlaintextMigration(
  db: Database,
  input: {
    projectId: string;
    migrationId: string;
    ownerDeviceId: string;
    keyEpoch: number;
    snapshotDigest: string;
    ownerPublicKeyPem: string;
    ownerSignature: string;
    serverFingerprint: string;
  },
  now = new Date(),
): ProjectPlaintextMigrationCompleted {
  requireOwner(db, input.projectId, input.ownerDeviceId);
  assertProjectUnlocked(db, input.projectId);
  const migration = requirePreparedMigration(
    db, input.projectId, input.migrationId, input.ownerDeviceId, input.snapshotDigest,
  );
  const keyState = projectKeyState(db, input.projectId);
  if (input.keyEpoch !== migration.keyEpoch || keyState.currentEpoch !== migration.keyEpoch || keyState.rotationRequired) {
    throw new Error("Project key state changed during plaintext migration");
  }
  const ownerKey = enrolledOwnerKey(db, input.ownerDeviceId);
  if (canonicalEd25519PublicKey(input.ownerPublicKeyPem) !== ownerKey) {
    throw new Error("Migration manifest owner key does not match the approved owner");
  }

  return db.transaction(() => {
    requireOwner(db, input.projectId, input.ownerDeviceId);
    assertProjectUnlocked(db, input.projectId);
    const currentInventory = buildProjectPlaintextInventory(db, input.projectId);
    if (projectPlaintextSnapshotDigest(currentInventory) !== migration.snapshotDigest
      || currentInventory.length !== migration.itemCount) {
      throw new Error("Legacy project content changed before migration commit");
    }
    const sources = db.query(`
      SELECT ordinal, source_kind AS sourceKind, source_id AS sourceId,
        source_digest AS sourceDigest, inventory_json AS inventoryJson,
        envelope_json AS envelopeJson, envelope_digest AS envelopeDigest
      FROM project_plaintext_migration_items
      WHERE migration_id = ? ORDER BY ordinal ASC
    `).all(input.migrationId) as MigrationItemRow[];
    if (sources.length !== migration.itemCount || sources.some(source => !source.envelopeJson || !source.envelopeDigest)) {
      throw new Error("Migration inventory is not fully staged");
    }
    const currentByIdentity = new Map(currentInventory.map(item => [`${item.kind}\u0000${item.sourceId}`, item]));
    const staged = sources.map(source => {
      const inventory = projectMigrationInventoryItemSchema.parse(JSON.parse(source.inventoryJson));
      const current = currentByIdentity.get(`${source.sourceKind}\u0000${source.sourceId}`);
      if (!current || current.sourceDigest !== source.sourceDigest || inventory.sourceDigest !== source.sourceDigest) {
        throw new Error("Migration staged source no longer matches the legacy inventory");
      }
      return { source, inventory, ...verifyStoredMigrationEnvelope(source, inventory, migration, ownerKey) };
    });
    const mappings = staged.map(item => ({
      kind: item.inventory.kind,
      sourceId: item.inventory.sourceId,
      sourceDigest: item.inventory.sourceDigest,
      envelopeDigest: item.envelopeDigest,
    }));
    const manifestTranscript = projectMigrationManifestSigningTranscript({
      serverFingerprint: input.serverFingerprint,
      projectId: input.projectId,
      migrationId: input.migrationId,
      keyEpoch: input.keyEpoch,
      snapshotDigest: input.snapshotDigest,
      ownerDeviceId: input.ownerDeviceId,
      ownerPublicKeyPem: ownerKey,
      mappings,
    });
    if (!verify(null, manifestTranscript, createPublicKey(ownerKey), Buffer.from(input.ownerSignature, "base64url"))) {
      throw new Error("Migration manifest owner signature is invalid");
    }

    const existingChats = db.query(`
      SELECT sequence, chat_id AS chatId, event_id AS eventId,
        sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
        client_created_at AS clientCreatedAt, accepted_at AS acceptedAt,
        task_id AS taskId, final, status, migration_id AS migrationId,
        migrated_attributed_device_id AS attributedDeviceId
      FROM project_chat_events WHERE project_id = ?
    `).all(input.projectId) as ExistingEncryptedChatRow[];
    const migratedChats = staged.filter(item => item.inventory.kind === "chat" || item.inventory.kind === "agent-response")
      .map(item => {
        const inventory = item.inventory as Extract<ProjectMigrationInventoryItem, { kind: "chat" | "agent-response" }>;
        return {
          acceptedAt: inventory.acceptedAt,
          migrated: true,
          order: inventory.sourceSequence,
          id: inventory.sourceId,
          chatId: inventory.chatId,
          eventId: inventory.sourceId,
          senderDeviceId: input.ownerDeviceId,
          envelopeJson: item.envelopeJson,
          clientCreatedAt: inventory.clientCreatedAt,
          taskId: inventory.kind === "agent-response" ? inventory.taskId : null,
          final: inventory.kind === "agent-response" && inventory.final ? 1 : 0,
          status: inventory.kind === "agent-response" ? inventory.status : "chat",
          migrationId: input.migrationId,
          attributedDeviceId: inventory.attributedDeviceId,
        };
      });
    const allChats = [
      ...existingChats.map(row => ({ ...row, migrated: false, order: row.sequence, id: row.eventId })),
      ...migratedChats,
    ].sort(compareHistoricalOrder);
    db.query("DELETE FROM project_chat_events WHERE project_id = ?").run(input.projectId);
    const insertChat = db.query(`
      INSERT INTO project_chat_events (
        project_id, chat_id, event_id, sender_device_id, envelope_json,
        client_created_at, accepted_at, task_id, final, status,
        migration_id, migrated_attributed_device_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const row of allChats) insertChat.run(
      input.projectId, row.chatId, row.eventId, row.senderDeviceId, row.envelopeJson,
      row.clientCreatedAt, row.acceptedAt, row.taskId, row.final, row.status,
      row.migrationId, row.attributedDeviceId,
    );

    const existingPrompts = db.query(`
      SELECT sequence, chat_id AS chatId, update_id AS updateId,
        sender_device_id AS senderDeviceId, envelope_json AS envelopeJson,
        accepted_at AS acceptedAt, migration_id AS migrationId
      FROM project_prompt_updates WHERE project_id = ?
    `).all(input.projectId) as ExistingEncryptedPromptRow[];
    const migratedPrompts = staged.filter(item => item.inventory.kind === "shared-prompt").map(item => {
      const inventory = item.inventory as Extract<ProjectMigrationInventoryItem, { kind: "shared-prompt" }>;
      return {
        acceptedAt: inventory.updatedAt,
        migrated: true,
        order: 0,
        id: inventory.sourceId,
        chatId: inventory.chatId,
        updateId: inventory.sourceId,
        senderDeviceId: input.ownerDeviceId,
        envelopeJson: item.envelopeJson,
        migrationId: input.migrationId,
      };
    });
    const allPrompts = [
      ...existingPrompts.map(row => ({ ...row, migrated: false, order: row.sequence, id: row.updateId })),
      ...migratedPrompts,
    ].sort(compareHistoricalOrder);
    db.query("DELETE FROM project_prompt_updates WHERE project_id = ?").run(input.projectId);
    const insertPrompt = db.query(`
      INSERT INTO project_prompt_updates (
        project_id, chat_id, update_id, sender_device_id, envelope_json,
        accepted_at, migration_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    for (const row of allPrompts) insertPrompt.run(
      input.projectId, row.chatId, row.updateId, row.senderDeviceId,
      row.envelopeJson, row.acceptedAt, row.migrationId,
    );

    for (const item of staged) {
      const inventory = item.inventory;
      if (inventory.kind === "shared-context") {
        const existing = db.query(`
          SELECT revision FROM encrypted_project_context WHERE project_id = ? AND chat_id = ?
        `).get(input.projectId, inventory.chatId) as { revision: number } | null;
        if (!existing || inventory.revision > existing.revision) {
          db.query(`
            INSERT INTO encrypted_project_context (
              project_id, chat_id, key_epoch, record_id, sender_device_id,
              envelope_json, revision, created_at, updated_at, migration_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, chat_id) DO UPDATE SET
              key_epoch = excluded.key_epoch,
              record_id = excluded.record_id,
              sender_device_id = excluded.sender_device_id,
              envelope_json = excluded.envelope_json,
              revision = excluded.revision,
              updated_at = excluded.updated_at,
              migration_id = excluded.migration_id
          `).run(
            input.projectId, inventory.chatId, input.keyEpoch, inventory.sourceId,
            input.ownerDeviceId, item.envelopeJson, inventory.revision,
            inventory.updatedAt, inventory.updatedAt, input.migrationId,
          );
        }
      } else if (inventory.kind === "artifact") {
        if (db.query("SELECT 1 FROM project_artifacts WHERE id = ?").get(inventory.sourceId)) {
          throw new Error("Legacy artifact ID collides with an encrypted artifact");
        }
        db.query(`
          INSERT INTO project_artifacts (
            id, project_id, chat_id, task_id, author_device_id, envelope_json,
            created_at, updated_at, migration_id, migrated_attributed_device_id
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          inventory.sourceId, input.projectId, inventory.chatId, inventory.taskId,
          input.ownerDeviceId, item.envelopeJson, inventory.createdAt, inventory.updatedAt,
          input.migrationId, inventory.attributedDeviceId,
        );
      } else if (inventory.kind === "task") {
        const updated = db.query(`
          UPDATE agent_tasks
          SET prompt = '[encrypted]', prompt_envelope_json = ?, migration_id = ?
          WHERE id = ? AND project_id = ? AND prompt <> '[encrypted]'
            AND status IN ('completed', 'failed')
        `).run(item.envelopeJson, input.migrationId, inventory.sourceId, input.projectId);
        if (updated.changes !== 1) throw new Error("Legacy task changed before migration commit");
      }
    }

    db.query("DELETE FROM chat_events WHERE project_id = ?").run(input.projectId);
    db.query("DELETE FROM shared_prompt_updates WHERE project_id = ?").run(input.projectId);
    db.query("DELETE FROM shared_prompt_documents WHERE project_id = ?").run(input.projectId);
    db.query("DELETE FROM artifacts WHERE project_id = ?").run(input.projectId);
    db.query("DELETE FROM shared_project_context WHERE project_id = ?").run(input.projectId);
    if (projectHasLegacyPlaintext(db, input.projectId)) throw new Error("Legacy plaintext remained after migration replacement");

    const completedAt = now.toISOString();
    const manifestDigest = createHash("sha256").update(manifestTranscript).digest("base64url");
    db.query(`
      UPDATE project_plaintext_migrations
      SET state = 'completed', manifest_digest = ?, owner_signature = ?,
        staged_count = item_count, updated_at = ?, completed_at = ?
      WHERE migration_id = ? AND state = 'prepared'
    `).run(manifestDigest, input.ownerSignature, completedAt, completedAt, input.migrationId);
    db.query("DELETE FROM project_plaintext_migration_items WHERE migration_id = ?").run(input.migrationId);
    return {
      projectId: input.projectId,
      migrationId: input.migrationId,
      keyEpoch: input.keyEpoch,
      snapshotDigest: input.snapshotDigest,
      migratedCount: migration.itemCount,
      resetChatIds: [...new Set(currentInventory.map(item => item.chatId))].sort(),
      completedAt,
    };
  }).immediate();
}
export function invalidateProjectPlaintextMigration(
  db: Database,
  projectId: string,
  now = new Date(),
): boolean {
  const prepared = db.query(`
    SELECT migration_id AS migrationId
    FROM project_plaintext_migrations
    WHERE project_id = ? AND state = 'prepared'
  `).get(projectId) as { migrationId: string } | null;
  if (!prepared) return false;
  db.query("DELETE FROM project_plaintext_migration_items WHERE migration_id = ?")
    .run(prepared.migrationId);
  const invalidated = db.query(`
    UPDATE project_plaintext_migrations
    SET state = 'invalidated', staged_count = 0, updated_at = ?
    WHERE migration_id = ? AND state = 'prepared'
  `).run(now.toISOString(), prepared.migrationId);
  if (invalidated.changes !== 1) {
    throw new Error("Historical project migration changed during invalidation");
  }
  return true;
}


export function assertNoPreparedProjectPlaintextMigration(db: Database, projectId: string): void {
  if (db.query(`
    SELECT 1 FROM project_plaintext_migrations
    WHERE project_id = ? AND state = 'prepared' LIMIT 1
  `).get(projectId)) {
    throw new Error("Historical project plaintext migration is still in progress");
  }
}
export function assertProjectPlaintextMigrationComplete(db: Database, projectId: string): void {
  if (projectHasLegacyPlaintext(db, projectId)) {
    throw new Error("Historical project plaintext must be migrated before encrypted writes are accepted");
  }
  assertNoPreparedProjectPlaintextMigration(db, projectId);
}

import { createHash } from "node:crypto";
import { z } from "zod";
import { canonicalEd25519PublicKey } from "./keys";
import { PROJECT_KEY_EPOCH_MAX, projectContentEnvelopeSchema, type ProjectContentEnvelope } from "./project-encryption";

export const PROJECT_MIGRATION_VERSION = 1 as const;
export const PROJECT_MIGRATION_PAGE_MAX_ITEMS = 32 as const;
export const PROJECT_MIGRATION_STAGE_MAX_ITEMS = 16 as const;
export const PROJECT_MIGRATION_MAX_ITEMS = 10_000 as const;
const PROJECT_CONTEXT_MAX_BYTES = 48 * 1024;

const requestId = z.uuid();
const projectId = z.uuid();
const chatId = z.uuid();
const deviceId = z.uuid();
const migrationId = z.uuid();
const sourceId = z.string().trim().min(1).max(256);
const sourceSequence = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const digestPattern = /^[A-Za-z0-9_-]{43}$/;
const sha256Digest = z.string().regex(digestPattern).refine(value => {
  const bytes = Buffer.from(value, "base64url");
  return bytes.byteLength === 32 && bytes.toString("base64url") === value;
}, "Migration digest must be canonical base64url SHA-256");
const signature = z.string().min(86).max(86).regex(/^[A-Za-z0-9_-]+$/).refine(value => {
  const bytes = Buffer.from(value, "base64url");
  return bytes.byteLength === 64 && bytes.toString("base64url") === value;
}, "Migration signature must encode exactly 64 bytes");
const boundedContext = z.record(z.string(), z.unknown()).superRefine((value, refinement) => {
  try {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > PROJECT_CONTEXT_MAX_BYTES) {
      refinement.addIssue({ code: "custom", message: "Migration context is too large" });
    }
  } catch {
    refinement.addIssue({ code: "custom", message: "Migration context must be JSON-serializable" });
  }
});
const canonicalBase64 = z.string().min(1).max(700_000).regex(/^[A-Za-z0-9+/]*={0,2}$/).refine(value => {
  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}, "Migration binary payload must be canonical base64");

export const projectMigrationSourceKindSchema = z.enum([
  "shared-context",
  "chat",
  "agent-response",
  "shared-prompt",
  "artifact",
  "task",
]);
export type ProjectMigrationSourceKind = z.infer<typeof projectMigrationSourceKindSchema>;

const inventoryBase = {
  sourceId,
  chatId,
  sourceDigest: sha256Digest,
  envelopeDigest: sha256Digest.optional(),
} as const;

export const projectMigrationInventoryItemSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("shared-context"),
    ...inventoryBase,
    revision: z.number().int().nonnegative().max(0x7fff_ffff),
    updatedByDeviceId: deviceId.nullable(),
    updatedAt: z.iso.datetime(),
    finalGoal: z.string().max(32_768),
    context: boundedContext,
    staged: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal("chat"),
    ...inventoryBase,
    sourceSequence,
    attributedDeviceId: deviceId,
    clientCreatedAt: z.iso.datetime(),
    acceptedAt: z.iso.datetime(),
    content: z.string().min(1).max(32_768),
    staged: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal("agent-response"),
    ...inventoryBase,
    sourceSequence,
    attributedDeviceId: deviceId,
    taskId: z.uuid(),
    final: z.boolean(),
    status: z.enum(["running", "completed", "failed"]),
    clientCreatedAt: z.iso.datetime(),
    acceptedAt: z.iso.datetime(),
    content: z.string().min(1).max(32_768),
    staged: z.boolean(),
  }).strict().superRefine((value, refinement) => {
    if (value.final !== (value.status === "completed" || value.status === "failed")) {
      refinement.addIssue({ code: "custom", path: ["final"], message: "Final flag and result status disagree" });
    }
  }),
  z.object({
    kind: z.literal("shared-prompt"),
    ...inventoryBase,
    updatedAt: z.iso.datetime(),
    updateBase64: canonicalBase64,
    staged: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal("artifact"),
    ...inventoryBase,
    attributedDeviceId: deviceId,
    taskId: z.uuid().nullable(),
    artifactType: z.enum(["finding", "plan", "decision", "api-contract", "schema", "code-change", "commit", "diff", "test-result", "review", "handoff", "documentation", "failure-report", "browser-result", "final-result"]),
    title: z.string().trim().min(1).max(200),
    summary: z.string().trim().min(1).max(4_000),
    content: z.string().min(1).max(256_000),
    status: z.enum(["draft", "ready", "accepted", "rejected", "superseded", "integrated"]),
    createdAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
    staged: z.boolean(),
  }).strict(),
  z.object({
    kind: z.literal("task"),
    ...inventoryBase,
    attributedDeviceId: deviceId,
    targetDeviceId: deviceId,
    agentId: z.string().trim().min(1).max(120),
    prompt: z.string().min(1).max(32_768),
    dependencies: z.array(z.uuid()).max(16),
    inputArtifactIds: z.array(z.uuid()).max(16),
    privateShareMessageId: z.uuid().nullable(),
    status: z.enum(["completed", "failed"]),
    acceptedAt: z.iso.datetime(),
    completedAt: z.iso.datetime(),
    staged: z.boolean(),
  }).strict(),
]).superRefine((value, refinement) => {
  if (value.staged !== Boolean(value.envelopeDigest)) {
    refinement.addIssue({ code: "custom", path: ["envelopeDigest"], message: "Staged migration items require their envelope digest" });
  }
});
export type ProjectMigrationInventoryItem = z.infer<typeof projectMigrationInventoryItemSchema>;

export const projectMigrationPrepareFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.prepare"),
  requestId,
  projectId,
}).strict();

export const projectMigrationInventoryFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.inventory"),
  requestId,
  projectId,
  migrationId,
  keyEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX),
  snapshotDigest: sha256Digest,
  itemCount: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
  stagedCount: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
}).strict().superRefine((value, refinement) => {
  if (value.stagedCount > value.itemCount) {
    refinement.addIssue({ code: "custom", path: ["stagedCount"], message: "Staged count exceeds inventory size" });
  }
});

export const projectMigrationPageFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.page"),
  requestId,
  projectId,
  migrationId,
  snapshotDigest: sha256Digest,
  cursor: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
}).strict();

export const projectMigrationPageResultFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.page.result"),
  requestId,
  projectId,
  migrationId,
  snapshotDigest: sha256Digest,
  cursor: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
  items: z.array(projectMigrationInventoryItemSchema).max(PROJECT_MIGRATION_PAGE_MAX_ITEMS),
  nextCursor: z.number().int().positive().max(PROJECT_MIGRATION_MAX_ITEMS).nullable(),
}).strict().superRefine((value, refinement) => {
  const expected = value.cursor + value.items.length;
  if (value.nextCursor !== null && value.nextCursor !== expected) {
    refinement.addIssue({ code: "custom", path: ["nextCursor"], message: "Migration cursor is not contiguous" });
  }
  if (value.items.length === 0 && value.nextCursor !== null) {
    refinement.addIssue({ code: "custom", path: ["items"], message: "Empty migration pages must terminate" });
  }
});

export const projectMigrationStageItemSchema = z.object({
  kind: projectMigrationSourceKindSchema,
  sourceId,
  sourceDigest: sha256Digest,
  envelope: projectContentEnvelopeSchema,
}).strict();
export type ProjectMigrationStageItem = z.infer<typeof projectMigrationStageItemSchema>;

export const projectMigrationStageFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.stage"),
  requestId,
  projectId,
  migrationId,
  snapshotDigest: sha256Digest,
  items: z.array(projectMigrationStageItemSchema).min(1).max(PROJECT_MIGRATION_STAGE_MAX_ITEMS),
}).strict().superRefine((value, refinement) => {
  const identities = new Set<string>();
  for (const [index, item] of value.items.entries()) {
    const identity = `${item.kind}\u0000${item.sourceId}`;
    if (identities.has(identity)) {
      refinement.addIssue({ code: "custom", path: ["items", index], message: "Migration stage contains a duplicate source item" });
    }
    identities.add(identity);
  }
});

export const projectMigrationStagedFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.staged"),
  requestId,
  projectId,
  migrationId,
  snapshotDigest: sha256Digest,
  accepted: z.number().int().nonnegative().max(PROJECT_MIGRATION_STAGE_MAX_ITEMS),
  stagedCount: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
  itemCount: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
}).strict().superRefine((value, refinement) => {
  if (value.stagedCount > value.itemCount) {
    refinement.addIssue({ code: "custom", path: ["stagedCount"], message: "Staged count exceeds inventory size" });
  }
});

export const projectMigrationCommitFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.commit"),
  requestId,
  projectId,
  migrationId,
  keyEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX),
  snapshotDigest: sha256Digest,
  ownerPublicKeyPem: z.string().min(64).max(2_048),
  ownerSignature: signature,
}).strict();

export const projectMigrationCompletedFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.completed"),
  requestId: requestId.optional(),
  projectId,
  migrationId,
  keyEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX),
  snapshotDigest: sha256Digest,
  migratedCount: z.number().int().nonnegative().max(PROJECT_MIGRATION_MAX_ITEMS),
  resetChatIds: z.array(chatId).max(1_024),
  completedAt: z.iso.datetime(),
}).strict();

export const projectMigrationRequiredFrameSchema = z.object({
  version: z.literal(PROJECT_MIGRATION_VERSION),
  type: z.literal("project.migration.required"),
  projectId,
  keyEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX),
  ownerDeviceId: deviceId,
}).strict();

export interface ProjectMigrationManifestMapping {
  kind: ProjectMigrationSourceKind;
  sourceId: string;
  sourceDigest: string;
  envelopeDigest: string;
}

export interface ProjectMigrationManifestSigningInput {
  serverFingerprint: string;
  projectId: string;
  migrationId: string;
  keyEpoch: number;
  snapshotDigest: string;
  ownerDeviceId: string;
  ownerPublicKeyPem: string;
  mappings: readonly ProjectMigrationManifestMapping[];
}

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

function requireDigest(value: string, label: string): string {
  if (!sha256Digest.safeParse(value).success) throw new Error(`${label} must be canonical base64url SHA-256`);
  return value;
}

export function projectMigrationEnvelopeDigest(envelope: ProjectContentEnvelope): string {
  const parsed = projectContentEnvelopeSchema.parse(envelope);
  const canonical = JSON.stringify(Object.fromEntries(
    Object.entries(parsed).sort(([left], [right]) => left.localeCompare(right)),
  ));
  return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

export function projectMigrationManifestSigningTranscript(input: ProjectMigrationManifestSigningInput): Buffer {
  const ownerKey = canonicalEd25519PublicKey(input.ownerPublicKeyPem);
  if (!Number.isSafeInteger(input.keyEpoch) || input.keyEpoch < 1 || input.keyEpoch > PROJECT_KEY_EPOCH_MAX) {
    throw new Error("Migration key epoch is invalid");
  }
  requireDigest(input.snapshotDigest, "Migration snapshot digest");
  if (input.mappings.length > PROJECT_MIGRATION_MAX_ITEMS) throw new Error("Migration manifest has too many items");
  const ordered = [...input.mappings].sort((left, right) =>
    left.kind.localeCompare(right.kind) || left.sourceId.localeCompare(right.sourceId));
  const identities = new Set<string>();
  const mappingHash = createHash("sha256");
  for (const mapping of ordered) {
    projectMigrationSourceKindSchema.parse(mapping.kind);
    sourceId.parse(mapping.sourceId);
    requireDigest(mapping.sourceDigest, "Migration source digest");
    requireDigest(mapping.envelopeDigest, "Migration envelope digest");
    const identity = `${mapping.kind}\u0000${mapping.sourceId.trim()}`;
    if (identities.has(identity)) throw new Error("Migration manifest contains a duplicate source item");
    identities.add(identity);
    for (const value of [mapping.kind, mapping.sourceId.trim(), mapping.sourceDigest, mapping.envelopeDigest]) {
      mappingHash.update(lengthPrefix(value));
    }
  }
  return Buffer.concat([
    Buffer.from("COCODEX-PROJECT-PLAINTEXT-MIGRATION\u0000", "utf8"),
    lengthPrefix(String(PROJECT_MIGRATION_VERSION)),
    lengthPrefix(input.serverFingerprint),
    lengthPrefix(projectId.parse(input.projectId)),
    lengthPrefix(migrationId.parse(input.migrationId)),
    lengthPrefix(String(input.keyEpoch)),
    lengthPrefix(input.snapshotDigest),
    lengthPrefix(deviceId.parse(input.ownerDeviceId)),
    lengthPrefix(ownerKey),
    lengthPrefix(String(ordered.length)),
    lengthPrefix(mappingHash.digest("base64url")),
  ]);
}

export type ProjectMigrationPrepareFrame = z.infer<typeof projectMigrationPrepareFrameSchema>;
export type ProjectMigrationInventoryFrame = z.infer<typeof projectMigrationInventoryFrameSchema>;
export type ProjectMigrationPageFrame = z.infer<typeof projectMigrationPageFrameSchema>;
export type ProjectMigrationPageResultFrame = z.infer<typeof projectMigrationPageResultFrameSchema>;
export type ProjectMigrationStageFrame = z.infer<typeof projectMigrationStageFrameSchema>;
export type ProjectMigrationStagedFrame = z.infer<typeof projectMigrationStagedFrameSchema>;
export type ProjectMigrationCommitFrame = z.infer<typeof projectMigrationCommitFrameSchema>;
export type ProjectMigrationCompletedFrame = z.infer<typeof projectMigrationCompletedFrameSchema>;
export type ProjectMigrationRequiredFrame = z.infer<typeof projectMigrationRequiredFrameSchema>;

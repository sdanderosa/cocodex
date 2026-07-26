import { z } from "zod";
import { projectContentEnvelopeSchema } from "./project-encryption";

const requestId = z.uuid();
const projectId = z.uuid();
const referenceId = z.uuid();
const artifactId = z.uuid();
const canonicalRelativePath = z.string().min(1).max(1024).superRefine((value, context) => {
  if (value.includes("\0") || value.includes("\\") || value.startsWith("/")
    || /^[A-Za-z]:/.test(value) || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)) {
    context.addIssue({ code: "custom", message: "File-reference paths must be canonical POSIX-relative paths" });
    return;
  }
  const segments = value.split("/");
  if (segments.some(segment => segment.length === 0 || segment === "." || segment === "..")) {
    context.addIssue({ code: "custom", message: "File-reference paths cannot contain empty, dot, or parent segments" });
  }
});

/** Decrypted only on trusted project-member clients. */
export const fileReferencePlaintextSchema = z.object({
  version: z.literal(1),
  referenceId,
  projectId,
  artifactId,
  hostDeviceId: z.uuid(),
  relativePath: canonicalRelativePath,
  workspaceMode: z.enum(["shared", "git-worktree"]),
  workspaceRef: z.string().trim().min(1).max(500),
  branch: z.string().trim().min(1).max(500).nullable(),
  commitSha: z.string().regex(/^[0-9a-f]{40,64}$/).nullable(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  sizeBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  mediaType: z.string().trim().min(1).max(160).nullable(),
}).strict();
export type FileReferencePlaintext = z.infer<typeof fileReferencePlaintextSchema>;

export const encryptedFileReferenceSchema = z.object({
  referenceId,
  projectId,
  artifactId,
  hostDeviceId: z.uuid(),
  authorDeviceId: z.uuid(),
  envelope: projectContentEnvelopeSchema,
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
}).strict();
export type EncryptedFileReference = z.infer<typeof encryptedFileReferenceSchema>;

export const encryptedFileReferencePublishFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.file-reference.publish"),
  requestId,
  referenceId,
  projectId,
  artifactId,
  envelope: projectContentEnvelopeSchema,
}).strict().superRefine((value, context) => {
  if (value.envelope.recordType !== "file-reference") {
    context.addIssue({ code: "custom", path: ["envelope", "recordType"], message: "Expected file-reference envelope" });
  }
  if (value.envelope.projectId !== value.projectId) {
    context.addIssue({ code: "custom", path: ["envelope", "projectId"], message: "Envelope project must match frame" });
  }
  if (value.envelope.recordId !== value.referenceId) {
    context.addIssue({ code: "custom", path: ["envelope", "recordId"], message: "Envelope record must match reference" });
  }
});

export const encryptedFileReferenceListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.file-reference.list"),
  requestId,
  projectId,
}).strict();

export const encryptedFileReferenceAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.file-reference.accepted"),
  requestId,
  projectId,
  reference: encryptedFileReferenceSchema,
}).strict();

export const encryptedFileReferencePublishedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.file-reference.published"),
  reference: encryptedFileReferenceSchema,
}).strict();

export const encryptedFileReferenceListResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.file-reference.list.result"),
  requestId,
  projectId,
  references: z.array(encryptedFileReferenceSchema).max(500),
}).strict();

export type EncryptedFileReferencePublishFrame = z.infer<typeof encryptedFileReferencePublishFrameSchema>;
export type EncryptedFileReferenceListFrame = z.infer<typeof encryptedFileReferenceListFrameSchema>;
export type EncryptedFileReferenceAcceptedFrame = z.infer<typeof encryptedFileReferenceAcceptedFrameSchema>;
export type EncryptedFileReferencePublishedFrame = z.infer<typeof encryptedFileReferencePublishedFrameSchema>;
export type EncryptedFileReferenceListResultFrame = z.infer<typeof encryptedFileReferenceListResultFrameSchema>;

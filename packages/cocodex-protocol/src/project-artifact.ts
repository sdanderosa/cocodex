import { z } from "zod";
import { projectContentEnvelopeSchema } from "./project-encryption";

const requestId = z.uuid();
const projectId = z.uuid();
const artifactId = z.uuid();

/** Metadata needed for routing an opaque artifact without exposing its content. */
export const encryptedArtifactSchema = z.object({
  artifactId,
  projectId,
  taskId: z.uuid().nullable(),
  authorDeviceId: z.uuid(),
  envelope: projectContentEnvelopeSchema,
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
}).strict();
export type EncryptedArtifact = z.infer<typeof encryptedArtifactSchema>;

export const encryptedArtifactPublishFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.artifact.publish"),
  requestId,
  artifactId,
  projectId,
  taskId: z.uuid().nullable(),
  envelope: projectContentEnvelopeSchema,
}).strict();

export const encryptedArtifactListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.artifact.list"),
  requestId,
  projectId,
}).strict();

export const encryptedArtifactAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.artifact.accepted"),
  requestId,
  projectId,
  artifact: encryptedArtifactSchema,
}).strict();

export const encryptedArtifactPublishedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.artifact.published"),
  artifact: encryptedArtifactSchema,
}).strict();

export const encryptedArtifactListResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.artifact.list.result"),
  requestId,
  projectId,
  artifacts: z.array(encryptedArtifactSchema).max(500),
}).strict();

export type EncryptedArtifactPublishFrame = z.infer<typeof encryptedArtifactPublishFrameSchema>;
export type EncryptedArtifactListFrame = z.infer<typeof encryptedArtifactListFrameSchema>;
export type EncryptedArtifactAcceptedFrame = z.infer<typeof encryptedArtifactAcceptedFrameSchema>;
export type EncryptedArtifactPublishedFrame = z.infer<typeof encryptedArtifactPublishedFrameSchema>;
export type EncryptedArtifactListResultFrame = z.infer<typeof encryptedArtifactListResultFrameSchema>;

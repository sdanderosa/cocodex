import { z } from "zod";
import { projectContentEnvelopeSchema } from "./project-encryption";

const requestId = z.uuid();
const projectId = z.uuid();
const chatId = z.uuid();
const deviceId = z.uuid();
const updateId = z.uuid();

/** An ordered opaque Yjs update routed by the collaboration server. */
export const encryptedPromptUpdateSchema = z.object({
  sequence: z.number().int().nonnegative(),
  projectId,
  chatId,
  updateId,
  senderDeviceId: deviceId,
  envelope: projectContentEnvelopeSchema,
  acceptedAt: z.iso.datetime(),
}).strict();
export type EncryptedPromptUpdate = z.infer<typeof encryptedPromptUpdateSchema>;

export const encryptedPromptSubscribeFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.prompt.subscribe"),
  requestId,
  projectId,
  chatId,
  afterSequence: z.number().int().nonnegative(),
}).strict();

export const encryptedPromptUpdateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.prompt.update"),
  requestId,
  projectId,
  chatId,
  updateId,
  envelope: projectContentEnvelopeSchema,
}).strict();

export const encryptedPromptSnapshotFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.prompt.snapshot"),
  requestId,
  projectId,
  chatId,
  updates: z.array(encryptedPromptUpdateSchema).max(500),
}).strict();

export const encryptedPromptAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.prompt.accepted"),
  requestId,
  projectId,
  chatId,
  update: encryptedPromptUpdateSchema,
}).strict();

export const encryptedPromptChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.prompt.changed"),
  update: encryptedPromptUpdateSchema,
}).strict();

export type EncryptedPromptSubscribeFrame = z.infer<typeof encryptedPromptSubscribeFrameSchema>;
export type EncryptedPromptUpdateFrame = z.infer<typeof encryptedPromptUpdateFrameSchema>;
export type EncryptedPromptSnapshotFrame = z.infer<typeof encryptedPromptSnapshotFrameSchema>;
export type EncryptedPromptAcceptedFrame = z.infer<typeof encryptedPromptAcceptedFrameSchema>;
export type EncryptedPromptChangedFrame = z.infer<typeof encryptedPromptChangedFrameSchema>;

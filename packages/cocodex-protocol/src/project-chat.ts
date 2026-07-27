import { z } from "zod";
import { projectContentEnvelopeSchema } from "./project-encryption";

const requestId = z.uuid();
const projectId = z.uuid();
const chatId = z.uuid();
const deviceId = z.uuid();
const eventId = z.uuid();

/** The routable, still-opaque form of one encrypted shared-chat event. */
export const encryptedChatEventSchema = z.object({
  sequence: z.number().int().nonnegative(),
  projectId,
  chatId,
  eventId,
  senderDeviceId: deviceId,
  envelope: projectContentEnvelopeSchema,
  clientCreatedAt: z.iso.datetime(),
  acceptedAt: z.iso.datetime(),
  taskId: z.uuid().optional(),
  final: z.boolean().optional(),
  status: z.enum(["running", "completed", "failed"]).optional(),
}).strict();
export type EncryptedChatEvent = z.infer<typeof encryptedChatEventSchema>;

export const encryptedChatSubscribeFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.subscribe"),
  requestId,
  projectId,
  chatId,
  afterSequence: z.number().int().nonnegative(),
}).strict();

export const encryptedChatSendFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.send"),
  requestId,
  projectId,
  chatId,
  eventId,
  envelope: projectContentEnvelopeSchema,
  clientCreatedAt: z.iso.datetime(),
}).strict();

export const encryptedChatSnapshotFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.snapshot"),
  requestId,
  projectId,
  chatId,
  events: z.array(encryptedChatEventSchema).max(500),
}).strict();

export const encryptedChatAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.accepted"),
  requestId,
  projectId,
  chatId,
  event: encryptedChatEventSchema,
}).strict();

export const encryptedChatEventFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.event"),
  event: encryptedChatEventSchema,
}).strict();

export type EncryptedChatSubscribeFrame = z.infer<typeof encryptedChatSubscribeFrameSchema>;
export type EncryptedChatSendFrame = z.infer<typeof encryptedChatSendFrameSchema>;
export type EncryptedChatSnapshotFrame = z.infer<typeof encryptedChatSnapshotFrameSchema>;
export type EncryptedChatAcceptedFrame = z.infer<typeof encryptedChatAcceptedFrameSchema>;
export type EncryptedChatEventFrame = z.infer<typeof encryptedChatEventFrameSchema>;

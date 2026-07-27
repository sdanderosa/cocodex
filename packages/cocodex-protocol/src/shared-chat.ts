import { z } from "zod";

const requestId = z.uuid();
const projectId = z.uuid();
const chatId = z.uuid();
const deviceId = z.uuid();

const canonicalNonce = z.string()
  .min(43)
  .max(43)
  .regex(/^[A-Za-z0-9_-]+$/)
  .refine(value => {
    try {
      const bytes = Buffer.from(value, "base64url");
      return bytes.byteLength === 32 && bytes.toString("base64url") === value;
    } catch {
      return false;
    }
  }, "Shared-chat nonce must encode exactly 32 bytes");

export const sharedChatStateSchema = z.enum(["active", "archived"]);

export const sharedChatSchema = z.object({
  id: chatId,
  projectId,
  title: z.string().trim().min(1).max(120),
  createdByDeviceId: deviceId,
  state: sharedChatStateSchema,
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
}).strict();
export type SharedChat = z.infer<typeof sharedChatSchema>;

export const sharedChatCreateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.create"),
  requestId,
  projectId,
  chatId,
  title: z.string().trim().min(1).max(120),
  nonce: canonicalNonce,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  signature: z.string().min(64).max(256),
}).strict();

export const sharedChatListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.list"),
  requestId,
  projectId,
}).strict();

export const sharedChatCreatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.created"),
  requestId,
  projectId,
  chat: sharedChatSchema,
  created: z.boolean(),
}).strict();

export const sharedChatListResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.list.result"),
  requestId,
  projectId,
  chats: z.array(sharedChatSchema).max(64),
}).strict();

export const sharedChatChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.chat.changed"),
  projectId,
  chat: sharedChatSchema,
}).strict();

export interface SharedChatCreationTranscriptInput {
  projectId: string;
  chatId: string;
  title: string;
  creatorDeviceId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

export function sharedChatCreationSigningTranscript(input: SharedChatCreationTranscriptInput): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-SHARED-CHAT-CREATE\u0000", "utf8"),
    ...[
      "1",
      input.projectId,
      input.chatId,
      input.title.trim(),
      input.creatorDeviceId,
      input.nonce,
      input.issuedAt,
      input.expiresAt,
    ].map(lengthPrefix),
  ]);
}

export type SharedChatCreateFrame = z.infer<typeof sharedChatCreateFrameSchema>;
export type SharedChatListFrame = z.infer<typeof sharedChatListFrameSchema>;
export type SharedChatCreatedFrame = z.infer<typeof sharedChatCreatedFrameSchema>;
export type SharedChatListResultFrame = z.infer<typeof sharedChatListResultFrameSchema>;
export type SharedChatChangedFrame = z.infer<typeof sharedChatChangedFrameSchema>;

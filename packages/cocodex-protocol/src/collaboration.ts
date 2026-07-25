import { z } from "zod";

const requestId = z.uuid();
const projectId = z.uuid();

export const clientFrameSchema = z.discriminatedUnion("type", [
  z.object({
    version: z.literal(1),
    type: z.literal("auth.response"),
    requestId,
    deviceId: z.uuid(),
    signature: z.string().min(64).max(256),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.list"),
    requestId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("chat.subscribe"),
    requestId,
    projectId,
    afterSequence: z.number().int().nonnegative(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("chat.send"),
    requestId,
    projectId,
    eventId: z.uuid(),
    content: z.string().min(1).max(32_768),
    clientCreatedAt: z.iso.datetime(),
  }).strict(),
]);

export type ClientFrame = z.infer<typeof clientFrameSchema>;

export interface SharedProject {
  id: string;
  name: string;
  role: "owner" | "member";
}

export interface ChatEvent {
  sequence: number;
  projectId: string;
  eventId: string;
  senderDeviceId: string;
  content: string;
  clientCreatedAt: string;
  acceptedAt: string;
}

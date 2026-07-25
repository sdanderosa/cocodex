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
  z.object({
    version: z.literal(1),
    type: z.literal("agent.request"),
    requestId,
    taskId: z.uuid(),
    projectId,
    targetDeviceId: z.uuid(),
    agentId: z.string().trim().min(1).max(120),
    prompt: z.string().min(1).max(32_768),
    clientCreatedAt: z.iso.datetime(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.result"),
    requestId,
    taskId: z.uuid(),
    eventId: z.uuid(),
    content: z.string().min(1).max(32_768),
    final: z.boolean(),
    status: z.enum(["running", "completed", "failed"]),
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

export interface AgentTask {
  id: string;
  projectId: string;
  requesterDeviceId: string;
  targetDeviceId: string;
  agentId: string;
  prompt: string;
  status: "queued" | "running" | "completed" | "failed";
  clientCreatedAt: string;
  acceptedAt: string;
}

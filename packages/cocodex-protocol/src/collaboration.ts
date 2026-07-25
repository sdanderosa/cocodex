import { z } from "zod";

const requestId = z.uuid();
const projectId = z.uuid();

interface WebSocketAuthTranscriptInput {
  serverFingerprint: string;
  deviceId: string;
  requestId: string;
  challenge: string;
}

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

export function websocketAuthTranscript(input: WebSocketAuthTranscriptInput): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-WEBSOCKET-AUTH\u0000", "utf8"),
    lengthPrefix("1"),
    lengthPrefix(input.serverFingerprint),
    lengthPrefix(input.deviceId),
    lengthPrefix(input.requestId),
    lengthPrefix(input.challenge),
  ]);
}

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
    agentId: z.string().trim().min(1).max(120),
    prompt: z.string().min(1).max(32_768),
    nonce: z.string().min(32).max(128),
    issuedAt: z.iso.datetime(),
    expiresAt: z.iso.datetime(),
    signature: z.string().min(64).max(256),
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

export const agentTaskSchema = z.object({
  id: z.uuid(),
  projectId,
  requesterDeviceId: z.uuid(),
  targetDeviceId: z.uuid(),
  agentId: z.string().trim().min(1).max(120),
  prompt: z.string().min(1).max(32_768),
  nonce: z.string().min(32).max(128),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  requesterSignature: z.string().min(64).max(256),
  requesterPublicKeyPem: z.string().min(64).max(2048),
  serverSignature: z.string().min(64).max(256),
  status: z.enum(["queued", "running", "completed", "failed"]),
  acceptedAt: z.iso.datetime(),
}).strict();

export const agentTaskFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.task"),
  task: agentTaskSchema,
}).strict();
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
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  requesterSignature: string;
  requesterPublicKeyPem: string;
  serverSignature: string;
  status: "queued" | "running" | "completed" | "failed";
  acceptedAt: string;
}

export interface AgentDefinition {
  id: string;
  projectId: string;
  name: string;
  hostDeviceId: string;
  enabled: boolean;
}

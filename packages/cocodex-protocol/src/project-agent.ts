import { z } from "zod";
import { projectContentEnvelopeSchema } from "./project-encryption";
import { encryptedArtifactSchema } from "./project-artifact";

const requestId = z.uuid();
const projectId = z.uuid();
const taskId = z.uuid();
const eventId = z.uuid();
const deviceId = z.uuid();
const agentId = z.string().trim().min(1).max(120);
const dependencies = z.array(z.uuid()).max(16).default([]);
const inputArtifactIds = z.array(z.uuid()).max(16).default([]);
const taskLifetime = {
  nonce: z.string().min(32).max(128),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
};
const resultStatus = z.enum(["running", "completed", "failed"]);

export const encryptedAgentRequestFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.agent.request"),
  requestId,
  taskId,
  projectId,
  agentId,
  ...taskLifetime,
  dependencies,
  inputArtifactIds,
  privateShareMessageId: z.uuid().optional(),
  envelope: projectContentEnvelopeSchema,
}).strict();

export const encryptedAgentResultSendFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.agent.result"),
  requestId,
  taskId,
  eventId,
  envelope: projectContentEnvelopeSchema,
  final: z.boolean(),
  status: resultStatus,
}).strict();

export const encryptedAgentTaskSchema = z.object({
  id: taskId,
  projectId,
  requesterDeviceId: deviceId,
  targetDeviceId: deviceId,
  agentId,
  prompt: z.literal("[encrypted]"),
  promptEnvelope: projectContentEnvelopeSchema,
  ...taskLifetime,
  dependencies,
  inputArtifactIds,
  inputArtifacts: z.array(encryptedArtifactSchema).max(16).default([]),
  privateShareMessageId: z.uuid().optional(),
  requesterSignature: z.string().min(64).max(256),
  requesterPublicKeyPem: z.string().min(64).max(2048),
  serverSignature: z.string().min(64).max(256),
  status: z.enum(["queued", "running", "completed", "failed"]),
  acceptedAt: z.iso.datetime(),
}).strict();
export type EncryptedAgentTask = z.infer<typeof encryptedAgentTaskSchema>;

export const encryptedAgentTaskFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.agent.task"),
  task: encryptedAgentTaskSchema,
}).strict();

export const encryptedAgentResultEventSchema = z.object({
  sequence: z.number().int().nonnegative(),
  projectId,
  taskId,
  eventId,
  senderDeviceId: deviceId,
  envelope: projectContentEnvelopeSchema,
  final: z.boolean(),
  status: resultStatus,
  clientCreatedAt: z.iso.datetime(),
  acceptedAt: z.iso.datetime(),
}).strict();
export type EncryptedAgentResultEvent = z.infer<typeof encryptedAgentResultEventSchema>;

export const encryptedAgentResultChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.agent.result"),
  taskId,
  final: z.boolean(),
  status: resultStatus,
  event: encryptedAgentResultEventSchema,
}).strict();

export type EncryptedAgentRequestFrame = z.infer<typeof encryptedAgentRequestFrameSchema>;
export type EncryptedAgentResultFrame = z.infer<typeof encryptedAgentResultSendFrameSchema>;
export type EncryptedAgentTaskFrame = z.infer<typeof encryptedAgentTaskFrameSchema>;

import { createHash } from "node:crypto";

export interface AgentRequestTranscriptInput {
  taskId: string;
  projectId: string;
  agentId: string;
  prompt: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface AgentDispatchTranscriptInput extends AgentRequestTranscriptInput {
  requesterDeviceId: string;
  targetDeviceId: string;
  requesterSignature: string;
  requesterPublicKeyPem: string;
}

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

function transcript(context: string, values: string[]): Buffer {
  return Buffer.concat([
    Buffer.from(`${context}\u0000`, "utf8"),
    ...values.map(lengthPrefix),
  ]);
}

export function agentRequestSigningTranscript(input: AgentRequestTranscriptInput): Buffer {
  return transcript("COCODEX-AGENT-REQUEST", [
    "1",
    input.taskId,
    input.projectId,
    input.agentId.trim(),
    createHash("sha256").update(input.prompt, "utf8").digest("base64url"),
    input.nonce,
    input.issuedAt,
    input.expiresAt,
  ]);
}

export function agentDispatchSigningTranscript(input: AgentDispatchTranscriptInput): Buffer {
  return transcript("COCODEX-AGENT-DISPATCH", [
    "1",
    input.taskId,
    input.projectId,
    input.agentId.trim(),
    createHash("sha256").update(input.prompt, "utf8").digest("base64url"),
    input.nonce,
    input.issuedAt,
    input.expiresAt,
    input.requesterDeviceId,
    input.targetDeviceId,
    input.requesterSignature,
    createHash("sha256").update(input.requesterPublicKeyPem, "utf8").digest("base64url"),
  ]);
}

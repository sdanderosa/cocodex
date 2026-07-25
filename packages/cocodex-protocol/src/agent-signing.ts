import { createHash } from "node:crypto";

export interface AgentRequestTranscriptInput {
  taskId: string;
  projectId: string;
  agentId: string;
  prompt: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  dependencies?: string[];
  inputArtifactIds?: string[];
  privateShareMessageId?: string;
}

export interface AgentDispatchTranscriptInput extends AgentRequestTranscriptInput {
  requesterDeviceId: string;
  targetDeviceId: string;
  requesterSignature: string;
  requesterPublicKeyPem: string;
}

export interface AgentEncryptedDispatchTranscriptInput {
  taskId: string;
  projectId: string;
  agentId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  dependencies?: string[];
  inputArtifactIds?: string[];
  privateShareMessageId?: string;
  requesterDeviceId: string;
  targetDeviceId: string;
  envelopeProjectId: string;
  envelopeKeyEpoch: number;
  envelopeRecordId: string;
  envelopeNonce: string;
  envelopeCiphertext: string;
  envelopeSenderDeviceId: string;
  envelopeSenderPublicKeyPem: string;
  envelopeSignature: string;
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
    JSON.stringify(input.dependencies ?? []),
    JSON.stringify(input.inputArtifactIds ?? []),
    input.privateShareMessageId ?? "",
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
    JSON.stringify(input.dependencies ?? []),
    JSON.stringify(input.inputArtifactIds ?? []),
    input.requesterDeviceId,
    input.targetDeviceId,
    input.requesterSignature,
    createHash("sha256").update(input.requesterPublicKeyPem, "utf8").digest("base64url"),
    input.privateShareMessageId ?? "",
  ]);
}

/**
 * Server-to-host proof for a task whose prompt remains inside a project
 * envelope. The envelope signature and exact ciphertext bytes are bound into
 * the dispatch proof; the host client decrypts only after verifying both.
 */
export function agentEncryptedDispatchSigningTranscript(input: AgentEncryptedDispatchTranscriptInput): Buffer {
  return transcript("COCODEX-AGENT-DISPATCH-ENCRYPTED", [
    "1",
    input.taskId,
    input.projectId,
    input.agentId.trim(),
    input.nonce,
    input.issuedAt,
    input.expiresAt,
    JSON.stringify(input.dependencies ?? []),
    JSON.stringify(input.inputArtifactIds ?? []),
    input.requesterDeviceId,
    input.targetDeviceId,
    input.privateShareMessageId ?? "",
    input.envelopeProjectId,
    String(input.envelopeKeyEpoch),
    input.envelopeRecordId,
    input.envelopeNonce,
    createHash("sha256").update(input.envelopeCiphertext, "utf8").digest("base64url"),
    input.envelopeSenderDeviceId,
    createHash("sha256").update(input.envelopeSenderPublicKeyPem, "utf8").digest("base64url"),
    input.envelopeSignature,
  ]);
}

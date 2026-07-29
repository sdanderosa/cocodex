import { createHash } from "node:crypto";
import { z } from "zod";
import { canonicalEd25519PublicKey } from "./keys";

/**
 * Project content is intentionally opaque to the collaboration server.  This
 * module contains only wire-level types and canonical transcripts; the client
 * owns all key material and encryption operations.
 */
export const PROJECT_ENCRYPTION_VERSION = 1 as const;
export const PROJECT_CONTENT_ENCRYPTION_VERSION = 2 as const;
export const PROJECT_KEY_BYTES = 32 as const;
export const PROJECT_KEY_EPOCH_MAX = 0x7fffffff as const;
export const PROJECT_WRAP_SEALED_KEY_BYTES = 80 as const;
export const PROJECT_CONTENT_NONCE_BYTES = 24 as const;
export const PROJECT_CONTENT_AUTH_TAG_BYTES = 16 as const;
export const PROJECT_CONTENT_MAX_BYTES = 512 * 1024;
export const PROJECT_CONTENT_CIPHERTEXT_MAX_BYTES = PROJECT_CONTENT_MAX_BYTES + PROJECT_CONTENT_AUTH_TAG_BYTES;

/**
 * These values are deliberately semantic rather than table names.  They are
 * authenticated as AAD so an opaque payload cannot be moved between project
 * records or interpreted as a different kind of content.
 */
export const projectRecordTypeSchema = z.enum([
  "shared-prompt",
  "chat",
  "agent-response",
  "shared-context",
  "task",
  "artifact",
  "project-note",
  "diff-summary",
  "file-reference",
]);
export type ProjectRecordType = z.infer<typeof projectRecordTypeSchema>;

const base64UrlPattern = /^[A-Za-z0-9_-]+$/;

function canonicalBase64Url(value: string): Uint8Array | undefined {
  if (!base64UrlPattern.test(value)) return undefined;
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length === 0 || bytes.toString("base64url") !== value) return undefined;
    return new Uint8Array(bytes);
  } catch {
    return undefined;
  }
}

function fixedBase64UrlBytes(byteLength: number, label: string) {
  return z.string()
    // Base64url has no padding in CoCodex envelopes.  These loose character
    // bounds keep malformed input out before the exact-byte refinement runs.
    .min(Math.max(1, Math.floor(byteLength * 4 / 3) - 2))
    .max(Math.ceil(byteLength * 4 / 3) + 2)
    .refine(value => canonicalBase64Url(value)?.byteLength === byteLength, {
      message: `${label} must encode exactly ${byteLength} bytes`,
    });
}

const boundedCiphertext = z.string()
  .min(1)
  .max(700_000)
  .refine(value => {
    const bytes = canonicalBase64Url(value);
    return bytes !== undefined
      && bytes.byteLength >= PROJECT_CONTENT_AUTH_TAG_BYTES
      && bytes.byteLength <= PROJECT_CONTENT_CIPHERTEXT_MAX_BYTES;
  }, {
    message: "Project ciphertext must be canonical base64url within the size limit",
  });

const senderPublicKeyPem = z.string().min(64).max(2_048);
const keyEpoch = z.number().int().min(1).max(PROJECT_KEY_EPOCH_MAX);
const projectId = z.uuid();
const chatId = z.uuid();
const deviceId = z.uuid();
const signature = fixedBase64UrlBytes(64, "Project signature");
const sealedProjectKey = fixedBase64UrlBytes(PROJECT_WRAP_SEALED_KEY_BYTES, "Sealed project key");
const contentNonce = fixedBase64UrlBytes(PROJECT_CONTENT_NONCE_BYTES, "Project content nonce");

/** A project key encrypted to one device's dedicated project-wrap key. */
export const projectKeyEnvelopeSchema = z.object({
  version: z.literal(PROJECT_ENCRYPTION_VERSION),
  projectId,
  keyEpoch,
  recipientDeviceId: deviceId,
  senderDeviceId: deviceId,
  sealedProjectKey,
  senderPublicKeyPem,
  signature,
}).strict();
export type ProjectKeyEnvelope = z.infer<typeof projectKeyEnvelopeSchema>;

/**
 * An authenticated opaque project record.  `senderPublicKeyPem` is carried so
 * a recipient can verify a signature after an offline delivery; callers must
 * still bind it to the trusted device certificate rather than trusting this
 * field by itself.
 */
const legacyProjectContentEnvelopeSchema = z.object({
  version: z.literal(1),
  projectId,
  keyEpoch,
  recordType: projectRecordTypeSchema,
  recordId: z.string().trim().min(1).max(256),
  nonce: contentNonce,
  ciphertext: boundedCiphertext,
  senderDeviceId: deviceId,
  senderPublicKeyPem,
  signature,
}).strict();

const chatBoundProjectContentEnvelopeSchema = z.object({
  version: z.literal(PROJECT_CONTENT_ENCRYPTION_VERSION),
  projectId,
  chatId,
  keyEpoch,
  recordType: projectRecordTypeSchema,
  recordId: z.string().trim().min(1).max(256),
  nonce: contentNonce,
  ciphertext: boundedCiphertext,
  senderDeviceId: deviceId,
  senderPublicKeyPem,
  signature,
}).strict();

export const projectContentEnvelopeSchema = z.discriminatedUnion("version", [
  legacyProjectContentEnvelopeSchema,
  chatBoundProjectContentEnvelopeSchema,
]);
export type ProjectContentEnvelope = z.infer<typeof projectContentEnvelopeSchema>;

export type ProjectKeyEnvelopeUnsigned = Omit<ProjectKeyEnvelope, "signature">;
export type ProjectContentEnvelopeUnsigned =
  | Omit<z.infer<typeof legacyProjectContentEnvelopeSchema>, "signature">
  | Omit<z.infer<typeof chatBoundProjectContentEnvelopeSchema>, "signature">;

export type ProjectContentAadInput =
  | Omit<z.infer<typeof legacyProjectContentEnvelopeSchema>, "ciphertext" | "signature">
  | Omit<z.infer<typeof chatBoundProjectContentEnvelopeSchema>, "ciphertext" | "signature">;

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

function canonicalSenderKey(value: string): string {
  try {
    return canonicalEd25519PublicKey(value);
  } catch {
    throw new Error("Project sender key must be an Ed25519 public key");
  }
}

function digestBase64Url(value: string): string {
  const bytes = canonicalBase64Url(value);
  if (!bytes) throw new Error("Project envelope contains invalid base64url");
  return createHash("sha256").update(bytes).digest("base64url");
}

/**
 * Signature transcript for a wrapped project key.  Hashing the sealed box
 * keeps the transcript compact while still binding its exact bytes.
 */
export function projectKeyEnvelopeSigningTranscript(input: ProjectKeyEnvelopeUnsigned): Buffer {
  const senderKey = canonicalSenderKey(input.senderPublicKeyPem);
  return transcript("COCODEX-PROJECT-KEY-ENVELOPE", [
    String(input.version),
    input.projectId,
    String(input.keyEpoch),
    input.recipientDeviceId,
    input.senderDeviceId,
    senderKey,
    digestBase64Url(input.sealedProjectKey),
  ]);
}

/**
 * AEAD associated data transcript.  Every field that gives an encrypted
 * record meaning is included, including the nonce and the sender key.  A
 * ciphertext copied to another project, epoch, record, or sender therefore
 * fails authentication even if the same project key is available there.
 */
export function projectContentAad(input: ProjectContentAadInput): Buffer {
  const senderKey = canonicalSenderKey(input.senderPublicKeyPem);
  if (input.version === 1) {
    return transcript("COCODEX-PROJECT-CONTENT-AAD", [
      String(input.version),
      input.projectId,
      String(input.keyEpoch),
      input.recordType,
      input.recordId.trim(),
      input.nonce,
      input.senderDeviceId,
      senderKey,
    ]);
  }
  return transcript("COCODEX-PROJECT-CONTENT-AAD-V2", [
    String(input.version),
    input.projectId,
    input.chatId,
    String(input.keyEpoch),
    input.recordType,
    input.recordId.trim(),
    input.nonce,
    input.senderDeviceId,
    senderKey,
  ]);
}

/** Signature transcript for an opaque project record. */
export function projectContentSigningTranscript(input: ProjectContentEnvelopeUnsigned): Buffer {
  const senderKey = canonicalSenderKey(input.senderPublicKeyPem);
  if (input.version === 1) {
    return transcript("COCODEX-PROJECT-CONTENT", [
      String(input.version),
      input.projectId,
      String(input.keyEpoch),
      input.recordType,
      input.recordId.trim(),
      input.nonce,
      input.senderDeviceId,
      senderKey,
      digestBase64Url(input.ciphertext),
    ]);
  }
  return transcript("COCODEX-PROJECT-CONTENT-V2", [
    String(input.version),
    input.projectId,
    input.chatId,
    String(input.keyEpoch),
    input.recordType,
    input.recordId.trim(),
    input.nonce,
    input.senderDeviceId,
    senderKey,
    digestBase64Url(input.ciphertext),
  ]);
}

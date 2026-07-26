import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import {
  canonicalEd25519PublicKey,
  projectContentAad,
  projectContentEnvelopeSchema,
  projectContentSigningTranscript,
  projectKeyEnvelopeSchema,
  projectKeyEnvelopeSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectContentEnvelopeUnsigned,
  type ProjectKeyEnvelope,
  type ProjectKeyEnvelopeUnsigned,
  type ProjectRecordType,
  PROJECT_CONTENT_NONCE_BYTES,
  PROJECT_CONTENT_MAX_BYTES,
  PROJECT_ENCRYPTION_VERSION,
  PROJECT_KEY_BYTES,
} from "../../packages/cocodex-protocol/src/index.ts";
import type * as Sodium from "libsodium-wrappers-sumo";

// The package's ESM wrapper is not initialized correctly by Bun 1.3.x; use
// the maintained CommonJS export, as the private-message implementation does.
const sodium = require("libsodium-wrappers-sumo") as typeof Sodium;

const PROJECT_KEY_WRAP_PUBLIC_BYTES = 32;

export interface SealProjectKeyEnvelopeInput {
  projectId: string;
  keyEpoch: number;
  recipientDeviceId: string;
  senderDeviceId: string;
  projectKey: Uint8Array;
  recipientProjectWrapPublicKeyPem: string;
  senderPrivateKeyPem: string;
  senderPublicKeyPem: string;
}

export interface OpenProjectKeyEnvelopeInput {
  envelope: ProjectKeyEnvelope;
  recipientDeviceId: string;
  expectedProjectId?: string;
  expectedKeyEpoch?: number;
  expectedSenderDeviceId?: string;
  recipientProjectWrapPrivateKeyPem: string;
  recipientProjectWrapPublicKeyPem: string;
  expectedSenderPublicKeyPem?: string;
}

export interface SealProjectContentInput {
  projectId: string;
  keyEpoch: number;
  recordType: ProjectRecordType;
  recordId: string;
  plaintext: string | Uint8Array;
  projectKey: Uint8Array;
  senderDeviceId: string;
  senderPrivateKeyPem: string;
  senderPublicKeyPem: string;
}

export interface OpenProjectContentInput {
  envelope: ProjectContentEnvelope;
  projectKey: Uint8Array;
  expectedProjectId?: string;
  expectedKeyEpoch?: number;
  expectedRecordType?: ProjectRecordType;
  expectedRecordId?: string;
  expectedSenderDeviceId?: string;
  expectedSenderPublicKeyPem?: string;
}

function assertProjectKey(projectKey: Uint8Array): Uint8Array {
  const key = new Uint8Array(projectKey);
  if (key.byteLength !== PROJECT_KEY_BYTES) {
    throw new Error(`Project encryption key must be exactly ${PROJECT_KEY_BYTES} bytes`);
  }
  return key;
}

function decodeBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function x25519PublicKey(value: string): Uint8Array {
  let key;
  try { key = createPublicKey(value); }
  catch { throw new Error("Project wrap public key is invalid"); }
  if (key.asymmetricKeyType !== "x25519") {
    throw new Error("Project wrap public key must be X25519");
  }
  const jwk = key.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Project wrap public key is invalid");
  const raw = decodeBase64Url(jwk.x);
  if (raw.byteLength !== PROJECT_KEY_WRAP_PUBLIC_BYTES) {
    throw new Error("Project wrap public key has an invalid length");
  }
  return raw;
}

function x25519PrivateKey(value: string): Uint8Array {
  let key;
  try { key = createPrivateKey(value); }
  catch { throw new Error("Project wrap private key is invalid"); }
  if (key.asymmetricKeyType !== "x25519") {
    throw new Error("Project wrap private key must be X25519");
  }
  const jwk = key.export({ format: "jwk" });
  if (typeof jwk.d !== "string") throw new Error("Project wrap private key is invalid");
  const raw = decodeBase64Url(jwk.d);
  if (raw.byteLength !== PROJECT_KEY_WRAP_PUBLIC_BYTES) {
    throw new Error("Project wrap private key has an invalid length");
  }
  return raw;
}

function canonicalSigningPublicKey(value: string): string {
  try { return canonicalEd25519PublicKey(value); }
  catch { throw new Error("Project sender key must be an Ed25519 public key"); }
}

function signingPrivateKey(value: string): ReturnType<typeof createPrivateKey> {
  let key;
  try { key = createPrivateKey(value); }
  catch { throw new Error("Project sender private key is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("Project sender private key must be Ed25519");
  }
  return key;
}

function signingPublicKey(value: string): ReturnType<typeof createPublicKey> {
  let key;
  try { key = createPublicKey(value); }
  catch { throw new Error("Project sender key is invalid"); }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("Project sender key must be Ed25519");
  }
  return key;
}

function assertSignature(
  transcript: Buffer,
  signature: string,
  publicKeyPem: string,
  invalidMessage: string,
): void {
  let valid = false;
  try {
    valid = verify(
      null,
      transcript,
      signingPublicKey(publicKeyPem),
      Buffer.from(signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error(invalidMessage);
}

function plaintextBytes(value: string | Uint8Array): Uint8Array {
  const bytes = typeof value === "string" ? new Uint8Array(Buffer.from(value, "utf8")) : new Uint8Array(value);
  if (bytes.byteLength > PROJECT_CONTENT_MAX_BYTES) {
    throw new Error(`Project content exceeds ${PROJECT_CONTENT_MAX_BYTES} bytes`);
  }
  return bytes;
}

/** Generate a fresh random 256-bit project key. */
export function createProjectKey(): Buffer {
  return randomBytes(PROJECT_KEY_BYTES);
}

/**
 * Encrypt a project key to one recipient and sign the routing metadata.  The
 * recipient key is a dedicated X25519 project-wrap key, not the private
 * messaging key.
 */
export async function sealProjectKeyEnvelope(
  input: SealProjectKeyEnvelopeInput,
): Promise<ProjectKeyEnvelope> {
  const projectKey = assertProjectKey(input.projectKey);
  const senderPublicKeyPem = canonicalSigningPublicKey(input.senderPublicKeyPem);
  const senderPrivateKeyPem = signingPrivateKey(input.senderPrivateKeyPem);
  await sodium.ready;
  const sealed = sodium.crypto_box_seal(projectKey, x25519PublicKey(input.recipientProjectWrapPublicKeyPem));
  const unsigned: ProjectKeyEnvelopeUnsigned = {
    version: PROJECT_ENCRYPTION_VERSION,
    projectId: input.projectId,
    keyEpoch: input.keyEpoch,
    recipientDeviceId: input.recipientDeviceId,
    senderDeviceId: input.senderDeviceId,
    sealedProjectKey: encodeBase64Url(sealed),
    senderPublicKeyPem,
  };
  const signature = sign(null, projectKeyEnvelopeSigningTranscript(unsigned), senderPrivateKeyPem)
    .toString("base64url");
  return projectKeyEnvelopeSchema.parse({ ...unsigned, signature });
}

/**
 * Verify a signed key envelope and decrypt it with the recipient's dedicated
 * project-wrap key.  The caller supplies the expected sender key from its
 * trusted-device record; the key embedded in the envelope is not trusted by
 * itself.
 */
export async function openProjectKeyEnvelope(
  input: OpenProjectKeyEnvelopeInput,
): Promise<Buffer> {
  const envelope = projectKeyEnvelopeSchema.parse(input.envelope);
  if (envelope.recipientDeviceId !== input.recipientDeviceId) {
    throw new Error("Project key envelope is addressed to another device");
  }
  if (input.expectedProjectId && envelope.projectId !== input.expectedProjectId) {
    throw new Error("Project key envelope belongs to another project");
  }
  if (input.expectedKeyEpoch !== undefined && envelope.keyEpoch !== input.expectedKeyEpoch) {
    throw new Error("Project key envelope has an unexpected epoch");
  }
  if (input.expectedSenderDeviceId && envelope.senderDeviceId !== input.expectedSenderDeviceId) {
    throw new Error("Project key envelope sender device is not trusted");
  }
  const senderPublicKeyPem = canonicalSigningPublicKey(envelope.senderPublicKeyPem);
  if (input.expectedSenderPublicKeyPem
    && senderPublicKeyPem !== canonicalSigningPublicKey(input.expectedSenderPublicKeyPem)) {
    throw new Error("Project key envelope sender key is not trusted");
  }
  assertSignature(
    projectKeyEnvelopeSigningTranscript({ ...envelope, senderPublicKeyPem }),
    envelope.signature,
    senderPublicKeyPem,
    "Project key envelope signature is invalid",
  );
  await sodium.ready;
  try {
    const opened = sodium.crypto_box_seal_open(
      decodeBase64Url(envelope.sealedProjectKey),
      x25519PublicKey(input.recipientProjectWrapPublicKeyPem),
      x25519PrivateKey(input.recipientProjectWrapPrivateKeyPem),
    );
    if (opened.byteLength !== PROJECT_KEY_BYTES) throw new Error("invalid project key length");
    return Buffer.from(opened);
  } catch {
    throw new Error("Project key envelope could not be decrypted");
  }
}

/** Encrypt one project record with XChaCha20-Poly1305-IETF and sign its envelope. */
export async function sealProjectContent(
  input: SealProjectContentInput,
): Promise<ProjectContentEnvelope> {
  const projectKey = assertProjectKey(input.projectKey);
  const senderPublicKeyPem = canonicalSigningPublicKey(input.senderPublicKeyPem);
  const senderPrivateKeyPem = signingPrivateKey(input.senderPrivateKeyPem);
  const plaintext = plaintextBytes(input.plaintext);
  const nonce = randomBytes(PROJECT_CONTENT_NONCE_BYTES);
  const unsignedBase = {
    version: PROJECT_ENCRYPTION_VERSION,
    projectId: input.projectId,
    keyEpoch: input.keyEpoch,
    recordType: input.recordType,
    recordId: input.recordId.trim(),
    nonce: encodeBase64Url(nonce),
    senderDeviceId: input.senderDeviceId,
    senderPublicKeyPem,
  } as const;
  await sodium.ready;
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    projectContentAad(unsignedBase),
    null,
    nonce,
    projectKey,
  );
  const unsigned: ProjectContentEnvelopeUnsigned = {
    ...unsignedBase,
    ciphertext: encodeBase64Url(ciphertext),
  };
  const signature = sign(null, projectContentSigningTranscript(unsigned), senderPrivateKeyPem)
    .toString("base64url");
  return projectContentEnvelopeSchema.parse({ ...unsigned, signature });
}

/** Verify and decrypt one project record. */
export async function openProjectContent(
  input: OpenProjectContentInput,
): Promise<Buffer> {
  const envelope = projectContentEnvelopeSchema.parse(input.envelope);
  if (input.expectedProjectId && envelope.projectId !== input.expectedProjectId) {
    throw new Error("Project content belongs to another project");
  }
  if (input.expectedKeyEpoch !== undefined && envelope.keyEpoch !== input.expectedKeyEpoch) {
    throw new Error("Project content has an unexpected epoch");
  }
  if (input.expectedRecordType && envelope.recordType !== input.expectedRecordType) {
    throw new Error("Project content has an unexpected record type");
  }
  if (input.expectedRecordId && envelope.recordId !== input.expectedRecordId) {
    throw new Error("Project content has an unexpected record ID");
  }
  if (input.expectedSenderDeviceId && envelope.senderDeviceId !== input.expectedSenderDeviceId) {
    throw new Error("Project content sender device is not trusted");
  }
  const senderPublicKeyPem = canonicalSigningPublicKey(envelope.senderPublicKeyPem);
  if (input.expectedSenderPublicKeyPem
    && senderPublicKeyPem !== canonicalSigningPublicKey(input.expectedSenderPublicKeyPem)) {
    throw new Error("Project content sender key is not trusted");
  }
  const unsigned: ProjectContentEnvelopeUnsigned = { ...envelope, senderPublicKeyPem };
  assertSignature(
    projectContentSigningTranscript(unsigned),
    envelope.signature,
    senderPublicKeyPem,
    "Project content signature is invalid",
  );
  const projectKey = assertProjectKey(input.projectKey);
  await sodium.ready;
  try {
    const opened = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decodeBase64Url(envelope.ciphertext),
      projectContentAad(unsigned),
      decodeBase64Url(envelope.nonce),
      projectKey,
    );
    return Buffer.from(opened);
  } catch {
    throw new Error("Project content could not be decrypted");
  }
}

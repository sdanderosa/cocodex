import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { publicKeyFingerprint } from "../../packages/cocodex-protocol/src/index.ts";
import type * as Sodium from "libsodium-wrappers-sumo";

// The package's ESM wrapper is not initialized correctly by Bun 1.3.x; its
// maintained CommonJS export uses the same reviewed implementation and API.
const sodium = require("libsodium-wrappers-sumo") as typeof Sodium;

const SEALED_BOX_OVERHEAD = 48;
const MAX_PRIVATE_PLAINTEXT_BYTES = 64 * 1024;
const MAX_PRIVATE_CIPHERTEXT_BYTES = 72 * 1024;

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url value");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error("Invalid base64url value");
  return new Uint8Array(decoded);
}

function decodeCiphertext(value: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Private message ciphertext is not canonical base64url");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength < SEALED_BOX_OVERHEAD || decoded.byteLength > MAX_PRIVATE_CIPHERTEXT_BYTES
    || decoded.toString("base64url") !== value) {
    throw new Error("Private message ciphertext is outside the supported bounds");
  }
  return new Uint8Array(decoded);
}

function assertPlaintextBounds(plaintext: Uint8Array): void {
  if (plaintext.byteLength < 1 || plaintext.byteLength > MAX_PRIVATE_PLAINTEXT_BYTES) {
    throw new Error("Private message plaintext is outside the supported bounds");
  }
}

function x25519PublicKey(value: string): Uint8Array {
  const jwk = createPublicKey(value).export({ format: "jwk" });
  if (!jwk.x) throw new Error("Invalid X25519 public key");
  return decodeBase64Url(jwk.x);
}

function x25519PrivateKey(value: string): Uint8Array {
  const jwk = createPrivateKey(value).export({ format: "jwk" });
  if (!jwk.d) throw new Error("Invalid X25519 private key");
  return decodeBase64Url(jwk.d);
}

export async function sealPrivateMessage(
  plaintext: string,
  recipientX25519PublicKeyPem: string,
): Promise<string> {
  await sodium.ready;
  const plaintextBytes = sodium.from_string(plaintext);
  assertPlaintextBounds(plaintextBytes);
  return sodium.to_base64(
    sodium.crypto_box_seal(plaintextBytes, x25519PublicKey(recipientX25519PublicKeyPem)),
    sodium.base64_variants.URLSAFE_NO_PADDING,
  );
}

export async function openPrivateMessage(
  ciphertext: string,
  recipientX25519PrivateKeyPem: string,
  recipientX25519PublicKeyPem: string,
): Promise<string> {
  await sodium.ready;
  try {
    const sealed = decodeCiphertext(ciphertext);
    const plaintext = sodium.crypto_box_seal_open(
      sealed,
      x25519PublicKey(recipientX25519PublicKeyPem),
      x25519PrivateKey(recipientX25519PrivateKeyPem),
    );
    assertPlaintextBounds(plaintext);
    return sodium.to_string(plaintext);
  } catch {
    throw new Error("Private message could not be decrypted");
  }
}

export type PrivateMessageKind = "message" | "reaction" | "edit" | "delete";

export interface PrivateMessagePlaintext {
  version: 1 | 2;
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  text: string;
  clientCreatedAt: string;
  senderPublicKeyPem: string;
  signature: string;
  kind: PrivateMessageKind;
  targetMessageId?: string;
  replyToMessageId?: string;
  emoji?: string;
  reactionOperation?: "add" | "remove";
}

export type PrivateMessageInput = Omit<PrivateMessagePlaintext,
  "version" | "senderPublicKeyPem" | "signature" | "kind"> & { kind?: PrivateMessageKind };

function transcript(values: string[]): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-PRIVATE-MESSAGE\u0000", "utf8"),
    ...values.map(value => {
      const data = Buffer.from(value, "utf8");
      const length = Buffer.allocUnsafe(4);
      length.writeUInt32BE(data.length);
      return Buffer.concat([length, data]);
    }),
  ]);
}

function privateMessageTranscript(input: PrivateMessageInput, version: 1 | 2): Buffer {
  const base = [String(version), input.messageId, input.senderDeviceId, input.recipientDeviceId,
    input.text, input.clientCreatedAt];
  return transcript(version === 1 ? base : [...base, input.kind ?? "message",
    input.targetMessageId ?? "", input.replyToMessageId ?? "", input.emoji ?? "",
    input.reactionOperation ?? ""]);
}

function validateAction(input: PrivateMessageInput): void {
  const kind = input.kind ?? "message";
  const isUuid = (value: unknown): value is string => typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
  if (kind === "message") {
    if (input.text.length < 1 || input.text.length > 32_768) throw new Error("Private message text is invalid");
    if (input.replyToMessageId !== undefined && !isUuid(input.replyToMessageId)) throw new Error("Private reply target is invalid");
    if (input.targetMessageId !== undefined || input.emoji !== undefined || input.reactionOperation !== undefined) {
      throw new Error("Private message action fields are invalid");
    }
    return;
  }
  if (!isUuid(input.targetMessageId) || input.replyToMessageId !== undefined) throw new Error("Private message action target is invalid");
  if (kind === "edit" && (input.text.length < 1 || input.text.length > 32_768)) throw new Error("Private edit text is invalid");
  if (kind === "delete" && (input.text !== "" || input.emoji !== undefined || input.reactionOperation !== undefined)) {
    throw new Error("Private delete payload is invalid");
  }
  if (kind === "reaction") {
    if (input.text !== "" || typeof input.emoji !== "string" || input.emoji.length < 1 || input.emoji.length > 32
      || (input.reactionOperation !== "add" && input.reactionOperation !== "remove")) {
      throw new Error("Private reaction payload is invalid");
    }
  } else if (input.emoji !== undefined || input.reactionOperation !== undefined) {
    throw new Error("Private message action fields are invalid");
  }
}

export async function sealSignedPrivateMessage(
  input: PrivateMessageInput,
  senderPrivateKeyPem: string,
  senderPublicKeyPem: string,
  recipientPublicKeyPem: string,
): Promise<string> {
  validateAction(input);
  const payload: PrivateMessagePlaintext = {
    version: 2,
    ...input,
    kind: input.kind ?? "message",
    senderPublicKeyPem,
    signature: sign(null, privateMessageTranscript(input, 2), senderPrivateKeyPem).toString("base64url"),
  };
  return sealPrivateMessage(JSON.stringify(payload), recipientPublicKeyPem);
}

export async function openSignedPrivateMessage(
  ciphertext: string,
  recipientPrivateKeyPem: string,
  recipientPublicKeyPem: string,
  envelope: { messageId: string; senderDeviceId: string; recipientDeviceId: string; clientCreatedAt: string },
  expectedSenderFingerprint: string,
): Promise<PrivateMessagePlaintext> {
  let decoded: PrivateMessagePlaintext;
  try {
    decoded = JSON.parse(await openPrivateMessage(ciphertext, recipientPrivateKeyPem, recipientPublicKeyPem)) as PrivateMessagePlaintext;
  } catch {
    throw new Error("Private-message payload is invalid");
  }
  if ((decoded.version !== 1 && decoded.version !== 2) || decoded.messageId !== envelope.messageId
    || decoded.senderDeviceId !== envelope.senderDeviceId
    || decoded.recipientDeviceId !== envelope.recipientDeviceId
    || decoded.clientCreatedAt !== envelope.clientCreatedAt
    || typeof decoded.text !== "string"
    || typeof decoded.senderPublicKeyPem !== "string" || typeof decoded.signature !== "string") {
    throw new Error("Private-message envelope validation failed");
  }
  if (publicKeyFingerprint(decoded.senderPublicKeyPem) !== expectedSenderFingerprint) {
    throw new Error("Private-message sender identity is not trusted");
  }
  const normalized: PrivateMessagePlaintext = decoded.version === 1
    ? { ...decoded, kind: "message" }
    : decoded;
  try {
    validateAction(normalized);
  } catch {
    throw new Error("Private-message envelope validation failed");
  }
  const valid = verify(null, privateMessageTranscript(normalized, decoded.version),
    createPublicKey(decoded.senderPublicKeyPem), Buffer.from(decoded.signature, "base64url"));
  if (!valid) throw new Error("Private-message signature validation failed");
  return normalized;
}

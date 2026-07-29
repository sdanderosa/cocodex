import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { hardenSecretDir, hardenSecretPath } from "./windows-secret-acl";

const MAX_SECRET_BYTES = 1024 * 1024;
const MAX_PROTECTED_PAYLOAD_BYTES = MAX_SECRET_BYTES + 64 * 1024;
const MAX_ENVELOPE_BYTES = 1_600_000;
const ENVELOPE_VERSION = 1;
const DPAPI_PROTECTION = "windows-dpapi-current-user";
const FILESYSTEM_PROTECTION = "filesystem-user-only";

interface NativeDpapiBindings {
  protectData(data: Uint8Array, entropy: Uint8Array, scope: "CurrentUser"): Uint8Array;
  unprotectData(data: Uint8Array, entropy: Uint8Array, scope: "CurrentUser"): Uint8Array;
}

let nativeDpapi: NativeDpapiBindings | undefined;
try {
  if (process.platform === "win32" && process.arch === "x64") {
    nativeDpapi = require("@primno/dpapi/prebuilds/win32-x64/@primno+dpapi.node");
  } else if (process.platform === "win32" && process.arch === "arm64") {
    nativeDpapi = require("@primno/dpapi/prebuilds/win32-arm64/@primno+dpapi.node");
  }
} catch {
  // Loading errors may contain installation paths or native diagnostics.
  // Keep the boundary fail-closed and report only the sanitized category.
  nativeDpapi = undefined;
}

interface ProtectedSecretEnvelope {
  version: 1;
  protection: typeof DPAPI_PROTECTION | typeof FILESYSTEM_PROTECTION;
  purpose: string;
  payload: string;
  digest: string;
}

const decryptedCache = new Map<string, {
  purpose: string;
  stored: string;
  secret: Buffer;
}>();

function assertPurpose(purpose: string): string {
  if (!/^[a-z0-9][a-z0-9._-]{2,127}$/.test(purpose)) {
    throw new Error("Protected-secret purpose is invalid");
  }
  return purpose;
}

function assertSecretBounds(secret: Buffer): Buffer {
  if (secret.byteLength < 1 || secret.byteLength > MAX_SECRET_BYTES) {
    throw new Error("Protected secret is outside the supported bounds");
  }
  return secret;
}

function assertProtectedPayloadBounds(payload: Buffer): Buffer {
  if (payload.byteLength < 1 || payload.byteLength > MAX_PROTECTED_PAYLOAD_BYTES) {
    throw new Error("Protected-secret ciphertext is outside the supported bounds");
  }
  return payload;
}

function digest(purpose: string, secret: Buffer): string {
  return createHash("sha256")
    .update("COCODEX-LOCAL-PROTECTED-SECRET\u0000", "utf8")
    .update(purpose, "utf8")
    .update("\u0000", "utf8")
    .update(secret)
    .digest("base64url");
}

function entropy(purpose: string): Buffer {
  return createHash("sha256")
    .update("COCODEX-DPAPI-PURPOSE\u0000", "utf8")
    .update(purpose, "utf8")
    .digest();
}

function runDpapi(operation: "protect" | "unprotect", value: Buffer, purpose: string): Buffer {
  if (!nativeDpapi) {
    throw new Error(
      `Windows user-bound secret ${operation === "protect" ? "protection" : "unprotection"} failed`
      + " (category=native-unavailable)",
    );
  }
  try {
    const result = operation === "protect"
      ? nativeDpapi.protectData(value, entropy(purpose), "CurrentUser")
      : nativeDpapi.unprotectData(value, entropy(purpose), "CurrentUser");
    const output = Buffer.from(result);
    return operation === "protect"
      ? assertProtectedPayloadBounds(output)
      : assertSecretBounds(output);
  } catch {
    throw new Error(
      `Windows user-bound secret ${operation === "protect" ? "protection" : "unprotection"} failed`
      + " (category=native-operation)",
    );
  }
}

function encodeEnvelope(secret: Buffer, purpose: string): string {
  const protection = process.platform === "win32" ? DPAPI_PROTECTION : FILESYSTEM_PROTECTION;
  const payload = protection === DPAPI_PROTECTION ? runDpapi("protect", secret, purpose) : secret;
  const envelope: ProtectedSecretEnvelope = {
    version: ENVELOPE_VERSION,
    protection,
    purpose,
    payload: payload.toString("base64"),
    digest: digest(purpose, secret),
  };
  return `${JSON.stringify(envelope)}\n`;
}

function parseEnvelope(stored: string, expectedPurpose: string): ProtectedSecretEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(stored);
  } catch {
    throw new Error("Protected-secret envelope is invalid");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Protected-secret envelope is invalid");
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.version !== ENVELOPE_VERSION
    || (candidate.protection !== DPAPI_PROTECTION && candidate.protection !== FILESYSTEM_PROTECTION)
    || candidate.purpose !== expectedPurpose
    || typeof candidate.payload !== "string"
    || typeof candidate.digest !== "string"
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(candidate.payload)
    || !/^[A-Za-z0-9_-]{43}$/.test(candidate.digest)) {
    throw new Error("Protected-secret envelope validation failed");
  }
  if (process.platform === "win32" && candidate.protection !== DPAPI_PROTECTION) {
    throw new Error("Windows refuses a private key that is not user-bound");
  }
  if (process.platform !== "win32" && candidate.protection === DPAPI_PROTECTION) {
    throw new Error("This protected secret is bound to Windows");
  }
  const payload = Buffer.from(candidate.payload, "base64");
  if (payload.toString("base64") !== candidate.payload) {
    throw new Error("Protected-secret payload is not canonical base64");
  }
  assertProtectedPayloadBounds(payload);
  return candidate as unknown as ProtectedSecretEnvelope;
}

function decodeEnvelope(stored: string, purpose: string): Buffer {
  const envelope = parseEnvelope(stored, purpose);
  const payload = assertProtectedPayloadBounds(Buffer.from(envelope.payload, "base64"));
  const secret = envelope.protection === DPAPI_PROTECTION
    ? runDpapi("unprotect", payload, purpose)
    : assertSecretBounds(payload);
  if (digest(purpose, secret) !== envelope.digest) {
    throw new Error("Protected-secret integrity validation failed");
  }
  return secret;
}

function atomicReplace(path: string, stored: string): void {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, stored, { encoding: "utf8", mode: 0o600, flag: "wx" });
    hardenSecretPath(temporary, { required: true });
    if (process.platform !== "win32") chmodSync(temporary, 0o600);
    renameSync(temporary, path);
    hardenSecretPath(path, { required: true, force: true });
  } finally {
    try {
      if (existsSync(temporary)) unlinkSync(temporary);
    } catch {
      // Best-effort cleanup. The temporary filename contains no secret material.
    }
  }
}

export function writeProtectedSecret(path: string, purpose: string, secret: string | Buffer): void {
  const absolutePath = resolve(path);
  const canonicalPurpose = assertPurpose(purpose);
  const bytes = assertSecretBounds(Buffer.isBuffer(secret) ? Buffer.from(secret) : Buffer.from(secret, "utf8"));
  mkdirSync(dirname(absolutePath), { recursive: true });
  hardenSecretDir(dirname(absolutePath), { required: true });
  const stored = encodeEnvelope(bytes, canonicalPurpose);
  writeFileSync(absolutePath, stored, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(absolutePath, { required: true });
  if (process.platform !== "win32") chmodSync(absolutePath, 0o600);
  decryptedCache.set(absolutePath, {
    purpose: canonicalPurpose,
    stored,
    secret: Buffer.from(bytes),
  });
}

/**
 * Read a local secret and transparently replace a legacy raw-PEM file only
 * after a protected envelope has been successfully created.
 */
export function readProtectedSecret(path: string, purpose: string): Buffer {
  const absolutePath = resolve(path);
  const canonicalPurpose = assertPurpose(purpose);
  hardenSecretDir(dirname(absolutePath), { required: true });
  hardenSecretPath(absolutePath, { required: true });
  const status = lstatSync(absolutePath);
  if (!status.isFile() || status.size < 1 || status.size > MAX_ENVELOPE_BYTES) {
    throw new Error("Protected-secret file is outside the supported bounds");
  }
  const stored = readFileSync(absolutePath, "utf8");
  const cached = decryptedCache.get(absolutePath);
  if (cached?.purpose === canonicalPurpose && cached.stored === stored) {
    return Buffer.from(cached.secret);
  }
  if (stored.trimStart().startsWith("-----BEGIN ")) {
    const legacy = assertSecretBounds(Buffer.from(stored, "utf8"));
    const migrated = encodeEnvelope(legacy, canonicalPurpose);
    atomicReplace(absolutePath, migrated);
    decryptedCache.set(absolutePath, {
      purpose: canonicalPurpose,
      stored: migrated,
      secret: Buffer.from(legacy),
    });
    return Buffer.from(legacy);
  }
  const secret = decodeEnvelope(stored, canonicalPurpose);
  decryptedCache.set(absolutePath, {
    purpose: canonicalPurpose,
    stored,
    secret: Buffer.from(secret),
  });
  return Buffer.from(secret);
}

export function replaceProtectedSecret(path: string, purpose: string, secret: string | Buffer): void {
  const absolutePath = resolve(path);
  const canonicalPurpose = assertPurpose(purpose);
  const bytes = assertSecretBounds(Buffer.isBuffer(secret) ? Buffer.from(secret) : Buffer.from(secret, "utf8"));
  mkdirSync(dirname(absolutePath), { recursive: true });
  hardenSecretDir(dirname(absolutePath), { required: true });
  const stored = encodeEnvelope(bytes, canonicalPurpose);
  atomicReplace(absolutePath, stored);
  decryptedCache.set(absolutePath, {
    purpose: canonicalPurpose,
    stored,
    secret: Buffer.from(bytes),
  });
}

export function protectedSecretStorageKind(): "windows-dpapi-current-user" | "filesystem-user-only" {
  return process.platform === "win32" ? DPAPI_PROTECTION : FILESYSTEM_PROTECTION;
}

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

function powershellExecutable(): string {
  return `${process.env.SystemRoot?.trim() || "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
}

function encodedPowerShell(operation: "protect" | "unprotect"): string {
  const method = operation === "protect" ? "Protect" : "Unprotect";
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -AssemblyName System.Security",
    "$lines = [Console]::In.ReadToEnd().Split([char]10)",
    "if ($lines.Length -lt 2) { throw 'invalid protected-secret input' }",
    "$purpose = [Convert]::FromBase64String($lines[0].Trim())",
    "$value = [Convert]::FromBase64String($lines[1].Trim())",
    `$result = [Security.Cryptography.ProtectedData]::${method}($value, $purpose, [Security.Cryptography.DataProtectionScope]::CurrentUser)`,
    "[Console]::Out.Write([Convert]::ToBase64String($result))",
  ].join("\r\n");
  return Buffer.from(script, "utf16le").toString("base64");
}

function runDpapi(operation: "protect" | "unprotect", value: Buffer, purpose: string): Buffer {
  const input = `${entropy(purpose).toString("base64")}\n${value.toString("base64")}\n`;
  const invoke = () => Bun.spawnSync([
    powershellExecutable(),
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
    encodedPowerShell(operation),
  ], {
    stdin: Buffer.from(input, "ascii"),
    stdout: "pipe",
    stderr: "pipe",
    timeout: 15_000,
    windowsHide: true,
    env: {
      ...process.env,
      SystemRoot: process.env.SystemRoot || "C:\\Windows",
      WINDIR: process.env.WINDIR || process.env.SystemRoot || "C:\\Windows",
    },
  });
  let result = invoke();
  // Windows can transiently refuse a process launch when multiple isolated
  // Client/Server tests start together. Retry only a no-exit-code spawn failure;
  // cryptographic or parse failures still fail closed below.
  if (!result.success && !result.exitedDueToTimeout && result.exitCode === null) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    result = invoke();
  }
  if (!result.success || result.exitedDueToTimeout) {
    throw new Error(
      `Windows user-bound secret ${operation === "protect" ? "protection" : "unprotection"} failed`,
    );
  }
  const output = result.stdout.toString().trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(output)) {
    throw new Error(`Windows user-bound secret ${operation === "protect" ? "protection" : "unprotection"} returned invalid data`);
  }
  const decoded = Buffer.from(output, "base64");
  return operation === "protect"
    ? assertProtectedPayloadBounds(decoded)
    : assertSecretBounds(decoded);
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

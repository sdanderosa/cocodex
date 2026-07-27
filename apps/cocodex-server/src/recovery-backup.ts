import {
  X509Certificate,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  scryptSync,
  sign,
  verify,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isIP } from "node:net";
import { basename, dirname, resolve, sep } from "node:path";
import { Database } from "bun:sqlite";
import { publicKeyFingerprint } from "../../../packages/cocodex-protocol/src/index.ts";
import { hardenSecretDir, hardenSecretPath } from "../../../src/lib/windows-secret-acl";
import { loadConfig, type ServerConfig } from "./config";
import type { ServerIdentity } from "./identity";
import { serverPaths, type ServerPaths } from "./paths";
import { serverAuthorityStatus, serverEpoch, serverIdentityFingerprint } from "./server-state";

const RECOVERY_BACKUP_VERSION = 2 as const;
const RECOVERY_PAYLOAD_VERSION = 1 as const;
const MAX_RECOVERY_ARCHIVE_BYTES = 1_500_000_000;
const MAX_DATABASE_BYTES = 1_000_000_000;
const MAX_PEM_BYTES = 128 * 1024;
const SCRYPT_N = 65_536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 128 * 1024 * 1024;

type RecoveryEntry =
  | "config"
  | "database"
  | "identityPrivateKey"
  | "identityPublicKey"
  | "tlsPrivateKey"
  | "tlsCertificate";

interface RecoveryPayload {
  version: typeof RECOVERY_PAYLOAD_VERSION;
  config: {
    version: 1;
    hostname: string;
    port: number;
    publicHost: string;
    adminTokenHash?: string;
  };
  databaseBase64Url: string;
  identityPrivateKeyPem: string;
  identityPublicKeyPem: string;
  tlsPrivateKeyPem: string;
  tlsCertificatePem: string;
  sha256: Record<RecoveryEntry, string>;
}

interface RecoveryArchiveHeader {
  version: typeof RECOVERY_BACKUP_VERSION;
  kind: "cocodex-server-recovery";
  createdAt: string;
  serverFingerprint: string;
  serverEpoch: number;
  publicHost: string;
  port: number;
  tlsFingerprint: string;
  payloadSha256: string;
  kdf: {
    name: "scrypt";
    salt: string;
    N: typeof SCRYPT_N;
    r: typeof SCRYPT_R;
    p: typeof SCRYPT_P;
  };
  cipher: {
    name: "aes-256-gcm";
    iv: string;
  };
}

export interface EncryptedServerRecoveryBackup extends RecoveryArchiveHeader {
  authTag: string;
  ciphertext: string;
  signature: string;
}

export interface RestoredServerRecovery {
  archive: EncryptedServerRecoveryBackup;
  rollbackPath: string | null;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function archiveHeader(archive: EncryptedServerRecoveryBackup): RecoveryArchiveHeader {
  return {
    version: archive.version,
    kind: archive.kind,
    createdAt: archive.createdAt,
    serverFingerprint: archive.serverFingerprint,
    serverEpoch: archive.serverEpoch,
    publicHost: archive.publicHost,
    port: archive.port,
    tlsFingerprint: archive.tlsFingerprint,
    payloadSha256: archive.payloadSha256,
    kdf: archive.kdf,
    cipher: archive.cipher,
  };
}

function signingTranscript(
  header: RecoveryArchiveHeader,
  authTag: string,
  ciphertext: string,
): Buffer {
  return canonicalJson({ ...header, authTag, ciphertext });
}

function protectedArchiveKey(passphrase: string, salt: Buffer): Buffer {
  if (passphrase.length < 12) throw new Error("Backup passphrase must be at least 12 characters");
  return scryptSync(passphrase, salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

function strictBase64Url(value: string, label: string, expectedBytes?: number): Buffer {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`Invalid CoCodex recovery ${label}`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value || (expectedBytes !== undefined && decoded.length !== expectedBytes)) {
    throw new Error(`Invalid CoCodex recovery ${label}`);
  }
  return decoded;
}

function pemWithinLimit(value: unknown, label: string): string {
  if (typeof value !== "string" || Buffer.byteLength(value) === 0 || Buffer.byteLength(value) > MAX_PEM_BYTES) {
    throw new Error(`Invalid CoCodex recovery ${label}`);
  }
  return value;
}

function tlsFingerprint(certificatePem: string): string {
  const certificate = new X509Certificate(certificatePem);
  const hex = createHash("sha256").update(certificate.raw).digest("hex").toUpperCase();
  return hex.match(/.{1,4}/g)?.join("-") ?? hex;
}

function certificateCoversHost(certificate: X509Certificate, host: string): boolean {
  return Boolean(isIP(host) ? certificate.checkIP(host) : certificate.checkHost(host));
}

function publicDer(key: string): Buffer {
  return createPublicKey(key).export({ type: "spki", format: "der" });
}

function validateKeyAndCertificateRelationships(
  payload: RecoveryPayload,
  expectedFingerprint: string,
  expectedTlsFingerprint: string,
): ServerIdentity {
  createPrivateKey(payload.identityPrivateKeyPem);
  const identityPublicKey = createPublicKey(payload.identityPublicKeyPem);
  const identityPublicDer = identityPublicKey.export({ type: "spki", format: "der" });
  const derivedIdentityPublicDer = createPublicKey(payload.identityPrivateKeyPem)
    .export({ type: "spki", format: "der" });
  if (!identityPublicDer.equals(derivedIdentityPublicDer)) {
    throw new Error("CoCodex recovery identity private key does not match its public key");
  }
  const fingerprint = publicKeyFingerprint(payload.identityPublicKeyPem);
  if (fingerprint !== expectedFingerprint) {
    throw new Error("CoCodex recovery identity fingerprint mismatch");
  }

  const certificate = new X509Certificate(payload.tlsCertificatePem);
  createPrivateKey(payload.tlsPrivateKeyPem);
  const derivedTlsPublicDer = createPublicKey(payload.tlsPrivateKeyPem)
    .export({ type: "spki", format: "der" });
  const certificatePublicDer = certificate.publicKey.export({ type: "spki", format: "der" });
  if (!derivedTlsPublicDer.equals(certificatePublicDer)) {
    throw new Error("CoCodex recovery TLS private key does not match its certificate");
  }
  if (tlsFingerprint(payload.tlsCertificatePem) !== expectedTlsFingerprint) {
    throw new Error("CoCodex recovery TLS fingerprint mismatch");
  }
  if (!certificateCoversHost(certificate, payload.config.publicHost)) {
    throw new Error("CoCodex recovery TLS certificate does not cover its configured public host");
  }
  return {
    publicKeyPem: payload.identityPublicKeyPem,
    privateKeyPem: payload.identityPrivateKeyPem,
    fingerprint,
  };
}

function validatePayload(
  value: unknown,
  expected: Pick<
    RecoveryArchiveHeader,
    "serverFingerprint" | "tlsFingerprint" | "publicHost" | "port"
  >,
): { payload: RecoveryPayload; identity: ServerIdentity; database: Buffer } {
  if (!value || typeof value !== "object") throw new Error("Invalid CoCodex recovery payload");
  const candidate = value as Partial<RecoveryPayload>;
  if (candidate.version !== RECOVERY_PAYLOAD_VERSION || !candidate.config || typeof candidate.config !== "object") {
    throw new Error("Invalid CoCodex recovery payload");
  }
  const config = candidate.config as RecoveryPayload["config"];
  if (
    config.version !== 1
    || typeof config.hostname !== "string"
    || !config.hostname.trim()
    || typeof config.publicHost !== "string"
    || !config.publicHost.trim()
    || !Number.isInteger(config.port)
    || config.port < 1
    || config.port > 65_535
    || (config.adminTokenHash !== undefined && !/^[0-9a-f]{64}$/i.test(config.adminTokenHash))
    || config.publicHost !== expected.publicHost
    || config.port !== expected.port
  ) {
    throw new Error("Invalid CoCodex recovery configuration");
  }
  if (!candidate.sha256 || typeof candidate.sha256 !== "object") {
    throw new Error("Invalid CoCodex recovery checksum manifest");
  }
  const database = strictBase64Url(String(candidate.databaseBase64Url ?? ""), "database");
  if (database.length === 0 || database.length > MAX_DATABASE_BYTES) {
    throw new Error("Invalid CoCodex recovery database size");
  }
  const payload: RecoveryPayload = {
    version: RECOVERY_PAYLOAD_VERSION,
    config,
    databaseBase64Url: candidate.databaseBase64Url as string,
    identityPrivateKeyPem: pemWithinLimit(candidate.identityPrivateKeyPem, "identity private key"),
    identityPublicKeyPem: pemWithinLimit(candidate.identityPublicKeyPem, "identity public key"),
    tlsPrivateKeyPem: pemWithinLimit(candidate.tlsPrivateKeyPem, "TLS private key"),
    tlsCertificatePem: pemWithinLimit(candidate.tlsCertificatePem, "TLS certificate"),
    sha256: candidate.sha256 as Record<RecoveryEntry, string>,
  };
  const configBytes = canonicalJson(payload.config);
  const actualChecksums: Record<RecoveryEntry, string> = {
    config: sha256(configBytes),
    database: sha256(database),
    identityPrivateKey: sha256(payload.identityPrivateKeyPem),
    identityPublicKey: sha256(payload.identityPublicKeyPem),
    tlsPrivateKey: sha256(payload.tlsPrivateKeyPem),
    tlsCertificate: sha256(payload.tlsCertificatePem),
  };
  for (const entry of Object.keys(actualChecksums) as RecoveryEntry[]) {
    if (!/^[0-9a-f]{64}$/.test(payload.sha256[entry] ?? "")
      || payload.sha256[entry] !== actualChecksums[entry]) {
      throw new Error(`CoCodex recovery ${entry} checksum mismatch`);
    }
  }
  const identity = validateKeyAndCertificateRelationships(
    payload,
    expected.serverFingerprint,
    expected.tlsFingerprint,
  );
  return { payload, identity, database };
}

function assertArchive(value: unknown): asserts value is EncryptedServerRecoveryBackup {
  if (!value || typeof value !== "object") throw new Error("Invalid CoCodex recovery archive");
  const archive = value as Partial<EncryptedServerRecoveryBackup>;
  if (
    archive.version !== RECOVERY_BACKUP_VERSION
    || archive.kind !== "cocodex-server-recovery"
    || typeof archive.createdAt !== "string"
    || !Number.isFinite(Date.parse(archive.createdAt))
    || typeof archive.serverFingerprint !== "string"
    || !Number.isSafeInteger(archive.serverEpoch)
    || (archive.serverEpoch as number) < 1
    || typeof archive.publicHost !== "string"
    || !archive.publicHost.trim()
    || !Number.isInteger(archive.port)
    || (archive.port as number) < 1
    || (archive.port as number) > 65_535
    || typeof archive.tlsFingerprint !== "string"
    || !/^[0-9a-f]{64}$/i.test(archive.payloadSha256 ?? "")
    || archive.kdf?.name !== "scrypt"
    || archive.kdf.N !== SCRYPT_N
    || archive.kdf.r !== SCRYPT_R
    || archive.kdf.p !== SCRYPT_P
    || archive.cipher?.name !== "aes-256-gcm"
    || typeof archive.authTag !== "string"
    || typeof archive.cipher.iv !== "string"
    || typeof archive.ciphertext !== "string"
    || typeof archive.signature !== "string"
  ) {
    throw new Error("Invalid CoCodex recovery archive");
  }
  strictBase64Url(archive.kdf.salt, "salt", 16);
  strictBase64Url(archive.cipher.iv, "IV", 12);
  strictBase64Url(archive.authTag, "authentication tag", 16);
  strictBase64Url(archive.signature, "signature", 64);
  const ciphertext = strictBase64Url(archive.ciphertext, "ciphertext");
  if (ciphertext.length === 0 || ciphertext.length > MAX_RECOVERY_ARCHIVE_BYTES) {
    throw new Error("Invalid CoCodex recovery ciphertext size");
  }
}

function checkpointDatabase(path: string): Buffer {
  if (!existsSync(path)) throw new Error("CoCodex Server database does not exist");
  const checkpoint = new Database(path, { strict: true });
  try { checkpoint.exec("PRAGMA wal_checkpoint(TRUNCATE)"); }
  finally { checkpoint.close(); }
  const database = readFileSync(path);
  if (database.length === 0 || database.length > MAX_DATABASE_BYTES) {
    throw new Error("CoCodex Server database is outside the recovery size limit");
  }
  return database;
}

function recoveryConfig(config: ServerConfig): RecoveryPayload["config"] {
  return {
    version: 1,
    hostname: config.hostname,
    port: config.port,
    publicHost: config.publicHost,
    ...(config.adminTokenHash ? { adminTokenHash: config.adminTokenHash } : {}),
  };
}

function writeProtectedFile(path: string, value: string | Buffer, publicFile = false): void {
  writeFileSync(path, value, { flag: "wx", mode: publicFile ? 0o644 : 0o600 });
  if (!publicFile) hardenSecretPath(path, { required: true });
  if (process.platform !== "win32") chmodSync(path, publicFile ? 0o644 : 0o600);
}

function validateStagedDatabase(
  path: string,
  expectedIdentityFingerprint: string,
  expectedEpoch: number,
): void {
  const db = new Database(path, { strict: true, readonly: true });
  try {
    const quick = db.query("PRAGMA quick_check(1)").get() as { quick_check?: string } | null;
    if (quick?.quick_check !== "ok") throw new Error("CoCodex recovery database integrity check failed");
    if (db.query("PRAGMA foreign_key_check").all().length !== 0) {
      throw new Error("CoCodex recovery database foreign-key check failed");
    }
    if (serverIdentityFingerprint(db) !== expectedIdentityFingerprint) {
      throw new Error("CoCodex recovery database authority identity mismatch");
    }
    if (serverEpoch(db) !== expectedEpoch) {
      throw new Error("CoCodex recovery database authority epoch mismatch");
    }
    if (serverAuthorityStatus(db) !== "active") {
      throw new Error("CoCodex recovery archive does not contain an active authority");
    }
  } finally {
    db.close();
  }
}

function writeStagedState(
  targetPaths: ServerPaths,
  stageRoot: string,
  payload: RecoveryPayload,
  database: Buffer,
): ServerPaths {
  const staged = serverPaths(stageRoot);
  hardenSecretDir(stageRoot, { required: true });
  const restoredConfig: ServerConfig = {
    ...payload.config,
    tlsCertificate: targetPaths.tlsCertificate,
    tlsPrivateKey: targetPaths.tlsPrivateKey,
  };
  writeProtectedFile(staged.config, `${JSON.stringify(restoredConfig, null, 2)}\n`);
  writeProtectedFile(staged.database, database);
  writeProtectedFile(staged.identityPrivateKey, payload.identityPrivateKeyPem);
  writeProtectedFile(staged.identityPublicKey, payload.identityPublicKeyPem, true);
  writeProtectedFile(staged.tlsPrivateKey, payload.tlsPrivateKeyPem);
  writeProtectedFile(staged.tlsCertificate, payload.tlsCertificatePem, true);
  return staged;
}

function safeRemoveStage(stageRoot: string, parent: string, prefix: string): void {
  const resolvedStage = resolve(stageRoot);
  const resolvedParent = resolve(parent);
  if (resolvedStage.startsWith(`${resolvedParent}${sep}`) && basename(resolvedStage).startsWith(prefix)) {
    rmSync(resolvedStage, { recursive: true, force: true });
  }
}

function swapStateRoot(
  targetPaths: ServerPaths,
  stageRoot: string,
  validateFinal: () => void,
): string | null {
  const parent = dirname(targetPaths.root);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const rollbackPath = existsSync(targetPaths.root)
    ? `${targetPaths.root}.pre-restore-${stamp}`
    : null;
  if (rollbackPath && existsSync(rollbackPath)) throw new Error("CoCodex recovery rollback path already exists");
  if (rollbackPath) {
    const targetStat = lstatSync(targetPaths.root);
    if (!targetStat.isDirectory()) throw new Error("CoCodex Server state root is not a directory");
    const entries = readdirSync(targetPaths.root);
    if (entries.length > 0 && !entries.some(entry => [
      basename(targetPaths.config),
      basename(targetPaths.database),
      basename(targetPaths.identityPrivateKey),
      basename(targetPaths.identityPublicKey),
      basename(targetPaths.tlsPrivateKey),
      basename(targetPaths.tlsCertificate),
    ].includes(entry))) {
      throw new Error("Refusing to replace a non-CoCodex state directory");
    }
    renameSync(targetPaths.root, rollbackPath);
  }
  try {
    renameSync(stageRoot, targetPaths.root);
    try {
      validateFinal();
    } catch (error) {
      const failedPath = `${targetPaths.root}.failed-restore-${stamp}-${randomBytes(4).toString("hex")}`;
      renameSync(targetPaths.root, failedPath);
      if (rollbackPath) renameSync(rollbackPath, targetPaths.root);
      throw error;
    }
  } catch (error) {
    if (!existsSync(targetPaths.root) && rollbackPath && existsSync(rollbackPath)) {
      renameSync(rollbackPath, targetPaths.root);
    }
    throw error;
  }
  if (rollbackPath) hardenSecretDir(rollbackPath, { required: false, force: true });
  return rollbackPath;
}

export function createEncryptedServerRecoveryBackup(
  paths: ServerPaths,
  identity: ServerIdentity,
  outputPath: string,
  passphrase: string,
  now = new Date(),
): EncryptedServerRecoveryBackup {
  const config = loadConfig(paths);
  if (resolve(config.tlsCertificate) !== paths.tlsCertificate || resolve(config.tlsPrivateKey) !== paths.tlsPrivateKey) {
    throw new Error("CoCodex Server configuration references TLS files outside its state root");
  }
  const database = checkpointDatabase(paths.database);
  const db = new Database(paths.database, { strict: true, readonly: true });
  let epoch: number;
  try {
    epoch = serverEpoch(db);
    if (serverIdentityFingerprint(db) !== identity.fingerprint) {
      throw new Error("CoCodex Server identity does not match its database authority");
    }
    if (serverAuthorityStatus(db) !== "active") {
      throw new Error("Only an active CoCodex Server authority can be backed up");
    }
  } finally {
    db.close();
  }
  const payloadConfig = recoveryConfig(config);
  const payload: RecoveryPayload = {
    version: RECOVERY_PAYLOAD_VERSION,
    config: payloadConfig,
    databaseBase64Url: database.toString("base64url"),
    identityPrivateKeyPem: readFileSync(paths.identityPrivateKey, "utf8"),
    identityPublicKeyPem: readFileSync(paths.identityPublicKey, "utf8"),
    tlsPrivateKeyPem: readFileSync(paths.tlsPrivateKey, "utf8"),
    tlsCertificatePem: readFileSync(paths.tlsCertificate, "utf8"),
    sha256: {
      config: sha256(canonicalJson(payloadConfig)),
      database: sha256(database),
      identityPrivateKey: sha256(readFileSync(paths.identityPrivateKey)),
      identityPublicKey: sha256(readFileSync(paths.identityPublicKey)),
      tlsPrivateKey: sha256(readFileSync(paths.tlsPrivateKey)),
      tlsCertificate: sha256(readFileSync(paths.tlsCertificate)),
    },
  };
  if (!publicDer(identity.publicKeyPem).equals(publicDer(payload.identityPublicKeyPem))
    || !publicDer(identity.privateKeyPem).equals(publicDer(payload.identityPublicKeyPem))) {
    throw new Error("Loaded CoCodex Server identity does not match the archived identity files");
  }
  validatePayload(payload, {
    serverFingerprint: identity.fingerprint,
    publicHost: config.publicHost,
    port: config.port,
    tlsFingerprint: tlsFingerprint(payload.tlsCertificatePem),
  });
  validateStagedDatabase(paths.database, identity.fingerprint, epoch);

  const plaintext = canonicalJson(payload);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const header: RecoveryArchiveHeader = {
    version: RECOVERY_BACKUP_VERSION,
    kind: "cocodex-server-recovery",
    createdAt: now.toISOString(),
    serverFingerprint: identity.fingerprint,
    serverEpoch: epoch,
    publicHost: config.publicHost,
    port: config.port,
    tlsFingerprint: tlsFingerprint(payload.tlsCertificatePem),
    payloadSha256: sha256(plaintext),
    kdf: { name: "scrypt", salt: salt.toString("base64url"), N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
    cipher: { name: "aes-256-gcm", iv: iv.toString("base64url") },
  };
  const cipher = createCipheriv("aes-256-gcm", protectedArchiveKey(passphrase, salt), iv);
  cipher.setAAD(canonicalJson(header));
  const ciphertextBytes = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag().toString("base64url");
  const ciphertext = ciphertextBytes.toString("base64url");
  const archive: EncryptedServerRecoveryBackup = {
    ...header,
    authTag,
    ciphertext,
    signature: sign(null, signingTranscript(header, authTag, ciphertext), identity.privateKeyPem)
      .toString("base64url"),
  };
  if (!verify(
    null,
    signingTranscript(header, authTag, ciphertext),
    payload.identityPublicKeyPem,
    strictBase64Url(archive.signature, "signature", 64),
  )) {
    throw new Error("CoCodex recovery archive signature self-check failed");
  }
  writeFileSync(outputPath, `${JSON.stringify(archive, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  try {
    hardenSecretPath(outputPath, { required: true });
    if (process.platform !== "win32") chmodSync(outputPath, 0o600);
  } catch (error) {
    rmSync(outputPath, { force: true });
    throw error;
  }
  return archive;
}

export function restoreEncryptedServerRecoveryBackup(
  paths: ServerPaths,
  inputPath: string,
  passphrase: string,
): RestoredServerRecovery {
  const fileSize = statSync(inputPath).size;
  if (fileSize <= 0 || fileSize > MAX_RECOVERY_ARCHIVE_BYTES) {
    throw new Error("CoCodex recovery archive is outside the supported size limit");
  }
  const archiveValue = JSON.parse(readFileSync(inputPath, "utf8")) as unknown;
  assertArchive(archiveValue);
  const archive = archiveValue;
  const header = archiveHeader(archive);
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      protectedArchiveKey(passphrase, strictBase64Url(archive.kdf.salt, "salt", 16)),
      strictBase64Url(archive.cipher.iv, "IV", 12),
    );
    decipher.setAAD(canonicalJson(header));
    decipher.setAuthTag(strictBase64Url(archive.authTag, "authentication tag", 16));
    plaintext = Buffer.concat([
      decipher.update(strictBase64Url(archive.ciphertext, "ciphertext")),
      decipher.final(),
    ]);
  } catch {
    throw new Error("CoCodex recovery passphrase is invalid or the archive is damaged");
  }
  if (sha256(plaintext) !== archive.payloadSha256) {
    throw new Error("CoCodex recovery payload checksum mismatch");
  }
  let parsedPayload: unknown;
  try { parsedPayload = JSON.parse(plaintext.toString("utf8")); }
  catch { throw new Error("Invalid CoCodex recovery payload"); }
  const { payload, identity, database } = validatePayload(parsedPayload, header);
  if (!verify(
    null,
    signingTranscript(header, archive.authTag, archive.ciphertext),
    identity.publicKeyPem,
    strictBase64Url(archive.signature, "signature", 64),
  )) {
    throw new Error("CoCodex recovery archive signature is invalid");
  }

  const parent = dirname(paths.root);
  mkdirSync(parent, { recursive: true });
  const stagePrefix = `${basename(paths.root)}.restore-stage-`;
  const stageRoot = mkdtempSync(resolve(parent, stagePrefix));
  try {
    const staged = writeStagedState(paths, stageRoot, payload, database);
    validateStagedDatabase(staged.database, identity.fingerprint, archive.serverEpoch);
    const rollbackPath = swapStateRoot(paths, stageRoot, () => {
      const finalConfig = loadConfig(paths);
      if (finalConfig.publicHost !== archive.publicHost || finalConfig.port !== archive.port) {
        throw new Error("CoCodex restored configuration does not match its archive");
      }
      const finalIdentityPrivate = readFileSync(paths.identityPrivateKey, "utf8");
      const finalIdentityPublic = readFileSync(paths.identityPublicKey, "utf8");
      if (!publicDer(finalIdentityPrivate).equals(publicDer(finalIdentityPublic))
        || publicKeyFingerprint(finalIdentityPublic) !== archive.serverFingerprint) {
        throw new Error("CoCodex restored identity verification failed");
      }
      if (tlsFingerprint(readFileSync(paths.tlsCertificate, "utf8")) !== archive.tlsFingerprint) {
        throw new Error("CoCodex restored TLS verification failed");
      }
      validateStagedDatabase(paths.database, identity.fingerprint, archive.serverEpoch);
    });
    return { archive, rollbackPath };
  } finally {
    if (existsSync(stageRoot)) safeRemoveStage(stageRoot, parent, stagePrefix);
  }
}

import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync, sign, verify } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import type { ServerIdentity } from "./identity";
import type { ServerPaths } from "./paths";
import { serverEpoch } from "./server-state";

const BACKUP_VERSION = 1 as const;
const TRANSFER_VERSION = 1 as const;

export interface ServerBackup {
  version: typeof BACKUP_VERSION;
  createdAt: string;
  serverFingerprint: string;
  serverEpoch: number;
  databaseSha256: string;
  databaseBase64: string;
  signature: string;
}

export interface EncryptedServerTransfer {
  version: typeof TRANSFER_VERSION;
  createdAt: string;
  serverFingerprint: string;
  serverEpoch: number;
  databaseSha256: string;
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
  signature: string;
}

function transcript(backup: Omit<ServerBackup, "signature">): Buffer {
  return Buffer.from(JSON.stringify({
    version: backup.version,
    createdAt: backup.createdAt,
    serverFingerprint: backup.serverFingerprint,
    serverEpoch: backup.serverEpoch,
    databaseSha256: backup.databaseSha256,
    databaseBase64: backup.databaseBase64,
  }), "utf8");
}

function transferTranscript(transfer: Omit<EncryptedServerTransfer, "signature">): Buffer {
  return Buffer.from(JSON.stringify({
    version: transfer.version,
    createdAt: transfer.createdAt,
    serverFingerprint: transfer.serverFingerprint,
    serverEpoch: transfer.serverEpoch,
    databaseSha256: transfer.databaseSha256,
    salt: transfer.salt,
    iv: transfer.iv,
    authTag: transfer.authTag,
    ciphertext: transfer.ciphertext,
  }), "utf8");
}

function transferKey(passphrase: string, salt: Buffer): Buffer {
  if (passphrase.length < 12) throw new Error("Transfer passphrase must be at least 12 characters");
  return scryptSync(passphrase, salt, 32, { N: 16_384, r: 8, p: 1 });
}

function assertTransfer(value: unknown): asserts value is EncryptedServerTransfer {
  if (!value || typeof value !== "object") throw new Error("Invalid CoCodex encrypted transfer");
  const transfer = value as Partial<EncryptedServerTransfer>;
  if (transfer.version !== TRANSFER_VERSION
    || typeof transfer.createdAt !== "string"
    || typeof transfer.serverFingerprint !== "string"
    || !Number.isSafeInteger(transfer.serverEpoch) || (transfer.serverEpoch as number) < 1
    || typeof transfer.databaseSha256 !== "string"
    || typeof transfer.salt !== "string" || typeof transfer.iv !== "string"
    || typeof transfer.authTag !== "string" || typeof transfer.ciphertext !== "string"
    || typeof transfer.signature !== "string") {
    throw new Error("Invalid CoCodex encrypted transfer");
  }
  if (Buffer.from(transfer.salt, "base64url").length !== 16
    || Buffer.from(transfer.iv, "base64url").length !== 12
    || Buffer.from(transfer.authTag, "base64url").length !== 16
    || Buffer.from(transfer.ciphertext, "base64url").length === 0) {
    throw new Error("Invalid CoCodex encrypted transfer");
  }
}

function assertBackup(value: unknown): asserts value is ServerBackup {
  if (!value || typeof value !== "object") throw new Error("Invalid CoCodex backup");
  const backup = value as Partial<ServerBackup>;
  if (backup.version !== BACKUP_VERSION
    || typeof backup.createdAt !== "string"
    || typeof backup.serverFingerprint !== "string"
    || !Number.isSafeInteger(backup.serverEpoch) || (backup.serverEpoch as number) < 1
    || typeof backup.databaseSha256 !== "string"
    || typeof backup.databaseBase64 !== "string"
    || typeof backup.signature !== "string") {
    throw new Error("Invalid CoCodex backup");
  }
  const database = Buffer.from(backup.databaseBase64, "base64");
  if (database.length === 0 || createHash("sha256").update(database).digest("hex") !== backup.databaseSha256) {
    throw new Error("CoCodex backup database checksum mismatch");
  }
}

export function createServerBackup(paths: ServerPaths, identity: ServerIdentity, outputPath: string): ServerBackup {
  if (!existsSync(paths.database)) throw new Error("CoCodex Server database does not exist");
  const checkpoint = new Database(paths.database, { strict: true });
  try { checkpoint.exec("PRAGMA wal_checkpoint(TRUNCATE)"); }
  finally { checkpoint.close(); }
  const database = readFileSync(paths.database);
  const epochDb = new Database(paths.database, { strict: true });
  let epoch: number;
  try { epoch = serverEpoch(epochDb); }
  finally { epochDb.close(); }
  const unsigned: Omit<ServerBackup, "signature"> = {
    version: BACKUP_VERSION,
    createdAt: new Date().toISOString(),
    serverFingerprint: identity.fingerprint,
    serverEpoch: epoch,
    databaseSha256: createHash("sha256").update(database).digest("hex"),
    databaseBase64: database.toString("base64"),
  };
  const backup: ServerBackup = {
    ...unsigned,
    signature: sign(null, transcript(unsigned), identity.privateKeyPem).toString("base64url"),
  };
  writeFileSync(outputPath, `${JSON.stringify(backup, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  return backup;
}

export function restoreServerBackup(paths: ServerPaths, identity: ServerIdentity, inputPath: string): ServerBackup {
  const backup = JSON.parse(readFileSync(inputPath, "utf8")) as unknown;
  assertBackup(backup);
  if (backup.serverFingerprint !== identity.fingerprint) {
    throw new Error("CoCodex backup belongs to a different server identity");
  }
  if (!verify(null, transcript({ ...backup, signature: undefined } as Omit<ServerBackup, "signature">),
    identity.publicKeyPem, Buffer.from(backup.signature, "base64url"))) {
    throw new Error("CoCodex backup signature is invalid");
  }
  const temporary = `${paths.database}.restore-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, Buffer.from(backup.databaseBase64, "base64"), { flag: "wx", mode: 0o600 });
  try {
    renameSync(temporary, paths.database);
  } catch (error) {
    try { writeFileSync(paths.database, Buffer.from(backup.databaseBase64, "base64"), { flag: "w", mode: 0o600 }); }
    finally { try { renameSync(temporary, `${temporary}.failed`); } catch { /* best effort */ } }
    if (error instanceof Error && !existsSync(paths.database)) throw error;
  }
  return backup;
}

export function createEncryptedServerTransfer(
  paths: ServerPaths,
  identity: ServerIdentity,
  outputPath: string,
  passphrase: string,
): EncryptedServerTransfer {
  if (!existsSync(paths.database)) throw new Error("CoCodex Server database does not exist");
  const checkpoint = new Database(paths.database, { strict: true });
  try { checkpoint.exec("PRAGMA wal_checkpoint(TRUNCATE)"); }
  finally { checkpoint.close(); }
  const database = readFileSync(paths.database);
  const epochDb = new Database(paths.database, { strict: true });
  let epoch: number;
  try { epoch = serverEpoch(epochDb); }
  finally { epochDb.close(); }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", transferKey(passphrase, salt), iv);
  const ciphertext = Buffer.concat([cipher.update(database), cipher.final()]);
  const unsigned: Omit<EncryptedServerTransfer, "signature"> = {
    version: TRANSFER_VERSION,
    createdAt: new Date().toISOString(),
    serverFingerprint: identity.fingerprint,
    serverEpoch: epoch,
    databaseSha256: createHash("sha256").update(database).digest("hex"),
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    authTag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
  const transfer: EncryptedServerTransfer = {
    ...unsigned,
    signature: sign(null, transferTranscript(unsigned), identity.privateKeyPem).toString("base64url"),
  };
  writeFileSync(outputPath, `${JSON.stringify(transfer, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  return transfer;
}

export function restoreEncryptedServerTransfer(
  paths: ServerPaths,
  identity: ServerIdentity,
  inputPath: string,
  passphrase: string,
): EncryptedServerTransfer {
  const transfer = JSON.parse(readFileSync(inputPath, "utf8")) as unknown;
  assertTransfer(transfer);
  if (transfer.serverFingerprint !== identity.fingerprint) throw new Error("CoCodex transfer belongs to a different server identity");
  if (!verify(null, transferTranscript({ ...transfer, signature: undefined } as Omit<EncryptedServerTransfer, "signature">),
    identity.publicKeyPem, Buffer.from(transfer.signature, "base64url"))) {
    throw new Error("CoCodex encrypted transfer signature is invalid");
  }
  let database: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", transferKey(passphrase, Buffer.from(transfer.salt, "base64url")), Buffer.from(transfer.iv, "base64url"));
    decipher.setAuthTag(Buffer.from(transfer.authTag, "base64url"));
    database = Buffer.concat([decipher.update(Buffer.from(transfer.ciphertext, "base64url")), decipher.final()]);
  } catch {
    throw new Error("CoCodex encrypted transfer passphrase is invalid or the transfer is damaged");
  }
  if (createHash("sha256").update(database).digest("hex") !== transfer.databaseSha256) throw new Error("CoCodex transfer database checksum mismatch");
  const temporary = `${paths.database}.transfer-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, database, { flag: "wx", mode: 0o600 });
  try { renameSync(temporary, paths.database); }
  catch (error) {
    try { writeFileSync(paths.database, database, { flag: "w", mode: 0o600 }); }
    finally { try { renameSync(temporary, `${temporary}.failed`); } catch { /* best effort */ } }
    if (error instanceof Error && !existsSync(paths.database)) throw error;
  }
  return transfer;
}

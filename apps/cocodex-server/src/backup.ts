import { createHash, sign, verify } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import type { ServerIdentity } from "./identity";
import type { ServerPaths } from "./paths";

const BACKUP_VERSION = 1 as const;

export interface ServerBackup {
  version: typeof BACKUP_VERSION;
  createdAt: string;
  serverFingerprint: string;
  databaseSha256: string;
  databaseBase64: string;
  signature: string;
}

function transcript(backup: Omit<ServerBackup, "signature">): Buffer {
  return Buffer.from(JSON.stringify({
    version: backup.version,
    createdAt: backup.createdAt,
    serverFingerprint: backup.serverFingerprint,
    databaseSha256: backup.databaseSha256,
    databaseBase64: backup.databaseBase64,
  }), "utf8");
}

function assertBackup(value: unknown): asserts value is ServerBackup {
  if (!value || typeof value !== "object") throw new Error("Invalid CoCodex backup");
  const backup = value as Partial<ServerBackup>;
  if (backup.version !== BACKUP_VERSION
    || typeof backup.createdAt !== "string"
    || typeof backup.serverFingerprint !== "string"
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
  const unsigned: Omit<ServerBackup, "signature"> = {
    version: BACKUP_VERSION,
    createdAt: new Date().toISOString(),
    serverFingerprint: identity.fingerprint,
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

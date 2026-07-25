import { createCipheriv, createDecipheriv, createHash, createPublicKey, randomBytes, scryptSync, sign, verify, X509Certificate } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { Database } from "bun:sqlite";
import type { ServerIdentity } from "./identity";
import type { ServerPaths } from "./paths";
import {
  initializeServerAuthority,
  requireActiveServerAuthority,
  serverEpoch,
  serverAuthorityStatus,
  serverIdentityFingerprint,
  setServerEpoch,
  retireServerAuthority,
} from "./server-state";
import {
  encryptedServerTransferSchema,
  encryptedServerTransferSigningTranscript,
  encodeServerAuthorityCertificate,
  serverAuthorityCertificateSchema,
  serverAuthorityCertificateSigningTranscript,
  serverTransferTargetSchema,
  type EncryptedServerAuthorityTransfer,
  type ServerAuthorityCertificate,
  type ServerTransferTarget,
} from "@cocodex/protocol";
import { openDatabase } from "./database";
import { canonicalEd25519PublicKey, publicKeyFingerprint } from "@cocodex/protocol";

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

function certificateFingerprint(certificatePem: string): string {
  const certificate = new X509Certificate(certificatePem);
  return createHash("sha256").update(certificate.raw).digest("hex").toUpperCase().match(/.{1,4}/g)?.join("-") ?? "";
}

function assertCertificateCoversHost(certificatePem: string, host: string): void {
  const certificate = new X509Certificate(certificatePem);
  const matchedHost = isIP(host) ? certificate.checkIP(host) : certificate.checkHost(host);
  if (!matchedHost) throw new Error("CoCodex transfer TLS certificate does not cover its target host");
}

function verifyAuthorityCertificate(certificate: ServerAuthorityCertificate): void {
  const sourcePublicKey = canonicalEd25519PublicKey(certificate.sourceIdentityPublicKeyPem);
  if (publicKeyFingerprint(sourcePublicKey) !== certificate.sourceIdentityFingerprint) {
    throw new Error("CoCodex authority certificate source identity fingerprint mismatch");
  }
  if (publicKeyFingerprint(certificate.targetIdentityPublicKeyPem) !== certificate.targetIdentityFingerprint) {
    throw new Error("CoCodex authority certificate target identity fingerprint mismatch");
  }
  if (certificateFingerprint(certificate.targetTlsCertificatePem) !== certificate.targetTlsFingerprint) {
    throw new Error("CoCodex authority certificate TLS fingerprint mismatch");
  }
  assertCertificateCoversHost(certificate.targetTlsCertificatePem, certificate.targetHost);
  const { signature: _signature, ...unsigned } = certificate;
  if (!verify(null, serverAuthorityCertificateSigningTranscript(unsigned), createPublicKey(sourcePublicKey), Buffer.from(certificate.signature, "base64url"))) {
    throw new Error("CoCodex authority certificate signature is invalid");
  }
}

function targetIsValid(target: ServerTransferTarget, now = new Date()): void {
  serverTransferTargetSchema.parse(target);
  const created = Date.parse(target.createdAt);
  const expires = Date.parse(target.expiresAt);
  if (!Number.isFinite(created) || !Number.isFinite(expires) || expires <= now.getTime() || expires - created > 15 * 60_000) {
    throw new Error("CoCodex transfer target request is expired or lives too long");
  }
  if (publicKeyFingerprint(target.targetIdentityPublicKeyPem) !== target.targetIdentityFingerprint) {
    throw new Error("CoCodex transfer target identity fingerprint mismatch");
  }
  if (certificateFingerprint(target.targetTlsCertificatePem) !== target.targetTlsFingerprint) {
    throw new Error("CoCodex transfer target TLS fingerprint mismatch");
  }
  assertCertificateCoversHost(target.targetTlsCertificatePem, target.targetHost);
}

function assertAuthorityTargetMatchesRequest(
  certificate: ServerAuthorityCertificate,
  target: ServerTransferTarget,
): void {
  if (
    canonicalEd25519PublicKey(certificate.targetIdentityPublicKeyPem) !== canonicalEd25519PublicKey(target.targetIdentityPublicKeyPem)
    || certificate.targetIdentityFingerprint !== target.targetIdentityFingerprint
    || certificate.targetTlsFingerprint !== target.targetTlsFingerprint
    || certificate.targetHost !== target.targetHost
    || certificate.targetPort !== target.targetPort
  ) {
    throw new Error("CoCodex authority handoff target does not match its target request");
  }
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

/**
 * Create a destination-bound handoff. The source signs the new identity,
 * endpoint, TLS pin, and next authority epoch before retiring itself.
 */
export function createEncryptedAuthorityServerTransfer(
  paths: ServerPaths,
  identity: ServerIdentity,
  outputPath: string,
  passphrase: string,
  target: ServerTransferTarget,
  now = new Date(),
): EncryptedServerAuthorityTransfer {
  targetIsValid(target, now);
  const db = openDatabase(paths.database);
  try {
    const recordedIdentity = serverIdentityFingerprint(db);
    if (recordedIdentity && recordedIdentity !== identity.fingerprint) {
      throw new Error("CoCodex Server identity does not match the active database authority");
    }
    if (!recordedIdentity) initializeServerAuthority(db, identity.fingerprint, "active");
    requireActiveServerAuthority(db);
  } finally {
    db.close();
  }
  if (!existsSync(paths.database)) throw new Error("CoCodex Server database does not exist");
  const checkpoint = new Database(paths.database, { strict: true });
  try { checkpoint.exec("PRAGMA wal_checkpoint(TRUNCATE)"); }
  finally { checkpoint.close(); }
  const database = readFileSync(paths.database);
  const sourceDb = openDatabase(paths.database);
  const sourceEpoch = serverEpoch(sourceDb);
  sourceDb.close();
  const unsignedCertificate: Omit<ServerAuthorityCertificate, "signature"> = {
    version: 1,
    sourceIdentityPublicKeyPem: identity.publicKeyPem,
    sourceIdentityFingerprint: identity.fingerprint,
    targetIdentityPublicKeyPem: target.targetIdentityPublicKeyPem,
    targetIdentityFingerprint: target.targetIdentityFingerprint,
    targetTlsCertificatePem: target.targetTlsCertificatePem,
    targetTlsFingerprint: target.targetTlsFingerprint,
    targetHost: target.targetHost,
    targetPort: target.targetPort,
    serverEpoch: sourceEpoch + 1,
    issuedAt: now.toISOString(),
  };
  const authorityCertificate: ServerAuthorityCertificate = {
    ...unsignedCertificate,
    signature: sign(null, serverAuthorityCertificateSigningTranscript(unsignedCertificate), identity.privateKeyPem).toString("base64url"),
  };
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", transferKey(passphrase, salt), iv);
  const ciphertext = Buffer.concat([cipher.update(database), cipher.final()]);
  const unsigned: Omit<EncryptedServerAuthorityTransfer, "signature"> = {
    version: 2,
    createdAt: now.toISOString(),
    sourceIdentityPublicKeyPem: identity.publicKeyPem,
    sourceIdentityFingerprint: identity.fingerprint,
    sourceServerEpoch: sourceEpoch,
    target,
    databaseSha256: createHash("sha256").update(database).digest("hex"),
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    authTag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    authorityCertificate,
  };
  const transfer: EncryptedServerAuthorityTransfer = {
    ...unsigned,
    signature: sign(null, encryptedServerTransferSigningTranscript(unsigned), identity.privateKeyPem).toString("base64url"),
  };
  encryptedServerTransferSchema.parse(transfer);
  writeFileSync(outputPath, `${JSON.stringify(transfer, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  const retiredDb = openDatabase(paths.database);
  try { retireServerAuthority(retiredDb); }
  finally { retiredDb.close(); }
  return transfer;
}

/** Restore a destination-bound handoff into a prepared destination identity. */
export function restoreEncryptedAuthorityServerTransfer(
  paths: ServerPaths,
  identity: ServerIdentity,
  inputPath: string,
  passphrase: string,
): { transfer: EncryptedServerAuthorityTransfer; authorityCode: string } {
  if (!existsSync(paths.database)) throw new Error("Prepared destination database does not exist");
  const preparedDb = openDatabase(paths.database);
  try {
    if (serverAuthorityStatus(preparedDb) !== "prepared") throw new Error("Destination Server must be prepared for an authority transfer");
  } finally {
    preparedDb.close();
  }
  const transfer = encryptedServerTransferSchema.parse(JSON.parse(readFileSync(inputPath, "utf8")));
  const sourcePublicKey = canonicalEd25519PublicKey(transfer.sourceIdentityPublicKeyPem);
  if (publicKeyFingerprint(sourcePublicKey) !== transfer.sourceIdentityFingerprint) {
    throw new Error("CoCodex transfer source identity fingerprint mismatch");
  }
  const { signature: _signature, ...unsigned } = transfer;
  if (!verify(null, encryptedServerTransferSigningTranscript(unsigned), createPublicKey(sourcePublicKey), Buffer.from(transfer.signature, "base64url"))) {
    throw new Error("CoCodex encrypted authority transfer signature is invalid");
  }
  verifyAuthorityCertificate(transfer.authorityCertificate);
  assertAuthorityTargetMatchesRequest(transfer.authorityCertificate, transfer.target);
  if (transfer.authorityCertificate.sourceIdentityPublicKeyPem !== sourcePublicKey
    || transfer.authorityCertificate.serverEpoch !== transfer.sourceServerEpoch + 1) {
    throw new Error("CoCodex authority handoff does not match the transfer");
  }
  if (publicKeyFingerprint(identity.publicKeyPem) !== transfer.target.targetIdentityFingerprint
    || canonicalEd25519PublicKey(identity.publicKeyPem) !== canonicalEd25519PublicKey(transfer.target.targetIdentityPublicKeyPem)) {
    throw new Error("Prepared destination identity does not match the transfer target");
  }
  if (!existsSync(paths.tlsCertificate) || certificateFingerprint(readFileSync(paths.tlsCertificate, "utf8")) !== transfer.target.targetTlsFingerprint) {
    throw new Error("Prepared destination TLS certificate does not match the transfer target");
  }
  let database: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", transferKey(passphrase, Buffer.from(transfer.salt, "base64url")), Buffer.from(transfer.iv, "base64url"));
    decipher.setAuthTag(Buffer.from(transfer.authTag, "base64url"));
    database = Buffer.concat([decipher.update(Buffer.from(transfer.ciphertext, "base64url")), decipher.final()]);
  } catch {
    throw new Error("CoCodex encrypted authority transfer passphrase is invalid or the transfer is damaged");
  }
  if (createHash("sha256").update(database).digest("hex") !== transfer.databaseSha256) throw new Error("CoCodex transfer database checksum mismatch");
  const temporary = `${paths.database}.authority-transfer-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, database, { flag: "wx", mode: 0o600 });
  try { renameSync(temporary, paths.database); }
  catch (error) {
    try { writeFileSync(paths.database, database, { flag: "w", mode: 0o600 }); }
    finally { try { renameSync(temporary, `${temporary}.failed`); } catch { /* best effort */ } }
    if (error instanceof Error && !existsSync(paths.database)) throw error;
  }
  const db = openDatabase(paths.database);
  try {
    if (serverEpoch(db) !== transfer.sourceServerEpoch) throw new Error("CoCodex transfer database epoch does not match its signed metadata");
    setServerEpoch(db, transfer.authorityCertificate.serverEpoch);
    initializeServerAuthority(db, identity.fingerprint, "active");
  } finally {
    db.close();
  }
  return { transfer, authorityCode: encodeServerAuthorityCertificate(transfer.authorityCertificate) };
}

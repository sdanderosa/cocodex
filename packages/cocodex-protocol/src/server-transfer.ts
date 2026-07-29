import { z } from "zod";

const publicKeyPem = z.string().min(64).max(2_048);
const certificatePem = z.string().min(128).max(32_768);
const fingerprint = z.string().trim().min(16).max(256);
const host = z.string().trim().min(1).max(253);
const port = z.number().int().min(1).max(65_535);
const epoch = z.number().int().positive().max(0x7fffffff);

export const serverTransferTargetSchema = z.object({
  version: z.literal(1),
  requestId: z.uuid(),
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  targetHost: host,
  targetPort: port,
  targetIdentityPublicKeyPem: publicKeyPem,
  targetIdentityFingerprint: fingerprint,
  targetTlsCertificatePem: certificatePem,
  targetTlsFingerprint: fingerprint,
}).strict();
export type ServerTransferTarget = z.infer<typeof serverTransferTargetSchema>;

export const serverAuthorityCertificateSchema = z.object({
  version: z.literal(1),
  sourceIdentityPublicKeyPem: publicKeyPem,
  sourceIdentityFingerprint: fingerprint,
  targetIdentityPublicKeyPem: publicKeyPem,
  targetIdentityFingerprint: fingerprint,
  targetTlsCertificatePem: certificatePem,
  targetTlsFingerprint: fingerprint,
  targetHost: host,
  targetPort: port,
  serverEpoch: epoch,
  issuedAt: z.iso.datetime(),
  signature: z.string().min(64).max(256),
}).strict();
export type ServerAuthorityCertificate = z.infer<typeof serverAuthorityCertificateSchema>;

export const encryptedServerTransferSchema = z.object({
  version: z.literal(2),
  createdAt: z.iso.datetime(),
  sourceIdentityPublicKeyPem: publicKeyPem,
  sourceIdentityFingerprint: fingerprint,
  sourceServerEpoch: epoch,
  target: serverTransferTargetSchema,
  databaseSha256: z.string().regex(/^[0-9a-f]{64}$/),
  salt: z.string().min(20).max(32),
  iv: z.string().min(16).max(24),
  authTag: z.string().min(20).max(32),
  ciphertext: z.string().min(1).max(8_000_000),
  authorityCertificate: serverAuthorityCertificateSchema,
  signature: z.string().min(64).max(256),
}).strict();
export type EncryptedServerAuthorityTransfer = z.infer<typeof encryptedServerTransferSchema>;

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

function targetValues(target: ServerTransferTarget): string[] {
  return [
    String(target.version), target.requestId, target.createdAt, target.expiresAt,
    target.targetHost, String(target.targetPort), target.targetIdentityPublicKeyPem,
    target.targetIdentityFingerprint, target.targetTlsCertificatePem, target.targetTlsFingerprint,
  ];
}

export function serverTransferTargetSigningTranscript(target: ServerTransferTarget): Buffer {
  return transcript("COCODEX-SERVER-TRANSFER-TARGET", targetValues(target));
}

export function serverAuthorityCertificateSigningTranscript(
  certificate: Omit<ServerAuthorityCertificate, "signature">,
): Buffer {
  return transcript("COCODEX-SERVER-AUTHORITY-HANDOFF", [
    String(certificate.version), certificate.sourceIdentityPublicKeyPem,
    certificate.sourceIdentityFingerprint, certificate.targetIdentityPublicKeyPem,
    certificate.targetIdentityFingerprint, certificate.targetTlsCertificatePem,
    certificate.targetTlsFingerprint, certificate.targetHost, String(certificate.targetPort),
    String(certificate.serverEpoch), certificate.issuedAt,
  ]);
}

export function encryptedServerTransferSigningTranscript(
  transfer: Omit<EncryptedServerAuthorityTransfer, "signature">,
): Buffer {
  return transcript("COCODEX-ENCRYPTED-SERVER-TRANSFER", [
    String(transfer.version), transfer.createdAt, transfer.sourceIdentityPublicKeyPem,
    transfer.sourceIdentityFingerprint, String(transfer.sourceServerEpoch),
    ...targetValues(transfer.target), transfer.databaseSha256, transfer.salt, transfer.iv,
    transfer.authTag, transfer.ciphertext,
    ...authorityValues(transfer.authorityCertificate),
  ]);
}

function authorityValues(certificate: ServerAuthorityCertificate): string[] {
  return [
    String(certificate.version), certificate.sourceIdentityPublicKeyPem,
    certificate.sourceIdentityFingerprint, certificate.targetIdentityPublicKeyPem,
    certificate.targetIdentityFingerprint, certificate.targetTlsCertificatePem,
    certificate.targetTlsFingerprint, certificate.targetHost, String(certificate.targetPort),
    String(certificate.serverEpoch), certificate.issuedAt, certificate.signature,
  ];
}

export function encodeServerAuthorityCertificate(certificate: ServerAuthorityCertificate): string {
  const parsed = serverAuthorityCertificateSchema.parse(certificate);
  return `ccx-transfer1.${Buffer.from(JSON.stringify(parsed), "utf8").toString("base64url")}`;
}

export function decodeServerAuthorityCertificate(value: string): ServerAuthorityCertificate {
  if (!value.startsWith("ccx-transfer1.")) throw new Error("Unsupported CoCodex server-transfer certificate");
  try {
    return serverAuthorityCertificateSchema.parse(JSON.parse(Buffer.from(value.slice("ccx-transfer1.".length), "base64url").toString("utf8")));
  } catch {
    throw new Error("Malformed or invalid CoCodex server-transfer certificate");
  }
}

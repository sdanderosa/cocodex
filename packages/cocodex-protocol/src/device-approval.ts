import { createHash, createPublicKey } from "node:crypto";
import { z } from "zod";

const requestId = z.uuid();
const operationId = z.uuid();
const deviceId = z.uuid();
const deviceFingerprint = z.string().regex(
  /^[0-9A-F]{4}(?:-[0-9A-F]{4}){15}$/,
  "Device fingerprint must be canonical grouped SHA-256",
);
const enrollmentDigest = z.string().regex(
  /^[A-Za-z0-9_-]{43}$/,
  "Enrollment digest must be canonical base64url SHA-256",
);
const signature = z.string().regex(/^[A-Za-z0-9_-]{86}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 64
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Device-approval signature must canonically encode exactly 64 bytes",
);
const nonce = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 32
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Device-approval nonce must encode exactly 32 random bytes",
);

export const pendingDeviceApprovalSchema = z.object({
  deviceId,
  displayName: z.string().trim().min(1).max(80),
  fingerprint: deviceFingerprint,
  devicePublicKeyPem: z.string().min(64).max(2_048),
  messagingPublicKeyPem: z.string().min(64).max(2_048),
  projectWrapPublicKeyPem: z.string().min(64).max(2_048).nullable(),
  invitationId: z.uuid(),
  invitationTokenHash: z.string().regex(/^[0-9a-f]{64}$/),
  invitationExpiresAt: z.iso.datetime(),
  enrolledAt: z.iso.datetime(),
  approvalExpiresAt: z.iso.datetime(),
  approvalRevision: z.literal(0),
  enrollmentDigest,
}).strict();
export type PendingDeviceApproval = z.infer<typeof pendingDeviceApprovalSchema>;

export const deviceApprovalListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("device.approval.list"),
  requestId,
}).strict();

export const deviceApprovalUpdateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("device.approval.update"),
  requestId,
  operationId,
  targetDeviceId: deviceId,
  targetFingerprint: deviceFingerprint,
  targetEnrollmentDigest: enrollmentDigest,
  expectedRevision: z.literal(0),
  decision: z.enum(["approve", "reject"]),
  serverIdentityFingerprint: deviceFingerprint,
  serverEpoch: z.number().int().positive().max(0x7fffffff),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  nonce,
  signature,
}).strict();
export type DeviceApprovalUpdateFrame = z.infer<typeof deviceApprovalUpdateFrameSchema>;

export const deviceApprovalSnapshotFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("device.approval.snapshot"),
  requestId: requestId.optional(),
  serverIdentityFingerprint: deviceFingerprint,
  serverEpoch: z.number().int().positive().max(0x7fffffff),
  devices: z.array(pendingDeviceApprovalSchema).max(256),
}).strict();

const deviceApprovalResultFields = {
  operationId,
  targetDeviceId: deviceId,
  targetFingerprint: deviceFingerprint,
  decision: z.enum(["approve", "reject"]),
  status: z.enum(["approved", "rejected"]),
  approverDeviceId: deviceId,
  resultingRevision: z.literal(1),
  decidedAt: z.iso.datetime(),
} as const;

export const deviceApprovalUpdatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("device.approval.updated"),
  requestId,
  ...deviceApprovalResultFields,
  created: z.boolean(),
}).strict();

export const deviceApprovalChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("device.approval.changed"),
  ...deviceApprovalResultFields,
}).strict();

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

function canonicalPublicKey(value: string, expectedType: "ed25519" | "x25519"): string {
  const key = createPublicKey(value);
  if (key.asymmetricKeyType !== expectedType) {
    throw new Error(`Enrollment ${expectedType} public key is invalid`);
  }
  return key.export({ type: "spki", format: "pem" }).toString();
}

export interface DeviceEnrollmentDigestInput {
  serverTlsFingerprint: string;
  serverIdentityFingerprint: string;
  invitationId: string;
  invitationTokenHash: string;
  invitationExpiresAt: string;
  deviceId: string;
  displayName: string;
  fingerprint: string;
  devicePublicKeyPem: string;
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem?: string | null;
  enrolledAt: string;
  approvalExpiresAt: string;
  approvalRevision: 0;
}

export function deviceEnrollmentDigest(input: DeviceEnrollmentDigestInput): string {
  const transcript = Buffer.concat([
    Buffer.from("COCODEX-DEVICE-ENROLLMENT-ATTESTATION\u0000", "utf8"),
    ...[
      "1",
      input.serverTlsFingerprint,
      input.serverIdentityFingerprint,
      input.invitationId,
      input.invitationTokenHash,
      input.invitationExpiresAt,
      "device-enrollment",
      input.deviceId,
      input.displayName.trim(),
      input.fingerprint,
      canonicalPublicKey(input.devicePublicKeyPem, "ed25519"),
      canonicalPublicKey(input.messagingPublicKeyPem, "x25519"),
      input.projectWrapPublicKeyPem
        ? canonicalPublicKey(input.projectWrapPublicKeyPem, "x25519")
        : "",
      input.enrolledAt,
      input.approvalExpiresAt,
      String(input.approvalRevision),
    ].map(lengthPrefix),
  ]);
  return createHash("sha256").update(transcript).digest("base64url");
}

const VERIFICATION_WORDS = [
  "amber", "birch", "cobalt", "dawn",
  "ember", "fern", "garnet", "harbor",
  "indigo", "juniper", "keystone", "lunar",
  "maple", "nova", "opal", "pine",
] as const;

export function deviceVerificationPhrase(
  serverIdentityFingerprint: string,
  targetDeviceId: string,
  targetFingerprint: string,
): string {
  const digest = createHash("sha256").update(Buffer.concat([
    Buffer.from("COCODEX-DEVICE-VERIFICATION-PHRASE\u0000", "utf8"),
    lengthPrefix(serverIdentityFingerprint),
    lengthPrefix(targetDeviceId),
    lengthPrefix(targetFingerprint),
  ])).digest();
  // The phrase is a comparison aid, not the cryptographic identity itself.
  // Keep 64 bits so a casually guessed phrase is not a useful approval oracle.
  const hex = digest.subarray(0, 8).toString("hex");
  return [...hex].map(value => VERIFICATION_WORDS[Number.parseInt(value, 16)]).join(" ");
}

export function deviceApprovalSigningTranscript(
  input: Omit<DeviceApprovalUpdateFrame, "type" | "requestId" | "signature">,
): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-DEVICE-APPROVAL\u0000", "utf8"),
    ...[
      String(input.version),
      input.operationId,
      input.targetDeviceId,
      input.targetFingerprint,
      input.targetEnrollmentDigest,
      String(input.expectedRevision),
      input.decision,
      input.serverIdentityFingerprint,
      String(input.serverEpoch),
      input.issuedAt,
      input.expiresAt,
      input.nonce,
    ].map(lengthPrefix),
  ]);
}

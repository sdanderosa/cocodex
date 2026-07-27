import { createHash } from "node:crypto";
import { z } from "zod";
import { canonicalEd25519PublicKey } from "./keys";
import { projectKeyEnvelopeSchema, type ProjectKeyEnvelope } from "./project-encryption";

const requestId = z.uuid();
const invitationId = z.uuid();
const projectId = z.uuid();
const deviceId = z.uuid();
const signature = z.string().regex(/^[A-Za-z0-9_-]{86}$/);
const nonce = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 32
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project invitation nonce must encode exactly 32 random bytes",
);
const serverFingerprint = z.string().trim().min(16).max(256);

export const projectInvitationStatusSchema = z.enum([
  "pending",
  "accepted",
  "declined",
  "cancelled",
  "expired",
]);
export type ProjectInvitationStatus = z.infer<typeof projectInvitationStatusSchema>;

export const projectInvitationDecisionSchema = z.enum(["accept", "decline", "cancel"]);
export type ProjectInvitationDecision = z.infer<typeof projectInvitationDecisionSchema>;

export const projectInvitationCreateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.create"),
  requestId,
  invitationId,
  projectId,
  serverFingerprint,
  recipientDeviceId: deviceId,
  keyEpoch: z.number().int().positive().max(0x7fffffff),
  envelope: projectKeyEnvelopeSchema,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  nonce,
  signature,
}).strict();
export type ProjectInvitationCreateFrame = z.infer<typeof projectInvitationCreateFrameSchema>;

export const projectInvitationListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.list"),
  requestId,
}).strict();

export const projectInvitationRespondFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.respond"),
  requestId,
  invitationId,
  decision: z.enum(["accept", "decline"]),
  signature,
}).strict();
export type ProjectInvitationRespondFrame = z.infer<typeof projectInvitationRespondFrameSchema>;

export const projectInvitationCancelFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.cancel"),
  requestId,
  invitationId,
  signature,
}).strict();

export const projectInvitationViewSchema = z.object({
  invitationId,
  projectId,
  projectName: z.string().trim().min(1).max(120),
  serverFingerprint,
  ownerDeviceId: deviceId,
  ownerDisplayName: z.string().trim().min(1).max(80),
  ownerFingerprint: z.string().trim().min(16).max(256),
  ownerDeviceKeyCertificate: z.string().min(256).max(8_192),
  recipientDeviceId: deviceId,
  recipientDisplayName: z.string().trim().min(1).max(80),
  recipientFingerprint: z.string().trim().min(16).max(256),
  keyEpoch: z.number().int().positive().max(0x7fffffff),
  envelope: projectKeyEnvelopeSchema,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  nonce,
  ownerSignature: signature,
  status: projectInvitationStatusSchema,
}).strict();
export type ProjectInvitationView = z.infer<typeof projectInvitationViewSchema>;

export const projectInvitationListResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.list.result"),
  requestId,
  invitations: z.array(projectInvitationViewSchema).max(256),
}).strict();

export const projectInvitationCreatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.created"),
  requestId,
  invitation: projectInvitationViewSchema,
  created: z.boolean(),
}).strict();

export const projectInvitationChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.changed"),
  invitation: projectInvitationViewSchema,
}).strict();

export const projectInvitationRespondedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.invite.responded"),
  requestId,
  invitation: projectInvitationViewSchema,
  created: z.boolean(),
}).strict();

export interface ProjectInvitationSigningInput {
  invitationId: string;
  projectId: string;
  serverFingerprint: string;
  ownerDeviceId: string;
  recipientDeviceId: string;
  keyEpoch: number;
  envelope: ProjectKeyEnvelope;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
}

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

function envelopeDigest(envelope: ProjectKeyEnvelope): string {
  const parsed = projectKeyEnvelopeSchema.parse(envelope);
  const canonical = JSON.stringify(Object.fromEntries(
    Object.entries(parsed).sort(([left], [right]) => left.localeCompare(right)),
  ));
  return createHash("sha256").update(canonical).digest("base64url");
}

function transcript(context: string, values: string[]): Buffer {
  return Buffer.concat([
    Buffer.from(`${context}\u0000`, "utf8"),
    ...values.map(lengthPrefix),
  ]);
}

export function projectInvitationSigningTranscript(input: ProjectInvitationSigningInput): Buffer {
  return transcript("COCODEX-PROJECT-INVITATION", [
    "1",
    input.invitationId,
    input.projectId,
    input.serverFingerprint,
    input.ownerDeviceId,
    input.recipientDeviceId,
    String(input.keyEpoch),
    envelopeDigest(input.envelope),
    input.issuedAt,
    input.expiresAt,
    input.nonce,
  ]);
}

export function projectInvitationDecisionTranscript(
  input: ProjectInvitationSigningInput,
  decision: ProjectInvitationDecision,
): Buffer {
  return transcript("COCODEX-PROJECT-INVITATION-DECISION", [
    "1",
    decision,
    input.invitationId,
    input.projectId,
    input.serverFingerprint,
    input.ownerDeviceId,
    input.recipientDeviceId,
    String(input.keyEpoch),
    envelopeDigest(input.envelope),
    input.issuedAt,
    input.expiresAt,
    input.nonce,
  ]);
}

export function canonicalInvitationOwnerKey(value: string): string {
  return canonicalEd25519PublicKey(value);
}

import { z } from "zod";

const requestId = z.uuid();
const projectId = z.uuid();
const deviceId = z.uuid();
const signature = z.string().regex(/^[A-Za-z0-9_-]{86}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 64
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project-leave signature must canonically encode exactly 64 bytes",
);
const nonce = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 32
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project-leave nonce must encode exactly 32 random bytes",
);

export const projectMemberLeaveFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.member.leave"),
  requestId,
  projectId,
  serverFingerprint: z.string().trim().min(16).max(256),
  serverEpoch: z.number().int().positive().max(0x7fffffff),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  nonce,
  signature,
}).strict();
export type ProjectMemberLeaveFrame = z.infer<typeof projectMemberLeaveFrameSchema>;

export const projectMemberLeaveRequestedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.member.leave-requested"),
  requestId,
  projectId,
  deviceId,
  requestedAt: z.iso.datetime(),
  created: z.boolean(),
}).strict();
export type ProjectMemberLeaveRequestedFrame = z.infer<typeof projectMemberLeaveRequestedFrameSchema>;

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

export function projectMemberLeaveSigningTranscript(
  input: Omit<ProjectMemberLeaveFrame, "type" | "signature">,
): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-PROJECT-MEMBER-LEAVE\u0000", "utf8"),
    ...[
      String(input.version),
      input.requestId,
      input.projectId,
      input.serverFingerprint,
      String(input.serverEpoch),
      input.issuedAt,
      input.expiresAt,
      input.nonce,
    ].map(lengthPrefix),
  ]);
}

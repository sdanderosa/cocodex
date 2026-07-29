import { z } from "zod";

const requestId = z.uuid();
const operationId = z.uuid();
const projectId = z.uuid();
const deviceId = z.uuid();
const signature = z.string().regex(/^[A-Za-z0-9_-]{86}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 64
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project-lock signature must canonically encode exactly 64 bytes",
);
const nonce = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 32
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project-lock nonce must encode exactly 32 random bytes",
);

export const projectLockStateSchema = z.object({
  state: z.enum(["active", "locked"]),
  revision: z.number().int().nonnegative().max(0x7fffffff),
  lockedAt: z.iso.datetime().nullable(),
  lockedByDeviceId: deviceId.nullable(),
  reason: z.string().trim().min(1).max(512).nullable(),
}).strict().superRefine((value, context) => {
  const locked = value.state === "locked";
  if (locked !== (value.lockedAt !== null)
    || locked !== (value.lockedByDeviceId !== null)
    || locked !== (value.reason !== null)) {
    context.addIssue({
      code: "custom",
      message: "Project lock metadata must be present only while the project is locked",
    });
  }
});
export type ProjectLockState = z.infer<typeof projectLockStateSchema>;

export const projectLockUpdateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.lock.update"),
  requestId,
  operationId,
  projectId,
  action: z.enum(["lock", "unlock"]),
  expectedRevision: z.number().int().nonnegative().max(0x7ffffffe),
  reason: z.string().trim().min(1).max(512),
  serverFingerprint: z.string().trim().min(16).max(256),
  serverEpoch: z.number().int().positive().max(0x7fffffff),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  nonce,
  signature,
}).strict();
export type ProjectLockUpdateFrame = z.infer<typeof projectLockUpdateFrameSchema>;

export const projectLockTransitionSchema = z.object({
  operationId,
  projectId,
  action: z.enum(["lock", "unlock"]),
  actorDeviceId: deviceId,
  reason: z.string().trim().min(1).max(512),
  state: projectLockStateSchema,
  createdAt: z.iso.datetime(),
}).strict();
export type ProjectLockTransition = z.infer<typeof projectLockTransitionSchema>;

const cancelledTaskSchema = z.object({
  taskId: z.uuid(),
  targetDeviceId: deviceId,
}).strict();

export const projectLockUpdatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.lock.updated"),
  requestId,
  transition: projectLockTransitionSchema,
  created: z.boolean(),
  cancelledTaskCount: z.number().int().nonnegative(),
  cancelledTasks: z.array(cancelledTaskSchema).max(256),
}).strict().superRefine((value, context) => {
  if (value.cancelledTaskCount < value.cancelledTasks.length) {
    context.addIssue({
      code: "custom",
      path: ["cancelledTaskCount"],
      message: "Cancelled task count cannot be smaller than the included task list",
    });
  }
});

export const projectLockChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.lock.changed"),
  transition: projectLockTransitionSchema,
  cancelledTaskCount: z.number().int().nonnegative(),
  cancelledTasks: z.array(cancelledTaskSchema).max(256),
}).strict().superRefine((value, context) => {
  if (value.cancelledTaskCount < value.cancelledTasks.length) {
    context.addIssue({
      code: "custom",
      path: ["cancelledTaskCount"],
      message: "Cancelled task count cannot be smaller than the included task list",
    });
  }
});

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

export function projectLockSigningTranscript(
  input: Omit<ProjectLockUpdateFrame, "type" | "requestId" | "signature">,
): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-PROJECT-LOCK\u0000", "utf8"),
    ...[
      String(input.version),
      input.operationId,
      input.projectId,
      input.action,
      String(input.expectedRevision),
      input.reason.trim(),
      input.serverFingerprint,
      String(input.serverEpoch),
      input.issuedAt,
      input.expiresAt,
      input.nonce,
    ].map(lengthPrefix),
  ]);
}

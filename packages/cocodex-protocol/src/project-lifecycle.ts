import { z } from "zod";

const requestId = z.uuid();
const operationId = z.uuid();
const projectId = z.uuid();
const deviceId = z.uuid();
const signature = z.string().regex(/^[A-Za-z0-9_-]{86}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 64
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project-lifecycle signature must canonically encode exactly 64 bytes",
);
const nonce = z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine(value =>
  Buffer.from(value, "base64url").byteLength === 32
  && Buffer.from(value, "base64url").toString("base64url") === value,
  "Project-lifecycle nonce must encode exactly 32 random bytes",
);

export const projectLifecycleStateSchema = z.enum(["active", "archived"]);
export const projectLifecycleActionSchema = z.enum(["rename", "archive", "restore", "delete"]);
export type ProjectLifecycleState = z.infer<typeof projectLifecycleStateSchema>;
export type ProjectLifecycleAction = z.infer<typeof projectLifecycleActionSchema>;

export const projectLifecycleUpdateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.lifecycle.update"),
  requestId,
  operationId,
  projectId,
  action: projectLifecycleActionSchema,
  expectedRevision: z.number().int().nonnegative().max(0x7ffffffe),
  name: z.string().trim().min(1).max(120).optional(),
  confirmationName: z.string().min(1).max(120).optional(),
  serverFingerprint: z.string().trim().min(16).max(256),
  serverEpoch: z.number().int().positive().max(0x7fffffff),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  nonce,
  signature,
}).strict().superRefine((value, context) => {
  if ((value.action === "rename") !== (value.name !== undefined)) {
    context.addIssue({ code: "custom", path: ["name"], message: "Rename requires exactly one project name" });
  }
  if ((value.action === "delete") !== (value.confirmationName !== undefined)) {
    context.addIssue({ code: "custom", path: ["confirmationName"], message: "Delete requires exact project-name confirmation" });
  }
});
export type ProjectLifecycleUpdateFrame = z.infer<typeof projectLifecycleUpdateFrameSchema>;

export const projectLifecycleTransitionSchema = z.object({
  operationId,
  projectId,
  action: projectLifecycleActionSchema,
  actorDeviceId: deviceId,
  previousName: z.string().trim().min(1).max(120),
  resultingName: z.string().trim().min(1).max(120),
  previousState: projectLifecycleStateSchema,
  resultingState: projectLifecycleStateSchema.nullable(),
  resultingRevision: z.number().int().positive().max(0x7fffffff),
  createdAt: z.iso.datetime(),
}).strict().superRefine((value, context) => {
  if ((value.action === "delete") !== (value.resultingState === null)) {
    context.addIssue({ code: "custom", path: ["resultingState"], message: "Only deletion has no resulting project state" });
  }
});
export type ProjectLifecycleTransition = z.infer<typeof projectLifecycleTransitionSchema>;

export const projectLifecycleUpdatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.lifecycle.updated"),
  requestId,
  transition: projectLifecycleTransitionSchema,
  created: z.boolean(),
}).strict();

export const projectDeletedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.deleted"),
  transition: projectLifecycleTransitionSchema.refine(value => value.action === "delete", {
    message: "Project deletion frame requires a delete transition",
  }),
}).strict();

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([length, bytes]);
}

export function projectLifecycleSigningTranscript(
  input: Omit<ProjectLifecycleUpdateFrame, "type" | "requestId" | "signature">,
): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-PROJECT-LIFECYCLE\u0000", "utf8"),
    ...[
      String(input.version),
      input.operationId,
      input.projectId,
      input.action,
      String(input.expectedRevision),
      input.name?.trim() ?? "",
      input.confirmationName ?? "",
      input.serverFingerprint,
      String(input.serverEpoch),
      input.issuedAt,
      input.expiresAt,
      input.nonce,
    ].map(lengthPrefix),
  ]);
}

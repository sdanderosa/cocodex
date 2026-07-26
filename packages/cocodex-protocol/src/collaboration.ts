import { z } from "zod";
import { usageReportSchema } from "./usage";
import {
  PROJECT_KEY_EPOCH_MAX,
  projectContentEnvelopeSchema,
  projectKeyEnvelopeSchema,
} from "./project-encryption";
import {
  encryptedChatAcceptedFrameSchema,
  encryptedChatEventFrameSchema,
  encryptedChatSendFrameSchema,
  encryptedChatSnapshotFrameSchema,
  encryptedChatSubscribeFrameSchema,
} from "./project-chat";
import {
  encryptedPromptAcceptedFrameSchema,
  encryptedPromptChangedFrameSchema,
  encryptedPromptSnapshotFrameSchema,
  encryptedPromptSubscribeFrameSchema,
  encryptedPromptUpdateFrameSchema,
} from "./project-prompt";
import {
  encryptedArtifactAcceptedFrameSchema,
  encryptedArtifactListFrameSchema,
  encryptedArtifactListResultFrameSchema,
  encryptedArtifactPublishFrameSchema,
  encryptedArtifactPublishedFrameSchema,
} from "./project-artifact";
import {
  encryptedFileReferenceAcceptedFrameSchema,
  encryptedFileReferenceListFrameSchema,
  encryptedFileReferenceListResultFrameSchema,
  encryptedFileReferencePublishFrameSchema,
  encryptedFileReferencePublishedFrameSchema,
} from "./project-file-reference";
import {
  encryptedAgentRequestFrameSchema,
  encryptedAgentResultSendFrameSchema,
  encryptedAgentResultChangedFrameSchema,
  encryptedAgentTaskFrameSchema,
} from "./project-agent";

const requestId = z.uuid();
const projectId = z.uuid();
const deviceId = z.uuid();
const privateMessageId = z.uuid();
const agentModelId = z.string().trim().regex(
  /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/,
  "Agent model IDs may contain only letters, numbers, dot, underscore, colon, slash, and hyphen",
);
const agentReasoningEffort = z.enum(["minimal", "low", "medium", "high", "xhigh", "max"]);
const agentRuntimeDefinitionFields = {
  primaryModel: agentModelId,
  primaryEffort: agentReasoningEffort,
  coAgentModel: agentModelId.nullable(),
  coAgentEffort: agentReasoningEffort.nullable(),
  maxConcurrentCoAgents: z.number().int().min(0).max(8),
} as const;
function validateAgentRuntimeDefinition(
  value: {
    coAgentModel: string | null;
    coAgentEffort: z.infer<typeof agentReasoningEffort> | null;
    maxConcurrentCoAgents: number;
  },
  context: z.RefinementCtx,
): void {
  const configured = value.coAgentModel !== null && value.coAgentEffort !== null;
  if ((value.maxConcurrentCoAgents > 0) !== configured) {
    context.addIssue({
      code: "custom",
      path: ["maxConcurrentCoAgents"],
      message: "Positive co-agent limits require a model and effort; zero requires neither",
    });
  }
}
const PRIVATE_MESSAGE_CIPHERTEXT_MAX_BYTES = 72 * 1024;
const privateCiphertext = z.string().min(64).max(96_000).superRefine((value, refinement) => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    refinement.addIssue({ code: "custom", message: "Private-message ciphertext must be canonical base64url" });
    return;
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value || decoded.byteLength < 48 || decoded.byteLength > PRIVATE_MESSAGE_CIPHERTEXT_MAX_BYTES) {
    refinement.addIssue({ code: "custom", message: "Private-message ciphertext is outside the supported bounds" });
  }
});
const privateMessageEnvelopeSchema = z.object({
  sequence: z.number().int().positive(),
  messageId: privateMessageId,
  senderDeviceId: deviceId,
  recipientDeviceId: deviceId,
  ciphertext: privateCiphertext,
  clientCreatedAt: z.iso.datetime(),
  acceptedAt: z.iso.datetime(),
}).strict();
const privateReceiptType = z.enum(["delivered", "read"]);
const privateReceiptEnvelopeSchema = z.object({
  sequence: z.number().int().positive(),
  messageId: privateMessageId,
  senderDeviceId: deviceId,
  recipientDeviceId: deviceId,
  receipt: privateReceiptType,
  acceptedAt: z.iso.datetime(),
}).strict();
export const PROJECT_CONTEXT_MAX_BYTES = 48 * 1024;
const projectContext = z.record(z.string(), z.unknown()).superRefine((value, refinement) => {
  try {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > PROJECT_CONTEXT_MAX_BYTES) {
      refinement.addIssue({ code: "custom", message: "Project context is too large" });
    }
  } catch {
    refinement.addIssue({ code: "custom", message: "Project context must be JSON-serializable" });
  }
});
const cursorPosition = z.object({
  x: z.number().finite().min(0).max(1),
  y: z.number().finite().min(0).max(1),
}).strict();
const textCaret = z.object({
  anchor: z.number().int().min(0).max(32_768),
  head: z.number().int().min(0).max(32_768),
}).strict();

interface WebSocketAuthTranscriptInput {
  serverFingerprint: string;
  deviceId: string;
  requestId: string;
  challenge: string;
}

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

export function websocketAuthTranscript(input: WebSocketAuthTranscriptInput): Buffer {
  return Buffer.concat([
    Buffer.from("COCODEX-WEBSOCKET-AUTH\u0000", "utf8"),
    lengthPrefix("1"),
    lengthPrefix(input.serverFingerprint),
    lengthPrefix(input.deviceId),
    lengthPrefix(input.requestId),
    lengthPrefix(input.challenge),
  ]);
}

export const clientFrameSchema = z.discriminatedUnion("type", [
  z.object({
    version: z.literal(1),
    type: z.literal("auth.response"),
    requestId,
    deviceId: z.uuid(),
    signature: z.string().min(64).max(256),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.list"),
    requestId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("device.key-certificate.publish"),
    requestId,
    certificate: z.string().min(256).max(8_192),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.member.list"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.list"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.create"),
    requestId,
    projectId,
    agentId: z.uuid(),
    name: z.string().trim().min(1).max(120),
    ...agentRuntimeDefinitionFields,
    signature: z.string().min(64).max(256),
  }).strict().superRefine(validateAgentRuntimeDefinition),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.task.list"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.execution.report"),
    requestId,
    taskId: z.uuid(),
    projectId,
    agentId: z.string().trim().min(1).max(120),
    workspaceMode: z.enum(["shared", "git-worktree"]),
    workspaceRef: z.string().trim().min(1).max(500),
    branch: z.string().trim().min(1).max(500).nullable(),
    baseCommit: z.string().regex(/^[0-9a-f]{40,64}$/).nullable(),
    mergeTarget: z.string().trim().min(1).max(500).nullable(),
    startedAt: z.iso.datetime(),
    signature: z.string().min(64).max(256),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("chat.subscribe"),
    requestId,
    projectId,
    afterSequence: z.number().int().nonnegative(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("chat.send"),
    requestId,
    projectId,
    eventId: z.uuid(),
    content: z.string().min(1).max(32_768),
    clientCreatedAt: z.iso.datetime(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.request"),
    requestId,
    taskId: z.uuid(),
    projectId,
    agentId: z.string().trim().min(1).max(120),
    prompt: z.string().min(1).max(32_768),
    nonce: z.string().min(32).max(128),
    issuedAt: z.iso.datetime(),
    expiresAt: z.iso.datetime(),
    dependencies: z.array(z.uuid()).max(16).default([]),
    inputArtifactIds: z.array(z.uuid()).max(16).default([]),
    privateShareMessageId: z.uuid().optional(),
    signature: z.string().min(64).max(256),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.ready"),
    requestId,
    agentId: z.string().trim().min(1).max(120).optional(),
    primaryModel: agentModelId.optional(),
    primaryEffort: agentReasoningEffort.optional(),
    coAgentModel: agentModelId.nullable().optional(),
    coAgentEffort: agentReasoningEffort.nullable().optional(),
    maxConcurrentCoAgents: z.number().int().min(0).max(8).optional(),
  }).strict().superRefine((value, context) => {
    const runtime = [
      value.primaryModel,
      value.primaryEffort,
      value.coAgentModel,
      value.coAgentEffort,
      value.maxConcurrentCoAgents,
    ];
    const supplied = runtime.filter(item => item !== undefined).length;
    if (supplied !== 0 && supplied !== runtime.length) {
      context.addIssue({ code: "custom", message: "Agent ready runtime definition must be complete" });
      return;
    }
    if (supplied === runtime.length) validateAgentRuntimeDefinition(value as Required<typeof value>, context);
  }),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.cancel"),
    requestId,
    taskId: z.uuid(),
    reason: z.string().trim().min(1).max(512),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("agent.result"),
    requestId,
    taskId: z.uuid(),
    eventId: z.uuid(),
    content: z.string().min(1).max(32_768),
    final: z.boolean(),
    status: z.enum(["running", "completed", "failed"]),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("prompt.subscribe"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("presence.update"),
    requestId,
    projectId,
    cursor: cursorPosition.nullable(),
    caret: textCaret.nullable(),
    typing: z.boolean().default(false),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("prompt.update"),
    requestId,
    projectId,
    updateId: z.uuid(),
    update: z.string().min(4).max(256_000),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("private.subscribe"),
    requestId,
    afterSequence: z.number().int().nonnegative(),
    afterReceiptSequence: z.number().int().nonnegative().default(0),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("private.send"),
    requestId,
    messageId: privateMessageId,
    recipientDeviceId: deviceId,
    ciphertext: privateCiphertext,
    clientCreatedAt: z.iso.datetime(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("private.receipt.send"),
    requestId,
    messageId: privateMessageId,
    receipt: privateReceiptType,
  }).strict(),
  encryptedChatSubscribeFrameSchema,
  encryptedChatSendFrameSchema,
  encryptedPromptSubscribeFrameSchema,
  encryptedPromptUpdateFrameSchema,
  encryptedArtifactPublishFrameSchema,
  encryptedArtifactListFrameSchema,
  encryptedFileReferencePublishFrameSchema,
  encryptedFileReferenceListFrameSchema,
  encryptedAgentRequestFrameSchema,
  encryptedAgentResultSendFrameSchema,
  z.object({
    version: z.literal(1),
    type: z.literal("artifact.publish"),
    requestId,
    artifactId: z.uuid(),
    projectId,
    taskId: z.uuid().nullable(),
    artifactType: z.enum(["finding", "plan", "decision", "api-contract", "schema", "code-change", "commit", "diff", "test-result", "review", "handoff", "documentation", "failure-report", "browser-result", "final-result"]),
    title: z.string().trim().min(1).max(200),
    summary: z.string().trim().min(1).max(4_000),
    content: z.string().min(1).max(256_000),
    status: z.enum(["draft", "ready", "accepted", "rejected", "superseded", "integrated"]),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("context.get"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.key.get"),
    requestId,
    projectId,
    keyEpoch: z.number().int().min(1).max(PROJECT_KEY_EPOCH_MAX).optional(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.key.share"),
    requestId,
    projectId,
    envelope: projectKeyEnvelopeSchema,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.key.initialize"),
    requestId,
    projectId,
    keyEpoch: z.literal(1),
    envelopes: z.array(projectKeyEnvelopeSchema).min(1).max(128),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.key.rotate"),
    requestId,
    projectId,
    expectedEpoch: z.number().int().nonnegative().max(PROJECT_KEY_EPOCH_MAX - 1),
    envelopes: z.array(projectKeyEnvelopeSchema).min(1).max(128),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.member.remove"),
    requestId,
    projectId,
    deviceId: z.uuid(),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.member.remove-and-rotate"),
    requestId,
    projectId,
    deviceId: z.uuid(),
    expectedEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX - 1),
    envelopes: z.array(projectKeyEnvelopeSchema).min(1).max(127),
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.context.get"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("project.context.update"),
    requestId,
    projectId,
    expectedRevision: z.number().int().nonnegative(),
    envelope: projectContentEnvelopeSchema,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("context.update"),
    requestId,
    projectId,
    expectedRevision: z.number().int().nonnegative(),
    finalGoal: z.string().max(32_768),
    context: projectContext,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("artifact.list"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("usage.get"),
    requestId,
    projectId,
  }).strict(),
  z.object({
    version: z.literal(1),
    type: z.literal("usage.report"),
    requestId,
    report: usageReportSchema,
    signature: z.string().min(64).max(256),
  }).strict(),
]);

export const projectKeyResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.key.result"),
  requestId,
  projectId,
  envelopes: z.array(projectKeyEnvelopeSchema).max(128),
  currentEpoch: z.number().int().nonnegative().max(PROJECT_KEY_EPOCH_MAX).optional(),
  rotationRequired: z.boolean().optional(),
}).strict();

export const projectKeyAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.key.accepted"),
  requestId,
  projectId,
  envelope: projectKeyEnvelopeSchema,
  created: z.boolean(),
}).strict();

export const projectKeyInitializedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.key.initialized"),
  requestId,
  projectId,
  keyEpoch: z.literal(1),
  envelopes: z.array(projectKeyEnvelopeSchema).min(1).max(128),
  created: z.boolean(),
}).strict();

export const projectKeyChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.key.changed"),
  projectId,
  envelope: projectKeyEnvelopeSchema,
}).strict();

export const projectKeyRotatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.key.rotated"),
  requestId,
  projectId,
  keyEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX),
  envelopes: z.array(projectKeyEnvelopeSchema).max(128),
  created: z.boolean(),
}).strict();

export const projectKeyRotationRequiredFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.key.rotation-required"),
  projectId,
  removedDeviceId: z.uuid(),
  currentEpoch: z.number().int().positive().max(PROJECT_KEY_EPOCH_MAX),
}).strict();

export const projectMemberRemovedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.member.removed"),
  requestId: requestId.optional(),
  projectId,
  deviceId,
}).strict();

export const projectListResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.list.result"),
  requestId,
  projects: z.array(z.object({
    id: projectId,
    name: z.string().trim().min(1).max(120),
    role: z.enum(["owner", "member"]),
  }).strict()).max(10_000),
}).strict();

export const projectMemberViewSchema = z.object({
  deviceId,
  displayName: z.string().trim().min(1).max(80),
  fingerprint: z.string().trim().min(16).max(256),
  role: z.enum(["owner", "member"]),
  deviceKeyCertificate: z.string().min(256).max(8_192).nullable(),
}).strict();

export const projectMemberListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.member.list.result"),
  requestId,
  projectId,
  members: z.array(projectMemberViewSchema).min(1).max(128),
}).strict();

export const agentStatusSchema = z.enum(["offline", "available", "queued", "working", "completed", "failed"]);
export const agentTaskStatusSchema = z.enum(["queued", "running", "completed", "failed"]);
export const agentReasoningEffortSchema = agentReasoningEffort;

export const agentViewSchema = z.object({
  id: z.string().trim().min(1).max(120),
  projectId,
  name: z.string().trim().min(1).max(120),
  ...agentRuntimeDefinitionFields,
  hostDeviceId: z.uuid(),
  hostDisplayName: z.string().trim().min(1).max(80),
  enabled: z.boolean(),
  status: agentStatusSchema,
  activeTasks: z.number().int().nonnegative().max(64),
  queuedTasks: z.number().int().nonnegative().max(64),
  lastTaskAt: z.iso.datetime().nullable(),
}).strict().superRefine(validateAgentRuntimeDefinition);

export const agentListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.list.result"),
  requestId,
  projectId,
  agents: z.array(agentViewSchema).max(128),
}).strict();

export const agentCreatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.created"),
  requestId,
  projectId,
  agent: z.object({
    id: z.uuid(),
    projectId,
    name: z.string().trim().min(1).max(120),
    ...agentRuntimeDefinitionFields,
    hostDeviceId: z.uuid(),
    enabled: z.boolean(),
  }).strict().superRefine(validateAgentRuntimeDefinition),
  created: z.boolean(),
}).strict();

export const agentReadyAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.ready.accepted"),
  requestId,
  agentId: z.string().trim().min(1).max(120),
}).strict();

export const agentTaskViewSchema = z.object({
  id: z.uuid(),
  projectId,
  agentId: z.string().trim().min(1).max(120),
  agentName: z.string().trim().min(1).max(120),
  requesterDeviceId: z.uuid(),
  targetDeviceId: z.uuid(),
  status: agentTaskStatusSchema,
  dependencies: z.array(z.uuid()).max(16),
  inputArtifactIds: z.array(z.uuid()).max(16),
  workspaceMode: z.enum(["shared", "git-worktree"]).nullable(),
  workspaceRef: z.string().min(1).max(500).nullable(),
  branch: z.string().min(1).max(500).nullable(),
  baseCommit: z.string().regex(/^[0-9a-f]{40,64}$/).nullable(),
  mergeTarget: z.string().min(1).max(500).nullable(),
  acceptedAt: z.iso.datetime(),
  startedAt: z.iso.datetime().nullable(),
  completedAt: z.iso.datetime().nullable(),
  lastActivityAt: z.iso.datetime(),
  eventCount: z.number().int().nonnegative().max(256),
  encrypted: z.boolean(),
}).strict();

export const agentExecutionAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.execution.accepted"),
  requestId,
  taskId: z.uuid(),
  startedAt: z.iso.datetime(),
}).strict();

export const agentTaskListFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.task.list.result"),
  requestId,
  projectId,
  tasks: z.array(agentTaskViewSchema).max(256),
}).strict();

export const projectContextResultFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.context.result"),
  requestId,
  projectId,
  envelope: projectContentEnvelopeSchema.nullable(),
  revision: z.number().int().nonnegative(),
  updatedAt: z.iso.datetime().nullable(),
}).strict();

export const projectContextUpdatedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.context.updated"),
  requestId,
  projectId,
  envelope: projectContentEnvelopeSchema,
  revision: z.number().int().positive(),
  created: z.boolean(),
  updatedAt: z.iso.datetime(),
}).strict();

export const projectContextChangedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("project.context.changed"),
  projectId,
  envelope: projectContentEnvelopeSchema,
  revision: z.number().int().positive(),
  updatedAt: z.iso.datetime(),
}).strict();

const presenceMemberSchema = z.object({
  deviceId: z.uuid(),
  displayName: z.string().trim().min(1).max(80),
  cursor: cursorPosition.nullable(),
  caret: textCaret.nullable(),
  typing: z.boolean().default(false),
  updatedAt: z.iso.datetime(),
}).strict();

export const presenceSnapshotFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("presence.snapshot"),
  requestId: requestId.optional(),
  projectId,
  members: z.array(presenceMemberSchema).max(128),
}).strict();

export const presenceUpdateFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("presence.update"),
  requestId: requestId.optional(),
  projectId,
  deviceId: z.uuid(),
  displayName: z.string().trim().min(1).max(80),
  cursor: cursorPosition.nullable(),
  caret: textCaret.nullable(),
  typing: z.boolean().default(false),
  updatedAt: z.iso.datetime(),
}).strict();

export const presenceLeaveFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("presence.leave"),
  requestId: requestId.optional(),
  projectId,
  deviceId: z.uuid(),
}).strict();

export const presenceAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("presence.accepted"),
  requestId,
  projectId,
}).strict();

export const projectServerFrameSchema = z.discriminatedUnion("type", [
  projectListResultFrameSchema,
  encryptedChatSnapshotFrameSchema,
  encryptedChatAcceptedFrameSchema,
  encryptedChatEventFrameSchema,
  encryptedPromptSnapshotFrameSchema,
  encryptedPromptAcceptedFrameSchema,
  encryptedPromptChangedFrameSchema,
  encryptedArtifactAcceptedFrameSchema,
  encryptedArtifactPublishedFrameSchema,
  encryptedArtifactListResultFrameSchema,
  encryptedFileReferenceAcceptedFrameSchema,
  encryptedFileReferencePublishedFrameSchema,
  encryptedFileReferenceListResultFrameSchema,
  encryptedAgentTaskFrameSchema,
  encryptedAgentResultChangedFrameSchema,
  projectKeyResultFrameSchema,
  projectKeyAcceptedFrameSchema,
  projectKeyInitializedFrameSchema,
  projectKeyChangedFrameSchema,
  projectKeyRotatedFrameSchema,
  projectKeyRotationRequiredFrameSchema,
  projectMemberRemovedFrameSchema,
  projectMemberListFrameSchema,
  agentListFrameSchema,
  agentCreatedFrameSchema,
  agentReadyAcceptedFrameSchema,
  agentTaskListFrameSchema,
  agentExecutionAcceptedFrameSchema,
  projectContextResultFrameSchema,
  projectContextUpdatedFrameSchema,
  projectContextChangedFrameSchema,
  presenceSnapshotFrameSchema,
  presenceUpdateFrameSchema,
  presenceLeaveFrameSchema,
  presenceAcceptedFrameSchema,
]);

export const privateSnapshotFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("private.snapshot"),
  requestId,
  messages: z.array(privateMessageEnvelopeSchema).max(500),
  receipts: z.array(privateReceiptEnvelopeSchema).max(500).default([]),
}).strict();

export const privateAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("private.accepted"),
  requestId,
  message: privateMessageEnvelopeSchema,
}).strict();

export const privateMessageFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("private.message"),
  message: privateMessageEnvelopeSchema,
}).strict();

export const privateReceiptAcceptedFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("private.receipt.accepted"),
  requestId,
  receipt: privateReceiptEnvelopeSchema,
}).strict();

export const privateReceiptFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("private.receipt"),
  receipt: privateReceiptEnvelopeSchema,
}).strict();

export const privateServerFrameSchema = z.discriminatedUnion("type", [
  privateSnapshotFrameSchema,
  privateAcceptedFrameSchema,
  privateMessageFrameSchema,
  privateReceiptAcceptedFrameSchema,
  privateReceiptFrameSchema,
]);

export type ProjectServerFrame = z.infer<typeof projectServerFrameSchema>;
export type PrivateMessageEnvelope = z.infer<typeof privateMessageEnvelopeSchema>;
export type PrivateSnapshotFrame = z.infer<typeof privateSnapshotFrameSchema>;
export type PrivateAcceptedFrame = z.infer<typeof privateAcceptedFrameSchema>;
export type PrivateMessageFrame = z.infer<typeof privateMessageFrameSchema>;
export type PrivateReceiptEnvelope = z.infer<typeof privateReceiptEnvelopeSchema>;
export type PrivateReceiptAcceptedFrame = z.infer<typeof privateReceiptAcceptedFrameSchema>;
export type PrivateReceiptFrame = z.infer<typeof privateReceiptFrameSchema>;
export type ProjectKeyResultFrame = z.infer<typeof projectKeyResultFrameSchema>;
export type ProjectKeyAcceptedFrame = z.infer<typeof projectKeyAcceptedFrameSchema>;
export type ProjectKeyInitializedFrame = z.infer<typeof projectKeyInitializedFrameSchema>;
export type ProjectKeyChangedFrame = z.infer<typeof projectKeyChangedFrameSchema>;
export type ProjectKeyRotatedFrame = z.infer<typeof projectKeyRotatedFrameSchema>;
export type ProjectKeyRotationRequiredFrame = z.infer<typeof projectKeyRotationRequiredFrameSchema>;
export type ProjectMemberRemovedFrame = z.infer<typeof projectMemberRemovedFrameSchema>;
export type ProjectMemberView = z.infer<typeof projectMemberViewSchema>;
export type ProjectMemberListFrame = z.infer<typeof projectMemberListFrameSchema>;
export type AgentStatus = z.infer<typeof agentStatusSchema>;
export type AgentView = z.infer<typeof agentViewSchema>;
export type AgentListFrame = z.infer<typeof agentListFrameSchema>;
export type AgentCreatedFrame = z.infer<typeof agentCreatedFrameSchema>;
export type AgentReadyAcceptedFrame = z.infer<typeof agentReadyAcceptedFrameSchema>;
export type AgentTaskStatus = z.infer<typeof agentTaskStatusSchema>;
export type AgentTaskView = z.infer<typeof agentTaskViewSchema>;
export type AgentTaskListFrame = z.infer<typeof agentTaskListFrameSchema>;
export type AgentExecutionAcceptedFrame = z.infer<typeof agentExecutionAcceptedFrameSchema>;
export type ProjectContextResultFrame = z.infer<typeof projectContextResultFrameSchema>;
export type ProjectContextUpdatedFrame = z.infer<typeof projectContextUpdatedFrameSchema>;
export type ProjectContextChangedFrame = z.infer<typeof projectContextChangedFrameSchema>;

export const agentTaskSchema = z.object({
  id: z.uuid(),
  projectId,
  requesterDeviceId: z.uuid(),
  targetDeviceId: z.uuid(),
  agentId: z.string().trim().min(1).max(120),
  prompt: z.string().min(1).max(32_768),
  nonce: z.string().min(32).max(128),
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  dependencies: z.array(z.uuid()).max(16).default([]),
  inputArtifactIds: z.array(z.uuid()).max(16).default([]),
  privateShareMessageId: z.uuid().optional(),
  requesterSignature: z.string().min(64).max(256),
  requesterPublicKeyPem: z.string().min(64).max(2048),
  serverSignature: z.string().min(64).max(256),
  status: agentTaskStatusSchema,
  acceptedAt: z.iso.datetime(),
}).strict();

export const agentTaskFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.task"),
  task: agentTaskSchema,
}).strict();
export const agentCancelFrameSchema = z.object({
  version: z.literal(1),
  type: z.literal("agent.cancel"),
  taskId: z.uuid(),
  reason: z.string().trim().min(1).max(512),
}).strict();
export type ClientFrame = z.infer<typeof clientFrameSchema>;

export interface SharedProject {
  id: string;
  name: string;
  role: "owner" | "member";
}

export interface ChatEvent {
  sequence: number;
  projectId: string;
  eventId: string;
  senderDeviceId: string;
  content: string;
  clientCreatedAt: string;
  acceptedAt: string;
}

export interface AgentTask {
  id: string;
  projectId: string;
  requesterDeviceId: string;
  targetDeviceId: string;
  agentId: string;
  prompt: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  dependencies: string[];
  inputArtifactIds: string[];
  privateShareMessageId?: string;
  requesterSignature: string;
  requesterPublicKeyPem: string;
  serverSignature: string;
  status: "queued" | "running" | "completed" | "failed";
  acceptedAt: string;
}

export type ArtifactType = "finding" | "plan" | "decision" | "api-contract" | "schema" | "code-change" | "commit" | "diff" | "test-result" | "review" | "handoff" | "documentation" | "failure-report" | "browser-result" | "final-result";
export type ArtifactStatus = "draft" | "ready" | "accepted" | "rejected" | "superseded" | "integrated";
export interface Artifact {
  id: string;
  projectId: string;
  taskId: string | null;
  authorDeviceId: string;
  type: ArtifactType;
  title: string;
  summary: string;
  content: string;
  status: ArtifactStatus;
  createdAt: string;
  updatedAt: string;
}

export interface AgentDefinition {
  id: string;
  projectId: string;
  name: string;
  primaryModel: string;
  primaryEffort: z.infer<typeof agentReasoningEffortSchema>;
  coAgentModel: string | null;
  coAgentEffort: z.infer<typeof agentReasoningEffortSchema> | null;
  maxConcurrentCoAgents: number;
  hostDeviceId: string;
  enabled: boolean;
}

export type { UsageReport, UsageReportView } from "./usage";

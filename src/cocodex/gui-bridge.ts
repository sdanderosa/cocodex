import { existsSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { PassThrough } from "node:stream";
import { enrollClient, loadClientConnection } from "./client";
import { clientPaths, type ClientPaths } from "./paths";
import { runJsonLineSession, type JsonLineSessionOptions } from "./session";
import { loadLocalAgentPolicyStore } from "./agent-policy";
import { agentRuntimePaths } from "./agent-runtime-paths";
import { loadAgentSafety } from "./agent-safety";

const MAX_EVENTS = 500;
const RENDERER_SERVER_FRAME_TYPES = new Set([
  "project.list.result",
  "project.created",
  "project.changed",
  "project.member.list.result",
  "project.member.removed",
  "prompt.snapshot",
  "prompt.update",
  "context.result",
  "context.updated",
  "context.changed",
  "usage.result",
  "usage.changed",
  "usage.accepted",
  "agent.list.result",
  "agent.task.list.result",
  "artifact.list.result",
  "artifact.accepted",
  "artifact.published",
  "file-reference.list.result",
  "file-reference.accepted",
  "file-reference.published",
  "presence.snapshot",
  "presence.update",
  "presence.leave",
  "chat.snapshot",
  "chat.event",
  "agent.result",
  "private.receipt",
  "private.receipt.accepted",
]);
const SENSITIVE_RENDERER_KEYS = new Set([
  "ciphertext",
  "localCiphertext",
  "sealedProjectKey",
  "projectWrapPublicKeyPem",
  "deviceKeyCertificate",
  "privateKey",
  "privateKeyPem",
  "envelope",
  "envelopes",
]);
const RENDERER_FRAME_FIELDS = new Set([
  "version", "type", "requestId", "projectId",
  "projects", "project", "members", "events", "event", "updates", "update",
  "context", "reports", "report", "agents", "tasks", "artifacts", "artifact",
  "references", "reference",
  "id", "name", "role", "deviceId", "displayName", "fingerprint", "trusted",
  "sequence", "eventId", "messageId", "senderDeviceId", "recipientDeviceId", "receipt", "content", "acceptedAt",
  "updateId", "finalGoal", "revision", "updatedByDeviceId", "updatedAt",
  "requests", "inputTokens", "cachedInputTokens", "outputTokens",
  "reasoningOutputTokens", "activeAgents", "accountLabel",
  "fiveHourPercent", "fiveHourResetAt", "weeklyPercent", "weeklyResetAt",
  "monthlyPercent", "monthlyResetAt", "customWindows", "label", "percent", "resetAt",
  "agentId", "agentName", "primaryModel", "primaryEffort", "coAgentModel",
  "coAgentEffort", "maxConcurrentCoAgents", "hostDeviceId", "hostDisplayName",
  "enabled", "status", "activeTasks", "queuedTasks", "lastTaskAt",
  "requesterDeviceId", "targetDeviceId", "dependencies", "inputArtifactIds",
  "workspaceMode", "workspaceRef", "branch", "baseCommit", "mergeTarget",
  "startedAt", "completedAt", "lastActivityAt", "eventCount", "encrypted",
  "taskId", "authorDeviceId", "title", "summary", "createdAt",
  "referenceId", "artifactId", "relativePath", "commitSha", "sha256",
  "sizeBytes", "mediaType", "hostDeviceId",
  "cursor", "caret", "typing", "x", "y", "anchor", "head",
  "final", "created", "keyEpoch",
]);
const ALLOWED_COMMANDS = new Set([
  "project.list",
  "project.create",
  "project.invite.list",
  "project.invite.create",
  "project.invite.respond",
  "project.invite.cancel",
  "project.key.get",
  "project.key.share",
  "project.key.initialize",
  "project.key.rotate",
  "project.member.list",
  "project.member.remove-and-rotate",
  "project.member.remove",
  "device.trust",
  "chat.subscribe",
  "chat.send",
  "project.chat.subscribe",
  "project.chat.send",
  "prompt.subscribe",
  "prompt.update",
  "project.prompt.subscribe",
  "project.prompt.update",
  "context.get",
  "context.update",
  "project.context.get",
  "project.context.update",
  "usage.get",
  "presence.update",
  "agent.request",
  "agent.configure",
  "private.share",
  "agent.list",
  "agent.task.list",
  "agent.cancel",
  "agent.approval",
  "agent.safety.status",
  "agent.emergency.stop",
  "agent.emergency.resume",
  "agent.full-computer.enable",
  "agent.full-computer.disable",
  "private.send",
  "private.read",
  "artifact.publish",
  "artifact.list",
  "project.artifact.publish",
  "project.artifact.list",
  "project.file-reference.publish",
  "project.file-reference.list",
]);

type SessionRunner = (paths: ClientPaths, options: JsonLineSessionOptions) => Promise<void>;

export interface CoCodexGuiEvent {
  sequence: number;
  channel: "output" | "error";
  value: unknown;
}

export interface CoCodexGuiStatus {
  configured: boolean;
  running: boolean;
  state: "not-configured" | "stopped" | "connecting" | "connected" | "retrying";
  deviceId?: string;
  displayName?: string;
  server?: { host: string; port: number };
  agentConfigured: boolean;
  agentAccessProfile?: "project-only" | "full-computer";
  agentWorkspaceMode?: "shared" | "git-worktree";
  agentExecutionEnabled?: boolean;
  agentFullComputerEnabled?: boolean;
  localAgents: Array<{
    agentId: string;
    projectId: string;
    primaryModel: string;
    primaryEffort: string;
    coAgentModel: string | null;
    coAgentEffort: string | null;
    maxConcurrentCoAgents: number;
    accessProfile: "project-only" | "full-computer";
    workspaceMode: "shared" | "git-worktree";
    executionEnabled: boolean;
    fullComputerEnabled: boolean;
  }>;
  latestEventSequence: number;
}

function withoutSensitiveServerPayloads(value: unknown): unknown {
  if (!value || typeof value !== "object") return value;
  const record = value as Record<string, any>;
  if (record.source === "private-contacts" && Array.isArray(record.contacts)) {
    return {
      source: "private-contacts",
      contacts: record.contacts.map((candidate: unknown) => {
        const contact = candidate && typeof candidate === "object"
          ? candidate as Record<string, unknown>
          : {};
        return {
          deviceId: contact.deviceId,
          displayName: contact.displayName,
          fingerprint: contact.fingerprint,
          trusted: contact.trusted === true,
          projectCapable: contact.projectCapable === true,
        };
      }),
    };
  }
  if (record.source === "project-invitations" && Array.isArray(record.invitations)) {
    return {
      source: "project-invitations",
      invitations: record.invitations.map((candidate: unknown) => {
        const invitation = candidate && typeof candidate === "object"
          ? candidate as Record<string, unknown>
          : {};
        return {
          invitationId: invitation.invitationId,
          projectId: invitation.projectId,
          projectName: invitation.projectName,
          ownerDeviceId: invitation.ownerDeviceId,
          ownerDisplayName: invitation.ownerDisplayName,
          ownerFingerprint: invitation.ownerFingerprint,
          recipientDeviceId: invitation.recipientDeviceId,
          recipientDisplayName: invitation.recipientDisplayName,
          recipientFingerprint: invitation.recipientFingerprint,
          keyEpoch: invitation.keyEpoch,
          issuedAt: invitation.issuedAt,
          expiresAt: invitation.expiresAt,
          status: invitation.status,
          direction: invitation.direction,
          trusted: invitation.trusted === true,
          actionable: invitation.actionable === true,
        };
      }),
    };
  }
  if (record.source === "private" && record.message && typeof record.message === "object") {
    const message = record.message as Record<string, unknown>;
    return {
      source: "private",
      message: {
        messageId: message.messageId,
        senderDeviceId: message.senderDeviceId,
        recipientDeviceId: message.recipientDeviceId,
        text: message.text,
        ...(typeof message.clientCreatedAt === "string" ? { clientCreatedAt: message.clientCreatedAt } : {}),
        ...(typeof message.acceptedAt === "string" ? { acceptedAt: message.acceptedAt } : {}),
        ...(typeof message.serverSequence === "number" ? { serverSequence: message.serverSequence } : {}),
        ...(message.direction === "sent" || message.direction === "received"
          ? { direction: message.direction }
          : {}),
        ...(typeof message.restored === "boolean" ? { restored: message.restored } : {}),
        ...(message.deliveryState === "staged" || message.deliveryState === "queued"
          || message.deliveryState === "accepted" || message.deliveryState === "rejected"
          ? { deliveryState: message.deliveryState }
          : {}),
        ...(typeof message.rejectionReason === "string"
          ? { rejectionReason: message.rejectionReason }
          : {}),
      },
    };
  }
  const frame = record.frame;
  if (!frame || typeof frame !== "object") return value;
  if (frame.type === "project.key.result"
    || frame.type === "project.key.changed"
    || frame.type === "project.key.accepted"
    || frame.type === "project.key.initialized"
    || frame.type === "project.key.rotated") {
    return {
      source: "server",
      frame: {
        type: frame.type,
        ...(typeof frame.requestId === "string" ? { requestId: frame.requestId } : {}),
        ...(typeof frame.projectId === "string" ? { projectId: frame.projectId } : {}),
        ...(typeof frame.keyEpoch === "number" ? { keyEpoch: frame.keyEpoch } : {}),
        ...(typeof frame.currentEpoch === "number" ? { currentEpoch: frame.currentEpoch } : {}),
        ...(typeof frame.rotationRequired === "boolean" ? { rotationRequired: frame.rotationRequired } : {}),
        ...(typeof frame.created === "boolean" ? { created: frame.created } : {}),
      },
    };
  }
  if (frame.type === "private.message" && frame.message) {
    return { source: "server", frame: { ...frame, message: { ...frame.message, ciphertext: undefined } } };
  }
  if (frame.type === "private.accepted" && frame.message) {
    return { source: "server", frame: { ...frame, message: { ...frame.message, ciphertext: undefined } } };
  }
  if (frame.type === "private.snapshot" && Array.isArray(frame.messages)) {
    return {
      source: "server",
      frame: {
        ...frame,
        messages: frame.messages.map((message: Record<string, unknown>) => ({
          ...message,
          ciphertext: undefined,
        })),
      },
    };
  }
  if ((frame.type === "private.receipt" || frame.type === "private.receipt.accepted") && frame.receipt) {
    const receipt = frame.receipt as Record<string, unknown>;
    return {
      source: "server",
      frame: {
        type: frame.type,
        ...(typeof frame.requestId === "string" ? { requestId: frame.requestId } : {}),
        receipt: {
          sequence: receipt.sequence,
          messageId: receipt.messageId,
          senderDeviceId: receipt.senderDeviceId,
          recipientDeviceId: receipt.recipientDeviceId,
          receipt: receipt.receipt,
          acceptedAt: receipt.acceptedAt,
        },
      },
    };
  }
  if (record.source === "server" && !RENDERER_SERVER_FRAME_TYPES.has(String(frame.type))) {
    return { source: "protocol", error: "Unsupported server frame withheld from the renderer" };
  }
  const projectRendererFields = (candidate: unknown): unknown => {
    if (Array.isArray(candidate)) return candidate.map(projectRendererFields);
    if (!candidate || typeof candidate !== "object") return candidate;
    const projected: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(candidate as Record<string, unknown>)) {
      if (!RENDERER_FRAME_FIELDS.has(key) || SENSITIVE_RENDERER_KEYS.has(key)) continue;
      projected[key] = projectRendererFields(child);
    }
    return projected;
  };
  return { source: "server", frame: projectRendererFields(frame) };
}

export class CoCodexGuiBridge {
  private input?: PassThrough;
  private readonly capability = randomBytes(32).toString("base64url");
  private running = false;
  private state: CoCodexGuiStatus["state"] = "stopped";
  private sequence = 0;
  private readonly events: CoCodexGuiEvent[] = [];
  constructor(
    private readonly paths: ClientPaths = clientPaths(),
    private readonly runner: SessionRunner = runJsonLineSession,
  ) {}

  issueCapability(): string { return this.capability; }

  acceptsCapability(value: string | null): boolean {
    if (!value) return false;
    const actual = Buffer.from(value);
    const expected = Buffer.from(this.capability);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }

  status(): CoCodexGuiStatus {
    const configured = existsSync(this.paths.connection);
    let connection: ReturnType<typeof loadClientConnection> | undefined;
    if (configured) {
      try {
        connection = loadClientConnection(this.paths);
      } catch {
        // The resident session reports a precise local error when started.
      }
    }
    let agentAccessProfile: CoCodexGuiStatus["agentAccessProfile"];
    let agentWorkspaceMode: CoCodexGuiStatus["agentWorkspaceMode"];
    let agentExecutionEnabled: boolean | undefined;
    let agentFullComputerEnabled: boolean | undefined;
    const localAgents: CoCodexGuiStatus["localAgents"] = [];
    if (existsSync(this.paths.agentPolicy)) {
      try {
        const store = loadLocalAgentPolicyStore(this.paths.agentPolicy);
        for (const policy of store.agents) {
          const runtime = agentRuntimePaths(this.paths, policy.agentId, store.version === 1);
          const safety = loadAgentSafety(runtime.safety, policy);
          localAgents.push({
            agentId: policy.agentId,
            projectId: policy.projectId,
            primaryModel: policy.primaryModel,
            primaryEffort: policy.primaryEffort,
            coAgentModel: policy.coAgentModel,
            coAgentEffort: policy.coAgentEffort,
            maxConcurrentCoAgents: policy.maxConcurrentCoAgents,
            accessProfile: policy.accessProfile,
            workspaceMode: policy.workspaceMode,
            executionEnabled: safety.executionEnabled,
            fullComputerEnabled: safety.fullComputerEnabled,
          });
        }
        if (localAgents.length === 1) {
          agentAccessProfile = localAgents[0].accessProfile;
          agentWorkspaceMode = localAgents[0].workspaceMode;
          agentExecutionEnabled = localAgents[0].executionEnabled;
          agentFullComputerEnabled = localAgents[0].fullComputerEnabled;
        }
      } catch {
        // The resident session reports malformed policy details as an event.
      }
    }
    return {
      configured,
      running: this.running,
      state: configured ? this.state : "not-configured",
      ...(connection ? {
        deviceId: connection.deviceId,
        displayName: connection.displayName,
        server: { host: connection.host, port: connection.port },
      } : {}),
      agentConfigured: existsSync(this.paths.agentPolicy),
      agentAccessProfile,
      agentWorkspaceMode,
      agentExecutionEnabled,
      agentFullComputerEnabled,
      localAgents,
      latestEventSequence: this.sequence,
    };
  }

  async enroll(invite: string, displayName: string): Promise<CoCodexGuiStatus> {
    if (this.running) throw new Error("Stop the local CoCodex session before enrollment");
    if (invite.trim().length < 32) throw new Error("Paste a valid CoCodex invitation");
    if (displayName.trim().length < 1 || displayName.trim().length > 80) {
      throw new Error("Display name must be 1-80 characters");
    }
    await enrollClient(invite.trim(), displayName.trim(), this.paths);
    this.state = "stopped";
    return this.status();
  }

  start(): CoCodexGuiStatus {
    if (this.running) return this.status();
    if (!existsSync(this.paths.connection)) {
      throw new Error("Enroll this device before starting the CoCodex session");
    }
    const input = new PassThrough();
    const output = new PassThrough();
    const errorOutput = new PassThrough();
    this.input = input;
    this.running = true;
    this.state = "connecting";
    this.capture(output, "output");
    this.capture(errorOutput, "error");
    void this.runner(this.paths, { input, output, errorOutput })
      .catch(error => this.append("error", {
        source: "session",
        state: "stopped",
        error: error instanceof Error ? error.message : String(error),
      }))
      .finally(() => {
        if (this.input === input) this.input = undefined;
        this.running = false;
        this.state = "stopped";
        output.destroy();
        errorOutput.destroy();
      });
    return this.status();
  }

  stop(): CoCodexGuiStatus {
    if (this.input && !this.input.destroyed) {
      this.input.write(`${JSON.stringify({ id: crypto.randomUUID(), type: "shutdown" })}\n`);
      this.input.end();
    }
    return this.status();
  }

  command(command: Record<string, unknown>): { accepted: true; id: string } {
    if (!this.running || !this.input || this.input.destroyed) {
      throw new Error("The local CoCodex session is not running");
    }
    if (typeof command.type !== "string" || !ALLOWED_COMMANDS.has(command.type)) {
      throw new Error("Unsupported CoCodex GUI command");
    }
    if (command.type === "private.send" && "recipientKeyCertificate" in command) {
      throw new Error("The GUI must resolve private contacts inside the resident Client");
    }
    const id = typeof command.id === "string" && command.id.length > 0
      ? command.id
      : crypto.randomUUID();
    this.input.write(`${JSON.stringify({ ...command, id })}\n`);
    return { accepted: true, id };
  }

  eventsAfter(afterSequence: number): { events: CoCodexGuiEvent[]; latestEventSequence: number } {
    const after = Number.isSafeInteger(afterSequence) && afterSequence >= 0 ? afterSequence : 0;
    return {
      events: this.events.filter(event => event.sequence > after),
      latestEventSequence: this.sequence,
    };
  }

  private capture(stream: PassThrough, channel: CoCodexGuiEvent["channel"]): void {
    let pending = "";
    stream.setEncoding("utf8");
    stream.on("data", chunk => {
      pending += String(chunk);
      while (true) {
        const newline = pending.indexOf("\n");
        if (newline < 0) break;
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (!line.trim()) continue;
        try {
          this.append(channel, JSON.parse(line));
        } catch {
          this.append("error", { source: "bridge", error: "Invalid local session event" });
        }
      }
    });
  }

  private append(channel: CoCodexGuiEvent["channel"], rawValue: unknown): void {
    const value = withoutSensitiveServerPayloads(rawValue);
    const record = value && typeof value === "object" ? value as Record<string, unknown> : undefined;
    if (record?.source === "session" && typeof record.state === "string") {
      if (record.state === "connected") this.state = "connected";
      else if (record.state === "retrying") this.state = "retrying";
      else if (record.state === "disconnected") this.state = "connecting";
    }
    this.events.push({ sequence: ++this.sequence, channel, value });
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
  }
}

let sharedBridge: CoCodexGuiBridge | undefined;

export function getCoCodexGuiBridge(): CoCodexGuiBridge {
  sharedBridge ??= new CoCodexGuiBridge();
  return sharedBridge;
}

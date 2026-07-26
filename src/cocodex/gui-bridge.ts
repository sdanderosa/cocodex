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
const ALLOWED_COMMANDS = new Set([
  "project.list",
  "project.key.get",
  "project.key.share",
  "project.key.initialize",
  "project.key.rotate",
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
  const frame = record.frame;
  if (!frame || typeof frame !== "object") return value;
  if (frame.type === "project.key.result"
    || frame.type === "project.key.changed"
    || frame.type === "project.key.accepted"
    || frame.type === "project.key.initialized"
    || frame.type === "project.key.rotated") {
    return {
      ...record,
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
    return { ...record, frame: { ...frame, message: { ...frame.message, ciphertext: undefined } } };
  }
  if (frame.type === "private.accepted" && frame.message) {
    return { ...record, frame: { ...frame, message: { ...frame.message, ciphertext: undefined } } };
  }
  if (frame.type === "private.snapshot" && Array.isArray(frame.messages)) {
    return {
      ...record,
      frame: {
        ...frame,
        messages: frame.messages.map((message: Record<string, unknown>) => ({
          ...message,
          ciphertext: undefined,
        })),
      },
    };
  }
  return value;
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

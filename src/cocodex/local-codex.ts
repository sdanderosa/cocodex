import { randomBytes, randomUUID } from "node:crypto";
import { realpathSync, statSync } from "node:fs";
import { parse as parsePath } from "node:path";
import type { AgentTask } from "../../packages/cocodex-protocol/src/index.ts";
import { CodexAgentAdapter, type CodexUsage } from "./codex-agent-adapter";

const LOCAL_PROMPT_MAX_BYTES = 300_000;
const LOCAL_MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/;
const LOCAL_REASONING_EFFORTS = new Set([
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
]);

export interface LocalCodexTurnOptions {
  workspaceRoot: string;
  prompt: string;
  model?: string;
  effort?: "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
  signal?: AbortSignal;
  onOutput?: (content: string) => void;
  onUsage?: (usage: CodexUsage) => void;
}

export interface LocalCodexTurnResult {
  taskId: string;
  workspaceRoot: string;
  model: string;
  effort: "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
  output: string[];
  usage?: CodexUsage;
}

function canonicalWorkspace(value: string): string {
  const requested = value.trim();
  if (!requested) throw new Error("Local Codex workspace is required");
  const workspace = realpathSync(requested);
  if (!statSync(workspace).isDirectory()) {
    throw new Error("Local Codex workspace must be a directory");
  }
  if (parsePath(workspace).root === workspace || workspace.startsWith("\\\\")) {
    throw new Error("Local Codex workspace cannot be a drive root or network path");
  }
  return workspace;
}

/**
 * Execute one host-local official Codex turn without consulting CoCodex
 * Server. This is deliberately not a collaboration event: no task, prompt,
 * workspace path, or result is sent to the Server, and Server availability is
 * irrelevant. The local user remains the authority for this invocation.
 */
export async function runLocalCodexTurn(
  options: LocalCodexTurnOptions,
): Promise<LocalCodexTurnResult> {
  const workspaceRoot = canonicalWorkspace(options.workspaceRoot);
  const prompt = options.prompt.trim();
  if (!prompt || Buffer.byteLength(prompt, "utf8") > LOCAL_PROMPT_MAX_BYTES) {
    throw new Error(`Local Codex prompt must be 1-${LOCAL_PROMPT_MAX_BYTES} bytes`);
  }
  const model = (options.model ?? "gpt-5.6-sol").trim();
  if (!LOCAL_MODEL_PATTERN.test(model)) throw new Error("Local Codex model is invalid");
  const effort = options.effort ?? "medium";
  if (!LOCAL_REASONING_EFFORTS.has(effort)) {
    throw new Error("Local Codex reasoning effort is invalid");
  }

  const projectId = randomUUID();
  const deviceId = randomUUID();
  const taskId = randomUUID();
  const issuedAt = new Date().toISOString();
  const task = {
    id: taskId,
    projectId,
    chatId: projectId,
    requesterDeviceId: deviceId,
    targetDeviceId: deviceId,
    agentId: "local-codex",
    prompt,
    nonce: randomBytes(32).toString("base64url"),
    issuedAt,
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    dependencies: [],
    inputArtifactIds: [],
    requesterSignature: Buffer.alloc(64).toString("base64url"),
    requesterPublicKeyPem: "local-only",
    serverSignature: Buffer.alloc(64).toString("base64url"),
    status: "running",
    acceptedAt: issuedAt,
  } satisfies AgentTask;

  let usage: CodexUsage | undefined;
  const adapter = new CodexAgentAdapter({
    projectId,
    agentId: task.agentId,
    workspaceRoot,
    primaryModel: model,
    primaryEffort: effort,
    coAgentModel: null,
    coAgentEffort: null,
    maxConcurrentCoAgents: 0,
    sandbox: "workspace-write",
    accessProfile: "project-only",
    fullComputerOptIn: false,
    authorizeTask: () => true,
    onUsage: value => {
      usage = value;
      options.onUsage?.(value);
    },
  });
  const output: string[] = [];
  for await (const content of adapter.execute(task, options.signal)) {
    output.push(content);
    options.onOutput?.(content);
  }
  return {
    taskId,
    workspaceRoot,
    model,
    effort,
    output,
    ...(usage ? { usage } : {}),
  };
}

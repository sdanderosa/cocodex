import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { statSync } from "node:fs";
import type { AgentTask } from "../../packages/cocodex-protocol/src/index.ts";
import { codexExecInvocation } from "../codex/exec-invocation";
import { resolveCodexRuntime } from "../codex/runtime";
import type { LocalAgentAdapter } from "./agent-bridge";
import type { TaskWorkspace } from "./task-worktree";
import { modelMultiAgentVersion } from "./model-multi-agent-version";

const MAX_JSONL_LINE_BYTES = 1024 * 1024;
const MAX_STDOUT_BYTES = 8 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
const SAFE_ENVIRONMENT_KEYS = [
  "APPDATA", "CODEX_CLI_PATH", "CODEX_HOME", "HOME", "HOMEDRIVE", "HOMEPATH",
  "LOCALAPPDATA", "PATH", "PATHEXT", "SystemDrive", "SystemRoot",
  "TEMP", "TMP", "USERPROFILE", "WINDIR",
  // Deterministic integration-runtime inputs; neither contains credentials.
  "COCODEX_ACCOUNT_FIXTURE", "CODEX_RUNTIME_MARKER",
] as const;

function codexEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  for (const key of SAFE_ENVIRONMENT_KEYS) {
    if (source[key] !== undefined) result[key] = source[key];
  }
  return result;
}

export interface CodexUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
  reasoningOutputTokens?: number;
}

export interface CodexAgentAdapterOptions {
  projectId: string;
  agentId: string;
  workspaceRoot: string;
  primaryModel?: string;
  primaryEffort?: "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
  coAgentModel?: string | null;
  coAgentEffort?: "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | null;
  maxConcurrentCoAgents?: number;
  sandbox?: "read-only" | "workspace-write" | "danger-full-access";
  accessProfile?: "project-only" | "full-computer";
  fullComputerOptIn?: boolean;
  timeoutMs?: number;
  onUsage?: (usage: CodexUsage) => void;
  prepareWorkspace?: (task: AgentTask) => TaskWorkspace | Promise<TaskWorkspace>;
  onWorkspacePrepared?: (task: AgentTask, workspace: TaskWorkspace) => void | Promise<void>;
  authorizeTask?: (task: AgentTask, signal?: AbortSignal) => boolean | Promise<boolean>;
  resolveRuntime?: typeof resolveCodexRuntime;
  spawnProcess?: (
    file: string,
    args: string[],
    options: Parameters<typeof spawn>[2],
  ) => ChildProcessWithoutNullStreams;
}

function usageFrom(value: unknown): CodexUsage {
  const raw = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const number = (key: string) => typeof raw[key] === "number" ? raw[key] as number : undefined;
  return {
    inputTokens: number("input_tokens"),
    cachedInputTokens: number("cached_input_tokens"),
    outputTokens: number("output_tokens"),
    reasoningOutputTokens: number("reasoning_output_tokens"),
  };
}

function runtimePolicyPrompt(taskPrompt: string, options: CodexAgentAdapterOptions): string {
  const max = options.maxConcurrentCoAgents ?? 0;
  const coAgentRule = max === 0
    ? "Do not spawn co-agents for this task."
    : `You may run at most ${max} co-agent${max === 1 ? "" : "s"} concurrently. `
      + `When spawning one, use model "${options.coAgentModel}" and reasoning_effort "${options.coAgentEffort}".`;
  return `<cocodex_agent_policy>\nAgent ID: ${JSON.stringify(options.agentId)}\n${coAgentRule}\n`
    + "Keep this agent's runtime context independent. Use only the task and explicitly supplied artifacts below.\n"
    + `</cocodex_agent_policy>\n\n${taskPrompt}`;
}

export class CodexAgentAdapter implements LocalAgentAdapter {
  constructor(private readonly options: CodexAgentAdapterOptions) {}

  async authorize(task: AgentTask, signal?: AbortSignal): Promise<boolean> {
    if (task.projectId !== this.options.projectId || task.agentId !== this.options.agentId) return false;
    try {
      if (!statSync(this.options.workspaceRoot).isDirectory()) return false;
    } catch {
      return false;
    }
    if (!this.options.authorizeTask) return false;
    return this.options.authorizeTask(task, signal);
  }

  async *execute(task: AgentTask, signal?: AbortSignal): AsyncIterable<string> {
    if (signal?.aborted) throw new Error("Local agent execution was cancelled");
    const sandbox = this.options.sandbox ?? "workspace-write";
    if (sandbox === "danger-full-access"
      && (this.options.accessProfile !== "full-computer" || this.options.fullComputerOptIn !== true)) {
      throw new Error("Full-computer Codex execution requires an explicit local opt-in");
    }
    const workspace = this.options.prepareWorkspace
      ? await this.options.prepareWorkspace(task)
      : {
          mode: "shared" as const,
          workingDirectory: this.options.workspaceRoot,
          workspaceRef: "configured-workspace",
          branch: null,
          baseCommit: null,
          mergeTarget: null,
        };
    if (!statSync(workspace.workingDirectory).isDirectory()) {
      throw new Error("Prepared agent workspace is not a directory");
    }
    await this.options.onWorkspacePrepared?.(task, workspace);
    if (signal?.aborted) throw new Error("Local agent execution was cancelled");
    const primaryModel = (this.options.primaryModel ?? "gpt-5.6-sol").trim();
    const primaryEffort = this.options.primaryEffort ?? "medium";
    const maxConcurrentCoAgents = this.options.maxConcurrentCoAgents ?? 0;
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(primaryModel)) {
      throw new Error("Local agent model is invalid");
    }
    if (this.options.coAgentModel
      && !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(this.options.coAgentModel)) {
      throw new Error("Local co-agent model is invalid");
    }
    if (!Number.isInteger(maxConcurrentCoAgents) || maxConcurrentCoAgents < 0 || maxConcurrentCoAgents > 8) {
      throw new Error("Local co-agent limit is invalid");
    }
    if ((maxConcurrentCoAgents > 0)
      !== (Boolean(this.options.coAgentModel) && Boolean(this.options.coAgentEffort))) {
      throw new Error("Local co-agent model, effort, and limit are inconsistent");
    }
    const runtime = (this.options.resolveRuntime ?? resolveCodexRuntime)({
      discoverAlternatives: false,
    }).runtime;
    const threadLimit = maxConcurrentCoAgents + 1;
    const multiAgentVersion = modelMultiAgentVersion(primaryModel);
    if (maxConcurrentCoAgents > 0 && multiAgentVersion === null) {
      throw new Error("Co-agent limits require a primary model with known Codex multi-agent metadata");
    }
    const concurrencyArgs = multiAgentVersion === "v2"
      ? [
          "-c", "features.multi_agent_v2.enabled=true",
          "-c", `features.multi_agent_v2.max_concurrent_threads_per_session=${threadLimit}`,
        ]
      : multiAgentVersion === "v1"
        ? [
            "-c", "features.multi_agent_v2.enabled=false",
            "-c", `agents.max_threads=${threadLimit}`,
          ]
        : [];
    const invocation = codexExecInvocation(runtime.command, [
      "-C",
      workspace.workingDirectory,
      "--model",
      primaryModel,
      "-c",
      `model_reasoning_effort="${primaryEffort}"`,
      ...concurrencyArgs,
      "exec",
      "--json",
      "--ephemeral",
      "--sandbox",
      sandbox,
      "-",
    ]);
    const child = (this.options.spawnProcess ?? spawn)(
      invocation.file,
      invocation.args,
      {
        cwd: workspace.workingDirectory,
        env: codexEnvironment(process.env),
        shell: false,
        windowsHide: true,
        windowsVerbatimArguments: invocation.options.windowsVerbatimArguments,
        stdio: ["pipe", "pipe", "pipe"],
      },
    ) as ChildProcessWithoutNullStreams;

    const abort = () => child.kill();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const exited = new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    const timeout = setTimeout(() => child.kill(), this.options.timeoutMs ?? 15 * 60_000);
    let stderrBytes = 0;
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > MAX_STDERR_BYTES) child.kill();
    });
    child.stdin.end(runtimePolicyPrompt(task.prompt, this.options), "utf8");

    let buffer = "";
    let stdoutBytes = 0;
    let sawTerminal = false;
    try {
      for await (const raw of child.stdout) {
        const chunk = Buffer.from(raw);
        stdoutBytes += chunk.byteLength;
        if (stdoutBytes > MAX_STDOUT_BYTES) throw new Error("Codex JSONL output exceeded the safety limit");
        buffer += chunk.toString("utf8");
        let newline: number;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (!line) continue;
          if (Buffer.byteLength(line, "utf8") > MAX_JSONL_LINE_BYTES) {
            throw new Error("Codex emitted an oversized JSONL event");
          }
          const event = JSON.parse(line) as Record<string, unknown>;
          if (event.type === "error" || event.type === "turn.failed") {
            throw new Error("Codex reported a failed turn");
          }
          if (event.type === "turn.completed") {
            sawTerminal = true;
            this.options.onUsage?.(usageFrom(event.usage));
          }
          if (event.type === "item.completed") {
            const item = event.item as Record<string, unknown> | undefined;
            if (item?.type === "agent_message" && typeof item.text === "string" && item.text) {
              yield item.text;
            }
          }
        }
      }
      if (buffer.trim()) throw new Error("Codex ended with a truncated JSONL event");
      const exitCode = await exited;
      if (exitCode !== 0 || !sawTerminal) throw new Error("Codex did not complete successfully");
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      if (child.exitCode === null) child.kill();
    }
  }
}

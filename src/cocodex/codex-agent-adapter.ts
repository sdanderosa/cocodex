import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { statSync } from "node:fs";
import type { AgentTask } from "@cocodex/protocol";
import { codexExecInvocation } from "../codex/exec-invocation";
import { resolveCodexRuntime } from "../codex/runtime";
import type { LocalAgentAdapter } from "./agent-bridge";

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
  sandbox?: "read-only" | "workspace-write" | "danger-full-access";
  accessProfile?: "project-only" | "full-computer";
  fullComputerOptIn?: boolean;
  timeoutMs?: number;
  onUsage?: (usage: CodexUsage) => void;
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
    const runtime = (this.options.resolveRuntime ?? resolveCodexRuntime)({
      discoverAlternatives: false,
    }).runtime;
    const invocation = codexExecInvocation(runtime.command, [
      "-C",
      this.options.workspaceRoot,
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
        cwd: this.options.workspaceRoot,
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
    child.stdin.end(task.prompt, "utf8");

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

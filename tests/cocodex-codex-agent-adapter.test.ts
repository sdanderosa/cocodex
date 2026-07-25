import { describe, expect, test } from "bun:test";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { AgentTask } from "@cocodex/protocol";
import { CodexAgentAdapter } from "../src/cocodex/codex-agent-adapter";
import { loadLocalAgentPolicy } from "../src/cocodex/agent-policy";

const task = {
  id: "e3a91e9c-090a-45a6-b919-92ac31149883",
  projectId: "bd5b929c-1024-4a0b-bbd7-fc246a84de89",
  requesterDeviceId: "51f90a90-2168-4fc6-8abf-c5cda3a0a9df",
  targetDeviceId: "7982eaa9-0d78-49fe-a095-7c57e29870ef",
  agentId: "local-codex",
  prompt: "Inspect authentication.",
  nonce: "a".repeat(43),
  issuedAt: "2027-01-01T00:00:00.000Z",
  expiresAt: "2027-01-01T00:01:00.000Z",
  requesterSignature: "a".repeat(86),
  requesterPublicKeyPem: "x".repeat(80),
  serverSignature: "b".repeat(86),
  status: "queued",
  acceptedAt: "2027-01-01T00:00:01.000Z",
} satisfies AgentTask;

function fakeProcess(
  onInput: (input: string) => void,
  output: string[],
  exitCode = 0,
): ChildProcessWithoutNullStreams {
  const child = new EventEmitter() as ChildProcessWithoutNullStreams;
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  Object.assign(child, {
    stdin,
    stdout,
    stderr,
    exitCode: null,
    kill: () => true,
  });
  let input = "";
  stdin.on("data", chunk => input += String(chunk));
  stdin.on("finish", () => {
    onInput(input);
    queueMicrotask(() => {
      for (const chunk of output) stdout.write(chunk);
      stdout.end();
      Object.defineProperty(child, "exitCode", { value: exitCode, configurable: true });
      child.emit("close", exitCode);
    });
  });
  return child;
}

describe("official Codex local agent adapter", () => {
  test("uses shell-free codex exec JSONL, local workspace, local auth, and reports usage", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "cocodex-agent-workspace-"));
    try {
      let invoked: { file: string; args: string[]; options: any } | undefined;
      let stdin = "";
      let usage: unknown;
      const adapter = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
        onUsage: value => usage = value,
        authorizeTask: () => true,
        resolveRuntime: () => ({
          runtime: { command: "codex", version: "1.2.3", source: "path" },
          failures: [],
        }),
        spawnProcess: (file, args, options) => {
          invoked = { file, args, options };
          return fakeProcess(value => stdin = value, [
            '{"type":"thread.started","thread_id":"thread-1"}\n',
            '{"type":"item.completed","item":{"type":"reasoning","text":"private"}}\n',
            '{"type":"item.completed","item":{"type":"agent_message","text":"Inspection complete."}}\n',
            '{"type":"turn.completed","usage":{"input_tokens":11,"output_tokens":7}}\n',
          ]);
        },
      });
      await expect(adapter.authorize(task)).resolves.toBeTrue();
      const output: string[] = [];
      for await (const chunk of adapter.execute(task)) output.push(chunk);
      expect(output).toEqual(["Inspection complete."]);
      expect(stdin).toBe(task.prompt);
      expect(invoked?.options).toMatchObject({
        cwd: workspace,
        shell: false,
        windowsHide: true,
      });
      expect(invoked?.options.env).not.toBe(process.env);
      expect(invoked?.options.env?.PATH).toBe(process.env.PATH);
      expect(invoked?.options.env?.OPENAI_API_KEY).toBeUndefined();
      expect(invoked?.options.env?.COCODEX_ENV_CANARY).toBeUndefined();
      expect(invoked?.args).toContain("--json");
      expect(invoked?.args).toContain("--ephemeral");
      expect(invoked?.args).toContain("workspace-write");
      expect(invoked?.args).not.toContain("danger-full-access");
      expect(invoked?.args).not.toContain("--yolo");
      expect(usage).toMatchObject({ inputTokens: 11, outputTokens: 7 });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed for an unmapped task or malformed/truncated JSONL", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "cocodex-agent-workspace-"));
    try {
      const unapproved = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
      });
      await expect(unapproved.authorize(task)).resolves.toBeFalse();
      const adapter = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
        authorizeTask: () => true,
        resolveRuntime: () => ({
          runtime: { command: "codex", version: "1.2.3", source: "path" },
          failures: [],
        }),
        spawnProcess: () => fakeProcess(() => {}, ['{"type":"turn.completed"']),
      });
      await expect(adapter.authorize({ ...task, agentId: "server-chosen-command" })).resolves.toBeFalse();
      await expect(async () => {
        for await (const _ of adapter.execute(task)) { /* consume */ }
      }).toThrow("truncated JSONL");
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("requires explicit opt-in and maps the full-computer profile to Codex danger-full-access", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "cocodex-agent-full-computer-"));
    try {
      let invoked: { args: string[] } | undefined;
      const adapter = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
        sandbox: "danger-full-access",
        accessProfile: "full-computer",
        fullComputerOptIn: true,
        authorizeTask: () => true,
        resolveRuntime: () => ({
          runtime: { command: "codex", version: "1.2.3", source: "path" },
          failures: [],
        }),
        spawnProcess: (file, args) => {
          invoked = { args };
          return fakeProcess(() => {}, [
            '{"type":"item.completed","item":{"type":"agent_message","text":"Full access is explicitly enabled."}}\n',
            '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n',
          ]);
        },
      });
      const output: string[] = [];
      for await (const chunk of adapter.execute(task)) output.push(chunk);
      expect(output).toEqual(["Full access is explicitly enabled."]);
      expect(invoked?.args).toContain("danger-full-access");
      expect(invoked?.args).not.toContain("--yolo");

      const denied = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
        sandbox: "danger-full-access",
        accessProfile: "full-computer",
        fullComputerOptIn: false,
        authorizeTask: () => true,
        spawnProcess: () => { throw new Error("spawn must not be reached"); },
      });
      await expect(async () => {
        for await (const _ of denied.execute(task)) { /* consume */ }
      }).toThrow("explicit local opt-in");
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("loads legacy trusted-device policies without adding repetitive approvals", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-policy-"));
    const policyPath = join(root, "policy.json");
    try {
      writeFileSync(policyPath, JSON.stringify({
        version: 1,
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: root,
        sandbox: "workspace-write",
        trustedRequesterFingerprints: { [task.requesterDeviceId]: "A".repeat(32) },
      }));
      expect(loadLocalAgentPolicy(policyPath).approvalMode).toBe("trusted-device");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });});

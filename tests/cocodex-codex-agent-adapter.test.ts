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
  test("acknowledges the prepared task workspace before spawning Codex inside it", async () => {
    const configured = mkdtempSync(join(tmpdir(), "cocodex-agent-configured-"));
    const prepared = mkdtempSync(join(tmpdir(), "cocodex-agent-prepared-"));
    const order: string[] = [];
    try {
      let invoked: { args: string[]; options: any } | undefined;
      const adapter = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: configured,
        authorizeTask: () => true,
        prepareWorkspace: () => {
          order.push("prepare");
          return {
            mode: "git-worktree",
            workingDirectory: prepared,
            workspaceRef: `worktrees/${task.projectId}/${task.agentId}/${task.id}`,
            branch: `cocodex/${task.projectId.slice(0, 8)}/${task.agentId}/${task.id}`,
            baseCommit: "a".repeat(40),
            mergeTarget: "main",
          };
        },
        onWorkspacePrepared: () => {
          order.push("acknowledge");
        },
        resolveRuntime: () => ({
          runtime: { command: "codex", version: "1.2.3", source: "path" },
          failures: [],
        }),
        spawnProcess: (file, args, options) => {
          order.push("spawn");
          invoked = { args, options };
          return fakeProcess(() => {}, [
            '{"type":"item.completed","item":{"type":"agent_message","text":"Isolated."}}\n',
            '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}\n',
          ]);
        },
      });
      const output: string[] = [];
      for await (const chunk of adapter.execute(task)) output.push(chunk);
      expect(order).toEqual(["prepare", "acknowledge", "spawn"]);
      expect(output).toEqual(["Isolated."]);
      expect(invoked?.options.cwd).toBe(prepared);
      const directoryIndex = invoked?.args.indexOf("-C") ?? -1;
      expect(directoryIndex).toBeGreaterThanOrEqual(0);
      expect(invoked?.args[directoryIndex + 1]).toBe(prepared);
    } finally {
      rmSync(configured, { recursive: true, force: true });
      rmSync(prepared, { recursive: true, force: true });
    }
  });

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
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: "gpt-5.6-luna",
        coAgentEffort: "medium",
        maxConcurrentCoAgents: 3,
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
      expect(stdin).toContain(task.prompt);
      expect(stdin).toContain("at most 3 co-agents concurrently");
      expect(stdin).toContain('model "gpt-5.6-luna"');
      expect(stdin).toContain('reasoning_effort "medium"');
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
      expect(invoked?.args).toEqual(expect.arrayContaining([
        "--model",
        "gpt-5.6-sol",
        "-c",
        'model_reasoning_effort="medium"',
        "-c",
        "features.multi_agent_v2.enabled=true",
        "-c",
        "features.multi_agent_v2.max_concurrent_threads_per_session=4",
      ]));
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
      expect(loadLocalAgentPolicy(policyPath)).toMatchObject({
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("persists an isolated session and resumes it for the same agent chat", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "cocodex-agent-session-"));
    const sessionStorePath = join(workspace, "sessions.json");
    const invocations: string[][] = [];
    let turn = 0;
    try {
      const adapter = new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
        sessionStorePath,
        sessionIsolationKey: "trusted-policy-v1",
        authorizeTask: () => true,
        resolveRuntime: () => ({
          runtime: { command: "codex", version: "1.2.3", source: "path" },
          failures: [],
        }),
        spawnProcess: (_file, args) => {
          invocations.push(args);
          turn += 1;
          return fakeProcess(() => {}, turn === 1 ? [
            '{"type":"thread.started","thread_id":"11111111-1111-4111-8111-111111111111"}\n',
            '{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":0,"output_tokens":1}}\n',
          ] : [
            '{"type":"thread.started","thread_id":"11111111-1111-4111-8111-111111111111"}\n',
            '{"type":"turn.completed","usage":{"input_tokens":120,"cached_input_tokens":90,"output_tokens":1}}\n',
          ]);
        },
      });
      for await (const _ of adapter.execute(task)) { /* consume */ }
      for await (const _ of adapter.execute({ ...task, id: "22222222-2222-4222-8222-222222222222" })) { /* consume */ }
      expect(invocations[0]).not.toContain("--ephemeral");
      expect(invocations[0]).not.toContain("resume");
      expect(invocations[1]).toEqual(expect.arrayContaining([
        "resume",
        "11111111-1111-4111-8111-111111111111",
        "-",
      ]));
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rotates sessions at the configured context boundary and isolates chats and policies", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "cocodex-agent-rotation-"));
    const sessionStorePath = join(workspace, "sessions.json");
    const invocations: string[][] = [];
    let thread = 0;
    try {
      const makeAdapter = (sessionIsolationKey: string) => new CodexAgentAdapter({
        projectId: task.projectId,
        agentId: task.agentId,
        workspaceRoot: workspace,
        sessionStorePath,
        sessionIsolationKey,
        maxSessionTurns: 1,
        authorizeTask: () => true,
        resolveRuntime: () => ({
          runtime: { command: "codex", version: "1.2.3", source: "path" },
          failures: [],
        }),
        spawnProcess: (_file, args) => {
          invocations.push(args);
          thread += 1;
          const id = `00000000-0000-4000-8000-${String(thread).padStart(12, "0")}`;
          return fakeProcess(() => {}, [
            `{"type":"thread.started","thread_id":"${id}"}\n`,
            '{"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":1}}\n',
          ]);
        },
      });
      const adapter = makeAdapter("policy-a");
      for await (const _ of adapter.execute(task)) { /* consume */ }
      for await (const _ of adapter.execute({ ...task, id: "33333333-3333-4333-8333-333333333333" })) { /* consume */ }
      const changedPolicy = makeAdapter("policy-b");
      for await (const _ of changedPolicy.execute({ ...task, id: "44444444-4444-4444-8444-444444444444" })) { /* consume */ }
      const changedChat = makeAdapter("policy-b");
      for await (const _ of changedChat.execute({
        ...task,
        id: "55555555-5555-4555-8555-555555555555",
        chatId: "66666666-6666-4666-8666-666666666666",
      })) { /* consume */ }
      expect(invocations).toHaveLength(4);
      for (const invocation of invocations) expect(invocation).not.toContain("resume");
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });
});

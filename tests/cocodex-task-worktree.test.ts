import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentTask } from "@cocodex/protocol";
import type { LocalAgentPolicy } from "../src/cocodex/agent-policy";
import { prepareTaskWorkspace } from "../src/cocodex/task-worktree";

function git(directory: string, ...args: string[]): string {
  const result = spawnSync("git", ["-C", directory, ...args], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(String(result.stderr || result.stdout));
  }
  return String(result.stdout).trim();
}

function task(id: string, projectId: string, agentId = "local-codex"): AgentTask {
  return {
    id,
    projectId,
    requesterDeviceId: "51f90a90-2168-4fc6-8abf-c5cda3a0a9df",
    targetDeviceId: "7982eaa9-0d78-49fe-a095-7c57e29870ef",
    agentId,
    prompt: "Create an isolated change.",
    nonce: "w".repeat(43),
    issuedAt: "2027-01-01T00:00:00.000Z",
    expiresAt: "2027-01-01T00:01:00.000Z",
    dependencies: [],
    inputArtifactIds: [],
    requesterSignature: "a".repeat(86),
    requesterPublicKeyPem: "x".repeat(80),
    serverSignature: "b".repeat(86),
    status: "queued",
    acceptedAt: "2027-01-01T00:00:01.000Z",
  };
}

describe("CoCodex task Git worktrees", () => {
  test("creates locked task-owned branches without mutating the configured repository", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-task-worktrees-"));
    const repository = join(root, "repository");
    const worktreeRoot = join(root, "state", "worktrees");
    const registryPath = join(root, "state", "task-worktrees.json");
    const projectId = "bd5b929c-1024-4a0b-bbd7-fc246a84de89";
    try {
      git(root, "init", "-b", "main", repository);
      git(repository, "config", "user.name", "CoCodex Test");
      git(repository, "config", "user.email", "cocodex@example.invalid");
      writeFileSync(join(repository, "README.md"), "base\n");
      git(repository, "add", "README.md");
      git(repository, "commit", "-m", "base");
      const baseCommit = git(repository, "rev-parse", "HEAD");
      const policy: LocalAgentPolicy = {
        version: 1,
        projectId,
        agentId: "local-codex",
        workspaceRoot: repository,
        workspaceMode: "git-worktree",
        sandbox: "workspace-write",
        accessProfile: "project-only",
        fullComputerOptIn: false,
        approvalMode: "trusted-device",
        trustedRequesterFingerprints: {},
      };
      const firstTask = task("e3a91e9c-090a-45a6-b919-92ac31149883", projectId);
      const first = prepareTaskWorkspace(policy, firstTask, { worktreeRoot, registryPath });
      expect(first).toMatchObject({
        mode: "git-worktree",
        baseCommit,
        mergeTarget: "main",
        workspaceRef: `worktrees/${projectId}/local-codex/${firstTask.id}`,
      });
      expect(first.branch).toBe(`cocodex/${projectId.slice(0, 8)}/local-codex/${firstTask.id}`);
      expect(existsSync(first.workingDirectory)).toBeTrue();
      expect(git(first.workingDirectory, "rev-parse", "--abbrev-ref", "HEAD")).toBe(first.branch);
      expect(git(repository, "worktree", "list", "--porcelain"))
        .toContain(`locked CoCodex task ${firstTask.id}`);

      writeFileSync(join(first.workingDirectory, "README.md"), "task one\n");
      expect(readFileSync(join(repository, "README.md"), "utf8")).toBe("base\n");
      const replay = prepareTaskWorkspace(policy, firstTask, { worktreeRoot, registryPath });
      expect(replay).toEqual(first);

      const secondTask = task("f4b02f40-f9c7-4a64-af36-a0c85dcd60a8", projectId);
      const second = prepareTaskWorkspace(policy, secondTask, { worktreeRoot, registryPath });
      expect(second.workingDirectory).not.toBe(first.workingDirectory);
      expect(second.branch).not.toBe(first.branch);
      expect(git(repository, "rev-parse", "HEAD")).toBe(baseCommit);
      expect(git(repository, "status", "--porcelain=v1", "--untracked-files=all")).toBe("");

      expect(() => prepareTaskWorkspace(policy, {
        ...firstTask,
        agentId: "different-agent",
      }, { worktreeRoot, registryPath })).toThrow("ownership");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects dirty and detached configured repositories", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-task-worktree-reject-"));
    const repository = join(root, "repository");
    const projectId = "bd5b929c-1024-4a0b-bbd7-fc246a84de89";
    const policy: LocalAgentPolicy = {
      version: 1,
      projectId,
      agentId: "local-codex",
      workspaceRoot: repository,
      workspaceMode: "git-worktree",
      sandbox: "workspace-write",
      accessProfile: "project-only",
      fullComputerOptIn: false,
      approvalMode: "trusted-device",
      trustedRequesterFingerprints: {},
    };
    try {
      git(root, "init", "-b", "main", repository);
      git(repository, "config", "user.name", "CoCodex Test");
      git(repository, "config", "user.email", "cocodex@example.invalid");
      writeFileSync(join(repository, "README.md"), "base\n");
      git(repository, "add", "README.md");
      git(repository, "commit", "-m", "base");
      writeFileSync(join(repository, "README.md"), "dirty\n");
      expect(() => prepareTaskWorkspace(policy, task(
        "e3a91e9c-090a-45a6-b919-92ac31149883",
        projectId,
      ), {
        worktreeRoot: join(root, "state", "worktrees"),
        registryPath: join(root, "state", "task-worktrees.json"),
      })).toThrow("uncommitted");
      git(repository, "restore", "README.md");
      git(repository, "checkout", "--detach");
      expect(() => prepareTaskWorkspace(policy, task(
        "f4b02f40-f9c7-4a64-af36-a0c85dcd60a8",
        projectId,
      ), {
        worktreeRoot: join(root, "state", "worktrees"),
        registryPath: join(root, "state", "task-worktrees.json"),
      })).toThrow("named merge-target branch");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

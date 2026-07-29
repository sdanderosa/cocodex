import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createGitIntegrationArtifact,
  GitIntegrationBlockedError,
  integrateTask,
  previewTaskIntegration,
  type GitIntegrationRequest,
} from "../src/cocodex/git-integration";

function git(directory: string, ...args: string[]): string {
  const result = spawnSync("git", ["-C", directory, ...args], {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
  });
  if (result.status !== 0) throw new Error(String(result.stderr || result.stdout));
  return String(result.stdout).trim();
}

function createRepository(): { root: string; repository: string; baseCommit: string } {
  const root = mkdtempSync(join(tmpdir(), "cocodex-git-integration-"));
  const repository = join(root, "repository");
  git(root, "init", "-b", "main", repository);
  git(repository, "config", "user.name", "CoCodex Test");
  git(repository, "config", "user.email", "cocodex@example.test");
  writeFileSync(join(repository, "README.md"), "base\n");
  git(repository, "add", "README.md");
  git(repository, "commit", "-m", "base");
  return { root, repository, baseCommit: git(repository, "rev-parse", "HEAD") };
}

function request(repository: string, worktreePath: string, baseCommit: string, branch: string, expectedTargetCommit: string): GitIntegrationRequest {
  return {
    taskId: "e3a91e9c-090a-45a6-b919-92ac31149883",
    projectId: "bd5b929c-1024-4a0b-bbd7-fc246a84de89",
    agentId: "lucas",
    repositoryRoot: repository,
    worktreePath,
    branch,
    baseCommit,
    mergeTarget: "main",
    expectedTargetCommit,
  };
}

function addWorktree(repository: string, root: string, branch: string, baseCommit: string): string {
  const path = join(root, branch.replaceAll("/", "-"));
  git(repository, "worktree", "add", "-b", branch, path, baseCommit);
  return path;
}

describe("CoCodex Git integration workflow", () => {
  test("previews and explicitly integrates a clean owned task branch", () => {
    const { root, repository, baseCommit } = createRepository();
    try {
      const worktree = addWorktree(repository, join(root, "worktrees"), "cocodex/task/lucas", baseCommit);
      writeFileSync(join(worktree, "README.md"), "task change\n");
      git(worktree, "add", "README.md");
      git(worktree, "commit", "-m", "Lucas change");
      const preview = previewTaskIntegration(request(
        repository, worktree, baseCommit, "cocodex/task/lucas", baseCommit,
      ));
      expect(preview.status).toBe("ready");
      expect(preview.changedFiles).toEqual(["README.md"]);
      const result = integrateTask(request(
        repository, worktree, baseCommit, "cocodex/task/lucas", baseCommit,
      ));
      expect(result.status).toBe("integrated");
      expect(result.commit).toBe(git(repository, "rev-parse", "HEAD"));
      expect(result.artifact).toMatchObject({
        type: "git.integration",
        status: "integrated",
        taskId: "e3a91e9c-090a-45a6-b919-92ac31149883",
        changedFiles: ["README.md"],
        integrationCommit: result.commit,
      });
      expect(readFileSync(join(repository, "README.md"), "utf8").replaceAll("\r\n", "\n")).toBe("task change\n");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("blocks overlapping peer work and emits a revision artifact without merging", () => {
    const { root, repository, baseCommit } = createRepository();
    try {
      const worktreeRoot = join(root, "worktrees");
      const taskBranch = "cocodex/task/lucas";
      const peerBranch = "cocodex/task/angela";
      const taskWorktree = addWorktree(repository, worktreeRoot, taskBranch, baseCommit);
      const peerWorktree = addWorktree(repository, worktreeRoot, peerBranch, baseCommit);
      writeFileSync(join(taskWorktree, "README.md"), "Lucas\n");
      git(taskWorktree, "add", "README.md");
      git(taskWorktree, "commit", "-m", "Lucas change");
      writeFileSync(join(peerWorktree, "README.md"), "Angela\n");
      git(peerWorktree, "add", "README.md");
      git(peerWorktree, "commit", "-m", "Angela change");
      const preview = previewTaskIntegration({
        ...request(repository, taskWorktree, baseCommit, taskBranch, baseCommit),
        peers: [{ taskId: "f4b02f40-f9c7-4a64-af36-a0c85dcd60a8", branch: peerBranch, baseCommit }],
      });
      expect(preview.status).toBe("blocked");
      expect(preview.blockedReasons).toContain("overlap");
      expect(preview.overlaps).toEqual([{ taskId: "f4b02f40-f9c7-4a64-af36-a0c85dcd60a8", branch: peerBranch, files: ["README.md"] }]);
      const artifact = createGitIntegrationArtifact(preview, "revision-required", null, 2);
      expect(artifact).toMatchObject({ status: "revision-required", revision: 2, conflicts: [] });
      expect(git(repository, "rev-parse", "HEAD")).toBe(baseCommit);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("detects target conflicts and refuses a dirty task or stale target", () => {
    const { root, repository, baseCommit } = createRepository();
    try {
      const worktree = addWorktree(repository, join(root, "worktrees"), "cocodex/task/lucas", baseCommit);
      writeFileSync(join(worktree, "README.md"), "Lucas\n");
      git(worktree, "add", "README.md");
      git(worktree, "commit", "-m", "Lucas change");
      writeFileSync(join(repository, "README.md"), "Stephen\n");
      git(repository, "add", "README.md");
      git(repository, "commit", "-m", "Stephen change");
      const targetCommit = git(repository, "rev-parse", "HEAD");
      const conflictPreview = previewTaskIntegration(request(
        repository, worktree, baseCommit, "cocodex/task/lucas", targetCommit,
      ));
      expect(conflictPreview.status).toBe("blocked");
      expect(conflictPreview.blockedReasons).toContain("merge-conflict");
      expect(conflictPreview.conflicts).toContain("README.md");
      expect(() => integrateTask(request(
        repository, worktree, baseCommit, "cocodex/task/lucas", targetCommit,
      ))).toThrow(GitIntegrationBlockedError);
      writeFileSync(join(worktree, "dirty.txt"), "uncommitted\n");
      const dirtyPreview = previewTaskIntegration(request(
        repository, worktree, baseCommit, "cocodex/task/lucas", baseCommit,
      ));
      expect(dirtyPreview.blockedReasons).toContain("target-moved");
      expect(dirtyPreview.blockedReasons).toContain("task-dirty");
      expect(git(repository, "rev-parse", "HEAD")).toBe(targetCommit);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

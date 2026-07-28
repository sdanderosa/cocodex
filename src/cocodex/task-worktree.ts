import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { z } from "zod";
import type { AgentTask } from "../../packages/cocodex-protocol/src/index.ts";
import type { LocalAgentPolicy } from "./agent-policy";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const commitPattern = /^[0-9a-f]{40,64}$/;
const branchComponentPattern = /[^A-Za-z0-9._-]+/g;

const ownershipSchema = z.object({
  version: z.literal(1),
  tasks: z.record(z.uuid(), z.object({
    taskId: z.uuid(),
    projectId: z.uuid(),
    agentId: z.string().min(1).max(120),
    repositoryRoot: z.string().min(1),
    worktreePath: z.string().min(1),
    workspaceRef: z.string().min(1).max(500),
    branch: z.string().min(1).max(500),
    baseCommit: z.string().regex(commitPattern),
    mergeTarget: z.string().min(1).max(500),
    createdAt: z.iso.datetime(),
  }).strict()),
}).strict();

type WorktreeOwnership = z.infer<typeof ownershipSchema>;

export interface TaskWorkspace {
  mode: "shared" | "git-worktree";
  workingDirectory: string;
  workspaceRef: string;
  branch: string | null;
  baseCommit: string | null;
  mergeTarget: string | null;
}

export interface TaskWorktreeOptions {
  worktreeRoot: string;
  registryPath: string;
  gitCommand?: string;
}

interface GitResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runGit(command: string, args: string[]): GitResult {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (result.error) throw new Error(`Git could not start: ${result.error.message}`);
  return {
    status: result.status ?? -1,
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? ""),
  };
}

function requireGit(command: string, args: string[], failure: string): string {
  const result = runGit(command, args);
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim();
    throw new Error(detail ? `${failure}: ${detail}` : failure);
  }
  return result.stdout.trim();
}

function containedPath(root: string, ...parts: string[]): string {
  const absoluteRoot = resolve(root);
  const target = resolve(absoluteRoot, ...parts);
  const rel = relative(absoluteRoot, target);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || resolve(absoluteRoot, rel) !== target) {
    throw new Error("Task worktree path escapes the local worktree root");
  }
  return target;
}

function physicalPath(path: string): string {
  return realpathSync.native(resolve(path));
}

function physicalPathAllowMissing(path: string): string {
  let current = resolve(path);
  const suffix: string[] = [];
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) return resolve(path);
    suffix.unshift(basename(current));
    current = parent;
  }
  return resolve(physicalPath(current), ...suffix);
}

function physicalPathKey(path: string): string {
  const canonical = physicalPath(path);
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

export function samePhysicalPath(left: string, right: string): boolean {
  const leftStatus = statSync(resolve(left));
  const rightStatus = statSync(resolve(right));
  if (leftStatus.ino !== 0 && leftStatus.dev === rightStatus.dev && leftStatus.ino === rightStatus.ino) {
    return true;
  }
  return physicalPathKey(left) === physicalPathKey(right);
}

function branchComponent(value: string): string {
  const result = value.trim().replace(branchComponentPattern, "-").replace(/^-+|-+$/g, "").slice(0, 80);
  if (!result || result === "." || result === ".." || result.endsWith(".lock")) {
    throw new Error("Agent ID cannot form a safe Git branch");
  }
  return result;
}

function worktreePathComponent(prefix: "p" | "a" | "t", value: string): string {
  const digest = createHash("sha256").update(value, "utf8").digest("hex").slice(0, 16);
  return `${prefix}-${digest}`;
}

function loadOwnership(path: string): WorktreeOwnership {
  if (!existsSync(path)) return { version: 1, tasks: {} };
  hardenSecretPath(path, { required: true });
  return ownershipSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

function saveOwnership(path: string, value: WorktreeOwnership): void {
  const parsed = ownershipSchema.parse(value);
  mkdirSync(dirname(path), { recursive: true });
  hardenSecretDir(dirname(path), { required: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(parsed, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

function registeredWorktreePaths(git: string, repositoryCommandRoot: string): Set<string> {
  const output = requireGit(git, ["-C", repositoryCommandRoot, "worktree", "list", "--porcelain", "-z"],
    "Unable to inspect Git worktrees");
  const paths = new Set<string>();
  for (const field of output.split("\0")) {
    if (field.startsWith("worktree ")) {
      const path = field.slice("worktree ".length);
      if (existsSync(path)) paths.add(physicalPathKey(path));
    }
  }
  return paths;
}

function verifyOwnedWorktree(
  git: string,
  entry: WorktreeOwnership["tasks"][string],
  repositoryCommandRoot = entry.repositoryRoot,
  worktreeCommandPath = entry.worktreePath,
): TaskWorkspace {
  if (!existsSync(entry.worktreePath) || !statSync(entry.worktreePath).isDirectory()) {
    throw new Error("Owned task worktree is missing; repair it explicitly before retrying");
  }
  const repositoryRoot = physicalPath(entry.repositoryRoot);
  const worktreePath = physicalPath(entry.worktreePath);
  if (!registeredWorktreePaths(git, repositoryCommandRoot).has(physicalPathKey(worktreePath))) {
    throw new Error("Owned task path is not registered as a Git worktree");
  }
  const branch = requireGit(git, ["-C", worktreeCommandPath, "symbolic-ref", "--quiet", "--short", "HEAD"],
    "Owned task worktree has no named branch");
  if (branch !== entry.branch) throw new Error("Owned task worktree branch changed");
  const ancestry = runGit(git, ["-C", worktreeCommandPath, "merge-base", "--is-ancestor", entry.baseCommit, "HEAD"]);
  if (ancestry.status !== 0) throw new Error("Owned task worktree no longer descends from its recorded base");
  return {
    mode: "git-worktree",
    workingDirectory: worktreePath,
    workspaceRef: entry.workspaceRef,
    branch: entry.branch,
    baseCommit: entry.baseCommit,
    mergeTarget: entry.mergeTarget,
  };
}

export function prepareTaskWorkspace(
  policy: LocalAgentPolicy,
  task: AgentTask,
  options: TaskWorktreeOptions,
): TaskWorkspace {
  const configuredRoot = resolve(policy.workspaceRoot);
  if (policy.workspaceMode === "shared") {
    if (!existsSync(configuredRoot) || !statSync(configuredRoot).isDirectory()) {
      throw new Error("Configured shared workspace does not exist");
    }
    const repositoryRoot = physicalPath(configuredRoot);
    return {
      mode: "shared",
      workingDirectory: repositoryRoot,
      workspaceRef: "configured-workspace",
      branch: null,
      baseCommit: null,
      mergeTarget: null,
    };
  }

  if (!existsSync(configuredRoot) || !statSync(configuredRoot).isDirectory()) {
    throw new Error("Configured Git workspace does not exist");
  }
  const repositoryRoot = physicalPath(configuredRoot);
  const git = options.gitCommand ?? "git";
  const ownership = loadOwnership(options.registryPath);
  const agentComponent = branchComponent(task.agentId);
  const commandWorktreeRoot = resolve(options.worktreeRoot);
  const commandWorktreePath = containedPath(
    commandWorktreeRoot,
    worktreePathComponent("p", task.projectId),
    worktreePathComponent("a", task.agentId),
    worktreePathComponent("t", task.id),
  );
  const existing = ownership.tasks[task.id];
  if (existing) {
    if (existing.projectId !== task.projectId || existing.agentId !== task.agentId
      || !samePhysicalPath(existing.repositoryRoot, repositoryRoot)) {
      throw new Error("Task worktree ownership does not match this assignment");
    }
    const replayCommandPath = existsSync(commandWorktreePath)
      && samePhysicalPath(commandWorktreePath, existing.worktreePath)
      ? commandWorktreePath
      : existing.worktreePath;
    return verifyOwnedWorktree(git, existing, configuredRoot, replayCommandPath);
  }

  const discoveredRoot = requireGit(git, ["-C", configuredRoot, "rev-parse", "--show-toplevel"],
    "Configured workspace is not a Git repository");
  if (!samePhysicalPath(discoveredRoot, repositoryRoot)) {
    throw new Error("Configured Git workspace must be the repository root");
  }
  const dirty = requireGit(git, ["-C", configuredRoot, "status", "--porcelain=v1", "--untracked-files=all"],
    "Unable to inspect Git dirty state");
  if (dirty) throw new Error("Configured Git workspace has uncommitted changes");
  const baseCommit = requireGit(git, ["-C", configuredRoot, "rev-parse", "--verify", "HEAD^{commit}"],
    "Git repository has no valid base commit").toLowerCase();
  if (!commitPattern.test(baseCommit)) throw new Error("Git returned an invalid base commit");
  const mergeTarget = requireGit(git, ["-C", configuredRoot, "symbolic-ref", "--quiet", "--short", "HEAD"],
    "Git repository must be on a named merge-target branch");

  const branch = `cocodex/${task.projectId.slice(0, 8)}/${agentComponent}/${task.id}`;
  const branchExists = runGit(git, ["-C", configuredRoot, "show-ref", "--verify", "--quiet", `refs/heads/${branch}`]);
  if (branchExists.status === 0) throw new Error("Task Git branch already exists without CoCodex ownership");
  if (branchExists.status !== 1) throw new Error("Unable to inspect task Git branch");

  const physicalWorktreeRoot = physicalPathAllowMissing(options.worktreeRoot);
  const requestedWorktreePath = commandWorktreePath;
  if (existsSync(requestedWorktreePath)) throw new Error("Task worktree path already exists without CoCodex ownership");
  mkdirSync(dirname(requestedWorktreePath), { recursive: true });
  const physicalWorktreeParent = physicalPath(dirname(requestedWorktreePath));
  const parentRelative = relative(physicalWorktreeRoot, physicalWorktreeParent);
  if (parentRelative === ".." || parentRelative.startsWith(`..${sep}`)) {
    throw new Error("Task worktree parent escapes the local worktree root");
  }
  const reason = `CoCodex task ${task.id}`;
  requireGit(git, [
    "-c", "core.longpaths=true",
    "-C", configuredRoot, "worktree", "add", "--lock", "--reason", reason,
    "-b", branch, requestedWorktreePath, baseCommit,
  ], "Git could not create the task worktree");
  const worktreePath = physicalPath(requestedWorktreePath);
  const finalRelative = relative(physicalWorktreeRoot, worktreePath);
  if (finalRelative === ".." || finalRelative.startsWith(`..${sep}`)) {
    throw new Error("Created task worktree escapes the local worktree root");
  }

  const workspaceRef = ["worktrees", task.projectId, agentComponent, task.id].join("/");
  const entry: WorktreeOwnership["tasks"][string] = {
    taskId: task.id,
    projectId: task.projectId,
    agentId: task.agentId,
    repositoryRoot,
    worktreePath,
    workspaceRef,
    branch,
    baseCommit,
    mergeTarget,
    createdAt: new Date().toISOString(),
  };
  saveOwnership(options.registryPath, {
    version: 1,
    tasks: { ...ownership.tasks, [task.id]: entry },
  });
  return verifyOwnedWorktree(git, entry, configuredRoot, requestedWorktreePath);
}

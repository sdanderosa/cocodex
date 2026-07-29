import { randomUUID } from "node:crypto";
import { existsSync, realpathSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const commitPattern = /^[0-9a-f]{40,64}$/i;
const branchPattern = /^[A-Za-z0-9._/-]{1,500}$/;

export interface GitIntegrationPeer {
  taskId: string;
  branch: string;
  baseCommit: string;
}

export interface GitIntegrationRequest {
  taskId: string;
  projectId: string;
  agentId: string;
  repositoryRoot: string;
  worktreePath: string;
  branch: string;
  baseCommit: string;
  mergeTarget: string;
  expectedTargetCommit: string;
  peers?: readonly GitIntegrationPeer[];
  gitCommand?: string;
}

export type GitIntegrationBlockReason =
  | "target-moved"
  | "target-not-checked-out"
  | "target-dirty"
  | "task-dirty"
  | "worktree-not-owned"
  | "branch-mismatch"
  | "base-missing"
  | "empty-change"
  | "overlap"
  | "peer-invalid"
  | "merge-conflict";

export interface GitIntegrationOverlap {
  taskId: string;
  branch: string;
  files: string[];
}

export interface GitIntegrationPreview {
  version: 1;
  status: "ready" | "blocked";
  taskId: string;
  projectId: string;
  agentId: string;
  repositoryRoot: string;
  worktreePath: string;
  branch: string;
  baseCommit: string;
  mergeTarget: string;
  expectedTargetCommit: string;
  currentTargetCommit: string;
  changedFiles: string[];
  conflicts: string[];
  overlaps: GitIntegrationOverlap[];
  blockedReasons: GitIntegrationBlockReason[];
}

export interface GitIntegrationArtifact {
  version: 1;
  type: "git.integration";
  artifactId: string;
  projectId: string;
  taskId: string;
  agentId: string;
  branch: string;
  mergeTarget: string;
  baseCommit: string;
  targetCommit: string;
  integrationCommit: string | null;
  changedFiles: string[];
  conflicts: string[];
  overlaps: GitIntegrationOverlap[];
  status: "integrated" | "revision-required";
  revision: number;
  createdAt: string;
}

export interface GitIntegrationResult {
  status: "integrated";
  commit: string;
  preview: GitIntegrationPreview;
  artifact: GitIntegrationArtifact;
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
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) throw new Error("Git could not start: " + result.error.message);
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
    throw new Error(detail ? failure + ": " + detail : failure);
  }
  return result.stdout.trim();
}

function canonicalPath(path: string): string {
  return realpathSync.native(resolve(path));
}

function pathKey(path: string): string {
  const value = canonicalPath(path);
  return process.platform === "win32" ? value.toLowerCase() : value;
}

function samePath(left: string, right: string): boolean {
  const leftStatus = statSync(resolve(left));
  const rightStatus = statSync(resolve(right));
  if (leftStatus.ino !== 0 && leftStatus.dev === rightStatus.dev && leftStatus.ino === rightStatus.ino) return true;
  return pathKey(left) === pathKey(right);
}

function requireCommit(value: string, label: string): string {
  const normalized = value.trim().toLowerCase();
  if (!commitPattern.test(normalized)) throw new Error(label + " must be a full Git commit ID");
  return normalized;
}

function requireBranch(value: string, label: string): string {
  const branch = value.trim();
  if (!branchPattern.test(branch) || branch.startsWith("-") || branch.includes("..")
    || branch.includes("@{") || branch.endsWith("/") || branch.endsWith(".")) {
    throw new Error(label + " is not a safe Git branch name");
  }
  return branch;
}

function requireContainedPath(root: string, target: string): void {
  if (pathKey(root) === pathKey(target)) {
    throw new Error("Task worktree must be a separate path from the repository root");
  }
}

function refCommit(git: string, repositoryRoot: string, ref: string, label: string): string {
  return requireCommit(requireGit(git, ["-C", repositoryRoot, "rev-parse", "--verify", ref + "^{commit}"], "Unable to resolve " + label), label);
}

export function resolveGitTargetCommit(
  repositoryRoot: string,
  mergeTarget: string,
  gitCommand = "git",
): string {
  return refCommit(
    gitCommand,
    canonicalPath(repositoryRoot),
    requireBranch(mergeTarget, "Merge target"),
    "current target commit",
  );
}

function changedFiles(git: string, repositoryRoot: string, baseCommit: string, branch: string): string[] {
  const output = requireGit(git, ["-C", repositoryRoot, "diff", "--name-only", "-z", baseCommit + "^{commit}", branch + "^{commit}"], "Unable to inspect Git changes");
  return [...new Set(output.split("\0").filter(Boolean))].sort();
}

function registeredWorktreeBranch(git: string, repositoryRoot: string, worktreePath: string): string | null {
  const output = requireGit(git, ["-C", repositoryRoot, "worktree", "list", "--porcelain", "-z"], "Unable to inspect registered Git worktrees");
  let currentPath: string | null = null;
  for (const field of output.split("\0")) {
    if (field.startsWith("worktree ")) currentPath = field.slice("worktree ".length);
    else if (field.startsWith("branch ") && currentPath && samePath(currentPath, worktreePath)) {
      const ref = field.slice("branch ".length);
      return ref.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : ref;
    }
  }
  return null;
}

function conflictFiles(output: string): string[] {
  const files = new Set<string>();
  for (const line of output.split(/\r?\n/)) {
    const match = /Merge conflict in (.+)$/.exec(line.trim());
    if (match?.[1]) files.add(match[1].trim());
  }
  return [...files].sort();
}

function mergeConflicts(git: string, repositoryRoot: string, target: string, branch: string): string[] {
  const result = runGit(git, ["-C", repositoryRoot, "merge-tree", "--write-tree", target + "^{commit}", branch + "^{commit}"]);
  if (result.status === 0) return [];
  return conflictFiles(result.stdout + "\n" + result.stderr);
}

function overlapFor(
  git: string,
  repositoryRoot: string,
  changed: ReadonlySet<string>,
  peer: GitIntegrationPeer,
): GitIntegrationOverlap | null {
  const branch = requireBranch(peer.branch, "Peer branch");
  const baseCommit = requireCommit(peer.baseCommit, "Peer base commit");
  const peerFiles = changedFiles(git, repositoryRoot, baseCommit, branch);
  const files = peerFiles.filter(file => changed.has(process.platform === "win32" ? file.toLowerCase() : file));
  return files.length ? { taskId: peer.taskId, branch, files } : null;
}

function block(
  request: GitIntegrationRequest,
  status: GitIntegrationPreview["status"],
  currentTargetCommit: string,
  changed: string[],
  conflicts: string[],
  overlaps: GitIntegrationOverlap[],
  blockedReasons: GitIntegrationBlockReason[],
): GitIntegrationPreview {
  return {
    version: 1,
    status,
    taskId: request.taskId,
    projectId: request.projectId,
    agentId: request.agentId,
    repositoryRoot: canonicalPath(request.repositoryRoot),
    worktreePath: canonicalPath(request.worktreePath),
    branch: request.branch,
    baseCommit: request.baseCommit,
    mergeTarget: request.mergeTarget,
    expectedTargetCommit: request.expectedTargetCommit,
    currentTargetCommit,
    changedFiles: changed,
    conflicts,
    overlaps,
    blockedReasons: [...new Set(blockedReasons)],
  };
}

export function previewTaskIntegration(input: GitIntegrationRequest): GitIntegrationPreview {
  const request: GitIntegrationRequest = {
    ...input,
    branch: requireBranch(input.branch, "Task branch"),
    mergeTarget: requireBranch(input.mergeTarget, "Merge target"),
    baseCommit: requireCommit(input.baseCommit, "Task base commit"),
    expectedTargetCommit: requireCommit(input.expectedTargetCommit, "Expected target commit"),
  };
  if (request.branch === request.mergeTarget) throw new Error("Task branch cannot be the merge target");
  const git = request.gitCommand ?? "git";
  const repositoryRoot = canonicalPath(request.repositoryRoot);
  const worktreePath = canonicalPath(request.worktreePath);
  requireContainedPath(repositoryRoot, worktreePath);
  const discoveredRoot = canonicalPath(requireGit(git, ["-C", repositoryRoot, "rev-parse", "--show-toplevel"], "Configured path is not a Git repository"));
  if (!samePath(discoveredRoot, repositoryRoot)) throw new Error("Configured path is not the Git repository root");

  let currentTargetCommit = "";
  try { currentTargetCommit = refCommit(git, repositoryRoot, request.mergeTarget, "current target commit"); } catch { /* report below */ }
  const blockedReasons: GitIntegrationBlockReason[] = [];
  const overlaps: GitIntegrationOverlap[] = [];
  let changed: string[] = [];
  let conflicts: string[] = [];

  if (currentTargetCommit !== request.expectedTargetCommit) blockedReasons.push("target-moved");
  try {
    const checkedOut = requireGit(git, ["-C", repositoryRoot, "symbolic-ref", "--quiet", "--short", "HEAD"], "Merge target is detached");
    if (checkedOut !== request.mergeTarget) blockedReasons.push("target-not-checked-out");
  } catch { blockedReasons.push("target-not-checked-out"); }
  if (requireGit(git, ["-C", repositoryRoot, "status", "--porcelain=v1", "--untracked-files=all"], "Unable to inspect merge-target state")) {
    blockedReasons.push("target-dirty");
  }

  const registeredBranch = registeredWorktreeBranch(git, repositoryRoot, worktreePath);
  if (!registeredBranch) blockedReasons.push("worktree-not-owned");
  else if (registeredBranch !== request.branch) blockedReasons.push("branch-mismatch");
  try {
    const taskBranch = requireGit(git, ["-C", worktreePath, "symbolic-ref", "--quiet", "--short", "HEAD"], "Task worktree is detached");
    if (taskBranch !== request.branch) blockedReasons.push("branch-mismatch");
  } catch { blockedReasons.push("branch-mismatch"); }
  if (requireGit(git, ["-C", worktreePath, "status", "--porcelain=v1", "--untracked-files=all"], "Unable to inspect task worktree state")) {
    blockedReasons.push("task-dirty");
  }
  const taskCommit = refCommit(git, worktreePath, "HEAD", "task commit");
  const ancestry = runGit(git, ["-C", repositoryRoot, "merge-base", "--is-ancestor", request.baseCommit + "^{commit}", taskCommit + "^{commit}"]);
  if (ancestry.status !== 0) blockedReasons.push("base-missing");
  changed = changedFiles(git, repositoryRoot, request.baseCommit, request.branch);
  if (changed.length === 0) blockedReasons.push("empty-change");

  const changedSet = new Set(changed.map(file => process.platform === "win32" ? file.toLowerCase() : file));
  for (const peer of request.peers ?? []) {
    try {
      const overlap = overlapFor(git, repositoryRoot, changedSet, peer);
      if (overlap) overlaps.push(overlap);
    } catch {
      blockedReasons.push("peer-invalid");
    }
  }
  if (overlaps.length) blockedReasons.push("overlap");
  if (currentTargetCommit && !blockedReasons.includes("target-moved")) {
    conflicts = mergeConflicts(git, repositoryRoot, request.mergeTarget, request.branch);
    if (conflicts.length) blockedReasons.push("merge-conflict");
  }
  return block(request, blockedReasons.length ? "blocked" : "ready", currentTargetCommit, changed, conflicts, overlaps, blockedReasons);
}

export function createGitIntegrationArtifact(
  preview: GitIntegrationPreview,
  status: GitIntegrationArtifact["status"],
  integrationCommit: string | null = null,
  revision = 1,
): GitIntegrationArtifact {
  return {
    version: 1,
    type: "git.integration",
    artifactId: randomUUID(),
    projectId: preview.projectId,
    taskId: preview.taskId,
    agentId: preview.agentId,
    branch: preview.branch,
    mergeTarget: preview.mergeTarget,
    baseCommit: preview.baseCommit,
    targetCommit: preview.currentTargetCommit,
    integrationCommit,
    changedFiles: preview.changedFiles,
    conflicts: preview.conflicts,
    overlaps: preview.overlaps,
    status,
    revision,
    createdAt: new Date().toISOString(),
  };
}

export class GitIntegrationBlockedError extends Error {
  readonly preview: GitIntegrationPreview;
  readonly artifact: GitIntegrationArtifact;

  constructor(preview: GitIntegrationPreview, revision = 1) {
    super("Git integration blocked: " + (preview.blockedReasons.join(", ") || "unknown reason"));
    this.name = "GitIntegrationBlockedError";
    this.preview = preview;
    this.artifact = createGitIntegrationArtifact(preview, "revision-required", null, revision);
  }
}

export function integrateTask(input: GitIntegrationRequest, revision = 1): GitIntegrationResult {
  const preview = previewTaskIntegration(input);
  if (preview.status !== "ready") throw new GitIntegrationBlockedError(preview, revision);
  const git = input.gitCommand ?? "git";
  const result = runGit(git, ["-C", preview.repositoryRoot, "merge", "--no-ff", "--no-edit", preview.branch]);
  if (result.status !== 0) {
    runGit(git, ["-C", preview.repositoryRoot, "merge", "--abort"]);
    const failed = { ...preview, status: "blocked" as const, conflicts: conflictFiles(result.stdout + "\n" + result.stderr), blockedReasons: ["merge-conflict" as const] };
    throw new GitIntegrationBlockedError(failed, revision);
  }
  const commit = refCommit(git, preview.repositoryRoot, "HEAD", "integration commit");
  return {
    status: "integrated",
    commit,
    preview: { ...preview, currentTargetCommit: commit },
    artifact: createGitIntegrationArtifact({ ...preview, currentTargetCommit: commit }, "integrated", commit, revision),
  };
}

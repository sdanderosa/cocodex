import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import type { ClientPaths } from "./paths";

export interface AgentRuntimePaths {
  safety: string;
  journal: string;
  worktreeRegistry: string;
  worktreeRoot: string;
}

export function agentRuntimePaths(
  paths: ClientPaths,
  agentId: string,
  legacy = false,
): AgentRuntimePaths {
  if (legacy) {
    return {
      safety: paths.agentSafety,
      journal: paths.agentJournal,
      worktreeRegistry: paths.taskWorktreeRegistry,
      worktreeRoot: paths.taskWorktrees,
    };
  }
  if (!agentId.trim() || agentId.length > 120) throw new Error("Agent runtime state requires a bounded agent ID");
  const stateKey = createHash("sha256").update(agentId, "utf8").digest("hex");
  const root = resolve(paths.root, "agents", stateKey);
  return {
    safety: resolve(root, "safety.json"),
    journal: resolve(root, "execution-journal.json"),
    worktreeRegistry: resolve(root, "task-worktrees.json"),
    worktreeRoot: paths.taskWorktrees,
  };
}

function copyProtectedFileIfMissing(source: string, destination: string): void {
  if (!existsSync(source) || existsSync(destination)) return;
  const directory = dirname(destination);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${destination}.${randomUUID()}.tmp`;
  writeFileSync(temporary, readFileSync(source), { mode: 0o600, flag: "wx" });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, destination);
  hardenSecretPath(destination, { required: true });
}

/**
 * Copies singleton v1 runtime state before the v2 policy store becomes the
 * commit marker. The legacy files are intentionally retained for rollback.
 */
export function stageLegacyAgentRuntimeState(paths: ClientPaths, agentId: string): AgentRuntimePaths {
  const target = agentRuntimePaths(paths, agentId);
  copyProtectedFileIfMissing(paths.agentSafety, target.safety);
  copyProtectedFileIfMissing(paths.agentJournal, target.journal);
  copyProtectedFileIfMissing(paths.taskWorktreeRegistry, target.worktreeRegistry);
  return target;
}

# ADR 0024: Task-scoped Git worktree isolation

- **Status:** Accepted for implementation
- **Date:** 2026-07-25
- **Scope:** local Git repository validation, task branch/worktree creation,
  ownership metadata, host-signed execution reporting, and shared task status

## Context

CoCodex can route multiple agents to one host, but a fixed workspace directory
does not isolate concurrent indexes, branches, or uncommitted files. The
product specification requires Git worktrees by default for code agents,
known base commits, ownership metadata, dirty-state detection, and a refusal
to perform destructive cleanup.

Git's official worktree interface is the maintained component. Its porcelain
`-z` listing is stable for scripts; `worktree add -b` creates an isolated
branch/index; and `--lock --reason` prevents automatic pruning. OpenHands is a
reference only for separating runtime sessions and reporting typed execution
state. Core OpenHands is MIT licensed, but its `enterprise/` tree is under a
different source-available license and is excluded. No OpenHands code is
copied and no new dependency is added.

## Decision

New local agent configurations default to `git-worktree`; legacy policies
without the field load as `shared` for compatibility. A host can explicitly
choose either mode.

For `git-worktree`, the Client must:

1. resolve the configured workspace and require it to be the repository root;
2. require a named merge-target branch and a valid `HEAD` commit;
3. reject tracked or untracked dirty state;
4. derive a bounded branch from project, agent, and task IDs;
5. create a task worktree under the protected local CoCodex state root using
   `git worktree add --lock --reason ... -b ... <path> <base>`;
6. persist task ownership, repository, branch, base commit, and merge target
   atomically;
7. verify an existing owned worktree before idempotent reuse; and
8. run official Codex with both `-C` and process `cwd` set to that task
   worktree.

CoCodex never uses `--force`, `reset --hard`, branch replacement, worktree
removal, or automatic cleanup. Completed work remains for explicit review and
integration.

Before local Codex starts, the host sends a device-signed execution report.
The authoritative Server verifies project/task/agent/host bindings and the
signature, records sanitized metadata (`workspaceMode`, opaque local
`workspaceRef`, branch, base commit, merge target, and start time), and exposes
it through task activity. Absolute local paths never go to the Server.

## Security and failure behavior

- Requesters cannot choose host filesystem paths or branch names.
- Path containment is checked against the local worktree root before Git runs.
- Existing paths, branches, mismatched ownership, malformed Git output, dirty
  bases, detached heads, and changed worktrees fail closed.
- The runtime does not start unless the Server acknowledges the signed
  execution report.
- Shared mode reports only `configured-workspace`, never an absolute path.
- Git subprocesses use argument arrays with `shell: false`.
- Interrupted or failed tasks keep their worktrees; CoCodex does not erase
  evidence or user changes.

## Rejected alternatives

- Do not serialize every code agent into the main working tree.
- Do not use `git stash`, force checkout, hard reset, or automatic branch
  deletion to make a dirty repository look clean.
- Do not let the Server create worktrees or execute Git.
- Do not send absolute host paths to shared state.
- Do not copy worktree/runtime code from OpenHands.

## Required evidence

- Real Git tests create two isolated task worktrees and prove base-worktree
  files and branches are not modified.
- Dirty, detached, collision, ownership-mismatch, and idempotent recovery cases
  are covered.
- Adapter tests prove Codex uses the task worktree and reporting precedes
  process spawn.
- Server tests reject forged or wrong-host execution reports.
- The real three-process harness records execution metadata while preserving
  reciprocal execution and restart recovery.

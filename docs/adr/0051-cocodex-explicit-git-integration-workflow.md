# ADR 0051: Explicit Git integration workflow

Status: Accepted

## Decision

CoCodex integrates agent worktrees only through an explicit host-client
operation. A task branch is never merged merely because an agent reports a
successful result.

Before integration, the client creates a read-only preview that proves:

1. The configured repository is the physical Git repository root.
2. The task path is a registered CoCodex-owned worktree on the expected branch.
3. The task and merge-target worktrees are clean and the target is checked out.
4. The target commit still equals the caller's expected commit.
5. The task branch descends from its recorded base and contains a non-empty
   committed change.
6. Peer task branches have no overlapping changed paths unless the caller
   explicitly resolves the review first.
7. `git merge-tree --write-tree` reports no merge conflict.

The preview is exposed through `cocodex git-preview`. `cocodex git-integrate`
rechecks the preview and performs an explicit `git merge --no-ff --no-edit` only
when every check passes. A target race or merge failure is aborted and returns
a `revision-required` integration artifact containing changed files, conflicts,
overlapping tasks, target/base commits, and a revision number. Successful
integration returns an `integrated` artifact with the resulting commit.

The client keeps ownership of local Git paths and mutations. The server remains
authoritative for task and artifact metadata; a returned integration artifact
must use the existing encrypted artifact publication path before shared state is
updated. Worktrees and branches are not deleted automatically.

## Safety boundary

Git is spawned without a shell. Branches and commit IDs are validated, the
expected target commit prevents lost-update merges, dirty state fails closed,
and conflict handling never leaves a partial merge in the target worktree.

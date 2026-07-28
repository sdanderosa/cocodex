# Git integration workflow evidence

Date: 2026-07-28

The Client now has an explicit, fail-closed Git integration coordinator in
`src/cocodex/git-integration.ts` and two CLI entry points:

```text
cocodex git-preview ...
cocodex git-integrate ...
```

The preview checks repository/worktree ownership, branch/base ancestry, clean
state, expected target commit, changed files, peer overlap, and a read-only
`git merge-tree --write-tree` conflict proof. A blocked integration returns a
revision-required artifact; a successful explicit merge returns an integrated
artifact with the merge commit. The target branch is never silently advanced,
and a merge race is aborted.

## Verification

```text
tests/cocodex-git-integration.test.ts: 3 passed, 0 failed, 18 expectations
repository TypeScript check: exit 0
CLI help: git-preview and git-integrate both exposed
```

The tests use temporary real Git repositories and registered worktrees. They
prove a clean integration, overlapping peer detection without a merge, a
revision artifact, target conflict detection, stale-target refusal, and dirty
task refusal. The temporary repositories are removed after each test. No user
repository or the foreign listener on port 10100 was used.

This closes the local preview/integration workflow slice. The resident
Client/GUI continuation below publishes outcomes through the existing
encrypted artifact route; inclusion in the single uninterrupted 70-step
acceptance scenario remains required before the product can be called complete.

## Resident Client/GUI integration - 2026-07-28

The tested local workflow is now reachable from the resident Client and
chat-first GUI:

- src/cocodex/session.ts caches the server-authoritative task projection,
  verifies it against the local agent policy and owned worktree registry, and
  derives repository/worktree paths locally. Renderer commands cannot supply
  arbitrary paths, branches, or peer metadata.
- git.integration.preview captures the current merge-target commit when a
  review starts. git.integration.integrate requires that exact preview commit,
  rechecks all fail-closed Git conditions, and refuses a moved target, dirty
  worktree, ownership mismatch, overlap, or merge conflict.
- Successful merges and revision-required outcomes use the existing encrypted
  project-artifact/outbox route (commit or review artifact type). Shared
  content contains Git metadata and relative changed paths, not local absolute
  repository paths.
- src/cocodex/gui-bridge.ts allowlists and validates both commands. The GUI
  task rail presents Review integration and Integrate reviewed commit only for
  completed local Git-worktree tasks.

Current verification:

complete repository: 4,265 passed, 4 skipped, 0 failed
complete repository expectations: 21,702 across 359 files
dedicated CoCodex: 178 passed, 0 failed, 2,067 expectations
focused Git integration: 3 passed, 0 failed, 18 expectations
focused GUI bridge: 1 passed, 0 failed, 119 expectations
CoCodex TypeScript: exit 0
GUI lint: 0 errors, one pre-existing hook warning
GUI/package build: exit 0
privacy scan: passed
Tauri Rust tests: 2 passed, 0 failed
Tauri Clippy -D warnings: exit 0

The one uninterrupted 70-step scenario is still required. Mature ratcheted
private messaging, private attachments/multi-device fan-out, elevated helper,
official browser surface, optional Server service/update UX, signing/automatic
updates, and full visual acceptance remain product gaps.
## Final source/package freeze - 2026-07-28

The final source state passed the complete repository suite (4,265 passed,
4 skipped, 0 failed; 21,702 expectations across 359 files), the dedicated
CoCodex suite (178 passed, 0 failed; 2,067 expectations), focused Git/GUI
coverage (4 passed, 0 failed; 137 expectations), TypeScript, GUI lint/build,
privacy scan, Rust tests, and Clippy. GUI lint retains only the pre-existing
use-app-route-state hook warning.

The final Tauri artifacts are recorded below. No claim is made that the
broader product brief or single 70-step scenario is complete.
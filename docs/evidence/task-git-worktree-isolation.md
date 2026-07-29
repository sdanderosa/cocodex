# Task-scoped Git worktree execution evidence

Implementation commit:
`89dc6a5d28039f2e8bd068867c670f3f71dc521a`

This slice makes new local code-agent configurations use a locked Git
worktree and branch per task by default. Legacy policies remain explicit
`shared` workspaces. The Client prepares and verifies the local worktree,
signs sanitized execution metadata with its device identity, waits for the
authoritative Server to acknowledge that report, and only then starts the
official Codex runtime in the prepared directory. Absolute local paths never
enter shared state.

## Focused Git, protocol, and security verification

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-task-worktree.test.ts `
  .\tests\cocodex-codex-agent-adapter.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\packages\cocodex-protocol\tests\protocol.test.ts --timeout 60000
```

Exit status: `0`. Relevant output: `31 pass`, `0 fail`, `183 expect()`
calls across five files in `3.77s`.

The real Git tests created a repository with a named `main` branch and base
commit, then proved:

- two tasks receive different locked branches and registered worktrees;
- modifying one task worktree does not modify the configured repository or
  the other task;
- the configured repository remains on its original branch and commit;
- an owned worktree can be verified and reused idempotently;
- dirty and detached repositories fail closed; and
- mismatched ownership, pre-existing paths, and unowned branches are not
  adopted or overwritten.

The adapter test proves the order is `prepare`, Server acknowledgement, then
Codex process spawn. Both process `cwd` and the official Codex `-C` argument
name the prepared worktree.

The Server test proves that a wrong host, a forged device signature, changed
metadata, replay with different content, and a correctly signed but
agent-component-substituted workspace report are rejected. An exact replay is
idempotent. The accepted report changes the task to `running`, stores the
signature and sanitized metadata, and appends an
`agent.execution.started` audit event.

## Complete CoCodex product gate

```powershell
$env:COCODEX_TEST_TRACE = "1"
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status: `0`. The three sequential phases reported:

- safety CLI process test: `1 pass`, `0 fail`, `10 expect()` calls;
- private-alpha process test: `1 pass`, `0 fail`, `69 expect()` calls; and
- protocol/server/client serial suite: `101 pass`, `0 fail`, `886 expect()`
  calls across 30 files.

Total: `103 pass`, `0 fail`, `965 expect()` calls, and no skipped CoCodex
tests.

The private-alpha harness built standalone Server, Client, and Codex fixture
executables. It ran one Server plus isolated Stephen and Kai Client residents
with separate identities, state roots, databases, account fixtures, and
workspaces over the real TLS/WSS transport. Trace checkpoints confirmed:

```text
artifacts built
clients connected
Stephen agent completed
Kai agent completed
private message decrypted
private message explicitly shared with agent
encrypted artifact consumed by Stephen agent
encrypted agents completed
stopping first server
first server stopped
offline queues accepted
clients reconnected
recovered snapshots received
clients stopped
```

This baseline deliberately configures its non-Git fixture directories as
`shared`, then asserts the Server records only `configured-workspace` and
null Git fields. The separate real-Git test covers the new default worktree
path. The baseline still proves reciprocal local-account execution, encrypted
private delivery, ciphertext-only server storage, encrypted agent/artifact
routing, ordered offline queues, and recovery after a real Server process
restart.

## Regression, build, and privacy verification

The upstream root suite contains 338 files and does not complete reliably as
one monolithic Bun process on this Windows runner. It was therefore executed
from the repository's isolated-home test wrapper in alphabetical batches,
with the process-heavy CoCodex files handled by the complete product gate
above. Final successful batch outputs included:

- files 0-29: `305 pass`, `0 fail`;
- files 30-39: `130 pass`, `0 fail`, one pre-existing platform skip;
- files 40-49: `125 pass`, `0 fail`;
- files 50-59: all ten files passed in fresh isolated processes;
- files 77-106: `529 pass`, `0 fail`;
- files 107-136: `431 pass`, `0 fail`;
- files 137-166: `388 pass`, `0 fail`;
- files 167-196: `366 pass`, `0 fail`;
- files 197-226: `324 pass`, `0 fail`;
- files 227-256: `464 pass`, `0 fail`;
- files 257-286: `334 pass`, `0 fail`, three pre-existing Windows signal
  skips;
- files 287-316: `305 pass`, `0 fail`; and
- files 317-337: `268 pass`, `0 fail`.

The skipped launcher tests are existing POSIX signal cases for `SIGINT`,
`SIGTERM`, and `SIGHUP`; no CoCodex or security test was disabled or skipped.
Environment-dependent CLI tests use isolated fake Codex runtimes, and the two
tests that specifically require Node accept `OCX_TEST_NODE_EXE` so the bundled
Node 24 runtime can be exercised without changing the runner's protected
`PATH`.

The following commands also exited `0`:

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run build:cocodex-client
cd gui
..\node_modules\.bin\bun.exe run build
..\node_modules\.bin\bun.exe run lint
cd ..
.\node_modules\.bin\bun.exe run privacy:scan
git diff --check
```

The GUI production build emitted only its existing large-chunk advisory.
Lint exited with zero errors and the pre-existing
`use-app-route-state.ts:84` hook warning. The privacy scan passed.

## Adversarial review

The final review checked path traversal, branch and ref injection, dirty-base
handling, unowned collision adoption, command-shell injection, host/task/
project substitution, signature forgery and replay, device revocation,
finished-task mutation, timestamp bounds, local-path disclosure, and
execution-before-acknowledgement.

Confirmed controls:

- every Git subprocess uses an argument array with `shell: false`;
- the worktree path is resolved and proven contained below the protected
  local state root;
- branch components are bounded and derived independently by Client and
  Server from the registered agent ID;
- the Server binds the report to the assigned approved host, project, task,
  agent, and device key;
- report fields use a domain-separated, length-prefixed Ed25519 transcript;
- only an exact duplicate report is idempotent;
- Codex does not spawn until the matching Server acknowledgement arrives; and
- CoCodex never stashes, force-resets, removes, or automatically cleans a
  worktree or branch.

Interrupted worktrees intentionally remain locked for explicit human review.
If Git creates a worktree but protected ownership persistence fails, the next
attempt refuses to adopt the unowned path or branch; manual repair is required
instead of destructive automatic cleanup.

## Primary files

- `src/cocodex/task-worktree.ts`
- `src/cocodex/agent-execution-client.ts`
- `src/cocodex/codex-agent-adapter.ts`
- `apps/cocodex-server/src/agent-execution.ts`
- `apps/cocodex-server/src/agent-routing.ts`
- `packages/cocodex-protocol/src/agent-signing.ts`
- `packages/cocodex-protocol/src/collaboration.ts`
- `gui/src/pages/CoCodex.tsx`
- `docs/adr/0024-cocodex-task-git-worktree-isolation.md`

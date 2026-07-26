# ADR 0032: Bound finite CLI and Windows test-process lifecycles

- Status: Accepted
- Date: 2026-07-26
- Scope: inherited OpenCodex regression gate and one-shot CLI termination

## Context

The inherited root suite contains 339 test files. On this Windows host, one
monolithic Bun test process continued running beyond 15 minutes. Splitting the
files into batches exposed a second failure mode: after enough nested CLI
process launches, one-shot `status`, `models`, or `provider` commands could
finish their visible work but leave the child process alive.

This was not an acceptable reason to skip the inherited suite. It also exposed
a production lifecycle defect: `handleModels` launched asynchronous add/remove
work without awaiting it, and finite CLI commands relied on implicit event-loop
drain instead of terminating after their work completed.

## Decision

1. `status`, `provider`, and `models` explicitly exit after their finite work
   has completed.
2. `handleModels` is asynchronous and awaits add/remove operations before the
   CLI exits.
3. `scripts/test.ts` accepts a validated `OCX_TEST_TIMEOUT_MS` override while
   preserving its disposable HOME, USERPROFILE, OPENCODEX_HOME, and CODEX_HOME.
4. `bun run test:batched` recursively discovers every `*.test.ts` file below
   `tests/`, sorts the complete set, and runs each file in a fresh isolated Bun
   test process.
5. A fresh worker process is created after at most 25 files. This bounds the
   Windows parent-process lifetime and avoids the process-launch degradation
   observed after long child chains.
6. Every file and worker has a hard timeout. A timed-out owned process is
   terminated as a process tree on Windows (or a process group on POSIX)
   before its disposable state is removed. Any nonzero exit or timeout fails
   the aggregate command.
7. Test children receive an allowlisted system environment plus explicit
   `OCX_TEST_*` controls. Ambient provider keys, tokens, and authenticated
   proxy variables are not inherited.
8. Live catalog synchronization after a finite custom-model mutation is
   bounded to five seconds. The saved mutation remains authoritative and a
   sync timeout is reported as a warning rather than hanging the CLI.

The inherited `bun run test` command remains unchanged for normal and upstream
parity. The batched command is the reliable Windows evidence gate.

## Consequences

- Windows validation takes longer and creates more processes, but it terminates
  predictably and reports the exact failed file.
- The existing symlink skip and three POSIX-signal skips remain visible on
  Windows. No CoCodex or security test is skipped.
- One-shot model mutations now complete before process exit instead of racing
  shutdown.
- The runner has explicit seams for batch size, worker size, per-test timeout,
  per-file timeout, and worker timeout without weakening default coverage.

## Verification

- `tests/test-runner.test.ts` proves disposable state roots, recursive
  discovery, exact partitioning, credential filtering, owned descendant-tree
  cleanup, and validated timeout arguments.
- The full 339-file command completed with 4,161 passing tests, zero failures,
  20,703 assertions, four existing platform skips, and exit status 0.
- The 48 CLI lifecycle tests passed three consecutive times after the repair.

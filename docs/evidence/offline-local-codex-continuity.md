# Offline host-local Codex continuity evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `d96e89521639e243fac7c6f6e892a643bce99af0`
- Implementation commit: recorded by the commit containing this file
- Status: focused real-process, complete CoCodex, inherited OpenCodex, GUI,
  type, build, and privacy gates pass

## Behavior proved

The resident Kai Client completed an official Codex JSONL turn after the
separate CoCodex Server process had terminated and both Clients had reported
`disconnected`. The turn:

- ran in Kai's isolated workspace;
- used the Kai account fixture through the existing local Codex runtime
  resolver and adapter;
- streamed a real account-marked result through the resident Client;
- wrote the Codex fixture's execution marker on Kai's filesystem;
- left the authoritative Server `agent_tasks` row count unchanged; and
- left the original Kai Client PID resident.

Kai and Stephen then queued shared chat and end-to-end encrypted private
messages. After the Server restarted, both resident Clients reconnected,
flushed those queues, recovered ordered history, and retained the additional
Kai-local usage count.

## Real three-process evidence

```powershell
$env:COCODEX_TEST_TRACE='1'
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status `0`: `1 pass`, `0 fail`, `280 expect()` calls.

Relevant trace:

```text
[private-alpha] first server stopped
[private-alpha] Kai completed local Codex while collaboration server was offline
[private-alpha] offline queues accepted
[private-alpha] clients reconnected
```

The first two development runs are not counted as passing evidence: one exposed
a Windows-specific killed-process property assumption and the next correctly
showed that Kai's signed usage total increased from three to four after the new
local turn. Both assertions were repaired before the clean run above.

## Complete CoCodex regression

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status `0`: `156 pass`, `0 fail`, `1434 expect()` calls across 35 files.
The wrapper includes the same real compiled-process harness plus protocol,
Server, Client, execution, encryption, recovery, GUI-bridge, and security
tests.

## Static, build, and privacy evidence

The following commands exited `0`:

- `bun run typecheck`
- `bun run build:cocodex-server`
- `bun run build:cocodex-client`
- `bun run privacy:scan`

The compiled Client help includes:

```text
cocodex local-codex --workspace PATH --prompt TEXT [--model ID] [--effort LEVEL]
```

## Inherited OpenCodex regression

```powershell
.\node_modules\.bin\bun.exe run test:batched
```

Exit status `0`: all `346` files completed across `14` fresh workers. This
exercised the preserved proxy, provider, account, model, usage, service,
security, and Windows behavior in isolated batches.

## GUI regression

The following commands ran from `gui` and exited `0`:

- `bun test`: `118 pass`, `0 fail`, `573 expect()` calls across 21 files
- `bun run lint`: no errors; one pre-existing exhaustive-deps warning
- `bun run lint:i18n`
- `bun run build`: production TypeScript and Vite build completed

## Primary files

- `src/cocodex/local-codex.ts`
- `src/cocodex/session.ts`
- `src/cocodex/cli.ts`
- `tests/cocodex-private-alpha-process.test.ts`
- `docs/adr/0043-cocodex-offline-local-codex-continuity.md`
- `docs/cocodex-client.md`

## Limits

This checkpoint does not claim completion of collaborative shared-draft
submission, ratcheted multi-device private messaging, production installers,
or the remaining long-term CoCodex product vision.

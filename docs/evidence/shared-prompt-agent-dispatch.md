# Shared-prompt agent-dispatch evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `ba3c19b61c2265e3e8d7c6679acc9a50193cca81`
- Implementation commit: recorded by the commit containing this file
- Status: real encrypted three-process path and GUI regression pass

## Behavior proved

The compiled Stephen and Kai Clients subscribed to the same encrypted
per-chat prompt. Each created an independent Yjs update from an empty
document. The Server stored and routed only encrypted update envelopes. Both
Clients received both updates, applied them locally, and converged on the same
text containing both authors' edits. Kai then dispatched that merged value to
Lucas, the agent hosted by Stephen. Stephen approved it and the local official
Codex fixture executed it in Stephen's workspace.

The GUI command builder separately proves that selecting an agent uses the
shared prompt rather than the local chat draft, while ordinary chat remains
isolated. It rejects a blank selected source and snapshots artifact IDs.

## Focused real-process evidence

```powershell
$env:COCODEX_TEST_TRACE='1'
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status `0`: `1 pass`, `0 fail`, `285 expect()` calls.

Relevant trace:

```text
[private-alpha] clients connected
[private-alpha] concurrent shared prompt converged
[private-alpha] Lucas and Angela completed concurrently
```

## GUI evidence

```powershell
cd gui
..\node_modules\.bin\bun.exe test
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run lint:i18n
..\node_modules\.bin\bun.exe run build
```

Exit status `0`: `122 pass`, `0 fail`, `579 expect()` calls across 22 GUI
test files. Lint completed with no errors and one unrelated pre-existing
exhaustive-deps warning; the production TypeScript/Vite build completed.

## Complete CoCodex and static regression

The following commands exited `0`:

- `bun run test:cocodex`: `156 pass`, `0 fail`, `1434 expect()` calls across
  35 files; its focused three-process phase reported 285 assertions
- `bun run typecheck`
- `bun run privacy:scan`

## Primary files

- `gui/src/cocodex-composer-state.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/tests/cocodex-composer-state.test.ts`
- `tests/cocodex-private-alpha-process.test.ts`
- `docs/adr/0044-cocodex-shared-prompt-dispatch.md`

## Limits

Presence carets remain advisory absolute offsets, as documented. This
checkpoint does not claim a rich-text editor, inline remote caret overlay, or
stable Yjs RelativePositions.

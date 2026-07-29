# Explicit encrypted artifact-to-agent handoff evidence

Implementation commit: `90873ca2`

This slice connects the previously independent encrypted artifact and local
agent paths. A requester can publish a ready artifact, explicitly select it as
an input to one agent request, and have the remote host verify and decrypt that
exact artifact before its local Codex runtime starts. The ordered artifact IDs
are persisted and bound into the server dispatch signature. The server
validates that every ID belongs to the project but stores and routes only
opaque artifact envelopes.

The host verifies the server signature before any decrypt callback, verifies
the ID/envelope mapping and each enrolled sender signature, rejects
non-consumable statuses, and labels artifact contents as untrusted reference
data inside a bounded in-memory prompt. The GUI lists encrypted project
artifacts, publishes ready handoffs, and requires an explicit selection.

## Focused real-process and security verification

```powershell
.\node_modules\.bin\bun.exe test `
  .\packages\cocodex-protocol\tests\protocol.test.ts `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\apps\cocodex-server\tests\database-migration.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status: `0`; relevant output: `31 pass`, `0 fail`, `220 expect()`
calls. The three-process test built a standalone Server, Client, and Codex
fixture, ran one Server plus isolated Stephen and Kai residents, and proved:

- Kai's encrypted ready artifact is accepted without plaintext server storage;
- the exact artifact ID is carried on the signed task dispatch;
- Stephen approves and executes the task on Stephen's local account;
- Stephen's local Codex fixture receives both the normal prompt and the
  `ARTIFACT-HANDOFF-CANARY-4pV7s` artifact content;
- a substituted artifact ID prevents even the host decrypt callback;
- a missing artifact ID is rejected by server authority; and
- encrypted chat, reciprocal execution, private messaging, offline queues,
  server restart, and ordered recovery remain green.

## Complete CoCodex suite

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
```

Exit status: `0`; relevant output: `96 pass`, `0 fail`, `894 expect()` calls
across 30 files in `47.22s`. No tests were skipped or disabled.

## Static, GUI, and privacy verification

```powershell
.\node_modules\.bin\tsc.exe --noEmit
.\node_modules\.bin\tsc.exe -p gui\tsconfig.json --noEmit
.\node_modules\.bin\tsc.exe -p packages\cocodex-protocol\tsconfig.json --noEmit
.\node_modules\.bin\tsc.exe -p apps\cocodex-server\tsconfig.json --noEmit
cd gui
..\node_modules\.bin\bun.exe run build
..\node_modules\.bin\bun.exe run lint
cd ..
.\node_modules\.bin\bun.exe run privacy:scan
```

Every command exited `0`. The production GUI build completed; lint retained
the one pre-existing `use-app-route-state.ts:84` hook warning and no errors;
the privacy scan passed. Schema migration 20 and
`input_artifact_ids_json` are covered by the legacy-database migration test.

After the implementation commit, the server test was extended with an artifact
that exists in a different encrypted project. This focused command:

```powershell
.\node_modules\.bin\bun.exe test `
  .\apps\cocodex-server\tests\agent-routing.test.ts `
  .\tests\cocodex-agent-bridge-recovery.test.ts --timeout 120000
```

exited `0` with `10 pass`, `0 fail`, and `57 expect()` calls. It proves both
missing and cross-project artifact IDs are rejected, and that signature
substitution is rejected before decryption.

A later attempt to combine all five focused files in one concurrent Bun
invocation timed out at 120 seconds after the 30 protocol/routing/migration/
bridge tests passed and while the three-process file was starting. Process and
listener inspection found no orphaned CoCodex processes. The real three-process
file was immediately rerun alone and exited `0` with `1 pass`, `0 fail`, and
`68 expect()` calls in `7.73s`. The timed-out command is not counted as a
successful gate.

Primary files:

- `packages/cocodex-protocol/src/project-agent.ts`
- `packages/cocodex-protocol/src/agent-signing.ts`
- `apps/cocodex-server/src/encrypted-agent-routing.ts`
- `apps/cocodex-server/src/encrypted-artifacts.ts`
- `src/cocodex/session.ts`
- `src/cocodex/agent-bridge.ts`
- `gui/src/pages/CoCodex.tsx`
- `docs/adr/0023-cocodex-explicit-encrypted-artifact-inputs.md`

# Yjs-relative shared-prompt presence evidence

- Date: 2026-07-27
- Implementation commit: `349f32effe356a43aeb58073556e8ed72ec4eb51`
- Scope: chat-scoped ephemeral caret/selection/typing presence whose Yjs
  RelativePositions remain stable across ordinary concurrent textarea edits.

## Completion evidence

### CRDT behavior

Command:

```text
.\node_modules\.bin\bun.exe test .\gui\tests\cocodex-prompt-presence.test.ts
```

Exit status: `0`

Relevant output:

```text
2 pass
0 fail
CoCodex shared-prompt presence > tracks a remote selection across concurrent CRDT inserts
CoCodex shared-prompt presence > bounds legacy offsets and safely rejects malformed relative positions
```

The concurrency test uses two real `Y.Doc` replicas and the same minimal
prefix/suffix edit helper called by the production textarea.

### Protocol bounds and compatibility

Command:

```text
.\node_modules\.bin\bun.exe test .\packages\cocodex-protocol\tests\protocol.test.ts --timeout 30000
```

Exit status: `0`

Relevant output:

```text
24 pass
0 fail
159 expect() calls
CoCodex protocol > bounds presence cursor and caret frames
CoCodex protocol > strictly validates server presence snapshots, updates, and leaves
```

The assertions cover canonical Base64, noncanonical padding-bit rejection,
the exact 384-byte/512-character limit, oversize rejection, legacy omission,
and rejection of prompt presence without a chat ID.

### Real process and network behavior

Command:

```text
.\node_modules\.bin\bun.exe test .\apps\cocodex-server\tests\collaboration-server.test.ts --timeout 60000
```

Exit status: `0`

Relevant output:

```text
8 pass
0 fail
126 expect() calls
authenticated WSS collaboration > encrypted chat subscriptions also carry independent presence awareness
```

The test starts a real TLS/WSS server, authenticates Stephen and Kai as
separate cryptographic devices, opens two authoritative chats, relays an
opaque RelativePosition within the active chat, verifies the other chat's
snapshot is redacted, rejects a null-chat prompt-presence attempt, and keeps a
receiving-socket listener active through a bounded delivery window to prove no
cross-chat live update arrives.

### GUI, bridge, build, and privacy regression

Commands and exit statuses:

```text
.\node_modules\.bin\bun.exe test .\gui\tests
# exit 0: 124 pass, 0 fail

.\node_modules\.bin\bun.exe test .\tests\cocodex-gui-bridge.test.ts --timeout 30000
# exit 0: 1 pass, 0 fail, 109 assertions

.\node_modules\.bin\bun.exe run typecheck:cocodex
# exit 0

cd gui
..\node_modules\.bin\bun.exe run lint
# exit 0, with one pre-existing use-app-route-state warning

..\node_modules\.bin\bun.exe run build
# exit 0

.\node_modules\.bin\bun.exe run privacy:scan
# exit 0: Privacy scan passed
```

The GUI bridge assertion proves the renderer-provided relative anchors reach
the resident session without expanding the bridge's sensitive-field exposure.

## Files involved

- `gui/src/cocodex-prompt-presence.ts`
- `gui/src/pages/CoCodex.tsx`
- `packages/cocodex-protocol/src/collaboration.ts`
- `src/cocodex/gui-bridge.ts`
- `src/cocodex/session.ts`
- `apps/cocodex-server/src/server.ts`
- `gui/tests/cocodex-prompt-presence.test.ts`
- `packages/cocodex-protocol/tests/protocol.test.ts`
- `tests/cocodex-gui-bridge.test.ts`
- `apps/cocodex-server/tests/collaboration-server.test.ts`

## Independent review

The security reviewer initially found three blockers: noncanonical Base64,
replace-all Yjs editing, and cross-chat live presence leakage. All three were
repaired. The final re-review reported no blockers.

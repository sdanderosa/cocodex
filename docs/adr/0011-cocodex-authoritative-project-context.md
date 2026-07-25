# ADR 0011: Revisioned authoritative project context

- Status: Accepted for private alpha
- Date: 2026-07-25

## Decision

Store each project's pinned Final Goal and structured context in the CoCodex
Server SQLite database. Expose it through authenticated `context.get` and
`context.update` frames on the existing TLS/WSS port. Every write supplies the
last observed revision; the server accepts only an exact match, increments the
revision transactionally, and broadcasts the accepted value to project
members.

Client context writes use the existing durable outbox. Offline writes replay in
FIFO order after reconnect. A revision conflict is non-retryable for the stale
payload: the client reports the conflict and removes that event so it cannot
block later queued work. The user must refresh and explicitly rebase before
retrying.

## Rationale

The server is already authoritative for projects, chat order, tasks, and
artifacts. Keeping the Final Goal next to that state makes restart recovery and
audit straightforward. A monotonic optimistic-concurrency revision is enough
for a pinned goal and structured metadata; introducing a second CRDT would
conflict with the selected Yjs design for concurrent prompt text and add
unnecessary merge and security surfaces.

The server validates project membership before reads and writes, bounds the
goal and serialized context, stores only JSON, and returns the canonical
revision and updater identity. The local client decides whether shared context
is included in an agent prompt. Private-message ciphertext is not decoded or
implicitly copied into this context.

## Alternatives considered

- **Yjs or Automerge for all context:** rejected for this small authoritative
  record; Yjs remains the selected solution for the collaborative prompt, while
  structured context needs conflict detection and audit-friendly revisions.
- **Client-only Final Goal:** rejected because members must recover the same
  value after reconnect and server restart.
- **Last-write-wins:** rejected because a stale client could silently erase a
  newer goal or project metadata.

## Evidence

- `apps/cocodex-server/tests/shared-state.test.ts` verifies the default record,
  revision-one persistence, membership checks, and stale-writer rejection.
- `apps/cocodex-server/tests/collaboration-server.test.ts` verifies real WSS
  get/update frames, member broadcasts, and recovery after a server restart.
- `tests/cocodex-outbox.test.ts` verifies offline persistence and removal of a
  non-retryable stale update.
- `packages/cocodex-protocol/tests/protocol.test.ts` verifies strict bounded
  context frames.

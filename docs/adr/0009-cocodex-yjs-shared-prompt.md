# ADR 0009: Yjs shared prompt over the authoritative CoCodex transport

- Status: Accepted for private alpha
- Date: 2026-07-25
- Parent decisions: [ADR 0007](./0007-cocodex-private-alpha-architecture.md), [ADR 0008](./0008-cocodex-local-gui-and-execution-recovery.md)

## Context

Stephen and Kai need to edit one prompt concurrently, continue producing local
updates during a collaboration-server outage, converge after reconnect, and
recover the document after a server restart. Implementing a custom merge
algorithm would add unnecessary correctness and security risk.

Yjs is a mature, network-agnostic CRDT with idempotent binary updates and state
snapshots. Stable Yjs 13.6.31 and its lib0 dependency are MIT licensed. The
notices are included in `THIRD_PARTY_NOTICES.md`.

## Decision

Each project owns one Yjs `Y.Doc` with a `Y.Text` named `prompt`.

- The GUI creates and applies Yjs updates; it does not merge strings itself.
- The resident client durably queues `prompt.update` frames in the same atomic
  outbox as chat, private-message, and agent-request events.
- The authenticated CoCodex Server checks project membership before returning
  a snapshot or accepting an update.
- The server applies updates with Yjs, bounds update/state/text sizes, stores
  the canonical encoded state in SQLite, and records update IDs for changed-ID
  replay rejection and identical replay idempotency.
- Prompt subscriptions and broadcasts use the existing pinned TLS/WSS port.
  No second listener or Hocuspocus service is required for the private alpha.
- Clients resubscribe after reconnect and apply the full authoritative state.

Hocuspocus remains an architectural reference for authorization hooks and
transport lifecycle. Adding it now would duplicate the authenticated WSS
transport already required by the private-alpha path. It can be reconsidered
when awareness/caret protocols or horizontal collaboration scaling justify it.

## Security and limits

Yjs provides convergence, not authorization or sanitization. CoCodex therefore
checks membership before every snapshot/update, uses strict protocol schemas,
limits a single update to 128 KiB, the encoded document state to 512 KiB, and
prompt text to 32,768 characters. Update IDs are scoped to immutable sender,
project, and bytes. The server stores no executable interpretation of prompt
text.

The current slice synchronizes prompt text and offline updates. Remote carets,
selections, named awareness states, historical revision UI, and compaction are
later product requirements.

## Evidence

- strict prompt frame protocol tests;
- durable offline prompt-update outbox test;
- real two-client concurrent updates over WSS that converge under Yjs;
- SQLite restart snapshot recovery;
- GUI typecheck, lint, tests, and production build.
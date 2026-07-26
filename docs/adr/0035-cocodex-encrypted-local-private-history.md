# ADR 0035: CoCodex encrypted local private history

- Status: Accepted for the single-device private alpha
- Date: 2026-07-26
- Scope: sender echo, offline-readable private history, restart recovery, and
  local search

## Context

The private alpha already delivered signed sealed-box messages and retained
server cursors, but a cursor is not a user-visible history. Successfully opened
messages disappeared from the Client UI after a Client process restart, and a
sender could not decrypt the recipient envelope to reconstruct their own side
of the conversation. Replies, edits, deletion, notifications, and useful local
search all require a trustworthy local timeline first.

Persisting plaintext would widen the compromise boundary and contradict the
private-message requirements. Sending a second copy to the Server would also
give the Server unnecessary data and would not make the sender's local history
available while offline.

## Open-source reference and licensing decision

Matrix and Signal clients persist encrypted per-device state and reconstruct
user-visible timelines locally; Syncthing binds durable trusted state to a
cryptographic device identity. CoCodex adapts those boundaries only. It does
not copy Matrix, Signal, Syncthing, or libsignal source and adds no dependency.
The existing ISC-licensed `libsodium-wrappers-sumo` sealed-box implementation
remains the only private-history cryptographic dependency.

## Decision

Add a protected, bounded `private-history.json` owned by one CoCodex Client
device. Every entry stores routing metadata and one `localCiphertext`:

- received messages retain the original recipient ciphertext;
- sent messages create a separate self-sealed local copy with the same signed
  payload while the Server receives only the recipient ciphertext; and
- Server acceptance updates only the local sequence and acceptance timestamp.

Outgoing entries move through `staged`, `queued`, and `accepted` states. On
startup the Client reconciles staged entries against the durable outbox:
entries whose network envelope reached the outbox become queued, while
pre-outbox crash remnants are removed and never rendered as sent.

The Client decrypts history only in the resident process, verifies the original
Ed25519 sender identity and envelope binding again, and then emits the timeline
to the local GUI. The GUI deduplicates and orders accepted entries by
authoritative Server sequence, with client time only as the pending-message
fallback. It shows a sender echo, supports local text filtering, and permits
offline queueing while the resident session is running.

History is capped at 512 ciphertext entries and 64 MiB. Accepted entries are
evicted before pending entries; when all 512 entries are unaccepted, sending
fails explicitly instead of destroying a recoverable sender copy. Writes use
the existing protected-directory ACL and atomic temporary-file rename pattern.
Plaintext, signatures, device private keys, and provider credentials are never
serialized into the history file.

## Security invariants

- An entry must involve the owning device as sender or recipient.
- Message IDs are immutable; reuse with different ciphertext or routing data is
  rejected.
- Server sequence and acceptance time cannot change after acknowledgement.
- A staged sender copy is rendered only after reconciliation proves that its
  recipient envelope exists in the durable outbox.
- Persisted delivery and read receipts replay alongside history while offline.
- Every restart replay repeats ciphertext decryption, sender-fingerprint
  verification, and signed-envelope validation before exposing text.
- The sender's self-copy is never transmitted to CoCodex Server.
- History plaintext remains excluded from agent context unless the user invokes
  the existing explicit `private.share` path.
- The history file is a bounded single-device cache, not a forward-secret
  ratchet store and not a backup of another device's session keys.

## Consequences and limits

Private text is now available after a Client restart and while collaboration is
offline, without plaintext at rest. Search is local to the loaded bounded
timeline. This does not implement conversations, replies, reactions,
edit/delete events, encrypted attachments, multiple devices, notification
delivery, a Double Ratchet, forward secrecy, or post-compromise recovery.
Those remain separate requirements governed by ADR 0022.

The single-device alpha assumes one history writer at a time. Concurrent use
of the standalone CLI and resident Client against the same state root is not
supported until the store gains locking or is routed through resident IPC.
The OS-user ACL is also the local tamper boundary: the manifest is not
independently MACed, and possession of the device messaging private key
permits local history decryption. These limits are not forward-secrecy or
rollback-protection claims.

## Evidence

- `tests/cocodex-private-history.test.ts` validates ciphertext-only persistence,
  self-decryption, device ownership, immutable acknowledgement, conflicting-ID
  rejection, staged-send reconciliation, and pending-preserving capacity.
- `tests/cocodex-private-alpha-process.test.ts` restarts Stephen's real Client
  process and recovers both an inbound message and Stephen's offline-queued
  outbound message while proving their plaintext canaries are absent from the
  history file, then restarts Kai with the Server stopped and recovers the
  authoritative message order and stored read receipt offline.
- `gui/src/pages/CoCodex.tsx` performs local filtering and renders sent,
  delivered, and read states without receiving local ciphertext.

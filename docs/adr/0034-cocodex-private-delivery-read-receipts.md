# ADR 0034: CoCodex private delivery and read receipts

- Status: Accepted for the single-device private alpha
- Date: 2026-07-26
- Scope: ciphertext-only private-message delivery/read state and reconnect recovery

## Context

The private-alpha message path already encrypts and signs message plaintext on
the client, but the sender had no durable indication that the approved
recipient opened a message. A local mailbox cursor is not a delivery receipt:
it is private to the recipient and cannot tell the sender what happened.
Receipts must therefore travel through the authoritative Server without
exposing private text or ciphertext.

## Decision

Add a separate `private_message_receipts` SQLite table with its own monotonic
sequence. A receipt contains only the message ID, authenticated sender and
recipient device IDs, `delivered` or `read`, and the server acceptance time.
The server derives the sender/recipient pair from the stored message, accepts a
receipt only from the original recipient, requires `delivered` before `read`,
and makes each `(message, recipient, kind)` insert idempotent. The Server
routes the receipt to the original sender and includes receipts in the private
snapshot using an independent cursor.

The Client queues a `delivered` receipt only after successful ciphertext
decryption, signature verification, and durable outbox insertion. The GUI can
explicitly issue `private.read` for a resident decrypted message. Receipt
state is retained in the protected local mailbox with a bounded independent
cursor, so a server restart cannot lose sender-visible status or cause an
unbounded replay.

Receipt metadata is authenticated by the existing TLS/WSS device proof and
server-side recipient binding. It is not a new cryptographic protocol and does
not claim an independent signed event envelope. A future multi-device protocol
must add the reviewed Matrix/Signal-style session state and signed receipt
transcripts before broadening this design.

## Security invariants

- The Server never decrypts or stores private-message plaintext.
- An outsider, sender, pending device, or revoked device cannot submit a receipt.
- `read` cannot precede `delivered`, and a later `delivered` cannot downgrade a
  message already marked `read`.
- Duplicate receipt submissions return the original row and do not broadcast a
  second event.
- Receipt snapshots are bounded and use a cursor independent from ciphertext
  message delivery.
- The renderer receives receipt metadata only; ciphertext, keys, signatures,
  and encrypted envelopes remain stripped at the GUI bridge.

## Consequences and limits

This closes the connected alpha delivery/read recovery path for one approved
recipient device. It does not implement conversations, attachments, replies,
reactions, edit/delete events, typing indicators, multi-device fan-out,
forward-secret ratchets, or post-compromise recovery. Those remain later
requirements gated by ADR 0022 and a maintained compatible crypto runtime.

## Evidence

- `packages/cocodex-protocol/tests/protocol.test.ts` validates receipt frame
  schemas and backward-compatible snapshot defaults.
- `apps/cocodex-server/tests/shared-state.test.ts` validates recipient binding,
  idempotency, ordering, read-after-delivered, and downgrade rejection.
- `apps/cocodex-server/tests/collaboration-server.test.ts` validates live WSS
  delivery, sender routing, ciphertext-only persistence, and snapshot recovery.
- `tests/cocodex-private-alpha-process.test.ts` validates resident delivery/read
  receipts and recovery after a real server restart.
- `tests/cocodex-private-mailbox.test.ts` and
  `tests/cocodex-gui-bridge.test.ts` validate protected local cursor state and
  renderer redaction.

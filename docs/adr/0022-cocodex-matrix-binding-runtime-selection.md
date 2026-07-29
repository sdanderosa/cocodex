# ADR 0022: CoCodex Matrix binding runtime selection

- Status: Accepted for the private alpha; Matrix migration pending runtime support
- Date: 2026-07-25
- Scope: maintained E2EE state-machine bindings considered for private messages

## Context

The open-source reference requirements prohibit inventing a ratchet or an
unreviewed CoCodex encryption protocol. Matrix Olm/Megolm and vodozemac are the
closest maintained architecture for per-device sessions, offline encrypted
delivery, device verification, and ciphertext-only server storage. The Matrix
Rust SDK also gives CoCodex a useful push/pull state-machine model: outgoing
requests, server responses, and incoming sync changes must be processed and
persisted in order.

The CoCodex Client and Server are Bun-native TypeScript applications compiled
for desktop distribution. A candidate binding must therefore work in Bun,
persist state durably, and ship without an unsupported native runtime or
unreviewed helper process.

## Evaluation

The following maintained Apache-2.0 packages were evaluated locally:

- [`@matrix-org/matrix-sdk-crypto-wasm@18.3.1`](https://www.npmjs.com/package/%40matrix-org/matrix-sdk-crypto-wasm)
  initialized its `OlmMachine` in Bun when no store was requested. Initializing
  its durable store failed because the Bun desktop runtime returned no
  IndexedDB implementation.
- [`@matrix-org/matrix-sdk-crypto-nodejs@0.6.1`](https://www.npmjs.com/package/%40matrix-org/matrix-sdk-crypto-nodejs)
  initialized with SQLite under the cached Node runtime and produced the
  expected crypto requests. Bun could not load the package's native binding
  without a platform-specific binary, and the package's Node-version/native
  distribution requirements do not match the compiled Bun client artifacts.

The upstream [Matrix Rust SDK](https://github.com/matrix-org/matrix-rust-sdk)
documents the no-network `OlmMachine` and its SQLite store, while the
[Node.js binding API](https://matrix-org.github.io/matrix-rust-sdk-crypto-nodejs/classes/OlmMachine.html)
confirms that it is a Matrix Olm/Megolm state machine. No Matrix source code
was copied, and the evaluated packages were removed from the CoCodex lockfile
after the runtime audit.

## Decision

Keep the existing `libsodium-wrappers-sumo` sealed-box plus signed-envelope
format for the private alpha. Add protocol-grade safeguards around it:

- canonical base64url ciphertext and bounded private frames;
- a single immediate SQLite transaction for the message and replay index;
- an atomic client mailbox file with a monotonic cursor and bounded receipts;
- serialized snapshot/live delivery processing so a failed message cannot poison
  every later message; and
- a one-second server authorization sweep that closes already-authenticated
  sockets after device revocation.

This is a deliberate compatibility decision, not a claim that sealed boxes are
equivalent to Matrix/Signal sessions. The current path remains single-device
private-alpha messaging and does not claim forward secrecy, break-in recovery,
key rotation, multi-device sessions, or Matrix interoperability.

## Migration gate

A future Matrix implementation may replace this envelope only when all of the
following are demonstrated in the supported packaged runtime:

1. durable encrypted per-device state survives restart and rollback-safe writes;
2. key upload/claim, sync, outgoing-request acknowledgement, and retry are
   integrated with CoCodex Server authority;
3. approval, verification, revocation, and device fingerprints remain
   CoCodex authorization decisions rather than implicit Matrix trust;
4. unknown-device, replay, skipped/out-of-order, lost-state, rotation,
   attachment, and server-ciphertext-only tests pass; and
5. the selected dependency's Apache-2.0 notices, native artifacts, and
   transitive licenses are included in the release review.

Until that gate is met, code review must reject any change that presents the
sealed-box path as a ratchet or silently falls back from the selected Matrix
state machine to an unreviewed primitive.

## Evidence

- `packages/cocodex-protocol/tests/protocol.test.ts` validates canonical
  private-frame bounds.
- `tests/cocodex-private-mailbox.test.ts` validates durable cursors, device
  binding, deduplication, and receipt bounds.
- `apps/cocodex-server/tests/collaboration-server.test.ts` validates the real
  WSS authorization-revocation sweep.
- `tests/cocodex-private-alpha-process.test.ts` exercises the real three-process
  reconnect path with private messages and local mailbox persistence.

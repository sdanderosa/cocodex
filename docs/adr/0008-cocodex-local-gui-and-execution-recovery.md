# ADR 0008: Local GUI bridge and crash-safe execution delivery

- Status: Accepted for private alpha
- Date: 2026-07-25
- Parent decision: [ADR 0007](./0007-cocodex-private-alpha-architecture.md)

## Context

The React dashboard needs to control the resident CoCodex Client without
placing device private keys, server certificate material, or the remote WSS
connection in browser JavaScript. Remote agent execution also needs a defined
crash window: an at-least-once server delivery must never silently execute the
same local task twice.

## Decision

### Loopback-only GUI bridge

The existing authenticated OpenCodex management listener owns a singleton
resident CoCodex session bridge. The browser can:

- read redacted connection status and bounded local session events;
- enroll the local device through the backend;
- start or stop the resident collaboration session;
- list projects, subscribe to chat, send chat, request a registered agent,
  explicitly trust a device, and send an encrypted private message.

The browser cannot submit arbitrary protocol frames or shell commands. The
bridge uses a fixed command allowlist and inherits the management API's
same-origin and API-auth checks. Device signing/encryption keys remain in the
hardened client state root. Private-message ciphertext is removed from GUI
event snapshots after the local session has handled it.

The collaboration server remains a separate process and is not hosted by this
management listener.

### Explicit private-message trust

Private alpha uses libsodium sealed boxes plus an Ed25519-signed inner
envelope. The sender explicitly enters the recipient device ID, independently
verified Ed25519 fingerprint, and an Ed25519-signed device key certificate
that binds the recipient device ID to its X25519 messaging key. The local
client persists the fingerprint in its protected trusted-device list and
rejects certificates whose signer does not match it. The collaboration server
cannot choose or substitute the recipient key. The recipient likewise rejects
an inner sender key whose fingerprint is not in that dedicated trust list.

This narrow design provides ciphertext-only server storage and authenticated
single-device delivery. It does not claim Double Ratchet forward secrecy,
post-compromise recovery, multi-device sessions, or Signal compatibility.

### Durable outbox and execution journal

Chat sends, private-message ciphertext envelopes, and signed agent requests
enter an atomic local outbox before delivery. Removal happens only after the
server acknowledges the exact request ID. A newly enqueued event cannot be
erased while an older acknowledgement is pending.

Before invoking Codex, the host client records the task ID as `started` in a
hardened execution journal. Every result chunk is journaled before network
delivery and removed only after the server acknowledges its event ID.

On redelivery:

- a new task executes once;
- a `started` task is not rerun and is completed with a deterministic
  interrupted-execution failure after pending chunks are replayed;
- a `finished` and acknowledged task is ignored;
- pending result events are replayed idempotently.

The server persists agent tasks, releases them only after the host announces
that its local bridge is ready, and accepts an identical result event ID
idempotently. The server derives the host from the authoritative agent record;
the requester cannot choose the target device.

### Runtime credential boundary

The official `codex exec --json --ephemeral` child process receives only a
small allowlist of operating-system, Codex-home, path, and deterministic test
fixture variables. Provider/API credentials and unrelated CoCodex environment
values are not inherited. The prompt is written to stdin with shell execution
disabled.

## Consequences

- GUI usability does not weaken the local-client execution boundary.
- A compromised collaboration server cannot directly invoke a raw shell or
  obtain browser-held device keys because the browser holds none.
- Execution recovery prefers an explicit failed task over an unsafe duplicate
  execution after a crash.
- Private-alpha recipients must exchange and verify fingerprints and messaging
  public keys; automatic key transparency remains future work.
- The GUI event buffer is bounded and process-local. Authoritative history
  always comes from the collaboration server.

## Required tests

- GUI hash routing and production build.
- Bridge command allowlist and ciphertext redaction.
- Outbox enqueue-versus-acknowledgement race.
- Journal `new`, `started`, `finished`, pending, and acknowledged states.
- Result-event idempotency and changed-duplicate rejection.
- Real three-process reciprocal execution, private ciphertext, forced server
  restart, same client PIDs, and offline queue recovery over TLS/WSS.
- Environment allowlist proving provider credentials are absent from the
  official Codex child process.

# ADR 0016: CoCodex encrypted agent prompts and results

- Status: Accepted for the keyed private-alpha path
- Date: 2026-07-25
- Scope: remote agent task prompts, streamed results, cancellation, and chat recovery when a project key exists

## Context

The server must route a remote task to the correct host without becoming a
plaintext prompt or result authority. A project key already protects shared
chat and artifacts, but the earlier agent transport still stored task prompts
and streamed output in `agent_tasks` and `chat_events`.

## Decision

Use the existing signed project-content envelope with `recordType: "task"` for
the requester prompt and `recordType: "agent-response"` for each streamed host
result. The requester seals the prompt locally. The server validates project
membership, current key epoch, envelope sender, task routing, dependencies,
expiry, and idempotency, then stores `[encrypted]` plus the opaque envelope.

The server signs a dispatch transcript that binds the task metadata, exact
envelope ciphertext, requester/target device IDs, and requester envelope
signature. The host verifies that proof and decrypts only after checking its
trusted requester key and local project key. The local Codex adapter receives a
normal in-memory task and executes on the host device; the server never sees
the prompt.

Each streamed result is sealed by the host, journaled locally for reconnect
replay, acknowledged by the server, and inserted into the authoritative
`project_chat_events` sequence with only task ID, final/status routing metadata,
and the opaque envelope. Clients decrypt the result and emit the existing
`agent.result` shape. Encrypted cancellation is routed as control only; the
host emits the encrypted terminal failure event so result attribution remains
host-bound. Plain legacy tasks keep the existing plaintext compatibility path
when no project key is available.

## Rejected alternatives

- Do not put plaintext task prompts or result content in server rows merely to
  simplify dependency checks or UI rendering.
- Do not let the server decrypt project content or fabricate a host-signed
  result during cancellation.
- Do not copy MeshCentral, OpenHands, Matrix, Signal, or RustDesk source code;
  reuse only the independently implemented architecture and maintained
  dependencies already selected by the project.

## Consequences and remaining work

The keyed agent path is ciphertext-only at the server and recovers streamed
results from SQLite after a restart. Legacy plaintext compatibility remains
for projects without a key, and file references, full multi-device ratchets,
automatic key rotation orchestration, and richer agent artifacts still require
separate decisions and end-to-end coverage.

## Evidence

- `packages/cocodex-protocol/tests/protocol.test.ts` checks strict encrypted
  request/task/result schemas and rejects a plaintext field.
- `apps/cocodex-server/tests/agent-routing.test.ts` checks opaque storage,
  dependencies, and cancellation authorization.
- `tests/cocodex-agent-bridge-recovery.test.ts` checks encrypted cancellation
  produces an opaque terminal result.
- `tests/cocodex-private-alpha-process.test.ts` runs one real TLS/WSS server and
  isolated Stephen/Kai client processes, executes reciprocal encrypted tasks,
  checks SQLite canaries, and recovers encrypted result events after restart.

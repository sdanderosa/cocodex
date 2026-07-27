# ADR 0041: Authoritative project lock and unlock

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** Shared project writes, remote agent execution, owner incident
  control, reconnect, and local execution safety

## Context

A project owner needs one emergency control that freezes new shared changes
and server-routed execution without disconnecting every member, destroying
history, revoking project keys, or disabling ordinary local OpenCodex work.
A renderer-only flag or a check in one WebSocket route would leave direct
storage calls, queued work, agent-ready replay, and reconnect paths open.

## Decision

Every project has an authoritative SQLite lock record. New projects begin
`active` at revision 0. Only the current approved owner may submit a strict
`project.lock.update` frame. The resident Client signs a length-prefixed
transcript binding the operation ID, project, action, expected revision,
bounded reason, stable enrolled server endpoint fingerprint and authority
epoch, validity window, and a canonical 32-byte nonce.

The Server verifies the enrolled Ed25519 owner key and executes each transition
in one immediate transaction. A lock:

1. advances the monotonic revision;
2. stores the owner, reason, signature, nonce, authority binding, and exact
   replay record;
3. terminally fails every queued or running task in the project;
4. stores durable per-host cancellation deliveries;
5. expires pending project invitations;
6. records an audit event; and
7. publishes a bounded lock-state notice and clears ephemeral presence.

Exact replay of the same signed operation remains idempotent after its original
validity window only while that transition is still the current authoritative
revision. A superseded operation cannot regress a reconnecting client. A reused
operation ID with changed content, a stale revision, a wrong authority binding,
an invalid signature, a member request, or a same-state transition fails
closed. Unlock advances the revision again and never resurrects canceled tasks
or expired invitations.

Read-only history, member/device removal and key recovery, explicit task
cancellation, device revocation, key rotation, private messaging, usage
reporting, and local OpenCodex remain available while locked. New membership,
shared chat, prompt, context, artifact, file-reference, presence, invitation,
agent registration, agent request, execution-report, and result writes are
rejected. Pending-task queries also require an active project so reconnect and
dependency release cannot redispatch locked work.

The resident Client retains the last authoritative state, blocks new
project mutations while locked, and drops an already queued mutation after an
authoritative `PROJECT_LOCKED` rejection so it cannot replay unexpectedly
after unlock. A project lock pauses each matching local agent bridge before
encrypted prompt decryption or authorization and aborts active work. This
pause is separate from the host's durable emergency stop: owner unlock cannot
resume an agent the host stopped locally.

The GUI receives only a projected lock DTO. It never receives owner signatures,
nonces, task IDs, key material, certificates, or ciphertext. Owner controls
remain advisory; the Server rechecks authority.

## Open-source reference and licensing decision

MeshCentral's Apache-2.0 authoritative-server/installed-agent boundary informs
the rule that the Server validates and routes a stop while the endpoint Client
aborts local execution. GitHub and GitLab archival behavior informed the
readable-but-not-writable project state and explicit restoration action.
Syncthing's explicit cryptographic device identity informed owner authority.

Only concepts were adapted. No source was copied and no dependency was added.
The existing MIT/ISC-compatible protocol, SQLite, Ed25519, and local runtime
components implement the slice independently.

## Security consequences

- A lock is an authorization freeze, not cryptographic revocation. Members
  retain ciphertext and keys they already possessed. A compromised device
  still requires revoke/remove plus key rotation.
- Mutation checks exist in synchronous authoritative storage paths and the WSS
  boundary. The single-authority server performs those checks and writes
  without an asynchronous yield; the immediate lock transaction serializes
  against other writes on the authoritative SQLite connection.
- Durable transition and cancellation evidence survives server restart.
- Unlock cannot clear local emergency-stop or full-computer policy state.
- The lock tables add only bounded reasons, signatures, authority metadata,
  and task identifiers. Encrypted project paths remain ciphertext-only; the
  separately documented legacy compatibility paths may retain plaintext.
- Cancellation delivery is deliberately at-least-once and idempotent. The
  newest 512 durable cancellations are replayed per host connection and rows
  are removed by the existing task/project foreign-key lifecycle.

## Evidence requirement

Completion requires protocol transcript/schema tests, migration and storage
tests, mutation rejection, task-cancellation evidence, local bridge and GUI
boundary tests, real TLS/WSS lock/restart/unlock coverage, privacy scanning,
and all inherited OpenCodex tests.

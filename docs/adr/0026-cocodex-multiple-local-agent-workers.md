# ADR 0026: Multiple local agent workers per Client

- Status: Accepted
- Date: 2026-07-26
- Scope: concurrent local agents, worker leases, policy migration, and
  agent-scoped execution state

## Context

The private-alpha scenario requires one Stephen Client to host Lucas and
Angela concurrently. The original Client had one local policy, one safety
file, one execution journal, and one agent bridge attached to the shared
collaboration socket. Adding a second policy would either overwrite the first
or let unrelated workers consume the same broadcast task.

MeshCentral's authoritative-server/local-endpoint boundary and OpenHands'
runtime-session separation are architectural references only. No source was
copied. The implementation continues to use OpenCodex and the official Codex
runtime.

## Decision

One resident Client maintains:

- one authenticated control WSS connection for shared projects, chat, prompt,
  private messages, artifacts, presence, and usage;
- one authenticated worker WSS connection for each enabled local agent;
- an agent-bound `agent.ready` lease on each worker connection;
- one bridge, safety record, execution journal, and worktree registry per
  agent; and
- an aggregate usage projection whose active-agent count is the sum of active
  local workers.

The local policy file has a bounded version-2 container with one to eight
unique agent entries. Version-1 single-agent policies remain readable. When a
second agent is added, legacy singleton runtime state is copied atomically into
the first agent's scoped directory before the version-2 policy becomes the
commit marker. The original files are retained for recovery.

The Server permits up to eight agents for one host/project. It binds every
plaintext or encrypted result to the authenticated socket's exact ready agent
lease. A worker for Angela cannot complete Lucas's task even though both use
the same approved host device.

## Security and failure behavior

- Agent identity comes from the signed server definition and authenticated
  worker lease, never the display name.
- Missing agent-scoped safety state fails closed with execution and
  full-computer access disabled.
- Full-computer access remains a separate local enable action for each agent.
- Cancellation for an unknown task is ignored by a bridge, so a broadcast
  cancellation cannot abort another local agent's work.
- Worker shutdown closes every socket, aborts its bridge, and awaits all
  reconnect loops.
- The policy cap, unique IDs, strict ready-ack schema, and exact result binding
  prevent unbounded or cross-agent worker registration.

## Consequences and limits

Agents can execute concurrently when they use separate workspaces or
task-scoped Git worktrees. Two agents deliberately configured against the same
shared directory can still race; the GUI defaults code agents to
`git-worktree`.

The policy container is atomically replaced, but server registration plus
local policy commit is not yet one crash-atomic cross-process transaction. A
crash between those steps can leave an offline roster entry. The trusted-device
store is device-wide, although each policy records its own requester trust.
Device-wide concurrency limits across all local agents and automatic
invalidation after project-member removal remain follow-ups.

## Evidence

- Policy migration and safety isolation:
  `tests/cocodex-agent-safety.test.ts`
- Exact worker-result lease enforcement over real TLS/WSS:
  `apps/cocodex-server/tests/collaboration-server.test.ts`
- Two ready workers in one resident Client:
  `tests/cocodex-project-encryption-session.test.ts`
- Deterministic concurrent runtime execution and restart recovery:
  `tests/cocodex-private-alpha-process.test.ts`

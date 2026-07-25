# ADR 0018: CoCodex authoritative agent roster and status

- **Status:** Accepted for the private-alpha roster slice
- **Date:** 2026-07-25
- **Scope:** Named-agent discovery and server-derived availability in the
  shared project UI

## Context

The private-alpha path needs both members to see the same named agents and to
know whether a destination can accept work. A client-supplied name or a GUI
counter is not authoritative: the server owns project membership, agent
registration, task state, and the host-device trust boundary. MeshCentral's
authoritative server / local endpoint-agent boundary is the closest reference,
while OpenHands contributes only typed event and streaming concepts.

The first slice must remain small and connected. It does not attempt to build
the complete future agent registry, co-agent graph, activity feed, or desktop
automation surface before the reciprocal private-alpha execution path is
stable.

## Decision

Add a strict `agent.list` request and `agent.list.result` response to the
versioned WSS protocol. The server derives each `AgentView` from the project
membership, registered agent row, host approval state, host socket readiness,
and persisted task rows. The response contains only bounded display and task
metadata:

- stable agent ID, project ID, display name, and approved host device;
- enabled flag and server-derived status (`offline`, `available`, `queued`,
  `working`, `completed`, or `failed`);
- active and queued task counts;
- the last accepted or completed task timestamp.

The client identifies the named agent in its `agent.ready` bridge message. A
legacy bridge without an agent ID is accepted only when that device has one
enabled registered agent; multi-agent hosts must identify the agent explicitly.
An authenticated device with no enabled registered agent is rejected rather
than being treated as ready for every agent on that device.
The server binds readiness and pending-task delivery to that registered agent,
and the local bridge rejects a task whose agent ID does not match its policy.
The GUI requests the roster on project subscription and refreshes it while
connected; it hides stale data while disconnected and rejects frames for
another project.

The same authority exposes `agent.task.list.result`, a bounded projection of
the project task graph. It includes agent identity, requester/host device IDs,
status, dependency IDs, accepted/start/completion timestamps, event count, and
an encrypted flag. It deliberately omits prompts, result text, private
messages, and provider data. Legacy and encrypted result tables are combined
so the activity card remains useful without decrypting server-side.

## Security and authority

- The server checks project membership before listing anything.
- Host display names come from the approved device row, never from a request.
- Readiness is tied to an authenticated, approved socket that has announced
  the same enabled, project-member agent ID; a disconnected or revoked host is
  `offline`.
- Task counts and terminal status are derived from SQLite task records, not
  client claims. The server never exposes prompt, result, private-message, or
  provider-account data in the roster.
- Protocol schemas are strict and bounded. Unknown fields, oversized lists,
  invalid UUIDs, invalid timestamps, and negative counts are rejected.
- Task activity is derived from authoritative task/event rows. The client
  cannot invent a status, dependency, timestamp, or event count.
- The roster is advisory routing state. `agent.request` still performs the
  complete server authorization, signature, dependency, replay, and local-host
  policy checks before execution.
- Member removal invalidates queued work for that host and requires an owner
  key rotation before encrypted writes resume; the roster never overrides that
  project-key gate.

## Reuse and licensing

Only architectural concepts from MeshCentral and OpenHands are reused. No
source code is copied and no new dependency is added. The approach remains
compatible with the MIT CoCodex distribution and its existing dependency
notice review.

## Focused evidence

The bounded roster slice is covered by:

- `CoCodex protocol > strictly validates the authoritative agent roster`;
- `authoritative agent dependencies > lists only project agents with
  server-derived host and task status`;
- `authenticated WSS collaboration > two members share authoritative chat
  order and recover history by cursor` (including roster discovery);
- `CoCodex GUI bridge > runs the resident session without exposing private
  ciphertext` (including the `agent.list` command allowlist).
- `CoCodex protocol > strictly validates task activity without carrying prompt
  content` and the WSS collaboration task-list assertions.

The current working-tree validation command and result are recorded in
`docs/evidence/private-alpha.md`. Persistent activity history, task editing,
dependency-graph visualization, co-agents, full computer/browser tools, and
privileged helpers remain explicitly deferred requirements.

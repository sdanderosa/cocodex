# ADR 0025: Authenticated self-hosted agent setup

- Status: Accepted
- Date: 2026-07-26
- Scope: first desktop workflow for creating a named agent and binding its local execution policy

## Context

Agent routing was already end-to-end, but setup required two unrelated operator
commands: `cocodex-server agent-add` for shared authority and
`cocodex-client configure-agent` for host-local policy. That made the normal
desktop product unable to create the agent it was expected to host.

MeshCentral's endpoint boundary remains the closest architectural reference:
the server authorizes a registered endpoint, while the installed endpoint owns
and performs local execution. No MeshCentral source was copied.

## Decision

An approved project member may create an agent hosted only by its own
authenticated device:

1. The Client preflights the local repository, workspace mode, requester trust,
   and safe access profile.
2. It generates an opaque UUID for the agent and signs the exact project, ID,
   name, and authenticated host-device ID.
3. CoCodex Server derives the host from the WSS identity, verifies membership
   and signature, applies limits, writes one audit event, and returns an
   idempotent `agent.created`.
4. The Client validates that acknowledgement, atomically writes supporting
   trust/safety state, writes the local policy as the final marker, and
   reconnects.
5. On reconnect the Client loads the local policy and announces
   `agent.ready`; only then does the roster show the agent as available.

The network frame contains no workspace, sandbox, access-profile, or
full-computer fields. Server input therefore cannot widen local authority.
Full-computer access remains disabled after setup and requires its separate
local enable action.

ADR 0026 extends this setup with a bounded version-2 local policy store and one
agent-scoped worker connection per local agent. One device/project can now host
up to eight agents concurrently; the project roster remains capped at 128.
Version-1 policies continue to load and migrate without overwriting the first
agent.

## Security properties

- The authenticated socket, not a submitted field, selects `hostDeviceId`.
- Network-created IDs are UUIDs, avoiding human-name reservation across
  projects.
- Exact replay is idempotent and does not duplicate audit records.
- A different definition using the same ID is rejected.
- Nonmembers and invalid signatures cannot create an agent.
- A newer ready session replaces an older ready lease for the same
  device/agent, preventing duplicate task delivery.
- Git-worktree mode requires the canonical repository root. Drive roots,
  network paths, nonexistent paths, files, and repository subdirectories are
  rejected before the server mutation.

## Known follow-up

The pending setup transaction is replayable during the same resident-session
lifetime, but it is not yet a durable cross-process intent. A process crash
after the server commits and before the local policy commit can leave an
offline server roster entry. Do not claim crash-atomic agent setup until a
durable setup intent or signed server compensation flow is implemented.

## Evidence

- Protocol strictness and forbidden authority fields:
  `packages/cocodex-protocol/tests/protocol.test.ts`
- Signature, replay, quota, and audit behavior:
  `apps/cocodex-server/tests/agent-routing.test.ts`
- Real WSS self-registration and nonmember rejection:
  `apps/cocodex-server/tests/collaboration-server.test.ts`
- Real resident Client setup, policy persistence, reconnect, and ready roster:
  `tests/cocodex-project-encryption-session.test.ts`
- GUI command allowlist:
  `tests/cocodex-gui-bridge.test.ts`

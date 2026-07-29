# ADR 0010: Ephemeral presence and local agent authorization

- Status: Accepted and hardened
- Date: 2026-07-25

## Decision

Presence is ephemeral server-routed state, not authoritative project history.
An authenticated project member may publish one bounded normalized mouse
cursor, one bounded text caret/selection, its equivalent pair of encoded Yjs
RelativePositions, and a short-lived typing indicator.
The server validates membership, broadcasts updates to the project's subscribed
sockets that are actively viewing the same chat, returns a redacted snapshot
when the chat subscription is opened, and emits a chat-scoped leave event when
a device disconnects or clears its state. Presence is never persisted in SQLite
and is never included in agent context.

Remote agent tasks require a host-owned local policy that pins the project,
agent, workspace, sandbox, requester device ID, and requester signing-key
fingerprint. The default `trusted-device` mode executes requests that pass that
policy without a repetitive prompt, preserving direct trusted-member control.
A host may select `always` mode to require an abortable five-minute allow-once
decision with the complete prompt and requester device visible. The server
still authenticates and signs every task and cannot bypass either local mode.

The requester or host may send a signed, authenticated `agent.cancel` command.
The server authoritatively records a final failed task event, routes a cancel
control frame to the host, and broadcasts the cancellation through shared chat.
The host aborts the local process through its `AbortSignal`.

## Consequences

- Cursor state disappears naturally during outages and does not create stale
  project history.
- The GUI can render remote pointers without exposing provider credentials or
  local files.
- Remote prompt collaborators see a named typing indicator and a caret or
  selection resolved against their current Yjs document; the UI does not mirror
  or persist prompt text through presence frames.
- New clients publish bounded canonical-base64 Yjs RelativePositions so a
  selection remains attached to the same collaborative content across
  concurrent inserts. The controlled textarea applies a minimal common
  prefix/suffix edit to Y.Text rather than replacing the whole CRDT value, so
  unchanged anchors are not tombstoned. Bounded UTF-16 offsets remain in the frame as a
  compatibility fallback for older clients or an unresolvable deleted anchor.
  The current UI renders labeled awareness/status chips; a rich inline
  text-decoration overlay remains a separate presentation enhancement.
- Existing and newly configured policies default to direct control for pinned
  trusted devices; unknown devices, projects, agents, or workspaces fail closed.
- The three-process harness selects `always` mode so the stricter allow-once
  path remains observable without making it the normal collaboration default.

## Evidence

- Strict cursor/caret/relative-position/typing protocol bounds and
  legacy-default tests.
- A two-document Yjs test proving a remote selection follows concurrent edits.
- Real two-member WSS presence update, opaque relative-position relay,
  typing-only update, same-chat delivery, cross-chat non-delivery, and leave
  test.
- GUI approval controls and approval-command allowlist test.
- Three-process reciprocal agent test with explicit host approvals.
- Real WSS cancellation test proving the host receives the cancel frame and the
  requester receives the authoritative final event.

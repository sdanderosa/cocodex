# ADR 0010: Ephemeral presence and explicit local agent approval

- Status: Accepted for private alpha
- Date: 2026-07-25

## Decision

Presence is ephemeral server-routed state, not authoritative project history.
An authenticated project member may publish one bounded normalized mouse
cursor and one bounded text caret/selection. The server validates membership,
broadcasts updates to the project's subscribed sockets, returns a snapshot when
the chat subscription is opened, and emits a leave event when a device
disconnects or clears its state. Presence is never persisted in SQLite and is
never included in agent context.

Remote agent tasks require an explicit one-time decision by the host client.
The local client displays the complete prompt and requester device before
running the task; approval is abortable, expires after five minutes, and is
lost when the client disconnects. The server still authenticates and signs the
task, but it cannot bypass the host's local approval boundary.

The requester or host may send a signed, authenticated `agent.cancel` command.
The server authoritatively records a final failed task event, routes a cancel
control frame to the host, and broadcasts the cancellation through shared chat.
The host aborts the local process through its `AbortSignal`.

## Consequences

- Cursor state disappears naturally during outages and does not create stale
  project history.
- The GUI can render remote pointers without exposing provider credentials or
  local files.
- Automated tests must explicitly approve local tasks in the three-process
  harness; this makes the safety boundary observable rather than implicit.
- A future trusted-session policy may allow a user-selected host-level shortcut,
  but the default remains explicit approval for remote execution.

## Evidence

- Strict cursor/caret protocol bounds test.
- Real two-member WSS presence update and leave test.
- GUI approval controls and approval-command allowlist test.
- Three-process reciprocal agent test with explicit host approvals.
- Real WSS cancellation test proving the host receives the cancel frame and the
  requester receives the authoritative final event.

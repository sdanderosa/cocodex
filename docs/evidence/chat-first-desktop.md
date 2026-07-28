# Chat-first desktop evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Status: first chat-first information-architecture slice implemented; full multi-device acceptance remains pending

## Implemented in this checkpoint

- The Tauri window opens `index.html#cocodex`, so the desktop client lands in
  collaboration rather than the legacy proxy dashboard. Browser-hosted
  administration retains its existing default route.
- The authenticated workspace preserves a three-column hierarchy: projects and
  chats, the chronological shared chat, and a focused detail rail.
- Usage, agents/tasks, artifacts, and end-to-end encrypted private messages are
  mutually exclusive right-rail tabs instead of one continuously scrolling
  administration column.
- The center chat remains visible while changing detail tabs.
- A persistent **Stop all agents** control appears in the workspace header
  whenever a local agent is executing.
- Global emergency stop targets every and only active local agent. It attempts
  all targets even when one host command fails, reports every rejected target,
  and then reloads authoritative local status. It never reports complete
  success after a partial stop.

## Automated checks

The full GUI suite passed with 128 tests, 0 failures, and 594 expectations.
The new focused tests cover:

- exactly four accessible detail tabs with exactly one selected;
- filtering the emergency-stop target set to executing local agents;
- attempting all stop targets and aggregating rejected targets.

GUI TypeScript compilation and production Vite build passed. ESLint passed
with zero errors and one existing `use-app-route-state.ts` hook warning. The
Tauri configuration test passed with 2 tests and 26 expectations, including
the `index.html#cocodex` launch route.

## Rendered verification

The production component was rendered through a local same-origin API fixture
that supplied only authenticated status, not fake production chat records. The
visible and accessibility trees showed:

- the projects rail on the left;
- the server-ordered shared chat, pinned Final Goal, shared CRDT prompt, empty
  chronological timeline, and composer in the center;
- the selected Agents tab and task activity on the right;
- a persistent Stop all agents control and Disconnect control above the shell.

Selecting **Private messages** changed the right panel to the encrypted contact,
local search, ciphertext-empty-state, and encrypted composer while leaving the
center chat mounted.

## Remaining evidence

This checkpoint does not yet prove the complete visual/product requirement.
It still needs a real two-device rendered pass with populated shared history,
concurrent agent activity, task and artifact handoffs, both human cursors,
private-message delivery, reconnection, and responsive breakpoints. Those
remain release gates rather than inferred completion.

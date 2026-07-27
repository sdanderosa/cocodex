# ADR 0044: Dispatch the converged shared prompt

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** CoCodex GUI composer, Yjs shared prompt, agent dispatch, and
  concurrent-edit preservation

## Context

The GUI already synchronized a per-chat `Y.Text` document through encrypted
prompt updates, but the agent composer submitted a separate component-local
draft. Two users could visibly converge on a prompt and then accidentally send
unrelated text. That broke the purpose of collaborative prompt editing and
left a private-alpha path disconnected at its final handoff.

## Decision

When a named agent is selected, both the composer textarea and its Run action
use the selected chat's current merged Yjs prompt. When no agent is selected,
the composer continues to use an independent chronological-chat draft.

The command builder snapshots and trims the selected source, copies the
selected artifact IDs, and produces exactly one `agent.request` or
`chat.send`. It never substitutes the chat draft for an empty shared prompt.
After successful handoff, the GUI clears a source only if its current raw value
still equals the submitted snapshot. Edits that arrive during submission are
therefore preserved.

## Open-source reference and licensing decision

Continue reusing `yjs` 13.6.31 under MIT. Yjs determines converged document
state; CoCodex retains responsibility for device authentication, project
authorization, encryption, authoritative update order, size limits, and the
explicit transition from collaborative text to an agent request. No
Hocuspocus source or dependency is introduced.

## Evidence requirement

The compiled three-process harness must have Stephen and Kai subscribe to the
same encrypted prompt, submit independent Yjs updates, apply both delivered
updates on both clients, prove convergence, and dispatch the merged text to
Stephen's real local agent. GUI tests must separately prove exact source
selection, blank-source rejection, chat isolation, and artifact snapshotting.

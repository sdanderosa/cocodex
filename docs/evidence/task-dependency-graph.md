# Authoritative task dependency graph evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Status: implemented in the chat-first desktop; fresh installer rebuild pending
  because this slice follows the last recorded bundle hashes

## Behavior

The Agents rail now renders a compact task dependency graph from the
server-authoritative `agent.task.list.result` projection rather than reducing
dependencies to a count.

For every task, the client derives and displays:

- graph layer;
- ready, running, completed, or failed state;
- waiting on an unfinished dependency;
- failed dependency propagation;
- missing dependency rejection visibility;
- bounded cycle detection;
- named upstream task chips;
- accepted artifact inputs and their source task;
- encrypted/event status; and
- shared-workspace or Git-worktree branch/base metadata.

The graph is presentation-only. It does not invent task state, reorder server
events, unblock work, or mutate dependencies. The Server remains authoritative
for dispatch readiness and task status.

## Verification

Focused graph checks:

```text
3 passed
0 failed
14 expectations
```

They prove ready/waiting/failed/missing derivation, bounded cycle handling,
layer ordering, accepted artifact handoff metadata, and rendered graph state.

Complete GUI gate after the slice:

```text
133 passed
0 failed
626 expectations
lint: 0 errors, one pre-existing hook warning
production build: exit 0
```

Primary files:

- `gui/src/cocodex-task-graph.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/src/styles-cocodex.css`
- `gui/tests/cocodex-task-graph.test.ts`
- `gui/tests/cocodex-task-graph-ui.test.tsx`

Honest limits: this closes dependency-graph visibility, not the separate Git
integration workflow. Diff overlap detection, test/merge orchestration,
conflict resolution, revision requests, and integration-artifact publication
remain required.

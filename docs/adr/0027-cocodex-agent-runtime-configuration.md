# ADR 0027: Signed agent runtime configuration

- Status: Accepted for implementation
- Date: 2026-07-26
- Scope: primary model, reasoning effort, co-agent model/effort, and concurrent
  co-agent limit

## Context

The required scenario gives Lucas, Angela, and Sue distinct model and
co-agent settings. CoCodex already routes named agents to the correct local
computer, but the definition contains only a name and host. The official Codex
runtime therefore inherits whichever model happens to be globally selected,
and the shared roster cannot distinguish configured behavior from display
text.

OpenCodex already exposes routed and native model IDs, reasoning-effort
ladders, sub-agent model guidance, and Codex multi-agent thread configuration.
CoCodex should reuse those surfaces instead of adding another model runtime.
OpenHands remains a runtime-session reference only; no source is copied.

## Decision

Each authoritative agent definition contains:

- `primaryModel`
- `primaryEffort`
- optional `coAgentModel`
- optional `coAgentEffort`
- `maxConcurrentCoAgents` from zero through eight

The host signs all fields during `agent.create`. CoCodex Server verifies the
signature, persists the exact immutable definition, returns it in
`agent.created`, and publishes it through the project-scoped roster. Replaying
an ID with different runtime settings fails. Every worker repeats the complete
definition in `agent.ready`; the Server compares it to the immutable row before
granting the ready lease or delivering queued work.

The host Client persists the same fields in its protected local policy and
starts official Codex with:

- `--model <primaryModel>`;
- a per-process `model_reasoning_effort` override; and
- a per-process Codex multi-agent thread limit equal to one main thread plus
  `maxConcurrentCoAgents`.

The Client selects the v1 or v2 concurrency key from the maintained bundled
Codex catalog metadata, explicitly forces the compatible feature mode for the
child process, and rejects a positive limit for an unknown/provider model whose
generation cannot be established safely.

The task prompt receives local guidance naming the requested co-agent model and
effort. A zero limit says not to spawn co-agents. The numeric thread cap is
runtime configuration; the child model and effort remain guidance because the
current official runtime does not expose a host interception hook for every
spawn. CoCodex must not claim those two fields are enforced until such a hook is
available. The server never receives the expanded prompt, local Codex
configuration, account credentials, or authentication state.

## Validation and compatibility

Model IDs are at most 160 characters and use a strict identifier grammar:
letters, numbers, dot, underscore, colon, slash, and hyphen. This excludes
quotes, whitespace, control characters, and config/prompt delimiters.
Reasoning effort uses the maintained OpenCodex/Codex labels:
`minimal`, `low`, `medium`, `high`, `xhigh`, and `max`.

A positive co-agent limit requires both a co-agent model and effort; a zero
limit requires both to be absent. Existing version-1 local policies load with
the safe default `gpt-5.6-sol` at `medium` and no co-agents. Migration 22 gives
existing server definitions the same explicit defaults.

The thread override is a resource bound, not permission to start work. A
co-agent can still start only through the official runtime after a trusted
human or authorized agent has started the parent task.

The local policy store also limits the aggregate of parent threads and declared
co-agent threads to 16 per device. This prevents eight configured agents from
each declaring an independent eight-child allowance.

## Security consequences

- A requester cannot select the destination model or widen its co-agent limit
  in an `agent.request`.
- Definition signatures prevent mutation between the host and server.
- Ready-lease comparison prevents a stale/offline local policy from silently
  running under settings different from the authoritative roster.
- Argument arrays and config overrides are generated from strict schemas and
  run with `shell: false`.
- The Client still owns accounts, credentials, runtime, workspaces, safety
  state, and emergency stop.
- The co-agent model instruction is policy guidance; the Codex thread setting
  enforces the numeric process limit. Future runtime APIs may provide stronger
  per-spawn model enforcement without changing the signed definition.

## Required evidence

- Protocol tests reject extra, inconsistent, and unsigned settings.
- Migration tests prove explicit defaults for legacy rows.
- Server tests prove signature binding, immutable replay, and roster values.
- Adapter tests inspect exact shell-free Codex arguments and local prompt
  policy.
- The three-process harness proves Lucas, Angela, and Sue keep distinct
  settings while completing an artifact-dependent chain.

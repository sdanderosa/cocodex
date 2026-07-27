# ADR 0043: Host-local Codex continuity during collaboration outages

- **Status:** Accepted
- **Date:** 2026-07-27
- **Scope:** CoCodex Client local runtime ownership, collaboration outages,
  local usage accounting, cancellation, and the mandatory three-process path

## Context

CoCodex Server is authoritative for shared state, but it must never become an
availability dependency or execution authority for normal work on a Client's
own computer. The existing three-process test stopped the Server and proved
offline collaboration queueing, but it did not execute a local Codex turn
during that outage. Code inspection alone was not enough to prove mandatory
private-alpha item 25 or end-to-end scenario step 54.

## Decision

CoCodex Client exposes one host-local official Codex path:

```powershell
cocodex local-codex --workspace PATH --prompt TEXT
```

The resident JSON-line Client exposes the equivalent `local.codex.run` and
`local.codex.cancel` commands. A local turn:

- resolves the installed official Codex runtime through the existing
  OpenCodex runtime resolver;
- invokes shell-free `codex exec --json --ephemeral`;
- uses the requested canonical local workspace and the safe
  `workspace-write` sandbox;
- reads local Codex authentication from the host environment;
- streams only to the local Client command/event surface;
- never creates a Server task, sends a prompt/result over WSS, or waits for
  CoCodex Server;
- remains cancellable by the local user and is aborted during Client
  shutdown; and
- updates the protected local usage summary, which may be published after
  collaboration reconnects.

The local path deliberately does not accept `danger-full-access`. Shared
full-computer agents continue to require their separately persisted host
policy and emergency controls.

## Open-source reference and licensing decision

Reuse the existing MIT-licensed OpenCodex runtime discovery and official Codex
adapter. OpenHands' MIT-licensed typed runtime-event design remains
concept-only guidance for the local streamed event shape. No OpenHands source,
new runtime, or new dependency is introduced.

## Consequences

- A collaboration outage cannot prevent a local user from invoking official
  Codex through CoCodex Client.
- Local prompts, workspace paths, and results do not enter shared project
  history automatically.
- Local usage is counted on the host and becomes a signed sanitized summary
  only when a Server connection is available.
- This slice proves local official Codex continuity. The inherited OpenCodex
  proxy remains independently available through the preserved `opencodex` /
  `ocx` compatibility commands and test suite.

## Evidence requirement

The real compiled-process harness must terminate CoCodex Server, retain both
Client PIDs, execute a Kai-local Codex turn with Kai's isolated account and
workspace, verify the fixture's filesystem marker, prove the Server task count
did not change, queue collaboration work, restart the Server, and recover the
queues in order. Focused adapter tests, Client build, type checks, privacy
scan, the full CoCodex suite, and inherited OpenCodex regressions remain
required.

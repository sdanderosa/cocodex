# ADR 0021: Local full-computer access profiles and emergency controls

- Status: Accepted for the next full-objective slice
- Date: 2026-07-25
- Scope: CoCodex Client local agent execution

## Context

The product specification requires a real full-computer execution profile while
preserving the MeshCentral-style boundary: the server authenticates and routes
an authorized task, but the destination CoCodex Client is the only component
that executes it. A remote participant must not be able to widen a local
workspace policy or bypass a host safety decision.

The installed official Codex runtime already exposes a supported
`--sandbox danger-full-access` mode. Reusing that runtime switch is preferable
to inventing a second shell or desktop execution engine. The profile is
dangerous by design, so it needs an explicit local opt-in, a durable kill
switch, and tests that prove the switch reaches an active child process.

## Decision

1. `local-agent-policy.json` now records `accessProfile` (`project-only` or
   `full-computer`) and `fullComputerOptIn`. The latter must be true before a
   full-computer policy can be saved.
2. `project-only` maps to the existing `read-only` or `workspace-write` Codex
   sandbox. `full-computer` maps only to the official runtime's
   `danger-full-access` flag and never adds `--yolo` or a shell wrapper.
3. `local-agent-safety.json` is a protected, atomically replaced state file.
   It records `executionEnabled` and `fullComputerEnabled`. An emergency stop
   disables both, aborts active local agent controllers, and blocks queued
   work. Resume and full-computer enable are separate local actions.
4. The JSON-line session and GUI bridge expose local-only controls:
   `agent.emergency.stop`, `agent.emergency.resume`,
   `agent.full-computer.enable`, `agent.full-computer.disable`, and
   `agent.safety.status`. The full-computer enable command requires an explicit
   confirmation field. The standalone client CLI exposes equivalent commands.
5. The server protocol and task signatures are unchanged. A server request is
   never an execution grant; the host policy and safety state are checked again
   on the destination client immediately before execution.

## Security and failure behavior

- Missing or malformed policy/safety state fails closed for full-computer use.
- A project-only policy cannot be widened by a stale safety file.
- The emergency state is local and remains effective while the server is
  offline.
- An active Codex child receives an abort/kill through the existing bridge
  controller. Interrupted execution is journaled and is not silently rerun.
- The server never receives a raw shell command, workspace path authorization,
  private account credential, or full-computer capability token.
- This slice does not claim an elevated Windows helper, browser automation, or
  remote desktop/input implementation. Those remain separate later slices and
  must have their own local consent and emergency boundaries.

## Alternatives considered

- **Remote server-side shell:** rejected because it violates the endpoint
  execution boundary and would expose host credentials.
- **Custom shell/desktop runner:** rejected because it duplicates the official
  Codex runtime and creates an unreviewed command authorization surface.
- **Implicit full access for trusted devices:** rejected; device trust is not
  equivalent to a local host's consent for dangerous execution.
- **Separate helper process in this slice:** deferred until the Windows
  elevation threat model and signed helper lifecycle are specified and tested.

## Evidence required

- Adapter test proves explicit opt-in maps to `danger-full-access` and absent
  opt-in never spawns Codex.
- Safety-store test proves atomic persistence, emergency stop, downgrade
  fail-closed behavior, and separate re-enable steps.
- Bridge recovery test proves an emergency stop aborts an active task and that
  the bridge can resume only through a local control.
- GUI bridge test proves the safety commands are allowlisted and forwarded
  without exposing private ciphertext.

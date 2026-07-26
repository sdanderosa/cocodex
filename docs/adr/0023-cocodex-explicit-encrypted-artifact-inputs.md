# ADR 0023: Explicit encrypted artifact inputs for agent handoffs

- **Status:** Accepted
- **Date:** 2026-07-25
- **Scope:** selecting, authorizing, routing, decrypting, and consuming project
  artifacts as inputs to a remote local agent

## Context

ADR 0015 made artifact content opaque to the server, and ADR 0016 made remote
agent prompts and results opaque. The two paths were not connected: a task
could wait for another task ID, but it could not identify the exact artifact
records it was allowed to consume. Copying artifact text into a prompt would
lose provenance, make the handoff implicit, and encourage broad shared-context
injection.

MeshCentral's server/local-agent boundary and OpenHands' typed event model are
the closest architectural references. They support explicit server-routed
work while leaving execution at the endpoint. No source code is reused.

## Decision

An agent request may carry at most 16 ordered, deduplicated
`inputArtifactIds`. The IDs are routing metadata; the artifact title, summary,
status, and body remain in the existing signed XChaCha20-Poly1305 project
envelope.

The authoritative server:

1. requires every ID to resolve to an immutable artifact in the same project;
2. persists the canonical ID list on the task;
3. binds the list into its Ed25519 dispatch transcript;
4. sends the exact opaque artifact envelopes with the task; and
5. exposes only the ID count/list in authoritative task activity.

The host client verifies the complete server dispatch signature before
decrypting the prompt or any input. It then verifies the ordered ID/envelope
mapping, project scope, key epoch, enrolled sender identity, envelope
signature, decrypted record metadata, and a consumable status (`ready`,
`accepted`, or `integrated`). Only then does it append a bounded JSON handoff
section to the in-memory Codex prompt. That section labels artifact content as
untrusted reference data rather than higher-priority instructions.

The requesting client also requires selected artifacts to be loaded,
same-project, and consumable before it creates a durable request. Legacy
plaintext projects reject artifact inputs. The GUI publishes encrypted ready
handoffs, lists project artifacts, and requires an explicit checkbox selection
for each agent request.

## Security consequences

- The server learns selected artifact IDs but not artifact content.
- An ID substitution invalidates the server dispatch signature before client
  decryption.
- A cross-project or missing ID is rejected before task creation.
- A draft, rejected, or superseded artifact is rejected by both the requesting
  client (when loaded) and the executing host after decryption.
- Artifact contents can contain prompt-injection text, so they are explicitly
  delimited and labeled untrusted. They are included only after a human
  selection; no project-wide automatic context injection is introduced.
- The combined prompt and artifact payload is bounded to 300,000 UTF-8 bytes.

## Rejected alternatives

- Do not inject every project artifact or shared-context record automatically.
- Do not duplicate plaintext artifact bodies inside the task envelope or
  server database.
- Do not trust client-supplied titles, status, or body metadata at the server.
- Do not add a second artifact store or copy MeshCentral/OpenHands code.

## Evidence

- Protocol tests cover strict bounded artifact-input fields.
- Server routing tests cover deduplication, same-project resolution, opaque
  envelope dispatch, and missing-ID rejection.
- Bridge tests prove an ID substitution prevents even the decrypt callback.
- The three-process private-alpha harness publishes an encrypted Kai handoff,
  routes it to Stephen's locally approved agent, and proves the local Codex
  fixture receives the artifact canary before the normal restart/recovery
  checks complete.

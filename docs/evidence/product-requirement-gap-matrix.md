# CoCodex authoritative product requirement gap matrix

- Audit date: 2026-07-28
- Source: supplied 2,316-line product brief, supplied visual reference,
  repository ADRs through ADR 0057, current filesystem/tests/runtime evidence
- Branch: `feat/cocodex-foundation`
- Completion status: not complete; do not publish

Status meanings:

- **Proven**: current code plus a directly scoped passing test/runtime artifact.
- **Partial**: meaningful implementation exists, but one or more explicit
  behaviors or the required verification scope is absent.
- **Missing**: no conforming implementation/evidence found.
- **External gate**: implementation cannot be called releasable without an
  operator-owned external asset or environment.

## Product areas

| Brief area | Status | Current evidence | Remaining requirement |
| --- | --- | --- | --- |
| Real OpenCodex fork/history/remotes | Proven locally | `origin=sdanderosa/cocodex`, `upstream=lidge-jun/opencodex`, feature branch and inherited 4,240-test suite | Re-check remote authentication immediately before push/PR |
| Separate Client and Server apps/processes/state | Proven | Separate compiled CLIs, roots, databases, health/lifecycle tests and real three-process harness | Polished standalone Server administration UI remains |
| Free direct self-hosting | Partial | TLS/WSS, invite address/fingerprint/token, UPnP/NAT-PMP/PCP, firewall attempt, manual/CGNAT diagnosis tests | Real two-network internet acceptance, stronger CGNAT diagnosis and polished guided setup |
| Server authority/client local authority | Proven | Signed membership/chat/context/task/artifact routes; Server boundary tests reject local execution/credentials | Keep in every later feature |
| Offline/reconnect/outbox/local Codex | Proven | Server-stop/restart three-process path, ordered shared/private outboxes, local Codex while offline | Invitation actions are not all crash-durable before Server receipt |
| Server backup/recovery/transfer/epoch | Proven in separate tests | Encrypted signed backup/transfer, real source/destination processes, stale epoch rejection | Execute inside the single mandatory 70-step scenario |
| OpenCodex compatibility | Proven at checkpoint | 4,267 passed, 4 skipped, 0 failed, 21,773 assertions across 360 files | Must rerun after every remaining product slice |
| Projects/chats/final goal | Proven at checkpoint | Encrypted owner/invitation lifecycle, multiple authoritative chats, ordered history, revisioned final goal, signed owner-only rename/archive/restore/delete, and fail-safe signed member leave with immediate quarantine plus owner-only successor-key rotation | Complete historical plaintext migration |
| Shared prompt/presence/cursors | Proven in process/UI | Yjs merge, stable RelativePositions, batching, reconnect, pointer/caret/typing transport, inline remote caret/selection labels, and unified exactly-two-cursor proof | Physical two-PC/reference-level acceptance remains an external gate |
| Named agents/direct remote control | Proven | Signed immutable definitions, host leases, trusted control, independent workers and queues | Persistent rich activity history and task editing |
| Runtime sessions/context independence | Proven | Durable scoped CLI resume, reset boundaries, controlled rotation and live cache metrics | Official-session open/status affordance in UI |
| Task dependencies/artifacts | Partial, with resident Client/GUI Git integration slice | Server dependency gate, encrypted artifacts, Lucas-Angela-Sue handoff, compact dependency graph, real Git preview/merge/revision tests, encrypted commit/review publication | Include the workflow in the single 70-step run |
| Co-agents | Partial | Signed model/effort/concurrency config and CLI-enforced concurrent-thread limit | Maximum total spawns, provider/tool/file/network allowlists, live child IDs/status/results/artifacts |
| Git worktrees | Partial | Per-task locked branches/worktrees, dirty/detached refusal, ownership report, overlap/conflict/revision/integration tests, resident review controls | Include the full workflow in the single 70-step run and complete broader product acceptance |
| Full Computer | Proven for host-user mode | Explicit opt-in, durable emergency controls, `danger-full-access` mapping and real fixture evidence | Resource locks outside Git |
| Elevated helper | Missing | ADR 0021 explicitly excludes it | Separate privileged app, install/enable lifecycle, signed local-only requests, confirmation policy |
| Official browser capability | Partial with truthful local boundary | Exact selected-runtime detection proves CLI unsupported vs installed official-app Browser; renderer-minimized Open in official Codex handoff and chat-first status UI | Hosted-agent execution, disabled/watch/shared-control policy, sanitized browser events/results, and optional encrypted live viewing |
| Usage sidebar | Proven | Signed host reports, account windows, active agents and per-agent cache share | Multi-account detail/stale/offline presentation audit |
| Private text messaging | Partial | Independent device keys, ciphertext-only Server, offline delivery, local history/search, receipts, explicit share, replies, reactions, edit/delete, ephemeral typing indicators, opt-in plaintext-free native desktop notifications (manual OS-toast acceptance pending) | Richer conversation management |
| Mature private-message crypto | Missing | Sealed-box signed envelopes are honestly documented | Maintained X3DH/PQXDH + Double Ratchet implementation, prekeys, forward secrecy and recovery |
| Private attachments/multi-device | Missing | No conforming private attachment session/fan-out | Local random attachment keys, progress, images/files, per-device sessions and lost-device recovery |
| Chat-first visual interface | Partial | Native Tauri route, chronological chat/activity, tabs, usage, messages, graph, emergency stop | Full reference-level visual QA and remaining left-nav/browser/messaging surfaces |
| Local API/security/privacy | Proven at checkpoint | Per-launch Tauri capability, exact-origin CORS, DPAPI keys, redaction/privacy tests | Reaudit with helper/browser/attachments |
| Server admin/service/update | Partial | Headless CLI plus user background mode; optional same-user Windows service; strict installed-package update-check plus clean isolated Update/state-canary/package lifecycle acceptance | Live packaged SCM/UAC/reboot acceptance and operator-grade update download/version policy |
| Distribution/update/signing | Partial / external gate | Verified archive installer plus fresh NSIS/MSI and hashes | Authenticode/Sigstore or transparency, signing identity, automatic update, standard ICE pass |
| Documentation | Partial | Extensive Client/Server/ADR/evidence docs | End-user coverage for every remaining browser/helper/messaging/service/update flow |
| Single 70-step acceptance run | Proven at process level | One uninterrupted compiled Server + Stephen Client + Kai Client scenario passes all 70 behavioral steps with 321 assertions | Physical two-PC packaged/UAC/reboot acceptance remains a separate release gate |

## Required 70-step scenario audit

| Steps | Status | Evidence and gap |
| --- | --- | --- |
| 1-4 install/init/background Server and two Clients | Partial | Separate compiled processes are exercised from temporary builds, not two physical normal-PC installations in one run |
| 5-11 team/invite/enroll/verify/trust/one-time token | Proven | Three-process enrollment and approval path plus replay rejection |
| 12-14 outsider/name/token-copy rejection | Proven in unified scenario | Replay, unenrolled connection, missing-signature token copy, and copied Kai connection without Kai private key all fail closed |
| 15-20 same project/chat, two cursors, collaborative prompt/revision/submit | Proven in unified scenario | Two accepted local cursor writes and two remote broadcasts identify exactly two humans; convergent Yjs prompt and authoritative revision/final goal follow |
| 21-26 Sue/Lucas/Angela definitions, models, co-agent config, final goal | Proven | Three-process fixtures verify host/model/effort/concurrency definitions and final goal |
| 27-31 direct Lucas/Sue execution and idle Angela | Proven | Host-local markers and no-start-before-instruction checks |
| 32-35 Angela consumes Lucas, chronological activity, independent concurrent contexts | Proven | Barrier-based concurrent agents, artifact input and persistent isolated CLI sessions; chat-first timeline tests |
| 36-39 Lucas/Angela/Sue artifact chain and integration | Proven in unified scenario | Lucas finding, Angela test result, Sue consumption/integration, encrypted artifact persistence, and chronological results occur in the same run |
| 40-41 same authoritative history and separate usage | Proven | Server history and signed per-device usage reports |
| 42-48 private exchange, ciphertext, local decrypt, isolation and explicit Sue share | Proven for text/single-device sealed boxes | Does not satisfy mature ratchet/multi-device/attachment requirements |
| 49-52 Sue Full Computer and Server-only routing | Proven | Explicit host-user full-computer fixture; not elevated-helper mode |
| 53-61 Server offline, local Codex, queued shared/private, ordered reconnect | Proven | Same resident Client PIDs and Server restart in three-process harness |
| 62-69 transfer to Kai, epoch, stale source, preserved history | Proven in unified scenario | Signed export/import retires Stephen source, advances epoch 1 to 2, starts Kai Server, reconnects both Clients, rejects stale source, and preserves exact sequences |
| 70 inherited OpenCodex functionality | Proven in unified smoke and complete repository gate | Isolated non-10100 inherited proxy health and GUI 200 pass inside the scenario; latest complete gate: 4,270 pass, 4 skip, 0 fail, 21,774 assertions across 361 files |

## Release decision

The current private-alpha foundation is substantial and tested, but the
authoritative product is not complete. The missing mature ratchet, private
attachments/multi-device fan-out, elevated helper, browser-control surface,
live packaged SCM/UAC/reboot acceptance and signed distribution remain release
blockers.

Fresh archive/NSIS/MSI/runtime hashes and ownership smokes for commit `0898f97a` are
recorded in `docs/evidence/tauri-managed-client-runtime.md`. These remain
unsigned private-alpha artifacts, not public-release evidence.

## Current Git/UI slice correction - 2026-07-28

The resident Client now publishes integration outcomes through the existing
encrypted Server artifact route, and the GUI exposes explicit review/integrate
controls. The remaining gap is inclusion in the single uninterrupted 70-step
scenario, not a missing Server/GUI publication path. The broader product
release blockers listed above remain binding.
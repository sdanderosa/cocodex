# CoCodex authoritative product requirement gap matrix

- Audit date: 2026-07-28
- Source: supplied 2,316-line product brief, supplied visual reference,
  repository ADRs through ADR 0050, current filesystem/tests/runtime evidence
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
| OpenCodex compatibility | Proven at checkpoint | 4,240 passed, 4 skipped, 0 failed | Must rerun after every remaining product slice |
| Projects/chats/final goal | Proven | Encrypted owner/invitation lifecycle, multiple authoritative chats, ordered history, revisioned final goal | Rename/archive/delete and complete historical plaintext migration |
| Shared prompt/presence/cursors | Partial | Yjs merge, stable RelativePositions, batching, reconnect, pointer/caret/typing transport | Rich inline remote caret/selection overlay and one-run exactly-two-cursor proof |
| Named agents/direct remote control | Proven | Signed immutable definitions, host leases, trusted control, independent workers and queues | Persistent rich activity history and task editing |
| Runtime sessions/context independence | Proven | Durable scoped CLI resume, reset boundaries, controlled rotation and live cache metrics | Official-session open/status affordance in UI |
| Task dependencies/artifacts | Proven for authority and visibility | Server dependency gate, encrypted artifacts, Lucas-Angela-Sue handoff, new compact dependency graph | Git integration/conflict workflow remains |
| Co-agents | Partial | Signed model/effort/concurrency config and CLI-enforced concurrent-thread limit | Maximum total spawns, provider/tool/file/network allowlists, live child IDs/status/results/artifacts |
| Git worktrees | Partial | Per-task locked branches/worktrees, dirty/detached refusal, ownership report | Overlap detection, tests, merge/conflict/revision/integration artifact workflow |
| Full Computer | Proven for host-user mode | Explicit opt-in, durable emergency controls, `danger-full-access` mapping and real fixture evidence | Resource locks outside Git |
| Elevated helper | Missing | ADR 0021 explicitly excludes it | Separate privileged app, install/enable lifecycle, signed local-only requests, confirmation policy |
| Official browser capability | Missing/partial preservation | Tasks run through official Codex CLI and user config is preserved | Detect support, status/events, disabled/watch/shared-control UX, privacy-safe summaries |
| Usage sidebar | Proven | Signed host reports, account windows, active agents and per-agent cache share | Multi-account detail/stale/offline presentation audit |
| Private text messaging | Partial | Independent device keys, ciphertext-only Server, offline delivery, local history/search, receipts, explicit share | Replies, reactions, edit/delete, typing, notifications, conversations |
| Mature private-message crypto | Missing | Sealed-box signed envelopes are honestly documented | Maintained X3DH/PQXDH + Double Ratchet implementation, prekeys, forward secrecy and recovery |
| Private attachments/multi-device | Missing | No conforming private attachment session/fan-out | Local random attachment keys, progress, images/files, per-device sessions and lost-device recovery |
| Chat-first visual interface | Partial | Native Tauri route, chronological chat/activity, tabs, usage, messages, graph, emergency stop | Full reference-level visual QA and remaining left-nav/browser/messaging surfaces |
| Local API/security/privacy | Proven at checkpoint | Per-launch Tauri capability, exact-origin CORS, DPAPI keys, redaction/privacy tests | Reaudit with helper/browser/attachments |
| Server admin/service/update | Partial | Headless CLI, init/start/stop/restart/status/migrate/backup/restore, user background mode | Optional CoCodex Server Windows service and separate verified update UX |
| Distribution/update/signing | Partial / external gate | Verified archive installer plus fresh NSIS/MSI and hashes | Authenticode/Sigstore or transparency, signing identity, automatic update, standard ICE pass |
| Documentation | Partial | Extensive Client/Server/ADR/evidence docs | End-user coverage for every remaining browser/helper/messaging/service/update flow |
| Single 70-step acceptance run | Missing | Many steps proven across separate suites | One uninterrupted three-process test must exercise all 70 in order |

## Required 70-step scenario audit

| Steps | Status | Evidence and gap |
| --- | --- | --- |
| 1-4 install/init/background Server and two Clients | Partial | Separate compiled processes are exercised from temporary builds, not two physical normal-PC installations in one run |
| 5-11 team/invite/enroll/verify/trust/one-time token | Proven | Three-process enrollment and approval path plus replay rejection |
| 12-14 outsider/name/token-copy rejection | Proven in focused security tests | Must be included explicitly in the final single scenario |
| 15-20 same project/chat, two cursors, collaborative prompt/revision/submit | Partial | Project/chat/prompt submission proven; presence transport proven separately, not exactly two visible cursors in the three-process run |
| 21-26 Sue/Lucas/Angela definitions, models, co-agent config, final goal | Proven | Three-process fixtures verify host/model/effort/concurrency definitions and final goal |
| 27-31 direct Lucas/Sue execution and idle Angela | Proven | Host-local markers and no-start-before-instruction checks |
| 32-35 Angela consumes Lucas, chronological activity, independent concurrent contexts | Proven | Barrier-based concurrent agents, artifact input and persistent isolated CLI sessions; chat-first timeline tests |
| 36-39 Lucas/Angela/Sue artifact chain and integration | Partial | Encrypted artifact chain is proven; Sue consumes both, but a real Git merge/integration workflow is not |
| 40-41 same authoritative history and separate usage | Proven | Server history and signed per-device usage reports |
| 42-48 private exchange, ciphertext, local decrypt, isolation and explicit Sue share | Proven for text/single-device sealed boxes | Does not satisfy mature ratchet/multi-device/attachment requirements |
| 49-52 Sue Full Computer and Server-only routing | Proven | Explicit host-user full-computer fixture; not elevated-helper mode |
| 53-61 Server offline, local Codex, queued shared/private, ordered reconnect | Proven | Same resident Client PIDs and Server restart in three-process harness |
| 62-69 transfer to Kai, epoch, stale source, preserved history | Proven only in separate transfer test | Not part of the same mandatory three-process scenario |
| 70 inherited OpenCodex functionality | Proven at checkpoint | 4,240 passed, 4 skipped, 0 failed; rerun required after remaining implementation |

## Release decision

The current private-alpha foundation is substantial and tested, but the
authoritative product is not complete. The missing mature ratchet, private
attachments/multi-device fan-out, elevated helper, browser-control surface,
Git integration workflow, Server service/update path, signed distribution, and
single uninterrupted 70-step acceptance run are release blockers.

The NSIS/MSI hashes recorded before the task-graph slice are now stale relative
to the current GUI source. They remain historical evidence only and must be
rebuilt after the next release-candidate freeze.

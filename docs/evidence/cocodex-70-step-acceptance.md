# CoCodex unified 70-step process acceptance

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Test: `tests/cocodex-private-alpha-process.test.ts`
- Scenario processes: compiled CoCodex Server, Stephen Client, Kai Client

## Result

```text
1 pass
0 fail
321 assertions
23.4 seconds in the maintained passing run
zero remaining cocodex-private-alpha temporary roots
```

The maintained CoCodex suite then passed 203 tests, 0 failures, and 2,184
assertions across 39 files. The scenario has a bounded 300-second full-load
budget and a 45-second cleanup hook with 30 seconds of Windows lock retries.

## Requirement map

| Steps | Evidence in the uninterrupted scenario |
| --- | --- |
| 1-5 | Fresh compiled private-alpha executables; isolated Server initialization/background process; separate Stephen and Kai resident Client processes |
| 6-10 | Stephen bootstrap approval, one-time Kai enrollment, exact verification phrase, signed approval, bilateral trusted-device records |
| 11-14 | Invitation replay rejected as already used; unenrolled Client rejected; copied token without signature rejected; copied Kai connection without Kai private key rejected as `Invalid device proof` |
| 15-20 | Same project/chat, two accepted local cursor writes and two remote cursor broadcasts for exactly two human devices, convergent Yjs prompt, authoritative revision/final-goal update |
| 21-26 | Sue on Kai; Lucas and Angela on Stephen; exact Sol/Luna model, effort, three-co-agent limit, idle Angela, and Final Goal assertions |
| 27-35 | Lucas/Sue dispatch to their owning PCs; barrier-proven Lucas/Angela concurrency; independent workspaces/accounts/contexts; chronological shared task/chat events |
| 36-41 | Lucas finding, Angela test result, Sue integration artifact chain; identical authoritative sequence history; signed per-device usage cards |
| 42-48 | Signed sealed private exchange, ciphertext-only Server storage, local decrypt/reply, no implicit agent disclosure, explicit one-message Sue share and bounded context |
| 49-52 | Separately enabled Sue Full Computer profile, Server policy/routing, Kai-local fixture execution, and Server database proof that it never executed the command |
| 53-61 | Server stop, Kai local Codex continuity, offline shared/private queues, same resident Client PIDs reconnect, ordered drain, encrypted private delivery |
| 62-69 | Prepared Kai Server root; source stop/retirement; encrypted signed authority export/import; new separate Server; epoch 1 to 2; both Client authority acceptances/reconnects; stale source start rejected; exact before/after history sequences |
| 70 | Isolated inherited OpenCodex proxy on an OS-assigned port explicitly not 10100; health and GUI 200 smoke; maintained inherited regression suite run separately in the complete repository gate |

## Safety and scope

All state roots, workspaces, transfer files, passphrases, Client homes, and the
step-70 OpenCodex/Codex homes are inside one temporary scenario root. The test
never binds port 10100. It stops only subprocesses it created and verifies zero
scenario roots remain after a passing run.

The scenario uses freshly compiled private-alpha executables. The separate
clean-package evidence proves actual installer/update/uninstall and NSIS/MSI
lifecycle behavior; it is not silently conflated with this process test.

This closes the previously missing single behavioral 70-step scenario. It does
not prove the still-missing mature ratchet, multi-device private attachments,
elevated helper, browser-control mode, signing/automatic update, physical
multi-PC/UAC/reboot acceptance, or final reference-level visual QA.

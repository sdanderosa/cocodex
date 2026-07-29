# Owner-attested historical plaintext migration evidence ? 2026-07-29

## Scope

ADR 0058 is implemented for projects that initialized end-to-end project encryption after Server-readable project content already existed. The transaction covers all six legacy classes:

1. shared Final Goal/context;
2. chat events;
3. agent-result events;
4. canonical Yjs shared-prompt state;
5. artifacts; and
6. terminal agent-task prompts.

The approved owner alone receives the frozen inventory, encrypts each item with the protected current project key, stages bounded signed envelopes, and signs a TLS-fingerprint-bound canonical manifest. One immediate SQLite transaction verifies exact source/envelope coverage and replaces all plaintext classes. Any late failure leaves every plaintext row and prior encrypted row unchanged.

Original author/requester attribution is preserved separately from the owner envelope signer and is accepted only with a completed migration ID. New records still require signer/author equality.

## Fail-safe and lifecycle behavior

- Legacy and encrypted project-content writes, lifecycle deletion, and ordinary rotation fail closed while migration is required or prepared.
- Emergency member removal and leave completion are never blocked. They atomically erase staging and mark the prepared migration invalid before revocation/successor-key rotation proceeds.
- Non-owners receive only a bounded migration-required status and cannot page, stage, or commit inventory.
- Staged envelope digests survive resident reconstruction and Server restart.
- Completion is sent once to the committing owner and every connected project member; residents clear affected chat/prompt/context/artifact cursors and request fresh encrypted snapshots.
- The Server never receives a project key and cannot manufacture or reinterpret migration ciphertext.

## Regression evidence

Final focused migration gate:

```text
13 passed, 0 failed, 117 assertions, 3 files
```

It proves strict protocol bounds and canonical signatures; all six plaintext classes; late-collision transaction rollback; non-owner, changed-snapshot, wrong-state, and nonterminal-task rejection; emergency removal invalidation; bounded batches; resident restart/resume from staged digests; and authenticated two-client TLS/WSS partial staging, Server restart on the same TLS identity/database/port, digest recovery, completion, and member broadcast.

The real two-resident encrypted session additionally proves that Stephen migrates all six classes, Kai receives completion and refreshed subscriptions, both decrypt chat/agent-result/prompt/context/artifact history, all legacy plaintext tables are empty, terminal task prompts become `[encrypted]`, and none of the plaintext canaries appears in stored encrypted rows.

Final broad gates:

```text
maintained CoCodex core: 222 passed, 0 failed, 2,456 assertions, 46 files
maintained migration:    13 passed, 0 failed,   117 assertions, 3 files
inherited root:       4,274 passed, 4 intentional skips, 0 failed,
                      21,811 assertions, 362 files
device approval:         27 passed, 0 failed, 307 assertions
project lock/emergency:  17 passed, 0 failed, 216 assertions
TypeScript root/CoCodex: passed
GUI lint: zero errors; one pre-existing exhaustive-deps warning
GUI production build: passed (bundle-size advisory only)
privacy scan: passed
Rust format: passed
Rust tests: 2 passed, 0 failed
Clippy all targets with warnings denied: passed
git diff --check: passed
```

The broad run initially exposed one invalid mixed-mode fixture: an encrypted-agent test inserted a legacy plaintext artifact after project-key initialization. The encrypted artifact path already covered the same target-device authorization, so the redundant plaintext insertion was removed. The exact test and then the complete maintained suite passed. The maintained migration gate also exposed a Windows TLS-directory `EBUSY` teardown leak; client WebSocket closure is now awaited before Server/database cleanup.

## Final native artifacts

Built from the exact tested worktree with `bun run build:tauri`:

| Artifact | Bytes | SHA-256 | Signature |
|---|---:|---|---|
| NSIS `CoCodex_0.1.0_x64-setup.exe` | 30,546,506 | `BDA67BD209D37830E9FAD4BD3D4A6D5BF22D34A1A519D87C4C94AFF7C998DD6F` | NotSigned |
| MSI `CoCodex_0.1.0_x64_en-US.msi` | 43,888,640 | `8061111153172916E3B121E1640E3AB309A6FD31AAAE5E08BA5725C59F7EFAA4` | NotSigned |
| bundled `cocodex-runtime.exe` | 104,903,680 | `AD6AC109FE1D1531E35EA5355BF222BA39E5F604FDF0B3E174BCAEC857C19CED` | NotSigned |
| release `cocodex-desktop.exe` | 11,854,848 | `59014E0D79BC65EAEB94941E5AC38C2B0DE3680F697DF40F9BADB02196B2BD00` | NotSigned |

Final NSIS isolated install exited 0. Path-verified desktop PID 49224 was responsive, had only direct child `msedgewebview2.exe`, started zero installed runtimes, and logged `foreign compatible runtime rejected pid=49016`. Installed desktop SHA-256 was `3183E7DC2908427805CC384EA228042C90267D5225AF4EAF02ED3A820CBA1552`. Only PID 49224 was stopped; silent uninstall exited 0 and both validated roots were removed.

Final MSI administrative extraction exited 0. Its runtime hash exactly matched the bundled runtime. Path-verified desktop PID 56616 was responsive, had only WebView2, started zero extracted runtimes, and logged the same foreign-owner rejection. Extracted desktop SHA-256 was `7855740CDDF7CD8499751FD613E6B15838198BDF42422BFAD0532B6B69D98F1D`. Only PID 56616 was stopped; all three validated extraction/state/log paths were removed. Pre-existing `msiexec.exe` PID 64672 remained present and was never stopped.

## Protected home state

After all tests, builds, and package smokes:

- `opencodex-proxy` scheduled task: Running;
- `GET /healthz`: status ok, OpenCodex 2.7.42, PID 49016, port 10100;
- `providers.openai.codexAccountMode`: `direct`;
- SunshineService: Running / Automatic;
- `sunshine.exe` PID 11100 retained TCP 47984, 47989, 47990, 48010 and UDP 47998, 47999, 48000.

No foreign process, service, IP, interface, firewall rule, or protected port was stopped, adopted, rebound, or reconfigured.

## Limits

These remain unsigned private-alpha artifacts. This evidence does not establish Authenticode signing, live UAC/SCM/reboot acceptance, physical two-PC acceptance, or completion of the broader product brief. No publication claim is made by this checkpoint.

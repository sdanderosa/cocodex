# Authoritative project-member leave evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Decision: [ADR 0056](../adr/0056-cocodex-fail-safe-project-member-leave.md)
- Host protection: [ADR 0054](../adr/0054-sunshine-host-service-protection.md)

## Proven behavior

- The resident Client constructs a strict, signed, expiring, authority-bound leave request and persists it until a matching Server acknowledgement.
- The Server immediately quarantines the member in one transaction: project authorization and listing are denied, all present and future key-envelope delivery excludes the member, hosted agents are disabled, queued/running task participation is failed, invitations expire and rotation becomes required.
- The acknowledged Client revokes its local project key before owner completion.
- The owner sees the pending leave and completes it with the existing atomic remove-and-rotate transaction. The successor key is generated only by the owner for the exact surviving roster.
- Owners cannot self-leave before ownership transfer exists; archive/delete remains the safe path.

## Verification results

- Focused protocol/Server/outbox/GUI: 16 pass, 0 fail, 81 assertions.
- Real authenticated WSS collaboration: 9 pass, 0 fail, 146 assertions.
- Bridge/migration/Sunshine protection: 6 pass, 0 fail, 256 assertions.
- Resident encrypted Client sessions: 3 pass, 0 fail, 83 assertions.
- Maintained CoCodex suite: 217 pass, 0 fail, 2,409 assertions across 45 files.
- GUI suite: 148 pass, 0 fail, 687 assertions across 31 files.
- TypeScript, privacy scan, GUI production build, Rust tests and clippy: pass. GUI lint: 0 errors and one pre-existing hook-dependency warning.
- Complete repository: 4,267 pass, 4 intentional skips, 0 fail, 21,773 assertions across 360 files in 237.4 seconds.

## Sunshine and foreign-listener non-interference

Before and after the implementation and full regression:

- `SunshineService` remained Running/Automatic at PID 5044.
- `sunshine.exe` remained PID 11100.
- TCP listeners remained `0.0.0.0:47984`, `:47989`, `:47990`, and `:48010`, all owned by PID 11100.
- UDP endpoints remained `0.0.0.0:47998`, `:47999`, and `:48000`, all owned by PID 11100.
- the foreign user-installed OpenCodex listener remained `127.0.0.1:10100`, PID 3704.

CoCodex performed no Sunshine IP/interface change, bind, reservation, forwarding, remapping, firewall mutation, stop, restart, reconfiguration, adoption, or process signal. The dedicated source regression passed 3 tests and covers every protected port from 47984 through 48010 plus prohibited IP/service/process commands.

## Release statement

This product slice is proven. It does not make the broader private alpha complete or publicly releasable; the remaining blockers in the product gap matrix remain binding.

## Clean-commit release artifacts

Source commit `ba9438b40ab6bd5b3ba31c72ebd706ca23073f30` (tree
`39c10f9368f469403e07d36fffa05be1f0a5cfe4`) was rebuilt from detached clean
worktree `release-ba9438b4`. Preserved ignored artifacts and smoke logs are in
`dist/release-evidence/ba9438b4/`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| private-alpha archive | 10,228,788 | `14f83d37f1d670c7a15e178ee28dff978475e56bbd435dd1f1359cbc51819a51` |
| NSIS installer | 30,546,364 | `f8b77dd3bc512b25a2bb0e11aff1a2287bd90257211c99944f1607e612aa4b10` |
| MSI installer | 43,880,448 | `1794751b834bb1f881447089e6f710c7574933f2d1d2f4ffc32ce958de5c3ea5` |
| bundled runtime | 104,883,712 | `fcad96ca1bbe9bba9293f82453241a7cd773ecb5db62ccd52b2e3851dfaf8d50` |
| release desktop | 11,854,336 | `862b8e44c6de4ec60ad5aecec0ce76cb390d0ef3ff5721720126d75682bb3a02` |

The NSIS smoke installed successfully. Path-verified desktop PID 33804 launched
only WebView2, started zero sidecars, logged the foreign PID 3704 rejection,
and left port 10100 unchanged. Its installed desktop hash was
`71121b848629c0d203b434e85272b117f95d2ac3852b7a2e9ca0f7ac9718215b`.
Only PID 33804 was stopped; uninstall succeeded and the validated root was
removed.

The MSI administrative extraction succeeded. Path-verified desktop PID 57608
also launched only WebView2, started zero sidecars and rejected PID 3704. Its
desktop hash was
`c54ac96ae1c50b73962d095ca79a97b0e541081b2eada6d3cd78cd200c920c6d`;
the extracted runtime exactly matched the bundled runtime. Only PID 57608 was
stopped. Pre-existing `msiexec.exe` PID 51396 remained present and was never
stopped.

The archive verifier passed in an isolated prefix: 126 shrinkwrap-bound
dependencies, OpenCodex health and GUI 200 on port 63094, and CoCodex Server
start/restart/stop on port 63111 (PIDs 56744 then 54456). The package was
uninstalled and its exact prefix removed.

Final home verification found OpenCodex Running and healthy at PID 3704,
`codexAccountMode` `direct`, and the Repair Codex shortcut intact. Sunshine
remained Running/Automatic with the exact listener snapshot above.

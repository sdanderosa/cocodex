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

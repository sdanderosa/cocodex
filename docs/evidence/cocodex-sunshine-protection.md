# CoCodex Sunshine protection evidence

Date: 2026-07-28

## Implemented boundary

- `protected-host-services.ts` defines the fail-closed Sunshine TCP/UDP range 47984-48010.
- Server configuration creation and load reject that range before startup.
- automatic UPnP, NAT-PMP, and PCP mapping rejects that range before any network request;
- Windows Firewall setup rejects that range before invoking `netsh`;
- `/healthz` includes the current CoCodex Server PID;
- direct `stop` and `restart` prove the exact healthy CoCodex service, protocol, and PID before signaling;
- no CoCodex Server setup path configures or replaces a Windows interface IP address.

## Regression evidence

Focused run:

```text
3 pass
0 fail
94 expect() calls
```

The full CoCodex Server directory run also included the protection suite:

```text
91 pass
0 fail
1040 expect() calls
```

The authoritative 70-step three-process scenario passed separately after the Server run:

```text
1 pass
0 fail
321 expect() calls
22.26s
```

The maintained CoCodex command explicitly includes the protection suite and passed after that command was updated:

```text
206 pass
0 fail
2288 expect() calls
40 files
```

The complete configured repository runner passed:

```text
4265 pass
4 skip
0 fail
21744 expect() calls
359 files
```

An intentionally harsher non-maintained order (all Server tests immediately followed by the 70-step scenario in one shell) reached step 70 with 318 assertions passed, then exhausted the scenario's outer 300-second timeout while its final isolated inherited runtime was starting. The same scenario immediately passed in its maintained order. This load/order timeout is not represented as a product pass and remains visible here as evidence discipline.

## Live-host before/after evidence

Before the focused and regression runs:

- `SunshineService`: Running, Automatic, PID 5044;
- `sunshine.exe`: PID 11100;
- TCP listeners owned by PID 11100: 47984, 47989, 47990, 48010;
- UDP listeners observed: 47998, 47999, 48000;
- foreign OpenCodex listener: `127.0.0.1:10100`, PID 3704.

After the runs:

- `SunshineService`: Running, Automatic, PID 5044;
- `sunshine.exe`: PID 11100;
- TCP listeners remained 47984, 47989, 47990, 48010, owned by PID 11100;
- foreign OpenCodex remained `127.0.0.1:10100`, PID 3704;
- UDP endpoints were not present in the later point-in-time query; CoCodex made no UDP bind, mapping, IP configuration, process signal, or Sunshine service operation. The stable service/process identity and enforced source boundary are the claims supported here—not an inference about Sunshine's own transient UDP lifecycle.

No Sunshine process or service was stopped, restarted, adopted, reconfigured, or signaled during these checks.

## Explicit non-interference clause verification - 2026-07-28

ADR 0054 now states the binding clause directly: CoCodex may read Sunshine
process, service, interface, and listener state for diagnostics, but must never
bind, reserve, forward, remap, firewall, stop, restart, reconfigure, or
otherwise mutate Sunshine's host IP, interfaces, service, processes, or TCP/UDP
ports. The source regression now scans the complete CoCodex Server source tree
for prohibited Windows IP/service/process mutation commands in addition to
testing every protected port and exact process ownership.

The focused Sunshine suite passed 3 tests, 0 failures, and 102 assertions. The
maintained CoCodex suite containing it passed 210 tests, 0 failures, and 2,350
assertions across 42 files. The final inherited root suite passed 4,265 tests,
4 skips, 0 failures, and 21,761 assertions across 359 files.

Before and after the source tests, clean build, NSIS smoke, MSI smoke, and
installed archive verifier, SunshineService remained Running/Automatic at PID
5044; `sunshine.exe` remained PID 11100; TCP listeners 47984, 47989, 47990,
and 48010 remained owned by PID 11100. Foreign OpenCodex PID 3704 remained the
sole `127.0.0.1:10100` owner. Neither service nor its IP/ports was changed.

## Project-leave continuation verification - 2026-07-28

The non-interference clause remains binding for the fail-safe project-member
leave transaction in ADR 0056. The full continuation gate passed 4,267 tests,
4 intentional skips, 0 failures, and 21,773 assertions across 360 files. The
focused Sunshine suite again passed 3 tests with no failures.

The post-gate snapshot exactly preserved `SunshineService` Running/Automatic at
PID 5044, `sunshine.exe` PID 11100, TCP listeners `0.0.0.0:47984`, `:47989`,
`:47990`, and `:48010`, and UDP endpoints `0.0.0.0:47998`, `:47999`, and
`:48000`, all under PID 11100. Foreign OpenCodex PID 3704 remained the sole
`127.0.0.1:10100` listener. No Sunshine IP, interface, port, firewall, service,
or process mutation occurred.

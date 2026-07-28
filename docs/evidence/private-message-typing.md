# Private-message typing evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Status: implemented and verified in source; installers not yet rebuilt

## Implemented behavior

Private typing uses dedicated `private.typing.send` and `private.typing`
frames. It does not reuse shared-project presence, enter encrypted message
history, or join the durable offline outbox.

CoCodex Server accepts typing only from an authenticated approved device,
rejects self-targeting and non-approved recipients, rate-limits each sender to
20 updates per second, routes only to the selected recipient's connected
sockets, and performs no database write for typing start or stop.

The resident Client resolves the recipient through its verified private-contact
certificate and trusted fingerprint store. It rejects unverified recipients,
requires a live Server connection, sends no offline typing event, parses the
strict Server frame, and emits only sender ID, recipient ID, and the boolean
state to the GUI bridge. A canary regression proves an injected ciphertext
field cannot reach the renderer.

The desktop sends one start signal instead of one event per keystroke, sends
stop after 1.8 seconds idle, sends stop before an encrypted message and when
switching contacts, clears local state on disconnect, and expires remote typing
after 5 seconds if a stop frame is lost. Its localized three-dot indicator is a
polite live status and disables animation under reduced-motion preferences.

## Verification

```text
protocol strictness: 24 passed, 0 failed, 164 expectations
real authenticated WSS Server: 8 passed, 0 failed, 129 expectations
compiled three-process path: 1 passed, 0 failed, 290 expectations
GUI bridge/redaction: 1 passed, 0 failed, 113 expectations
private state/helpers: 4 passed, 0 failed, 12 expectations
rendered chat shell: 5 passed, 0 failed, 20 expectations
explicit CoCodex main group: 178 passed, 0 failed, 2,061 expectations
complete GUI: 138 passed, 0 failed, 643 expectations
CoCodex TypeScript: passed
production GUI build: passed; 146 modules transformed
GUI lint: 0 errors, one pre-existing unrelated hook warning
localization lint: passed
privacy scan: passed
```

The first complete batched repository attempt ended with one failed worker out
of 15; the retained tail did not identify a test and no test process survived.
The identical full rerun passed all 354 files across all 15 fresh workers. This
is recorded rather than represented as two green runs.

## Remaining boundary

Typing indicators do not make the current sealed-box message transport a mature
ratchet. X3DH/PQXDH, Double Ratchet, forward secrecy, post-compromise recovery,
multi-device fan-out/recovery, encrypted attachments, attachment progress, and
desktop notifications remain open requirements.

The recorded MSI, NSIS, sidecar, and desktop hashes predate this source slice.
Foreign PID 23976 remained the sole listener on `127.0.0.1:10100` and was not
stopped or adopted.

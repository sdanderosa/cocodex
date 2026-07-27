# Windows user-bound private-key custody evidence

- Date: 2026-07-27
- Branch: `feat/cocodex-foundation`
- Base commit: `cda502ce`
- Implementation commit: recorded by the commit containing this file
- Status: complete focused, private-alpha, CoCodex, inherited OpenCodex, GUI,
  build, typecheck, and privacy gates pass

## Behavior proved

On Windows, CoCodex Client and Server private keys are stored in a strict
versioned envelope protected by Windows Data Protection API (DPAPI) with
`CurrentUser` scope and per-purpose entropy. The purposes independently bind
client signing, private messaging, project wrapping, Server identity, and
Server TLS material. Existing raw PEM files migrate through a protected
temporary file and atomic replacement.

The loader bounds and validates the stored envelope before asking DPAPI to
unprotect it, rejects noncanonical encoding and tampering, and validates every
private/public key relationship after decryption. Complete Server backups
unwrap keys only in memory and restores re-protect identity and TLS keys for the
restoring Windows user before validating the staged and final recovery state.

The same work fixes an independently reproduced private-mailbox ordering race:
an outbound `private.accepted` acknowledgement can no longer advance the
inbound message cursor past an earlier message delivered on another connection.

## Focused protection and cursor evidence

```powershell
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-local-protected-secret.test.ts `
  .\tests\cocodex-private-mailbox.test.ts `
  .\apps\cocodex-server\tests\backup.test.ts
```

Exit status `0`: `15 pass`, `0 fail`, `76 expect()` calls. The tests exercise
real Windows `CurrentUser` DPAPI, plaintext absence, wrong-purpose and tamper
rejection, pre-unprotect size bounds, legacy PEM migration, stable Client and
Server identity reload, keypair mismatch rejection, protected complete
recovery, and the deterministic mailbox cursor race.

## Real three-process evidence

```powershell
.\node_modules\.bin\bun.exe test `
  .\tests\cocodex-private-alpha-process.test.ts --timeout 120000
```

Exit status `0`: `1 pass`, `0 fail`, `290 expect()` calls.

The test launches one compiled CoCodex Server process and isolated Kai and
Stephen Client processes over real TLS/WSS transport. It proves enrollment,
approval, reconnect, authoritative project/chat state, reciprocal local-agent
execution, local-account usage attribution, streamed results, encrypted private
delivery, restart recovery, ordered queues, and private messages queued in both
directions around restart.

## Complete CoCodex and inherited regression

```powershell
.\node_modules\.bin\bun.exe run test:cocodex
.\node_modules\.bin\bun.exe run test:batched
```

Every command exited `0`:

- standalone compiled DPAPI packaging: `1 pass`, `0 fail`, `6 expect()` calls;
- agent safety CLI: `1 pass`, `0 fail`;
- three-process private alpha: `1 pass`, `0 fail`, `290 expect()` calls;
- complete CoCodex contract: `175 pass`, `0 fail`, `2020 expect()` calls
  across 37 files;
- inherited OpenCodex: all 349 files completed across 14 fresh isolated
  workers.

## Static, production, GUI, and privacy evidence

```powershell
.\node_modules\.bin\bun.exe run typecheck:cocodex
.\node_modules\.bin\bun.exe run build:cocodex-server
.\node_modules\.bin\bun.exe run build:cocodex-client
.\node_modules\.bin\bun.exe run privacy:scan
cd gui
..\node_modules\.bin\bun.exe test
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run lint:i18n
..\node_modules\.bin\bun.exe run build
```

Every command exited `0`: the Server bundled and compiled 371 modules; the
Client bundled and compiled 152 modules; privacy scanning passed; and the GUI
reported `122 pass`, `0 fail`, `579 expect()` calls. GUI lint had zero errors
and retained the existing unrelated `use-app-route-state.ts` exhaustive-deps
warning; i18n lint and the TypeScript/Vite production build passed.

## Security and licensing review

An independent security review checked the storage, migration, backup/restore,
native boundary, tests, and documentation. Its confirmed findings were
repaired: deterministic cursor coverage, bounded envelope reads, restored TLS
relationship validation, payload bounds, and precise trust-boundary language.
No production raw-private-key persistence bypass was found.

The design uses Windows DPAPI through exact `@primno/dpapi` 2.0.1 and
`node-gyp-build` 4.8.4 dependencies. Both are MIT-licensed, their notices are
preserved, and the audited private-alpha shrinkwrap includes their exact
integrity records. The architecture reference and ADR record the Microsoft
platform reference and the Syncthing concepts used for permanent device
identity; no GPL or MPL implementation code was copied.

## Primary files

- `src/lib/local-protected-secret.ts`
- `src/cocodex/identity.ts`
- `src/cocodex/session.ts`
- `apps/cocodex-server/src/identity.ts`
- `apps/cocodex-server/src/tls.ts`
- `apps/cocodex-server/src/recovery-backup.ts`
- `tests/cocodex-compiled-dpapi-standalone.test.ts`
- `tests/cocodex-local-protected-secret.test.ts`
- `tests/cocodex-private-mailbox.test.ts`
- `tests/cocodex-private-alpha-process.test.ts`
- `docs/adr/0047-cocodex-windows-user-bound-private-key-custody.md`

## Honest limits

`CurrentUser` DPAPI protects keys at rest from other Windows accounts and from
offline disk access; it does not defend against malware or a process already
running as the same user, nor against plaintext that legitimately exists in
process memory. A Server must be initialized, started, restarted, and restored
under the same Windows account. A future Windows Service installer must create
or restore protected state under its final service identity.

Non-Windows builds currently retain the explicit `filesystem-user-only`
compatibility envelope and do not claim encrypted at-rest key custody. Hardware
backed TPM/CNG non-exportable keys remain the preferred longer-term direction
once signing, X25519, TLS, and complete-recovery workflows can support them
coherently. Private messaging still uses static-recipient sealed boxes and does
not yet provide a maintained ratcheting protocol's forward secrecy or
post-compromise recovery.

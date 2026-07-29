# Encrypted file-reference UI evidence

## Scope

The CoCodex client now exposes the encrypted local-file-reference protocol as
an artifact-linked workflow. It lists locally decrypted reference metadata,
distinguishes local from remote hosts, and lets the artifact-producing device
publish a contained local path. It does not claim file upload, remote open, or
encrypted file-content transfer.

## Evidence commands

```powershell
cd gui
..\node_modules\.bin\bun.exe run lint
..\node_modules\.bin\bun.exe run build
..\node_modules\.bin\bun.exe test tests\cocodex-file-reference-ui.test.tsx

cd ..
.\node_modules\.bin\bun.exe test --max-concurrency=1 `
  .\tests\cocodex-gui-bridge.test.ts `
  .\tests\cocodex-project-encryption-session.test.ts `
  .\tests\cocodex-outbox.test.ts
.\node_modules\.bin\bun.exe run test:cocodex
```

## Assertions

- The project subscription requests `project.file-reference.list`.
- Accepted, published, and list-result events update artifact-linked reference
  state without exposing ciphertext.
- Only artifacts authored by this device appear in the publish selector.
- The visible DTO contains a canonical relative path, safe metadata, and a
  local/remote availability label. Server-originated file-reference DTOs do
  not carry an absolute workspace root or key material.
- The publish form sends its workspace root and path only to the local resident
  session through the origin- and capability-protected GUI bridge.
- The server-rendered component test renders decrypted reference metadata and
  rejects injected absolute-path and project-key canaries from its markup.
- A real resident-session regression proves raw project-key result and
  initialization frames do not reach its JSON event output. The GUI bridge
  independently strips any such envelope fields as defense in depth.
- Artifact-list reconciliation clears a selected artifact when it disappears
  or is not authored by the local device, and project changes reset the
  selection before requesting the next list.
- Production build, the complete GUI suite, and localization lint pass.

## Final results

Validated on 2026-07-26:

- `bun run test:cocodex`: exit 0; 116 passed, 0 failed, 1,041
  assertions across the complete private-alpha and CoCodex suites.
- `cd gui; bun test tests`: exit 0; 107 passed, 0 failed, 531
  assertions across the complete GUI suite.
- `cd gui; bun run lint`: exit 0 with one pre-existing unrelated
  `use-app-route-state.ts` hook-dependency warning.
- `cd gui; bun run build`: exit 0; TypeScript and the production Vite build
  completed.
- `bun run typecheck:cocodex`: exit 0.
- `bun run build:cocodex-server`: exit 0; produced the standalone server
  executable.
- `bun run build:cocodex-client`: exit 0; produced the standalone client
  executable.
- `bun run privacy:scan`: exit 0; `Privacy scan passed`.

Implementation commit: `45ea555a4929e56c4ee27d88da47624f195a629d`.

# Collaborative prompt caret and selection overlay evidence

- Date: 2026-07-28
- Implementation commit: `0c015519ddae450e74abf2652357d5086fd84415`
- Scope: privacy-safe inline remote caret, selection, and typing presentation
  over the authoritative Yjs shared-prompt textarea.

## Implemented behavior

`CollaborativePromptEditor` retains the production textarea and all existing
edit, focus, selection, and blur handlers. A pointer-inert visual layer mirrors
the textarea's wrapping and scroll position, segments bounded remote ranges,
renders overlapping selection state, and anchors a stable per-device colored
caret label at each remote head position. Device identifiers select colors but
are not serialized into rendered markup.

The overlay consumes the already authenticated, chat-scoped Yjs
RelativePosition presence projection. It does not create a second prompt
authority or transmit new plaintext fields.

## Focused and visual verification

Focused overlay tests passed `3/0/13`. Together with the existing Yjs
presence tests, the focused prompt gate passed `5/0/15`. Assertions cover
bounded and reversed ranges, overlapping selections, exact head carets,
zero-width end anchors, stable palette assignment, and omission of private
device IDs from markup.

An in-app-browser fixture exercised two remote users, a live typing label, a
multi-character selection, and a second zero-width caret. Initial visual QA
exposed clipped first-line labels and zero-width caret anchoring; the final CSS
reserves label headroom and uses inline-block caret anchors. The repeated
fixture showed both labels and selection/caret overlays, and browser console
errors and warnings were empty.

## Regression gates

```text
GUI                         145 pass, 0 fail, 674 assertions, 30 files
Maintained CoCodex          206 pass, 0 fail, 2,289 assertions, 40 files
Complete repository      4,265 pass, 4 skip, 0 fail, 21,745 assertions, 359 files
GUI lint                    0 errors, one pre-existing hook warning
GUI production build        exit 0, 152 modules
CoCodex TypeScript          exit 0
Privacy scan                passed
git diff --check            passed
```

The first complete run exposed a probabilistic TLS-negative fixture whose
replacement fingerprint could equal a real fingerprint beginning `FFFF-`.
The fixture now deterministically toggles between `FFFF-` and `0000-` and
asserts inequality. A later full-load run exposed scheduler sensitivity in the
device-revocation process harness; only its bounded wait/cleanup/test budgets
were widened. All revocation event assertions remain exact. Ten consecutive
focused TLS runs, an isolated revocation run, a concurrent heavy process/TLS
stress run, the maintained gate, and the final complete gate passed.

## Fresh clean-commit desktop artifacts

The private-alpha and Tauri builds completed from detached clean commit
`0c015519`. The first private-alpha attempt failed before packaging because the
release worktree lacked its GUI dependency junction; after preserving that
empty generated directory and wiring the already-installed GUI dependencies,
both builds exited zero. Exact outputs are preserved under
`dist/release-evidence/0c015519/`.

```text
Private-alpha archive  10,216,789 bytes  70d24242e2b441bc326487375562d3a3166fc26eb50aa76e1f1864eeb0c763fe
NSIS installer         30,564,458 bytes  b476b28ad692efdf7a669b4029b6ebd746794cd36ed69f4f748c9187b592b858
MSI installer          43,880,448 bytes  f78a49b36c0df919a252f8288b80269a55cb9b6f97d17c3897bbbb5f2f9afdb5
Bundled runtime       104,867,328 bytes  9020b0eb464160d9385aaa10a8e7c6711777af9c90d09d1f654292033d0d9a23
Release desktop        11,852,288 bytes  44d86c84cac548e34a8a001fb2815e1043da0464996048ea3e3882e2a986955c
```

Fresh NSIS silent installation and uninstall both exited zero. The installed
desktop hash was
`8599328c8bfe27893bc08a20407d569d5f6dbeaf472ea1260b9ec858dd9896e9`.
Its only direct child was Edge WebView2; it started zero bundled runtimes and
logged the foreign PID 3704 rejection.

Fresh MSI administrative extraction exited zero. Its desktop hash was
`5affbc3c42e1d488184b502a872873238dd4b5e2c41f5ea9f5a97d4fbc18237d`;
its runtime exactly matched the bundled runtime. Its only direct child was
Edge WebView2; it started zero bundled runtimes and logged the same foreign
owner rejection. Every pre-existing `msiexec.exe` remained present.

Across both smokes, PID 3704 retained `127.0.0.1:10100` and Sunshine PID 11100
retained TCP listeners 47984, 47989, 47990, and 48010. Final home checks showed
the OpenCodex task Running, `/healthz` status ok, OpenAI mode `direct`, and the
Repair Codex shortcut present.

These are unsigned private-alpha artifacts. Physical two-PC, live UAC/SCM and
reboot, signing/update, mature ratcheted multi-device attachments, elevated
helper, and official browser integration remain release gates.

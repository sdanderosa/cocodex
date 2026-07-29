# Private-message action evidence

- Date: 2026-07-28
- Branch: `feat/cocodex-foundation`
- Status: implemented and GUI-verified after commit `9975e21b`; not yet included in rebuilt installers

## Implemented boundary

The resident Client's version-2 private payload supports message, reply,
reaction, edit, and delete events. Action metadata is sealed inside the
ciphertext and bound by the Ed25519 signature transcript. The Server continues
to store and route ciphertext only.

The desktop now treats private history as an immutable event log and derives a
conversation projection:

- replies retain a same-conversation target;
- reactions retain the reacting sender IDs and support add/remove;
- only the original sender can edit or delete a projected message;
- cross-conversation and unauthorized mutations are ignored defensively; and
- deletion removes the old plaintext from the projected message.

The private-message panel exposes reply, thumbs-up reaction toggle, sender-only
edit, and sender-only delete controls. Composer and mutation commands are built
by tested shared constructors so their exact `private.send` payload matches the
resident Client contract.

## Verification

```text
focused projector and command constructors:
  4 passed, 0 failed, 10 expectations

complete GUI:
  137 passed, 0 failed, 636 expectations across 28 files

GUI lint:
  0 errors, one pre-existing use-app-route-state hook warning

GUI production build:
  TypeScript project build passed
  Vite production build passed
  146 modules transformed
```

Primary files:

- `src/cocodex/private-messaging.ts`
- `src/cocodex/session.ts`
- `gui/src/cocodex-private-message-state.ts`
- `gui/src/pages/CoCodex.tsx`
- `gui/src/styles-cocodex.css`
- `gui/tests/cocodex-private-message-state.test.ts`

## Explicit non-claims

This slice does not implement or claim X3DH/PQXDH, Double Ratchet, forward
secrecy, post-compromise recovery, multi-device fan-out/recovery, encrypted
attachments or desktop notifications. Typing indicators are covered separately
in `docs/evidence/private-message-typing.md`; the remaining items stay release
requirements in the product gap matrix.

The latest recorded NSIS/MSI/runtime hashes predate this GUI slice. They remain
valid evidence for the pushed release-gate checkpoint but must not be described
as installers containing these controls. Foreign PID 23976 remained the sole
listener on `127.0.0.1:10100` and was not stopped or adopted.

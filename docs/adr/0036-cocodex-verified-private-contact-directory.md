# ADR 0036: CoCodex verified private-contact directory

- Status: Accepted for the single-device private alpha
- Date: 2026-07-26
- Scope: approved-peer discovery, local fingerprint verification, and
  contact-based private messaging

## Context

CoCodex already transports signed, end-to-end encrypted private messages, but
the GUI requires a person to paste a recipient device UUID, fingerprint, and
full device-key certificate. That proves protocol mechanics without delivering
the requested **Messages → Stephen** product path. Replies, attachments,
notifications, and multi-device fan-out also need an authoritative recipient
directory rather than user-entered routing keys.

The Server already owns approved-device status and public enrollment metadata.
The Client already owns the explicit trusted-fingerprint list and verifies
self-signed device key certificates before using messaging keys.

## Open-source reference and licensing decision

Syncthing's device model informs the separation between discovered devices and
explicitly trusted fingerprints. MeshCentral informs the authoritative
server-directory/local-agent boundary. Matrix device lists inform distributing
public per-device identity metadata while keeping private session keys local.
Only concepts are adapted; no Syncthing (MPL-2.0), MeshCentral (Apache-2.0), or
Matrix source is copied, and no dependency is added.

## Decision

Add strict `private.contact.list` and `private.contact.snapshot` protocol
frames. An authenticated approved device may request a bounded snapshot of
other approved devices whose self-signed key certificate has been published.
Each contact contains:

- device ID;
- display name;
- enrolled Ed25519 fingerprint; and
- the public device-key certificate.

The Server excludes the requester, pending devices, revoked devices, and
devices without a certificate. It broadcasts a fresh snapshot when a
certificate is published and when the approved directory changes.

The resident Client verifies every certificate against its device ID and
advertised fingerprint. Raw certificates and public-key material remain inside
the resident process. The GUI receives only device ID, display name,
fingerprint, and whether that exact fingerprint is in the local trusted-device
store.

The verified public snapshot is cached in protected
`private-contacts.json`. The Client re-verifies every cached certificate on
load and binds the cache to the authenticated Server identity and authority
epoch. A previously verified contact remains usable for ciphertext queueing
after a Client restart while the same Server is offline, without carrying
contacts across an authority transfer or accidental repoint.

Discovery does not imply trust. The GUI requires the user to compare the
fingerprint with the contact through a separate trusted channel and enter the
independently confirmed value before **Verify** becomes available. The resident
binds that command to the current verified directory entry and rejects
arbitrary renderer-supplied device/fingerprint pairs. Only after this ceremony
may it resolve the retained certificate and encrypt a message. The GUI sends
only a selected contact ID and plaintext intended for that contact; it never
receives or supplies certificate JSON.

Certificate publication is idempotent and rate-limited. A repeated identical
certificate does not trigger a directory broadcast. If a cached recipient was
revoked while the Client was offline, the Server's terminal rejection removes
only that private envelope from the outbox, marks its encrypted local-history
entry **Not sent**, removes the stale resident contact, and continues draining
later durable work.

## Security invariants

- Only an authenticated approved device can enumerate contacts.
- Pending, revoked, self, and certificate-less devices are excluded.
- Device ID, certificate signature, enrolled fingerprint, and local trusted
  fingerprint must all agree before encryption.
- A display name is never used as an identity or routing key.
- The Server receives public certificates but never device private keys,
  messaging session keys, provider credentials, or private plaintext.
- The renderer never receives a device-key certificate or raw public key.
- Cached contacts are device- and Server-authority-bound, bounded, atomically
  written, ACL-protected, and cryptographically re-verified before use.
- Trust requires an independently confirmed fingerprint and is bound to the
  current resident contact, never merely to a display name or renderer claim.
- Revocation removes the peer from subsequent authoritative snapshots and the
  Server continues to reject delivery to a revoked device without allowing one
  terminal private frame to block later outbox events.

## Consequences and limits

The private panel can behave as a contact conversation instead of a
cryptographic setup form. This remains a device-level, single-device alpha
directory. User-level multi-device grouping, independent ratcheted sessions,
replacement/lost-device recovery, replies, reactions, attachments, and
notification delivery remain separate requirements.

## Required evidence

- strict protocol schema tests;
- storage tests excluding self, pending, revoked, and certificate-less rows;
- real WSS discovery and directory-change tests;
- resident and GUI-bridge tests proving certificate verification and renderer
  redaction; and
- the three-process harness sending both directions using only a discovered
  recipient device ID, then restarting offline, queueing through the verified
  cache, revoking that cached recipient, visibly rejecting only the stale
  private message, and draining a later shared event.

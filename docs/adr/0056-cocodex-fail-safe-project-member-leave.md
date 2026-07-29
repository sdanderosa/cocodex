# ADR 0056: Fail-safe project-member leave

Status: Accepted

## Context

A project member must be able to leave without continuing to receive encrypted project state. The departing member cannot safely generate the successor project key because that would preserve its access. Removing membership before an owner is available to rotate would also leave surviving clients using a key known to the leaver.

## Decision

A non-owner Client submits a strict, signed, expiring `project.member.leave` request bound to the project, Server fingerprint and Server epoch. The Client stores the exact frame in its durable outbox until a strict matching Server acknowledgement arrives.

The authoritative Server then commits one immediate quarantine transaction. It records the pending leave, marks project-key rotation required, denies the member all project authorization and project listing, excludes the member from key-envelope delivery and every future recipient set, disables its hosted agents, fails its queued/running task participation, expires pending project invitations, clears presence, and notifies surviving members. The departing Client revokes its local project access as soon as the acknowledgement is accepted.

The owner completes the leave with the existing atomic remove-and-rotate operation. Only the owner generates the successor key and envelopes for the exact surviving approved roster. Membership removal, key-epoch advancement, durable leave completion, task cleanup and audit records commit together. A project owner cannot use self-leave until an ownership-transfer protocol exists; the owner must archive or delete the project.

Duplicate delivery is an exact replay. Conflicting request IDs, signatures, nonces, authorities, validity windows, memberships or key epochs fail closed. A pending leaver cannot regain access by reconnecting or by replaying an old envelope request.

## Consequences

Leave can remain visibly pending until an owner comes online, but confidentiality fails closed immediately. The departing member never learns the successor key. Owners receive an explicit pending-leave roster state and a confirmation-gated complete-and-rotate action.

This transaction does not authorize host-network or process changes. ADR 0054 remains binding: Sunshine's IP configuration, interfaces, service, processes, and TCP/UDP ports are read-only to CoCodex, and any conflict fails closed without changing Sunshine.

## Verification

Coverage includes strict protocol parsing and signing, exact replay, authority and expiry rejection, immediate quarantine, task and agent cleanup, key-envelope exclusion, durable outbox acknowledgement, renderer privilege minimization, real WSS routing, resident Client signing/local revocation, owner-only completion, GUI confirmation and migration from schema versions 1 through 33.

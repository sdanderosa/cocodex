import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import {
  decodeInvitation,
  createDeviceKeyCertificate,
  enrollmentSigningTranscript,
  projectCreationSigningTranscript,
  projectContentSigningTranscript,
  projectKeyEnvelopeSigningTranscript,
  projectInvitationDecisionTranscript,
  projectInvitationSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectKeyEnvelope,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice, revokeDevice } from "../src/enrollment";
import { createInvitation } from "../src/invitations";
import {
  getEncryptedProjectContext,
  createEncryptedProject,
  getProjectKeyEpoch,
  getUnresolvedProjectRevocationIncidentForDevice,
  initializeProjectKeyEpoch,
  listUnresolvedProjectRevocationIncidentsForDevice,
  listProjectKeyEnvelopes,
  removeProjectMemberAndInvalidateKeys,
  removeProjectMemberAndRotateKeys,
  rotateProjectKeyEpoch,
  shareProjectKeyEnvelope,
  updateEncryptedProjectContext,
} from "../src/project-encryption-storage";
import {
  cancelProjectInvitation,
  createProjectInvitation,
  listProjectInvitations,
  respondToProjectInvitation,
} from "../src/project-invitations";
import { listEncryptedArtifacts, publishEncryptedArtifact } from "../src/encrypted-artifacts";
import { listEncryptedFileReferences, publishEncryptedFileReference } from "../src/encrypted-file-references";
import { addProjectMember, createProject } from "../src/shared-state";

interface TestDevice {
  id: string;
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  projectWrapPublicKey: string;
}

function approvedDevice(db: ReturnType<typeof openDatabase>, name: string): TestDevice {
  const signing = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const projectWrap = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const now = new Date("2027-01-01T00:00:00.000Z");
  const invitation = decodeInvitation(createInvitation(db, {
    host: "server.test",
    port: 10443,
    serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
    now,
  }));
  const challenge = createEnrollmentChallenge(db, invitation, signing.publicKey, invitation.serverFingerprint, now);
  const signature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: invitation.serverFingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName: name,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    projectWrapPublicKeyPem: projectWrap.publicKey,
  }), signing.privateKey).toString("base64url");
  const enrolled = enrollDevice(db, {
    invitation,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName: name,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    projectWrapPublicKeyPem: projectWrap.publicKey,
    signature,
  }, now);
  expect(approveDevice(db, enrolled.fingerprint, now)).toBeTrue();
  db.query("UPDATE devices SET device_key_certificate = ? WHERE id = ?").run(
    createDeviceKeyCertificate(enrolled.id, {
      publicKeyPem: signing.publicKey,
      privateKeyPem: signing.privateKey,
      messagingPublicKeyPem: messaging.publicKey,
      projectWrapPublicKeyPem: projectWrap.publicKey,
    }),
    enrolled.id,
  );
  return {
    id: enrolled.id,
    fingerprint: enrolled.fingerprint,
    publicKey: signing.publicKey,
    privateKey: signing.privateKey,
    projectWrapPublicKey: projectWrap.publicKey,
  };
}

function keyEnvelope(
  projectId: string,
  sender: TestDevice,
  recipientDeviceId: string,
  keyEpoch = 1,
  sealedProjectKey = randomBytes(80).toString("base64url"),
): ProjectKeyEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch,
    recipientDeviceId,
    senderDeviceId: sender.id,
    sealedProjectKey,
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectKeyEnvelopeSigningTranscript(unsigned), sender.privateKey).toString("base64url"),
  };
}

function projectInvitationFrame(
  projectId: string,
  owner: TestDevice,
  recipient: TestDevice,
  now = new Date("2027-01-01T00:00:00.000Z"),
  keyEpoch = 1,
) {
  const invitationId = randomUUID();
  const envelope = keyEnvelope(projectId, owner, recipient.id, keyEpoch);
  const input = {
    invitationId,
    projectId,
    serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
    ownerDeviceId: owner.id,
    recipientDeviceId: recipient.id,
    keyEpoch,
    envelope,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60 * 60 * 1_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
  };
  return {
    version: 1 as const,
    type: "project.invite.create" as const,
    requestId: randomUUID(),
    ...input,
    signature: sign(null, projectInvitationSigningTranscript(input), owner.privateKey).toString("base64url"),
  };
}

function contextEnvelope(
  projectId: string,
  sender: TestDevice,
  recordId: string,
  keyEpoch = 1,
  ciphertext = randomBytes(16).toString("base64url"),
): ProjectContentEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch,
    recordType: "shared-context" as const,
    recordId,
    nonce: randomBytes(24).toString("base64url"),
    ciphertext,
    senderDeviceId: sender.id,
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectContentSigningTranscript(unsigned), sender.privateKey).toString("base64url"),
  };
}

function artifactEnvelope(
  projectId: string,
  sender: TestDevice,
  artifactId: string,
  keyEpoch = 1,
  ciphertext = randomBytes(64).toString("base64url"),
): ProjectContentEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch,
    recordType: "artifact" as const,
    recordId: artifactId,
    nonce: randomBytes(24).toString("base64url"),
    ciphertext,
    senderDeviceId: sender.id,
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectContentSigningTranscript(unsigned), sender.privateKey).toString("base64url"),
  };
}

function fileReferenceEnvelope(
  projectId: string,
  sender: TestDevice,
  referenceId: string,
  keyEpoch = 1,
): ProjectContentEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch,
    recordType: "file-reference" as const,
    recordId: referenceId,
    nonce: randomBytes(24).toString("base64url"),
    ciphertext: randomBytes(96).toString("base64url"),
    senderDeviceId: sender.id,
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectContentSigningTranscript(unsigned), sender.privateKey).toString("base64url"),
  };
}

describe("opaque project-encryption server storage", () => {
  test("creates membership and epoch one atomically with exact replay", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const projectId = randomUUID();
      const name = "Nocturne Launcher";
      const envelopes = [keyEnvelope(projectId, owner, owner.id)];
      const signature = sign(null, projectCreationSigningTranscript({
        projectId,
        name,
        ownerDeviceId: owner.id,
        envelopes,
      }), owner.privateKey).toString("base64url");
      const creationId = randomUUID();

      expect(createEncryptedProject(
        db, projectId, name, owner.id, creationId, envelopes, signature,
      )).toMatchObject({
        project: { id: projectId, name, role: "owner" },
        keyEpoch: 1,
        created: true,
      });
      expect(db.query("SELECT role FROM project_members WHERE project_id = ? ORDER BY role DESC")
        .all(projectId)).toEqual([{ role: "owner" }]);
      expect(db.query("SELECT current_epoch AS currentEpoch FROM project_key_epochs WHERE project_id = ?")
        .get(projectId)).toEqual({ currentEpoch: 1 });
      expect(createEncryptedProject(
        db, projectId, name, owner.id, creationId, [...envelopes].reverse(), signature,
      ).created).toBeFalse();
      expect(() => createEncryptedProject(
        db, projectId, name, owner.id, randomUUID(), envelopes, signature,
      )).toThrow("already been initialized");
      const changedEnvelopes = [keyEnvelope(projectId, owner, owner.id)];
      const changedSignature = sign(null, projectCreationSigningTranscript({
        projectId,
        name,
        ownerDeviceId: owner.id,
        envelopes: changedEnvelopes,
      }), owner.privateKey).toString("base64url");
      expect(() => createEncryptedProject(
        db, projectId, name, owner.id, creationId, changedEnvelopes, changedSignature,
      )).toThrow("replay conflict");

      const rejectedProjectId = randomUUID();
      const other = approvedDevice(db, "Kai");
      const incomplete = [keyEnvelope(rejectedProjectId, owner, other.id)];
      const rejectedSignature = sign(null, projectCreationSigningTranscript({
        projectId: rejectedProjectId,
        name: "Rejected",
        ownerDeviceId: owner.id,
        envelopes: incomplete,
      }), owner.privateKey).toString("base64url");
      expect(() => createEncryptedProject(
        db, rejectedProjectId, "Rejected", owner.id, randomUUID(), incomplete, rejectedSignature,
      )).toThrow("only the owner");
      expect(db.query("SELECT COUNT(*) AS count FROM projects WHERE id = ?")
        .get(rejectedProjectId)).toEqual({ count: 0 });

      const revokedProjectId = randomUUID();
      const revokedEnvelopes = [
        keyEnvelope(revokedProjectId, owner, owner.id),
        keyEnvelope(revokedProjectId, owner, other.id),
      ];
      const revokedSignature = sign(null, projectCreationSigningTranscript({
        projectId: revokedProjectId,
        name: "Unsolicited member",
        ownerDeviceId: owner.id,
        envelopes: revokedEnvelopes,
      }), owner.privateKey).toString("base64url");
      expect(() => createEncryptedProject(
        db, revokedProjectId, "Unsolicited member", owner.id, randomUUID(), revokedEnvelopes, revokedSignature,
      )).toThrow("exactly the owner");
      expect(db.query("SELECT COUNT(*) AS count FROM projects WHERE id = ?")
        .get(revokedProjectId)).toEqual({ count: 0 });

      expect(() => createEncryptedProject(
        db, projectId, "Altered name", owner.id, creationId, envelopes, signature,
      )).toThrow("signature");
      expect(db.query("SELECT COUNT(*) AS count FROM projects WHERE id = ?")
        .get(projectId)).toEqual({ count: 1 });
    } finally {
      db.close();
    }
  });

  test("requires an addressed signed acceptance before atomically adding membership and its key", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const owner = approvedDevice(db, "Stephen");
      const recipient = approvedDevice(db, "Kai");
      const outsider = approvedDevice(db, "Outsider");
      const projectId = randomUUID();
      const ownerEnvelope = keyEnvelope(projectId, owner, owner.id);
      const creationSignature = sign(null, projectCreationSigningTranscript({
        projectId,
        name: "Invitation project",
        ownerDeviceId: owner.id,
        envelopes: [ownerEnvelope],
      }), owner.privateKey).toString("base64url");
      createEncryptedProject(
        db,
        projectId,
        "Invitation project",
        owner.id,
        randomUUID(),
        [ownerEnvelope],
        creationSignature,
        now,
      );

      const frame = projectInvitationFrame(projectId, owner, recipient, now);
      const created = createProjectInvitation(
        db,
        owner.id,
        frame.serverFingerprint,
        frame,
        now,
      );
      expect(created.created).toBeTrue();
      expect(createProjectInvitation(db, owner.id, frame.serverFingerprint, frame, now).created).toBeFalse();
      expect(db.query("SELECT COUNT(*) AS count FROM project_members WHERE project_id = ?")
        .get(projectId)).toEqual({ count: 1 });
      expect(db.query(`
        SELECT COUNT(*) AS count FROM project_key_envelopes
        WHERE project_id = ? AND recipient_device_id = ?
      `).get(projectId, recipient.id)).toEqual({ count: 0 });
      expect(listProjectInvitations(db, recipient.id, now)[0]).toMatchObject({
        invitationId: frame.invitationId,
        status: "pending",
        recipientDeviceId: recipient.id,
      });

      const signingInput = {
        invitationId: frame.invitationId,
        projectId,
        serverFingerprint: frame.serverFingerprint,
        ownerDeviceId: owner.id,
        recipientDeviceId: recipient.id,
        keyEpoch: 1,
        envelope: frame.envelope,
        issuedAt: frame.issuedAt,
        expiresAt: frame.expiresAt,
        nonce: frame.nonce,
      };
      const outsiderSignature = sign(
        null,
        projectInvitationDecisionTranscript(signingInput, "accept"),
        outsider.privateKey,
      ).toString("base64url");
      expect(() => respondToProjectInvitation(
        db,
        outsider.id,
        frame.serverFingerprint,
        frame.invitationId,
        "accept",
        outsiderSignature,
        now,
      )).toThrow("not addressed");
      const acceptanceSignature = sign(
        null,
        projectInvitationDecisionTranscript(signingInput, "accept"),
        recipient.privateKey,
      ).toString("base64url");
      const accepted = respondToProjectInvitation(
        db,
        recipient.id,
        frame.serverFingerprint,
        frame.invitationId,
        "accept",
        acceptanceSignature,
        now,
      );
      expect(accepted).toMatchObject({ created: true, invitation: { status: "accepted" } });
      expect(respondToProjectInvitation(
        db,
        recipient.id,
        frame.serverFingerprint,
        frame.invitationId,
        "accept",
        acceptanceSignature,
        now,
      ).created).toBeFalse();
      expect(createProjectInvitation(
        db,
        owner.id,
        frame.serverFingerprint,
        frame,
        now,
      )).toMatchObject({ created: false, invitation: { status: "accepted" } });
      expect(db.query(`
        SELECT role FROM project_members WHERE project_id = ? AND device_id = ?
      `).get(projectId, recipient.id)).toEqual({ role: "member" });
      expect(db.query(`
        SELECT COUNT(*) AS count FROM project_key_envelopes
        WHERE project_id = ? AND key_epoch = 1 AND recipient_device_id = ?
      `).get(projectId, recipient.id)).toEqual({ count: 1 });
      expect(db.query(`
        SELECT event_type AS eventType FROM audit_events WHERE subject_id = ?
      `).get(frame.invitationId)).toEqual({ eventType: "project.invite.accepted" });

      const secondRecipient = approvedDevice(db, "Angela");
      const declinedFrame = projectInvitationFrame(projectId, owner, secondRecipient, now);
      createProjectInvitation(db, owner.id, declinedFrame.serverFingerprint, declinedFrame, now);
      const declinedInput = {
        invitationId: declinedFrame.invitationId,
        projectId,
        serverFingerprint: declinedFrame.serverFingerprint,
        ownerDeviceId: owner.id,
        recipientDeviceId: secondRecipient.id,
        keyEpoch: 1,
        envelope: declinedFrame.envelope,
        issuedAt: declinedFrame.issuedAt,
        expiresAt: declinedFrame.expiresAt,
        nonce: declinedFrame.nonce,
      };
      const declinedSignature = sign(
        null,
        projectInvitationDecisionTranscript(declinedInput, "decline"),
        secondRecipient.privateKey,
      ).toString("base64url");
      expect(respondToProjectInvitation(
        db,
        secondRecipient.id,
        declinedFrame.serverFingerprint,
        declinedFrame.invitationId,
        "decline",
        declinedSignature,
        now,
      )).toMatchObject({ invitation: { status: "declined" } });
      expect(db.query(`
        SELECT COUNT(*) AS count FROM project_members WHERE project_id = ? AND device_id = ?
      `).get(projectId, secondRecipient.id)).toEqual({ count: 0 });

      const cancelRecipient = approvedDevice(db, "Sue");
      const cancelledFrame = projectInvitationFrame(projectId, owner, cancelRecipient, now);
      createProjectInvitation(db, owner.id, cancelledFrame.serverFingerprint, cancelledFrame, now);
      const cancelledInput = {
        invitationId: cancelledFrame.invitationId,
        projectId,
        serverFingerprint: cancelledFrame.serverFingerprint,
        ownerDeviceId: owner.id,
        recipientDeviceId: cancelRecipient.id,
        keyEpoch: 1,
        envelope: cancelledFrame.envelope,
        issuedAt: cancelledFrame.issuedAt,
        expiresAt: cancelledFrame.expiresAt,
        nonce: cancelledFrame.nonce,
      };
      const cancelSignature = sign(
        null,
        projectInvitationDecisionTranscript(cancelledInput, "cancel"),
        owner.privateKey,
      ).toString("base64url");
      expect(cancelProjectInvitation(
        db,
        owner.id,
        cancelledFrame.serverFingerprint,
        cancelledFrame.invitationId,
        cancelSignature,
        now,
      )).toMatchObject({ invitation: { status: "cancelled" } });

      const tamperRecipient = approvedDevice(db, "Tamper target");
      const tamperedFrame = projectInvitationFrame(projectId, owner, tamperRecipient, now);
      const tamperedSealedKey = Buffer.from(tamperedFrame.envelope.sealedProjectKey, "base64url");
      tamperedSealedKey[0] ^= 1;
      expect(() => createProjectInvitation(
        db,
        owner.id,
        tamperedFrame.serverFingerprint,
        {
          ...tamperedFrame,
          envelope: {
            ...tamperedFrame.envelope,
            sealedProjectKey: tamperedSealedKey.toString("base64url"),
          },
        },
        now,
      )).toThrow("envelope signature is invalid");
      const tamperedOwnerSignature = Buffer.from(tamperedFrame.signature, "base64url");
      tamperedOwnerSignature[0] ^= 1;
      expect(() => createProjectInvitation(
        db,
        owner.id,
        tamperedFrame.serverFingerprint,
        { ...tamperedFrame, signature: tamperedOwnerSignature.toString("base64url") },
        now,
      )).toThrow("invitation signature is invalid");
      expect(db.query(`
        SELECT COUNT(*) AS count FROM project_invitations WHERE invitation_id = ?
      `).get(tamperedFrame.invitationId)).toEqual({ count: 0 });

      const expiringRecipient = approvedDevice(db, "Expiry target");
      const expiringFrame = projectInvitationFrame(projectId, owner, expiringRecipient, now);
      createProjectInvitation(db, owner.id, expiringFrame.serverFingerprint, expiringFrame, now);
      const afterExpiry = new Date(new Date(expiringFrame.expiresAt).getTime() + 1);
      expect(listProjectInvitations(db, expiringRecipient.id, afterExpiry)[0]).toMatchObject({
        invitationId: expiringFrame.invitationId,
        status: "expired",
      });
      expect(db.query(`
        SELECT event_type AS eventType, details_json AS detailsJson
        FROM audit_events WHERE subject_id = ?
      `).get(expiringFrame.invitationId)).toEqual({
        eventType: "project.invite.expired",
        detailsJson: JSON.stringify({ projectId, reason: "time-window" }),
      });

      const staleRecipient = approvedDevice(db, "Stale epoch target");
      const staleFrame = projectInvitationFrame(projectId, owner, staleRecipient, now);
      createProjectInvitation(db, owner.id, staleFrame.serverFingerprint, staleFrame, now);
      rotateProjectKeyEpoch(
        db,
        projectId,
        owner.id,
        1,
        randomUUID(),
        [
          keyEnvelope(projectId, owner, owner.id, 2),
          keyEnvelope(projectId, owner, recipient.id, 2),
        ],
        now,
      );
      expect(listProjectInvitations(db, staleRecipient.id, now)[0]).toMatchObject({
        invitationId: staleFrame.invitationId,
        status: "expired",
      });
      expect(createProjectInvitation(
        db,
        owner.id,
        staleFrame.serverFingerprint,
        staleFrame,
        now,
      )).toMatchObject({ created: false, invitation: { status: "expired" } });
      expect(db.query(`
        SELECT details_json AS detailsJson FROM audit_events
        WHERE subject_id = ? AND event_type = 'project.invite.expired'
      `).get(staleFrame.invitationId)).toEqual({
        detailsJson: JSON.stringify({ projectId, reason: "key-epoch", minimumEpoch: 2 }),
      });

      const revokedRecipient = approvedDevice(db, "Revoked invite target");
      const revokedFrame = projectInvitationFrame(projectId, owner, revokedRecipient, now, 2);
      createProjectInvitation(db, owner.id, revokedFrame.serverFingerprint, revokedFrame, now);
      const revokedFingerprint = db.query(`
        SELECT fingerprint FROM devices WHERE id = ?
      `).get(revokedRecipient.id) as { fingerprint: string };
      expect(revokeDevice(db, revokedFingerprint.fingerprint, now)).toBeTrue();
      expect(db.query(`
        SELECT status FROM project_invitations WHERE invitation_id = ?
      `).get(revokedFrame.invitationId)).toEqual({ status: "expired" });
      expect(db.query(`
        SELECT details_json AS detailsJson FROM audit_events
        WHERE subject_id = ? AND event_type = 'project.invite.expired'
      `).get(revokedFrame.invitationId)).toEqual({
        detailsJson: JSON.stringify({
          projectId,
          reason: "device-revoked",
          deviceId: revokedRecipient.id,
        }),
      });
    } finally {
      db.close();
    }
  });

  test("initializes every approved member atomically and replays by request ID", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const project = createProject(db, "Atomic encrypted project", owner.id);
      addProjectMember(db, project.id, owner.id, member.id);
      const ownerEnvelope = keyEnvelope(project.id, owner, owner.id);
      const memberEnvelope = keyEnvelope(project.id, owner, member.id);
      const initializationId = randomUUID();

      const initialized = initializeProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        initializationId,
        [ownerEnvelope, memberEnvelope],
      );
      expect(initialized).toMatchObject({
        projectId: project.id,
        currentEpoch: 1,
        keyEpoch: 1,
        created: true,
        envelopes: [ownerEnvelope, memberEnvelope],
      });
      expect(db.query("SELECT COUNT(*) AS count FROM project_key_envelopes WHERE project_id = ?")
        .get(project.id)).toEqual({ count: 2 });
      expect(initializeProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        initializationId,
        [ownerEnvelope, memberEnvelope],
      ).created).toBeFalse();
      expect(db.query("SELECT COUNT(*) AS count FROM project_key_epochs WHERE project_id = ?")
        .get(project.id)).toEqual({ count: 1 });
      const secondProject = createProject(db, "Second atomic encrypted project", owner.id);
      addProjectMember(db, secondProject.id, owner.id, member.id);
      const secondInitialized = initializeProjectKeyEpoch(
        db,
        secondProject.id,
        owner.id,
        initializationId,
        [keyEnvelope(secondProject.id, owner, owner.id), keyEnvelope(secondProject.id, owner, member.id)],
      );
      expect(secondInitialized.created).toBeTrue();
      expect(() => initializeProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        randomUUID(),
        [keyEnvelope(project.id, owner, owner.id)],
      )).toThrow("every approved project member");

      const incompleteProject = createProject(db, "Incomplete encrypted project", owner.id);
      addProjectMember(db, incompleteProject.id, owner.id, member.id);
      expect(() => initializeProjectKeyEpoch(
        db,
        incompleteProject.id,
        owner.id,
        randomUUID(),
        [keyEnvelope(incompleteProject.id, owner, owner.id)],
      )).toThrow("every approved project member");
      expect(db.query("SELECT COUNT(*) AS count FROM project_key_envelopes WHERE project_id = ?")
        .get(incompleteProject.id)).toEqual({ count: 0 });
      expect(db.query("SELECT COUNT(*) AS count FROM project_key_epochs WHERE project_id = ?")
        .get(incompleteProject.id)).toEqual({ count: 0 });
    } finally {
      db.close();
    }
  });

  test("enforces owner key sharing, recipient membership, and idempotent envelopes", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const outsider = approvedDevice(db, "Outsider");
      const project = createProject(db, "Encrypted project", owner.id);
      addProjectMember(db, project.id, owner.id, member.id);
      const envelope = keyEnvelope(project.id, owner, member.id);

      expect(shareProjectKeyEnvelope(db, project.id, owner.id, envelope).created).toBeTrue();
      expect(shareProjectKeyEnvelope(db, project.id, owner.id, envelope).created).toBeFalse();
      expect(listProjectKeyEnvelopes(db, project.id, member.id)).toEqual([envelope]);
      expect(listProjectKeyEnvelopes(db, project.id, member.id, 2)).toEqual([]);
      const tamperedKeySignature = Buffer.from(envelope.signature, "base64url");
      tamperedKeySignature[0] ^= 1;
      expect(() => shareProjectKeyEnvelope(db, project.id, owner.id, {
        ...envelope,
        keyEpoch: 2,
        signature: tamperedKeySignature.toString("base64url"),
      })).toThrow("signature is invalid");
      expect(() => shareProjectKeyEnvelope(db, project.id, member.id, envelope))
        .toThrow("Only a project owner");
      const outsiderEnvelope = keyEnvelope(project.id, owner, outsider.id);
      expect(() => shareProjectKeyEnvelope(db, project.id, owner.id, outsiderEnvelope))
        .toThrow("approved project member");
      expect(() => shareProjectKeyEnvelope(
        db,
        project.id,
        owner.id,
        keyEnvelope(project.id, owner, member.id, 1, randomBytes(80).toString("base64url")),
      )).toThrow("replay conflict");
      expect(() => listProjectKeyEnvelopes(db, project.id, outsider.id)).toThrow("approved project member");
    } finally {
      db.close();
    }
  });

  test("manages monotonic key epochs and invalidates removed members", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const project = createProject(db, "Rotating encrypted project", owner.id);
      addProjectMember(db, project.id, owner.id, member.id);

      const epochOneOwner = keyEnvelope(project.id, owner, owner.id, 1);
      const epochOneMember = keyEnvelope(project.id, owner, member.id, 1);
      expect(shareProjectKeyEnvelope(db, project.id, owner.id, epochOneOwner).created).toBeTrue();
      expect(shareProjectKeyEnvelope(db, project.id, owner.id, epochOneMember).created).toBeTrue();
      expect(getProjectKeyEpoch(db, project.id, owner.id)).toMatchObject({ currentEpoch: 1 });

      const rotationId = randomUUID();
      const epochTwoOwner = keyEnvelope(project.id, owner, owner.id, 2);
      const epochTwoMember = keyEnvelope(project.id, owner, member.id, 2);
      const firstRotation = rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        1,
        rotationId,
        [epochTwoOwner, epochTwoMember],
      );
      expect(firstRotation).toMatchObject({ keyEpoch: 2, created: true });
      expect(firstRotation.envelopes).toEqual([epochTwoOwner, epochTwoMember]);
      expect(rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        1,
        rotationId,
        [epochTwoOwner, epochTwoMember],
      ).created).toBeFalse();
      expect(getProjectKeyEpoch(db, project.id, owner.id)).toMatchObject({ currentEpoch: 2 });

      expect(() => rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        1,
        randomUUID(),
        [epochTwoOwner, epochTwoMember],
      )).toThrow("rotation conflict");
      expect(() => shareProjectKeyEnvelope(
        db,
        project.id,
        owner.id,
        keyEnvelope(project.id, owner, member.id, 1),
      )).toThrow("stale");
      expect(() => shareProjectKeyEnvelope(
        db,
        project.id,
        owner.id,
        keyEnvelope(project.id, owner, member.id, 3),
      )).toThrow("requires a project key rotation");
      expect(() => rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        2,
        randomUUID(),
        [keyEnvelope(project.id, owner, owner.id, 3)],
      )).toThrow("every approved project member");
      expect(() => rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        2,
        randomUUID(),
        [
          keyEnvelope(project.id, owner, owner.id, 3),
          keyEnvelope(project.id, owner, owner.id, 3),
          keyEnvelope(project.id, owner, member.id, 3),
        ],
      )).toThrow("duplicate");

      removeProjectMemberAndInvalidateKeys(db, project.id, owner.id, member.id);
      expect(() => listProjectKeyEnvelopes(db, project.id, member.id))
        .toThrow("approved project member");
      expect(db.query(
        "SELECT COUNT(*) AS count FROM project_key_envelopes WHERE project_id = ? AND recipient_device_id = ?",
      ).get(project.id, member.id)).toEqual({ count: 0 });

      const epochThreeOwner = keyEnvelope(project.id, owner, owner.id, 3);
      const afterRemoval = rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        2,
        randomUUID(),
        [epochThreeOwner],
      );
      expect(afterRemoval).toMatchObject({ keyEpoch: 3, created: true });
      expect(getProjectKeyEpoch(db, project.id, owner.id)).toMatchObject({ currentEpoch: 3 });
    } finally {
      db.close();
    }
  });

  test("atomically removes a member, cancels both task directions, and rotates to the exact remaining roster", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const owner = approvedDevice(db, "Stephen");
      const removed = approvedDevice(db, "Kai");
      const survivor = approvedDevice(db, "Angela");
      const project = createProject(db, "Atomic member revocation", owner.id, now);
      addProjectMember(db, project.id, owner.id, removed.id, now);
      addProjectMember(db, project.id, owner.id, survivor.id, now);
      initializeProjectKeyEpoch(db, project.id, owner.id, randomUUID(), [
        keyEnvelope(project.id, owner, owner.id, 1),
        keyEnvelope(project.id, owner, removed.id, 1),
        keyEnvelope(project.id, owner, survivor.id, 1),
      ], now);

      const ownerAgent = randomUUID();
      const removedAgent = randomUUID();
      db.query(`
        INSERT INTO agents (id, project_id, host_device_id, name, enabled, created_at)
        VALUES (?, ?, ?, 'Owner agent', 1, ?), (?, ?, ?, 'Removed agent', 1, ?)
      `).run(ownerAgent, project.id, owner.id, now.toISOString(),
        removedAgent, project.id, removed.id, now.toISOString());
      const insertTask = db.query(`
        INSERT INTO agent_tasks (
          id, project_id, chat_id, requester_device_id, target_device_id, agent_id,
          prompt, nonce, issued_at, expires_at, requester_signature,
          server_signature, status, accepted_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'opaque', ?, ?, ?, 'request-signature',
          'server-signature', 'queued', ?)
      `);
      const removedRequesterTask = randomUUID();
      const removedTargetTask = randomUUID();
      const unrelatedTask = randomUUID();
      const expiry = new Date(now.getTime() + 60_000).toISOString();
      insertTask.run(removedRequesterTask, project.id, project.id, removed.id, owner.id, ownerAgent,
        randomUUID(), now.toISOString(), expiry, now.toISOString());
      insertTask.run(removedTargetTask, project.id, project.id, owner.id, removed.id, removedAgent,
        randomUUID(), now.toISOString(), expiry, now.toISOString());
      insertTask.run(unrelatedTask, project.id, project.id, owner.id, survivor.id, ownerAgent,
        randomUUID(), now.toISOString(), expiry, now.toISOString());

      const rotationId = randomUUID();
      const epochTwoOwner = keyEnvelope(project.id, owner, owner.id, 2);
      const epochTwoSurvivor = keyEnvelope(project.id, owner, survivor.id, 2);
      expect(() => removeProjectMemberAndRotateKeys(
        db, project.id, owner.id, removed.id, 1, rotationId, [epochTwoOwner], now,
      )).toThrow("every remaining approved project member");
      expect(db.query("SELECT role FROM project_members WHERE project_id = ? AND device_id = ?")
        .get(project.id, removed.id)).toEqual({ role: "member" });
      expect(getProjectKeyEpoch(db, project.id, owner.id)).toMatchObject({ currentEpoch: 1 });

      db.exec(`
        CREATE TRIGGER inject_atomic_removal_failure
        BEFORE INSERT ON project_member_removal_rotations
        BEGIN
          SELECT RAISE(ABORT, 'injected atomic removal failure');
        END;
      `);
      expect(() => removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        removed.id,
        1,
        rotationId,
        [epochTwoOwner, epochTwoSurvivor],
        now,
      )).toThrow("injected atomic removal failure");
      db.exec("DROP TRIGGER inject_atomic_removal_failure");
      expect(db.query("SELECT role FROM project_members WHERE project_id = ? AND device_id = ?")
        .get(project.id, removed.id)).toEqual({ role: "member" });
      expect(getProjectKeyEpoch(db, project.id, owner.id)).toMatchObject({ currentEpoch: 1 });
      expect(db.query("SELECT enabled FROM agents WHERE id = ?").get(removedAgent)).toEqual({ enabled: 1 });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(removedRequesterTask)).toEqual({ status: "queued" });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(removedTargetTask)).toEqual({ status: "queued" });

      const rotated = removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        removed.id,
        1,
        rotationId,
        [epochTwoOwner, epochTwoSurvivor],
        now,
      );
      expect(rotated).toMatchObject({
        created: true,
        keyEpoch: 2,
        removedDeviceId: removed.id,
        rotationRequired: false,
      });
      expect(rotated.cancelledTasks.map(task => task.taskId).sort())
        .toEqual([removedRequesterTask, removedTargetTask].sort());
      expect(db.query("SELECT role FROM project_members WHERE project_id = ? AND device_id = ?")
        .get(project.id, removed.id)).toBeNull();
      expect(db.query(`
        SELECT recipient_device_id AS recipientDeviceId
        FROM project_key_envelopes WHERE project_id = ? AND key_epoch = 2
        ORDER BY recipient_device_id
      `).all(project.id)).toEqual(
        [owner.id, survivor.id].sort().map(recipientDeviceId => ({ recipientDeviceId })),
      );
      expect(db.query("SELECT enabled FROM agents WHERE id = ?").get(removedAgent)).toEqual({ enabled: 0 });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(removedRequesterTask)).toEqual({ status: "failed" });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(removedTargetTask)).toEqual({ status: "failed" });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(unrelatedTask)).toEqual({ status: "queued" });
      expect(removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        removed.id,
        1,
        rotationId,
        [epochTwoOwner, epochTwoSurvivor],
        now,
      )).toMatchObject({ created: false, cancelledTasks: rotated.cancelledTasks });
      expect(() => removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        removed.id,
        1,
        rotationId,
        [keyEnvelope(project.id, owner, owner.id, 2), epochTwoSurvivor],
        now,
      )).toThrow("replay conflict");
      const epochThreeOwner = keyEnvelope(project.id, owner, owner.id, 3);
      const epochThreeSurvivor = keyEnvelope(project.id, owner, survivor.id, 3);
      expect(rotateProjectKeyEpoch(
        db,
        project.id,
        owner.id,
        2,
        randomUUID(),
        [epochThreeOwner, epochThreeSurvivor],
        now,
      )).toMatchObject({ created: true, keyEpoch: 3 });
      expect(removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        removed.id,
        1,
        rotationId,
        [epochTwoOwner, epochTwoSurvivor],
        now,
      )).toMatchObject({
        created: false,
        keyEpoch: 2,
        currentEpoch: 3,
        cancelledTasks: rotated.cancelledTasks,
      });
      expect(() => removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        removed.id,
        2,
        rotationId,
        [epochTwoOwner, epochTwoSurvivor],
        now,
      )).toThrow("replay conflict");
      expect(db.query("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("quarantines every keyed project on device revocation and resolves the survivor-visible incident after rotation", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const revokedOwner = approvedDevice(db, "Revoked owner");
      const firstSurvivor = approvedDevice(db, "First survivor");
      const secondSurvivor = approvedDevice(db, "Second survivor");
      const outsider = approvedDevice(db, "Outsider");
      const project = createProject(db, "Revocation incident", revokedOwner.id, now);
      addProjectMember(db, project.id, revokedOwner.id, firstSurvivor.id, now);
      addProjectMember(db, project.id, revokedOwner.id, secondSurvivor.id, now);
      initializeProjectKeyEpoch(db, project.id, revokedOwner.id, randomUUID(), [
        keyEnvelope(project.id, revokedOwner, revokedOwner.id),
        keyEnvelope(project.id, revokedOwner, firstSurvivor.id),
        keyEnvelope(project.id, revokedOwner, secondSurvivor.id),
      ], now);

      const revokedAgent = randomUUID();
      const survivorAgent = randomUUID();
      db.query(`
        INSERT INTO agents (id, project_id, host_device_id, name, enabled, created_at)
        VALUES (?, ?, ?, 'Revoked host', 1, ?), (?, ?, ?, 'Survivor host', 1, ?)
      `).run(
        revokedAgent, project.id, revokedOwner.id, now.toISOString(),
        survivorAgent, project.id, firstSurvivor.id, now.toISOString(),
      );
      const insertTask = db.query(`
        INSERT INTO agent_tasks (
          id, project_id, chat_id, requester_device_id, target_device_id, agent_id,
          prompt, nonce, issued_at, expires_at, requester_signature,
          server_signature, status, accepted_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'opaque', ?, ?, ?, 'request-signature',
          'server-signature', 'queued', ?)
      `);
      const revokedRequesterTask = randomUUID();
      const revokedTargetTask = randomUUID();
      const unrelatedTask = randomUUID();
      const expiry = new Date(now.getTime() + 60_000).toISOString();
      insertTask.run(
        revokedRequesterTask, project.id, project.id, revokedOwner.id,
        firstSurvivor.id, survivorAgent, randomUUID(), now.toISOString(),
        expiry, now.toISOString(),
      );
      insertTask.run(
        revokedTargetTask, project.id, project.id, firstSurvivor.id,
        revokedOwner.id, revokedAgent, randomUUID(), now.toISOString(),
        expiry, now.toISOString(),
      );
      insertTask.run(
        unrelatedTask, project.id, project.id, firstSurvivor.id,
        secondSurvivor.id, survivorAgent, randomUUID(), now.toISOString(),
        expiry, now.toISOString(),
      );

      const expectedRecoveryOwner = [firstSurvivor, secondSurvivor]
        .sort((left, right) => left.id.localeCompare(right.id))[0]!;
      const otherSurvivor = expectedRecoveryOwner.id === firstSurvivor.id
        ? secondSurvivor
        : firstSurvivor;
      expect(revokeDevice(db, revokedOwner.fingerprint, now)).toBeTrue();
      expect(db.query(`
        SELECT device_id AS deviceId, role FROM project_members
        WHERE project_id = ? ORDER BY device_id
      `).all(project.id)).toEqual([
        { deviceId: revokedOwner.id, role: "member" },
        { deviceId: firstSurvivor.id, role: expectedRecoveryOwner.id === firstSurvivor.id ? "owner" : "member" },
        { deviceId: secondSurvivor.id, role: expectedRecoveryOwner.id === secondSurvivor.id ? "owner" : "member" },
      ].sort((left, right) => left.deviceId.localeCompare(right.deviceId)));
      expect(getProjectKeyEpoch(db, project.id, expectedRecoveryOwner.id))
        .toMatchObject({ currentEpoch: 1, rotationRequired: true });
      expect(db.query("SELECT enabled FROM agents WHERE id = ?").get(revokedAgent))
        .toEqual({ enabled: 0 });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(revokedRequesterTask))
        .toEqual({ status: "failed" });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(revokedTargetTask))
        .toEqual({ status: "failed" });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(unrelatedTask))
        .toEqual({ status: "queued" });
      expect(db.query(`
        SELECT COUNT(*) AS count FROM project_key_envelopes WHERE project_id = ?
      `).get(project.id)).toEqual({ count: 0 });

      const incidents = listUnresolvedProjectRevocationIncidentsForDevice(
        db,
        expectedRecoveryOwner.id,
      );
      expect(incidents).toEqual([expect.objectContaining({
        projectId: project.id,
        revokedDeviceId: revokedOwner.id,
        recoveryOwnerDeviceId: expectedRecoveryOwner.id,
        currentEpoch: 1,
      })]);
      expect(incidents[0]!.cancelledTasks).toEqual(expect.arrayContaining([
        { taskId: revokedRequesterTask, targetDeviceId: firstSurvivor.id },
        { taskId: revokedTargetTask, targetDeviceId: revokedOwner.id },
      ]));
      expect(listUnresolvedProjectRevocationIncidentsForDevice(db, otherSurvivor.id))
        .toEqual(incidents);
      expect(getUnresolvedProjectRevocationIncidentForDevice(
        db,
        incidents[0]!.incidentId,
        outsider.id,
      )).toBeNull();
      expect(() => listUnresolvedProjectRevocationIncidentsForDevice(db, revokedOwner.id))
        .toThrow("not approved");

      const rotationId = randomUUID();
      const rotationEnvelopes = [
        keyEnvelope(project.id, expectedRecoveryOwner, expectedRecoveryOwner.id, 2),
        keyEnvelope(project.id, expectedRecoveryOwner, otherSurvivor.id, 2),
      ];
      const rotated = removeProjectMemberAndRotateKeys(
        db,
        project.id,
        expectedRecoveryOwner.id,
        revokedOwner.id,
        1,
        rotationId,
        rotationEnvelopes,
        new Date("2027-01-01T00:01:00.000Z"),
      );
      expect(rotated).toMatchObject({ created: true, keyEpoch: 2, rotationRequired: false });
      expect(listUnresolvedProjectRevocationIncidentsForDevice(db, expectedRecoveryOwner.id))
        .toEqual([]);
      expect(getUnresolvedProjectRevocationIncidentForDevice(
        db,
        incidents[0]!.incidentId,
        expectedRecoveryOwner.id,
      )).toBeNull();
      expect(db.query(`
        SELECT status, resolution_rotation_id AS resolutionRotationId
        FROM device_revocation_project_incidents WHERE incident_id = ?
      `).get(incidents[0]!.incidentId)).toEqual({
        status: "resolved",
        resolutionRotationId: rotationId,
      });
      expect(removeProjectMemberAndRotateKeys(
        db,
        project.id,
        expectedRecoveryOwner.id,
        revokedOwner.id,
        1,
        rotationId,
        rotationEnvelopes,
        new Date("2027-01-01T00:02:00.000Z"),
      )).toMatchObject({ created: false });
    } finally {
      db.close();
    }
  });

  test("keeps an owner-only encrypted project quarantined with an unresolved incident", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Only owner");
      const project = createProject(db, "Owner-only incident", owner.id);
      initializeProjectKeyEpoch(db, project.id, owner.id, randomUUID(), [
        keyEnvelope(project.id, owner, owner.id),
      ]);
      expect(revokeDevice(db, owner.fingerprint)).toBeTrue();
      expect(db.query(`
        SELECT rotation_required AS rotationRequired
        FROM project_key_epochs WHERE project_id = ?
      `).get(project.id)).toEqual({ rotationRequired: 1 });
      expect(db.query(`
        SELECT recovery_owner_device_id AS recoveryOwnerDeviceId, status
        FROM device_revocation_project_incidents WHERE project_id = ?
      `).get(project.id)).toEqual({
        recoveryOwnerDeviceId: null,
        status: "unresolved",
      });
      expect(db.query(`
        SELECT role FROM project_members WHERE project_id = ? AND device_id = ?
      `).get(project.id, owner.id)).toEqual({ role: "owner" });
    } finally {
      db.close();
    }
  });

  test("does not starve revocation incidents after the first 128 projects", () => {
    const db = openDatabase(":memory:");
    try {
      const survivor = approvedDevice(db, "Incident survivor");
      const revoked = approvedDevice(db, "Many-project revoked device");
      const now = new Date("2027-01-01T00:00:00.000Z");
      const projectIds: string[] = [];
      for (let index = 0; index < 129; index += 1) {
        const project = createProject(db, `Incident ${index}`, survivor.id, now);
        addProjectMember(db, project.id, survivor.id, revoked.id, now);
        projectIds.push(project.id);
      }
      expect(revokeDevice(db, revoked.fingerprint, now)).toBeTrue();
      const insertIncident = db.query(`
        INSERT INTO device_revocation_project_incidents (
          incident_id, project_id, revoked_device_id, recovery_owner_device_id,
          current_epoch, cancelled_tasks_json, status, created_at
        ) VALUES (?, ?, ?, ?, 1, '[]', 'unresolved', ?)
      `);
      for (const projectId of projectIds) {
        insertIncident.run(
          randomUUID(),
          projectId,
          revoked.id,
          survivor.id,
          now.toISOString(),
        );
      }
      const incidents = listUnresolvedProjectRevocationIncidentsForDevice(db, survivor.id);
      expect(incidents).toHaveLength(129);
      expect(new Set(incidents.map(incident => incident.projectId)))
        .toEqual(new Set(projectIds));
    } finally {
      db.close();
    }
  });

  test("stores only opaque encrypted context, verifies signatures, and rejects stale updates", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const project = createProject(db, "Encrypted context", owner.id);
      addProjectMember(db, project.id, owner.id, member.id);
      expect(shareProjectKeyEnvelope(db, project.id, owner.id, keyEnvelope(project.id, owner, owner.id)).created).toBeTrue();
      const first = contextEnvelope(project.id, member, randomUUID());
      const firstWrite = updateEncryptedProjectContext(db, project.id, member.id, 0, first);
      expect(firstWrite).toMatchObject({ revision: 1, created: true, envelope: first });
      expect(updateEncryptedProjectContext(db, project.id, member.id, 0, first).created).toBeFalse();
      expect(getEncryptedProjectContext(db, project.id, owner.id)).toMatchObject({
        revision: 1,
        envelope: first,
      });
      const next = contextEnvelope(project.id, member, randomUUID());
      expect(() => updateEncryptedProjectContext(db, project.id, member.id, 0, next))
        .toThrow("revision conflict");
      expect(updateEncryptedProjectContext(db, project.id, member.id, 1, next).revision).toBe(2);
      expect(updateEncryptedProjectContext(db, project.id, member.id, 1, next).created).toBeFalse();

      const tamperedSignature = Buffer.from(next.signature, "base64url");
      tamperedSignature[0] ^= 1;
      const tampered = { ...next, signature: tamperedSignature.toString("base64url") };
      expect(() => updateEncryptedProjectContext(db, project.id, member.id, 2, tampered))
        .toThrow("signature is invalid");
      const stored = db.query("SELECT envelope_json AS envelopeJson FROM encrypted_project_context WHERE project_id = ?")
        .get(project.id) as { envelopeJson: string };
      expect(stored.envelopeJson).not.toContain("plaintext");
      expect(stored.envelopeJson).not.toContain("secret");
      expect(stored.envelopeJson).toContain(next.ciphertext);
    } finally {
      db.close();
    }
  });

  test("stores opaque artifacts, verifies sender signatures, and recovers by project list", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const project = createProject(db, "Encrypted artifacts", owner.id, now);
      addProjectMember(db, project.id, owner.id, member.id, now);
      expect(shareProjectKeyEnvelope(db, project.id, owner.id, keyEnvelope(project.id, owner, owner.id), now).created).toBeTrue();
      expect(shareProjectKeyEnvelope(db, project.id, owner.id, keyEnvelope(project.id, owner, member.id), now).created).toBeTrue();

      const artifactId = randomUUID();
      const envelope = artifactEnvelope(project.id, owner, artifactId);
      const published = publishEncryptedArtifact(db, {
        artifactId,
        projectId: project.id,
        taskId: null,
        authorDeviceId: owner.id,
        envelope,
      }, now);
      expect(published.created).toBeTrue();
      expect(publishEncryptedArtifact(db, {
        artifactId,
        projectId: project.id,
        taskId: null,
        authorDeviceId: owner.id,
        envelope,
      }, now).created).toBeFalse();
      expect(listEncryptedArtifacts(db, project.id, member.id)).toEqual([published.artifact]);
      const stored = db.query("SELECT envelope_json AS envelopeJson FROM project_artifacts WHERE id = ?")
        .get(artifactId) as { envelopeJson: string };
      expect(stored.envelopeJson).not.toContain("The secret artifact body");
      expect(stored.envelopeJson).toContain(envelope.ciphertext);

      const badSignature = Buffer.from(envelope.signature, "base64url");
      badSignature[0] ^= 1;
      expect(() => publishEncryptedArtifact(db, {
        artifactId,
        projectId: project.id,
        taskId: null,
        authorDeviceId: owner.id,
        envelope: { ...envelope, signature: badSignature.toString("base64url") },
      })).toThrow("signature is invalid");
    } finally {
      db.close();
    }
  });

  test("stores immutable ciphertext-only file references bound to the artifact host", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const project = createProject(db, "Encrypted references", owner.id);
      addProjectMember(db, project.id, owner.id, member.id);
      shareProjectKeyEnvelope(db, project.id, owner.id, keyEnvelope(project.id, owner, owner.id));
      const artifactId = randomUUID();
      publishEncryptedArtifact(db, {
        artifactId,
        projectId: project.id,
        taskId: null,
        authorDeviceId: owner.id,
        envelope: artifactEnvelope(project.id, owner, artifactId),
      });
      const referenceId = randomUUID();
      const envelope = fileReferenceEnvelope(project.id, owner, referenceId);
      const first = publishEncryptedFileReference(db, {
        referenceId,
        projectId: project.id,
        artifactId,
        authorDeviceId: owner.id,
        envelope,
      });
      expect(first.created).toBeTrue();
      expect(publishEncryptedFileReference(db, {
        referenceId,
        projectId: project.id,
        artifactId,
        authorDeviceId: owner.id,
        envelope,
      }).created).toBeFalse();
      expect(listEncryptedFileReferences(db, project.id, member.id)).toEqual([first.reference]);
      expect(() => publishEncryptedFileReference(db, {
        referenceId: randomUUID(),
        projectId: project.id,
        artifactId,
        authorDeviceId: member.id,
        envelope: fileReferenceEnvelope(project.id, member, randomUUID()),
      })).toThrow("Only the artifact host");
      expect(() => publishEncryptedFileReference(db, {
        referenceId,
        projectId: project.id,
        artifactId,
        authorDeviceId: owner.id,
        envelope: fileReferenceEnvelope(project.id, owner, referenceId),
      })).toThrow("already used");
      const columns = (db.query("PRAGMA table_info(project_file_references)").all() as Array<{ name: string }>)
        .map(column => column.name);
      expect(columns).not.toContain("relative_path");
      expect(columns).not.toContain("sha256");
      expect(columns).not.toContain("media_type");
      const stored = db.query("SELECT envelope_json AS envelopeJson FROM project_file_references WHERE id = ?")
        .get(referenceId) as { envelopeJson: string };
      expect(stored.envelopeJson).toContain(envelope.ciphertext);
      expect(stored.envelopeJson).not.toContain("C:\\Users\\Stephen\\secret.txt");
      const insert = db.query(`
        INSERT INTO project_file_references
          (id, project_id, chat_id, artifact_id, host_device_id, author_device_id, envelope_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (let index = 1; index < 500; index += 1) {
        insert.run(randomUUID(), project.id, project.id, artifactId, owner.id, owner.id, stored.envelopeJson,
          new Date(1_800_000_000_000 + index).toISOString(), new Date(1_800_000_000_000 + index).toISOString());
      }
      const overflowId = randomUUID();
      expect(() => publishEncryptedFileReference(db, {
        referenceId: overflowId,
        projectId: project.id,
        artifactId,
        authorDeviceId: owner.id,
        envelope: fileReferenceEnvelope(project.id, owner, overflowId),
      })).toThrow("limit of 500");
    } finally {
      db.close();
    }
  });
});

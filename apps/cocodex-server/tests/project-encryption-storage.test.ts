import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import {
  decodeInvitation,
  enrollmentSigningTranscript,
  projectContentSigningTranscript,
  projectKeyEnvelopeSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectKeyEnvelope,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createInvitation } from "../src/invitations";
import {
  getEncryptedProjectContext,
  getProjectKeyEpoch,
  initializeProjectKeyEpoch,
  listProjectKeyEnvelopes,
  removeProjectMemberAndInvalidateKeys,
  rotateProjectKeyEpoch,
  shareProjectKeyEnvelope,
  updateEncryptedProjectContext,
} from "../src/project-encryption-storage";
import { listEncryptedArtifacts, publishEncryptedArtifact } from "../src/encrypted-artifacts";
import { addProjectMember, createProject } from "../src/shared-state";

interface TestDevice {
  id: string;
  publicKey: string;
  privateKey: string;
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
  }), signing.privateKey).toString("base64url");
  const enrolled = enrollDevice(db, {
    invitation,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName: name,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    signature,
  }, now);
  expect(approveDevice(db, enrolled.fingerprint, now)).toBeTrue();
  return { id: enrolled.id, publicKey: signing.publicKey, privateKey: signing.privateKey };
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

describe("opaque project-encryption server storage", () => {
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
});

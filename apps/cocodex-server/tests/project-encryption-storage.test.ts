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
  listProjectKeyEnvelopes,
  shareProjectKeyEnvelope,
  updateEncryptedProjectContext,
} from "../src/project-encryption-storage";
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

describe("opaque project-encryption server storage", () => {
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

  test("stores only opaque encrypted context, verifies signatures, and rejects stale updates", () => {
    const db = openDatabase(":memory:");
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const project = createProject(db, "Encrypted context", owner.id);
      addProjectMember(db, project.id, owner.id, member.id);
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
});

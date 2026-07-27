import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  createDeviceKeyCertificate,
  decodeInvitation,
  enrollmentSigningTranscript,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import {
  createEnrollmentChallenge,
  enrollDevice,
  revokeDevice,
} from "../src/enrollment";
import { createInvitation } from "../src/invitations";
import {
  listPrivateContacts,
  privateContactDirectoryRevision,
} from "../src/private-contacts";
import {
  approvePendingDeviceForTest,
  TEST_SERVER_IDENTITY_FINGERPRINT,
} from "./device-approval-fixture";

function enrolledDevice(
  db: ReturnType<typeof openDatabase>,
  displayName: string,
  status: "pending" | "approved" | "revoked",
  publishCertificate: boolean,
) {
  const signing = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const invitation = decodeInvitation(createInvitation(db, {
    host: "server.test",
    port: 10443,
    serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
  }));
  const challenge = createEnrollmentChallenge(
    db,
    invitation,
    signing.publicKey,
    invitation.serverFingerprint,
  );
  const claim = {
    serverFingerprint: invitation.serverFingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
  };
  const device = enrollDevice(db, {
    invitation,
    expectedServerFingerprint: invitation.serverFingerprint,
    serverIdentityFingerprint: TEST_SERVER_IDENTITY_FINGERPRINT,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    signature: sign(null, enrollmentSigningTranscript(claim), signing.privateKey).toString("base64url"),
  });
  if (status !== "pending") {
    approvePendingDeviceForTest(
      db,
      device,
      signing.privateKey,
      invitation.serverFingerprint,
    );
  }
  const certificate = createDeviceKeyCertificate(device.id, {
    publicKeyPem: signing.publicKey,
    privateKeyPem: signing.privateKey,
    messagingPublicKeyPem: messaging.publicKey,
  });
  if (publishCertificate) {
    db.query("UPDATE devices SET device_key_certificate = ? WHERE id = ?")
      .run(certificate, device.id);
  }
  if (status === "revoked") expect(revokeDevice(db, device.fingerprint)).toBeTrue();
  return { ...device, certificate, privateKey: signing.privateKey, serverTlsFingerprint: invitation.serverFingerprint };
}

describe("authoritative private-contact directory", () => {
  test("returns only other approved certificate-bearing devices", () => {
    const db = openDatabase(":memory:");
    try {
      const stephen = enrolledDevice(db, "Stephen", "approved", true);
      const kai = enrolledDevice(db, "Kai", "approved", true);
      enrolledDevice(db, "No certificate", "approved", false);
      enrolledDevice(db, "Pending outsider", "pending", true);
      enrolledDevice(db, "Revoked outsider", "revoked", true);

      expect(listPrivateContacts(db, stephen.id)).toEqual([{
        deviceId: kai.id,
        displayName: "Kai",
        fingerprint: kai.fingerprint,
        deviceKeyCertificate: kai.certificate,
      }]);
      expect(listPrivateContacts(db, kai.id)).toEqual([{
        deviceId: stephen.id,
        displayName: "Stephen",
        fingerprint: stephen.fingerprint,
        deviceKeyCertificate: stephen.certificate,
      }]);
    } finally {
      db.close();
    }
  });

  test("rejects an unapproved requester and revisions change with authority state", () => {
    const db = openDatabase(":memory:");
    try {
      const stephen = enrolledDevice(db, "Stephen", "approved", true);
      const pending = enrolledDevice(db, "Pending", "pending", true);
      const before = privateContactDirectoryRevision(db);
      expect(() => listPrivateContacts(db, pending.id)).toThrow("not approved");
      approvePendingDeviceForTest(
        db,
        pending,
        pending.privateKey,
        pending.serverTlsFingerprint,
      );
      expect(privateContactDirectoryRevision(db)).not.toBe(before);
      expect(listPrivateContacts(db, stephen.id).map(contact => contact.deviceId))
        .toContain(pending.id);
    } finally {
      db.close();
    }
  });
});

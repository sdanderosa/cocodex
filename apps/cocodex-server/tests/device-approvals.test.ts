import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import {
  decodeInvitation,
  deviceApprovalSigningTranscript,
  enrollmentSigningTranscript,
  type DeviceApprovalUpdateFrame,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import {
  listPendingDeviceApprovals,
  updateDeviceApproval,
} from "../src/device-approvals";
import {
  bootstrapApproveDevice,
  createEnrollmentChallenge,
  enrollDevice,
  revokeDevice,
} from "../src/enrollment";
import { createInvitation } from "../src/invitations";
import { serverEpoch } from "../src/server-state";
import { TEST_SERVER_IDENTITY_FINGERPRINT } from "./device-approval-fixture";

const TLS_FINGERPRINT = "AAAA-BBBB-CCCC-DDDD";

function enroll(db: ReturnType<typeof openDatabase>, displayName: string, now: Date) {
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
    port: 19463,
    serverFingerprint: TLS_FINGERPRINT,
    now,
  }));
  const challenge = createEnrollmentChallenge(
    db,
    invitation,
    signing.publicKey,
    TLS_FINGERPRINT,
    now,
  );
  const signature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: TLS_FINGERPRINT,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
  }), signing.privateKey).toString("base64url");
  const device = enrollDevice(db, {
    invitation,
    expectedServerFingerprint: TLS_FINGERPRINT,
    serverIdentityFingerprint: TEST_SERVER_IDENTITY_FINGERPRINT,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    signature,
  }, now);
  return { ...device, privateKey: signing.privateKey };
}

function approvalFrame(
  target: ReturnType<typeof listPendingDeviceApprovals>[number],
  approverPrivateKey: string,
  now: Date,
  decision: "approve" | "reject" = "approve",
): DeviceApprovalUpdateFrame {
  const unsigned = {
    version: 1 as const,
    operationId: randomUUID(),
    targetDeviceId: target.deviceId,
    targetFingerprint: target.fingerprint,
    targetEnrollmentDigest: target.enrollmentDigest,
    expectedRevision: 0 as const,
    decision,
    serverIdentityFingerprint: TEST_SERVER_IDENTITY_FINGERPRINT,
    serverEpoch: 1,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 120_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
  };
  return {
    ...unsigned,
    type: "device.approval.update",
    requestId: randomUUID(),
    signature: sign(
      null,
      deviceApprovalSigningTranscript(unsigned),
      approverPrivateKey,
    ).toString("base64url"),
  };
}

describe("signed trusted-device enrollment approval", () => {
  test("approves one immutable enrollment atomically and replays only the exact operation", () => {
    const db = openDatabase(":memory:");
    const now = new Date();
    try {
      const stephen = enroll(db, "Stephen", now);
      expect(bootstrapApproveDevice(db, stephen.fingerprint, new Date(now.getTime() + 1_000))).toBeTrue();
      const kai = enroll(db, "Kai", new Date(now.getTime() + 2_000));
      const pending = listPendingDeviceApprovals(
        db,
        stephen.id,
        TLS_FINGERPRINT,
        TEST_SERVER_IDENTITY_FINGERPRINT,
        new Date(now.getTime() + 3_000),
      );
      expect(pending).toHaveLength(1);
      expect(pending[0]?.deviceId).toBe(kai.id);
      expect(pending[0]?.devicePublicKeyPem).not.toContain("PRIVATE");

      const frame = approvalFrame(pending[0]!, stephen.privateKey, new Date(now.getTime() + 4_000));
      const created = updateDeviceApproval(
        db,
        stephen.id,
        frame,
        TLS_FINGERPRINT,
        TEST_SERVER_IDENTITY_FINGERPRINT,
        serverEpoch(db),
        new Date(now.getTime() + 4_500),
      );
      expect(created).toMatchObject({ created: true, status: "approved", targetDeviceId: kai.id });
      expect(updateDeviceApproval(
        db,
        stephen.id,
        frame,
        TLS_FINGERPRINT,
        TEST_SERVER_IDENTITY_FINGERPRINT,
        serverEpoch(db),
        new Date(now.getTime() + 5_000),
      )).toMatchObject({ created: false, status: "approved" });
      expect(() => updateDeviceApproval(
        db,
        stephen.id,
        { ...frame, decision: "reject" },
        TLS_FINGERPRINT,
        TEST_SERVER_IDENTITY_FINGERPRINT,
        serverEpoch(db),
        new Date(now.getTime() + 5_000),
      )).toThrow("signature is invalid");
      expect(db.query("SELECT status, approved_by_device_id AS approvedBy FROM devices WHERE id = ?")
        .get(kai.id)).toEqual({ status: "approved", approvedBy: stephen.id });
      expect((db.query(
        "SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'device.approved' AND subject_id = ?",
      ).get(kai.id) as { count: number }).count).toBe(1);
    } finally {
      db.close();
    }
  });

  test("keeps first-device bootstrap permanently consumed after revocation", () => {
    const db = openDatabase(":memory:");
    const now = new Date();
    try {
      const stephen = enroll(db, "Stephen", now);
      expect(bootstrapApproveDevice(db, stephen.fingerprint, new Date(now.getTime() + 1_000))).toBeTrue();
      expect(revokeDevice(db, stephen.fingerprint, new Date(now.getTime() + 2_000))).toBeTrue();
      const kai = enroll(db, "Kai", new Date(now.getTime() + 3_000));
      expect(() => bootstrapApproveDevice(
        db,
        kai.fingerprint,
        new Date(now.getTime() + 4_000),
      )).toThrow("already been consumed");
    } finally {
      db.close();
    }
  });
});

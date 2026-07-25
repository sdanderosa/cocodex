import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  decodeInvitation,
  enrollmentSigningTranscript,
  usageReportSigningTranscript,
  type UsageReport,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createInvitation } from "../src/invitations";
import { addProjectMember, createProject } from "../src/shared-state";
import { acceptUsageReport, listUsageReports, usageReportProjectIds } from "../src/usage";

function approvedDevice(db: ReturnType<typeof openDatabase>, name: string, now: Date): { id: string; privateKey: string } {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const invitation = decodeInvitation(createInvitation(db, {
    host: "server.test", port: 10443, serverFingerprint: "AAAA-BBBB-CCCC-DDDD", now,
  }));
  const challenge = createEnrollmentChallenge(db, invitation, pair.publicKey, invitation.serverFingerprint, now);
  const signature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: invitation.serverFingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName: name,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
  }), pair.privateKey).toString("base64url");
  const device = enrollDevice(db, {
    invitation,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName: name,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    signature,
  }, now);
  expect(approveDevice(db, device.fingerprint, now)).toBeTrue();
  return { id: device.id, privateKey: pair.privateKey };
}

function report(deviceId: string, revision = 1): UsageReport {
  return {
    version: 1,
    deviceId,
    revision,
    updatedAt: `2027-01-01T00:0${revision}:00.000Z`,
    requests: revision,
    inputTokens: 10 * revision,
    cachedInputTokens: 2 * revision,
    outputTokens: 5 * revision,
    reasoningOutputTokens: revision,
    activeAgents: revision % 2,
    accountLabel: "Main",
    fiveHourPercent: 20 + revision,
    weeklyPercent: 30 + revision,
    monthlyPercent: 40 + revision,
  };
}

function signed(value: UsageReport, privateKey: string): string {
  return sign(null, usageReportSigningTranscript(value), privateKey).toString("base64url");
}

describe("signed sanitized usage reports", () => {
  test("accepts current reports, filters by project membership, and rejects tampering/replay", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:05:00.000Z");
      const stephen = approvedDevice(db, "Stephen", now);
      const kai = approvedDevice(db, "Kai", now);
      const outsider = approvedDevice(db, "Outsider", now);
      const project = createProject(db, "Usage cards", stephen.id, now);
      addProjectMember(db, project.id, stephen.id, kai.id, now);
      const first = report(stephen.id);
      const accepted = acceptUsageReport(db, stephen.id, { report: first, signature: signed(first, stephen.privateKey) }, now);
      expect(accepted.created).toBeTrue();
      expect(accepted.view).toMatchObject({ deviceId: stephen.id, displayName: "Stephen", report: first });
      expect(acceptUsageReport(db, stephen.id, { report: first, signature: signed(first, stephen.privateKey) }, now).created).toBeFalse();
      expect(listUsageReports(db, project.id, kai.id)).toEqual([
        expect.objectContaining({ deviceId: stephen.id, displayName: "Stephen", report: first }),
        expect.objectContaining({ deviceId: kai.id, displayName: "Kai", report: null }),
      ]);
      expect(usageReportProjectIds(db, stephen.id)).toEqual([project.id]);
      expect(() => listUsageReports(db, project.id, outsider.id)).toThrow("approved project member");
      expect(() => acceptUsageReport(db, stephen.id, {
        report: { ...first, outputTokens: first.outputTokens + 1 }, signature: signed(first, stephen.privateKey),
      }, now)).toThrow("signature");
      expect(() => acceptUsageReport(db, stephen.id, {
        report: { ...first, deviceId: kai.id }, signature: signed({ ...first, deviceId: kai.id }, stephen.privateKey),
      }, now)).toThrow("does not match");
      expect(() => acceptUsageReport(db, stephen.id, {
        report: report(stephen.id, 0), signature: signed(report(stephen.id, 0), stephen.privateKey),
      }, now)).toThrow("stale");
    } finally {
      db.close();
    }
  });
});

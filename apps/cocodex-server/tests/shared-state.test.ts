import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { decodeInvitation, enrollmentSigningTranscript } from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createInvitation } from "../src/invitations";
import {
  addProjectMember,
  appendChatEvent,
  appendChatEventResult,
  chatEventsAfter,
  createProject,
  listProjects,
} from "../src/shared-state";
import { listArtifacts, publishArtifact } from "../src/artifacts";
import { appendPrivateMessage } from "../src/private-messages";

function approvedDevice(db: ReturnType<typeof openDatabase>, name: string, now: Date): string {
  const pair = generateKeyPairSync("ed25519", {
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
    now,
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
  return device.id;
}

describe("authoritative shared state", () => {
  test("orders two members' idempotent chat events and recovers by cursor", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = approvedDevice(db, "Stephen", now);
      const kai = approvedDevice(db, "Kai", now);
      const project = createProject(db, "Nocturne Launcher", stephen, now);
      addProjectMember(db, project.id, stephen, kai, now);
      expect(listProjects(db, stephen)).toEqual([project]);
      expect(listProjects(db, kai)).toEqual([{ ...project, role: "member" }]);

      const first = appendChatEvent(db, {
        projectId: project.id,
        eventId: "8661361f-ce2f-4bec-88fd-c4fb32f49704",
        senderDeviceId: kai,
        content: "Please inspect authentication.",
        clientCreatedAt: "2027-01-01T00:01:00.000Z",
      }, new Date("2027-01-01T00:01:01.000Z"));
      const second = appendChatEvent(db, {
        projectId: project.id,
        eventId: "4b9abf0f-94c3-4cfa-97a4-1a370b93bb2e",
        senderDeviceId: stephen,
        content: "I will review the result.",
        clientCreatedAt: "2027-01-01T00:01:00.500Z",
      }, new Date("2027-01-01T00:01:02.000Z"));
      expect(second.sequence).toBeGreaterThan(first.sequence);
      expect(appendChatEvent(db, {
        projectId: project.id,
        eventId: first.eventId,
        senderDeviceId: kai,
        content: first.content,
        clientCreatedAt: first.clientCreatedAt,
      }).sequence).toBe(first.sequence);
      expect(appendChatEventResult(db, {
        projectId: project.id,
        eventId: first.eventId,
        senderDeviceId: kai,
        content: first.content,
        clientCreatedAt: first.clientCreatedAt,
      })).toEqual({ event: first, created: false });
      expect(chatEventsAfter(db, project.id, kai, first.sequence)).toEqual([second]);
    } finally {
      db.close();
    }
  });

  test("stores project-scoped artifacts idempotently for downstream handoffs", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = approvedDevice(db, "Stephen", now);
      const kai = approvedDevice(db, "Kai", now);
      const project = createProject(db, "Artifact handoff", stephen, now);
      addProjectMember(db, project.id, stephen, kai, now);
      const input = {
        id: "8661361f-ce2f-4bec-88fd-c4fb32f49704",
        projectId: project.id,
        taskId: null,
        authorDeviceId: stephen,
        type: "finding" as const,
        title: "Refresh-token finding",
        summary: "Rotation is not persisted.",
        content: "The refresh token write is missing after rotation.",
        status: "ready" as const,
      };
      const published = publishArtifact(db, input, now);
      expect(published.created).toBeTrue();
      expect(publishArtifact(db, input, now).created).toBeFalse();
      expect(listArtifacts(db, project.id, kai)).toEqual([published.artifact]);
    } finally {
      db.close();
    }
  });

  test("rejects replay of the same ciphertext under a new message ID", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = approvedDevice(db, "Stephen", now);
      const kai = approvedDevice(db, "Kai", now);
      const message = { messageId: "8661361f-ce2f-4bec-88fd-c4fb32f49704", senderDeviceId: stephen, recipientDeviceId: kai, ciphertext: "A".repeat(80), clientCreatedAt: now.toISOString() };
      expect(appendPrivateMessage(db, message, now).created).toBeTrue();
      expect(() => appendPrivateMessage(db, { ...message, messageId: "4b9abf0f-94c3-4cfa-97a4-1a370b93bb2e" }, now)).toThrow("replay rejected");
    } finally { db.close(); }
  });
});

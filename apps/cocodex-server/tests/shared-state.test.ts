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
  listProjectMembers,
  listProjects,
} from "../src/shared-state";
import { listArtifacts, publishArtifact } from "../src/artifacts";
import { appendPrivateMessage, appendPrivateReceipt, privateReceiptsAfter } from "../src/private-messages";
import { getSharedProjectContext, updateSharedProjectContext } from "../src/shared-context";

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
      expect(listProjectMembers(db, project.id, stephen).map(member => ({
        deviceId: member.deviceId,
        displayName: member.displayName,
        role: member.role,
        deviceKeyCertificate: member.deviceKeyCertificate,
      }))).toEqual([
        { deviceId: stephen, displayName: "Stephen", role: "owner", deviceKeyCertificate: null },
        { deviceId: kai, displayName: "Kai", role: "member", deviceKeyCertificate: null },
      ]);

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

  test("stores a revisioned shared project context and rejects stale writers", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = approvedDevice(db, "Stephen", now);
      const kai = approvedDevice(db, "Kai", now);
      const outsider = approvedDevice(db, "Outsider", now);
      const project = createProject(db, "Context recovery", stephen, now);
      addProjectMember(db, project.id, stephen, kai, now);

      expect(getSharedProjectContext(db, project.id, stephen)).toEqual({
        projectId: project.id,
        finalGoal: "",
        context: {},
        revision: 0,
        updatedByDeviceId: null,
        updatedAt: null,
      });

      const first = updateSharedProjectContext(
        db,
        project.id,
        kai,
        0,
        "Build the private alpha",
        { acceptance: ["enrollment", "reconnect"], owner: "Stephen" },
        new Date("2027-01-01T00:01:00.000Z"),
      );
      expect(first).toMatchObject({
        projectId: project.id,
        finalGoal: "Build the private alpha",
        context: { acceptance: ["enrollment", "reconnect"], owner: "Stephen" },
        revision: 1,
        updatedByDeviceId: kai,
        updatedAt: "2027-01-01T00:01:00.000Z",
      });
      expect(getSharedProjectContext(db, project.id, stephen)).toEqual(first);

      expect(() => updateSharedProjectContext(
        db,
        project.id,
        stephen,
        0,
        "A stale overwrite",
        {},
        new Date("2027-01-01T00:02:00.000Z"),
      )).toThrow("revision conflict");
      expect(getSharedProjectContext(db, project.id, stephen)).toEqual(first);

      expect(() => getSharedProjectContext(db, project.id, outsider))
        .toThrow("approved project member");
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

  test("stores recipient-only delivery/read receipts with an independent cursor", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = approvedDevice(db, "Stephen", now);
      const kai = approvedDevice(db, "Kai", now);
      const first = {
        messageId: "8661361f-94c3-4bec-88fd-c4fb32f49704",
        senderDeviceId: stephen,
        recipientDeviceId: kai,
        ciphertext: "A".repeat(80),
        clientCreatedAt: now.toISOString(),
      };
      const second = {
        ...first,
        messageId: "4b9abf0f-94c3-4cfa-97a4-1a370b93bb2e",
        ciphertext: "B".repeat(80),
      };
      appendPrivateMessage(db, first, now);
      appendPrivateMessage(db, second, now);
      expect(() => appendPrivateReceipt(db, {
        messageId: first.messageId,
        recipientDeviceId: kai,
        receipt: "read",
      }, new Date("2027-01-01T00:00:01.000Z"))).toThrow("requires a delivered");
      const delivered = appendPrivateReceipt(db, {
        messageId: first.messageId,
        recipientDeviceId: kai,
        receipt: "delivered",
      }, new Date("2027-01-01T00:00:02.000Z"));
      expect(delivered.created).toBeTrue();
      expect(appendPrivateReceipt(db, {
        messageId: first.messageId,
        recipientDeviceId: kai,
        receipt: "delivered",
      }, new Date("2027-01-01T00:00:03.000Z"))).toEqual({
        created: false,
        envelope: delivered.envelope,
      });
      const read = appendPrivateReceipt(db, {
        messageId: first.messageId,
        recipientDeviceId: kai,
        receipt: "read",
      }, new Date("2027-01-01T00:00:04.000Z"));
      expect(read.created).toBeTrue();
      expect(() => appendPrivateReceipt(db, {
        messageId: first.messageId,
        recipientDeviceId: kai,
        receipt: "delivered",
      })).toThrow("cannot follow a read");
      expect(() => appendPrivateReceipt(db, {
        messageId: first.messageId,
        recipientDeviceId: stephen,
        receipt: "delivered",
      })).toThrow("Only the private-message recipient");
      expect(privateReceiptsAfter(db, stephen, 0)).toEqual([delivered.envelope, read.envelope]);
      expect(privateReceiptsAfter(db, stephen, delivered.envelope.sequence)).toEqual([read.envelope]);
    } finally { db.close(); }
  });
});

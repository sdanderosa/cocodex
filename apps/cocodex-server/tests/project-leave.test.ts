import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import {
  projectKeyEnvelopeSigningTranscript,
  projectMemberLeaveSigningTranscript,
  type ProjectKeyEnvelope,
  type ProjectMemberLeaveFrame,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import {
  initializeProjectKeyEpoch,
  listProjectKeyEnvelopesForDevice,
  removeProjectMemberAndRotateKeys,
  rotateProjectKeyEpoch,
} from "../src/project-encryption-storage";
import { requestProjectLeave } from "../src/project-leave";
import {
  addProjectMember,
  createProject,
  listProjectMembers,
  listProjects,
  requireProjectMembership,
} from "../src/shared-state";

const FINGERPRINT = "AA:BB:CC:DD:EE:FF";
const EPOCH = 4;

interface TestDevice {
  id: string;
  publicKey: string;
  privateKey: string;
}

function approvedDevice(db: ReturnType<typeof openDatabase>, name: string, now: Date): TestDevice {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const invitationId = randomUUID();
  const deviceId = randomUUID();
  db.query(`
    INSERT INTO invitations (id, token_hash, expires_at, consumed_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(invitationId, randomBytes(32).toString("hex"), now.toISOString(), now.toISOString(), now.toISOString());
  db.query(`
    INSERT INTO devices (
      id, public_key_pem, fingerprint, display_name, status, invitation_id,
      enrolled_at, approved_at
    ) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?)
  `).run(deviceId, pair.publicKey, randomBytes(32).toString("hex"), name,
    invitationId, now.toISOString(), now.toISOString());
  return { id: deviceId, publicKey: pair.publicKey, privateKey: pair.privateKey };
}

function keyEnvelope(
  projectId: string,
  sender: TestDevice,
  recipientDeviceId: string,
  keyEpoch: number,
): ProjectKeyEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch,
    recipientDeviceId,
    senderDeviceId: sender.id,
    sealedProjectKey: randomBytes(80).toString("base64url"),
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectKeyEnvelopeSigningTranscript(unsigned), sender.privateKey)
      .toString("base64url"),
  };
}

function leaveFrame(
  projectId: string,
  actor: TestDevice,
  now: Date,
  options: { requestId?: string; serverFingerprint?: string; issuedAt?: Date } = {},
): ProjectMemberLeaveFrame {
  const issued = options.issuedAt ?? now;
  const unsigned = {
    version: 1 as const,
    requestId: options.requestId ?? randomUUID(),
    projectId,
    serverFingerprint: options.serverFingerprint ?? FINGERPRINT,
    serverEpoch: EPOCH,
    issuedAt: issued.toISOString(),
    expiresAt: new Date(issued.getTime() + 120_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
  };
  return {
    ...unsigned,
    type: "project.member.leave",
    signature: sign(null, projectMemberLeaveSigningTranscript(unsigned), actor.privateKey)
      .toString("base64url"),
  };
}

function encryptedProject(
  db: ReturnType<typeof openDatabase>,
  owner: TestDevice,
  member: TestDevice,
  now: Date,
) {
  const project = createProject(db, "Leave safely", owner.id, now);
  addProjectMember(db, project.id, owner.id, member.id, now);
  initializeProjectKeyEpoch(db, project.id, owner.id, randomUUID(), [
    keyEnvelope(project.id, owner, owner.id, 1),
    keyEnvelope(project.id, owner, member.id, 1),
  ], now);
  return project;
}

describe("authoritative project-member leave", () => {
  test("quarantines the leaver, cancels work, excludes every future key, and completes through owner rotation", () => {
    const db = openDatabase(":memory:");
    const now = new Date("2030-01-01T00:00:00.000Z");
    try {
      const owner = approvedDevice(db, "Stephen", now);
      const member = approvedDevice(db, "Kai", now);
      const project = encryptedProject(db, owner, member, now);

      const ownerAgent = randomUUID();
      const memberAgent = randomUUID();
      db.query(`
        INSERT INTO agents (id, project_id, host_device_id, name, enabled, created_at)
        VALUES (?, ?, ?, 'Owner agent', 1, ?), (?, ?, ?, 'Member agent', 1, ?)
      `).run(ownerAgent, project.id, owner.id, now.toISOString(),
        memberAgent, project.id, member.id, now.toISOString());
      const taskId = randomUUID();
      db.query(`
        INSERT INTO agent_tasks (
          id, project_id, chat_id, requester_device_id, target_device_id, agent_id,
          prompt, nonce, issued_at, expires_at, requester_signature,
          server_signature, status, accepted_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'opaque', ?, ?, ?, 'request-signature',
          'server-signature', 'queued', ?)
      `).run(taskId, project.id, project.id, member.id, owner.id, ownerAgent,
        randomUUID(), now.toISOString(), new Date(now.getTime() + 60_000).toISOString(), now.toISOString());

      const frame = leaveFrame(project.id, member, now);
      const requested = requestProjectLeave(db, member.id, frame, FINGERPRINT, EPOCH, now);
      expect(requested).toMatchObject({
        requestId: frame.requestId,
        projectId: project.id,
        deviceId: member.id,
        created: true,
      });
      expect(requested.cancelledTasks).toEqual([{ taskId, targetDeviceId: owner.id }]);
      expect(requestProjectLeave(db, member.id, frame, FINGERPRINT, EPOCH, now))
        .toMatchObject({ created: false, requestedAt: requested.requestedAt });
      expect(() => requireProjectMembership(db, project.id, member.id)).toThrow("approved project member");
      expect(listProjects(db, member.id)).toEqual([]);
      expect(listProjectKeyEnvelopesForDevice(db, member.id)).toEqual([]);
      expect(listProjectMembers(db, project.id, owner.id).find(row => row.deviceId === member.id))
        .toMatchObject({
          leaveRequestId: frame.requestId,
          leaveRequestedAt: requested.requestedAt,
        });
      expect(db.query("SELECT enabled FROM agents WHERE id = ?").get(memberAgent)).toEqual({ enabled: 0 });
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(taskId)).toEqual({ status: "failed" });
      expect(db.query(`
        SELECT rotation_required AS rotationRequired
        FROM project_key_epochs WHERE project_id = ?
      `).get(project.id)).toEqual({ rotationRequired: 1 });

      const ownerEpochTwo = keyEnvelope(project.id, owner, owner.id, 2);
      expect(rotateProjectKeyEpoch(
        db, project.id, owner.id, 1, randomUUID(), [ownerEpochTwo], now,
      )).toMatchObject({ keyEpoch: 2, created: true });
      expect(db.query(`
        SELECT recipient_device_id AS recipientDeviceId
        FROM project_key_envelopes WHERE project_id = ? AND key_epoch = 2
      `).all(project.id)).toEqual([{ recipientDeviceId: owner.id }]);

      const rotationId = randomUUID();
      const completed = removeProjectMemberAndRotateKeys(
        db,
        project.id,
        owner.id,
        member.id,
        2,
        rotationId,
        [keyEnvelope(project.id, owner, owner.id, 3)],
        now,
      );
      expect(completed).toMatchObject({ created: true, keyEpoch: 3, removedDeviceId: member.id });
      expect(db.query(`
        SELECT state, completed_by_device_id AS completedByDeviceId,
          completion_rotation_id AS completionRotationId
        FROM project_member_leave_requests WHERE request_id = ?
      `).get(frame.requestId)).toEqual({
        state: "completed",
        completedByDeviceId: owner.id,
        completionRotationId: rotationId,
      });
      expect(db.query("SELECT 1 FROM project_members WHERE project_id = ? AND device_id = ?")
        .get(project.id, member.id)).toBeNull();
      expect(requestProjectLeave(db, member.id, frame, FINGERPRINT, EPOCH, now))
        .toMatchObject({ created: false });
      expect(db.query("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("rejects owners, wrong authority, expiry, tampering, uninitialized encryption, and conflicting pending requests", () => {
    const db = openDatabase(":memory:");
    const now = new Date("2030-01-01T00:00:00.000Z");
    try {
      const owner = approvedDevice(db, "Stephen", now);
      const member = approvedDevice(db, "Kai", now);
      const project = encryptedProject(db, owner, member, now);
      expect(() => requestProjectLeave(
        db, owner.id, leaveFrame(project.id, owner, now), FINGERPRINT, EPOCH, now,
      )).toThrow("owner cannot leave");
      const wrongAuthority = leaveFrame(project.id, member, now, {
        serverFingerprint: "FF:EE:DD:CC:BB:AA",
      });
      expect(() => requestProjectLeave(db, member.id, wrongAuthority, FINGERPRINT, EPOCH, now))
        .toThrow("different server authority");
      const expired = leaveFrame(project.id, member, now, {
        issuedAt: new Date(now.getTime() - 10 * 60_000),
      });
      expect(() => requestProjectLeave(db, member.id, expired, FINGERPRINT, EPOCH, now))
        .toThrow("validity window");
      const tampered = leaveFrame(project.id, member, now);
      expect(() => requestProjectLeave(db, member.id, {
        ...tampered,
        signature: Buffer.alloc(64, 9).toString("base64url"),
      }, FINGERPRINT, EPOCH, now)).toThrow("signature is invalid");

      const pending = leaveFrame(project.id, member, now);
      requestProjectLeave(db, member.id, pending, FINGERPRINT, EPOCH, now);
      expect(() => requestProjectLeave(
        db, member.id, leaveFrame(project.id, member, now), FINGERPRINT, EPOCH, now,
      )).toThrow("already pending");

      const other = approvedDevice(db, "Angela", now);
      const uninitialized = createProject(db, "No key", owner.id, now);
      addProjectMember(db, uninitialized.id, owner.id, other.id, now);
      expect(() => requestProjectLeave(
        db, other.id, leaveFrame(uninitialized.id, other, now), FINGERPRINT, EPOCH, now,
      )).toThrow("initialized project encryption");
    } finally {
      db.close();
    }
  });
});

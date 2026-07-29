import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decodeInvitation,
  agentDefinitionSigningTranscript,
  agentRequestSigningTranscript,
  enrollmentSigningTranscript,
  projectLockSigningTranscript,
  type ProjectLockUpdateFrame,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import { createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import {
  approvePendingDeviceForTest,
  testServerIdentityFingerprint,
} from "./device-approval-fixture";
import { createInvitation } from "../src/invitations";
import { addProjectMember, appendChatEvent, createProject, listProjects } from "../src/shared-state";
import { projectLockState, updateProjectLock } from "../src/project-locks";
import { createAgentForHost, createAgentTask, registerAgent } from "../src/agent-routing";

interface TestDevice {
  id: string;
  privateKey: string;
}

function approvedDevice(
  db: ReturnType<typeof openDatabase>,
  name: string,
  now: Date,
): TestDevice {
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
  const device = enrollDevice(db, {
    invitation,
    expectedServerFingerprint: invitation.serverFingerprint,
    serverIdentityFingerprint: testServerIdentityFingerprint(db),
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName: name,
    devicePublicKeyPem: signing.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    signature,
  }, now);
  approvePendingDeviceForTest(db, device, signing.privateKey, invitation.serverFingerprint, now);
  return { id: device.id, privateKey: signing.privateKey };
}

function signedUpdate(
  device: TestDevice,
  input: {
    projectId: string;
    action: "lock" | "unlock";
    expectedRevision: number;
    reason: string;
    now: Date;
  },
): ProjectLockUpdateFrame {
  const unsigned = {
    version: 1 as const,
    operationId: crypto.randomUUID(),
    projectId: input.projectId,
    action: input.action,
    expectedRevision: input.expectedRevision,
    reason: input.reason,
    serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
    serverEpoch: 1,
    issuedAt: input.now.toISOString(),
    expiresAt: new Date(input.now.getTime() + 120_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
  };
  return {
    ...unsigned,
    type: "project.lock.update",
    requestId: crypto.randomUUID(),
    signature: sign(null, projectLockSigningTranscript(unsigned), device.privateKey).toString("base64url"),
  };
}

describe("authoritative project lock", () => {
  test("requires a signed owner transition, persists it, blocks writes, and unlocks monotonically", () => {
    const db = openDatabase(":memory:");
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const owner = approvedDevice(db, "Stephen", now);
      const member = approvedDevice(db, "Kai", now);
      const prospectiveMember = approvedDevice(db, "Nocturne", now);
      const project = createProject(db, "Lock boundary", owner.id, now);
      addProjectMember(db, project.id, owner.id, member.id, now);
      expect(project.lock).toEqual({
        state: "active",
        revision: 0,
        lockedAt: null,
        lockedByDeviceId: null,
        reason: null,
      });
      const agentId = crypto.randomUUID();
      const definition = {
        projectId: project.id,
        agentId,
        name: "Kai agent",
        hostDeviceId: member.id,
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium" as const,
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      };
      createAgentForHost(db, {
        id: agentId,
        projectId: project.id,
        hostDeviceId: member.id,
        name: definition.name,
        primaryModel: definition.primaryModel,
        primaryEffort: definition.primaryEffort,
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
        signature: sign(
          null,
          agentDefinitionSigningTranscript(definition),
          member.privateKey,
        ).toString("base64url"),
      }, now);
      const serverPair = generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      const taskId = crypto.randomUUID();
      const issuedAt = now.toISOString();
      const expiresAt = new Date(now.getTime() + 120_000).toISOString();
      const request = {
        taskId,
        projectId: project.id,
        chatId: project.id,
        agentId,
        prompt: "Hold for security review",
        nonce: randomBytes(32).toString("base64url"),
        issuedAt,
        expiresAt,
        dependencies: [] as string[],
        inputArtifactIds: [] as string[],
      };
      createAgentTask(db, {
        publicKeyPem: serverPair.publicKey,
        privateKeyPem: serverPair.privateKey,
        fingerprint: "server-identity",
      }, {
        id: taskId,
        projectId: project.id,
        chatId: project.id,
        requesterDeviceId: owner.id,
        agentId,
        prompt: request.prompt,
        nonce: request.nonce,
        issuedAt,
        expiresAt,
        dependencies: [],
        inputArtifactIds: [],
        requesterSignature: sign(
          null,
          agentRequestSigningTranscript(request),
          owner.privateKey,
        ).toString("base64url"),
      }, now);

      const unauthorized = signedUpdate(member, {
        projectId: project.id,
        action: "lock",
        expectedRevision: 0,
        reason: "Member request",
        now,
      });
      expect(() => updateProjectLock(
        db, member.id, unauthorized, "AAAA-BBBB-CCCC-DDDD", 1, now,
      )).toThrow("owner");
      expect(projectLockState(db, project.id).revision).toBe(0);

      const lock = signedUpdate(owner, {
        projectId: project.id,
        action: "lock",
        expectedRevision: 0,
        reason: "Security review",
        now,
      });
      const accepted = updateProjectLock(db, owner.id, lock, "AAAA-BBBB-CCCC-DDDD", 1, now);
      expect(accepted.created).toBeTrue();
      expect(accepted.cancelledTasks).toEqual([{ taskId, targetDeviceId: member.id }]);
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(taskId))
        .toEqual({ status: "failed" });
      expect(db.query(`
        SELECT task_id AS taskId, target_device_id AS targetDeviceId
        FROM project_lock_task_cancellations WHERE task_id = ?
      `).get(taskId)).toEqual({ taskId, targetDeviceId: member.id });
      expect(accepted.transition.state).toEqual({
        state: "locked",
        revision: 1,
        lockedAt: now.toISOString(),
        lockedByDeviceId: owner.id,
        reason: "Security review",
      });
      expect(updateProjectLock(db, owner.id, lock, "AAAA-BBBB-CCCC-DDDD", 1, now).created).toBeFalse();
      expect(updateProjectLock(
        db,
        owner.id,
        lock,
        "AAAA-BBBB-CCCC-DDDD",
        1,
        new Date(now.getTime() + 10 * 60_000),
      ).created).toBeFalse();
      expect(listProjects(db, member.id)[0]?.lock).toEqual(accepted.transition.state);
      expect(() => appendChatEvent(db, {
        projectId: project.id,
        eventId: crypto.randomUUID(),
        senderDeviceId: member.id,
        content: "Must not persist",
        clientCreatedAt: now.toISOString(),
      }, now)).toThrow("PROJECT_LOCKED");
      expect(() => addProjectMember(
        db,
        project.id,
        owner.id,
        prospectiveMember.id,
        now,
      )).toThrow("PROJECT_LOCKED");
      expect(() => registerAgent(db, {
        id: crypto.randomUUID(),
        projectId: project.id,
        hostDeviceId: member.id,
        name: "Legacy CLI bypass attempt",
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      }, now)).toThrow("PROJECT_LOCKED");

      expect(() => updateProjectLock(db, owner.id, {
        ...lock,
        operationId: crypto.randomUUID(),
        signature: "A".repeat(86),
      }, "AAAA-BBBB-CCCC-DDDD", 1, now)).toThrow("signature");
      const staleUnlock = signedUpdate(owner, {
        projectId: project.id,
        action: "unlock",
        expectedRevision: 0,
        reason: "Stale",
        now,
      });
      expect(() => updateProjectLock(
        db, owner.id, staleUnlock, "AAAA-BBBB-CCCC-DDDD", 1, now,
      )).toThrow("stale");

      const unlock = signedUpdate(owner, {
        projectId: project.id,
        action: "unlock",
        expectedRevision: 1,
        reason: "Review complete",
        now: new Date(now.getTime() + 1_000),
      });
      const unlocked = updateProjectLock(
        db, owner.id, unlock, "AAAA-BBBB-CCCC-DDDD", 1, new Date(now.getTime() + 1_000),
      );
      expect(unlocked.transition.state).toEqual({
        state: "active",
        revision: 2,
        lockedAt: null,
        lockedByDeviceId: null,
        reason: null,
      });
      expect(() => updateProjectLock(
        db,
        owner.id,
        lock,
        "AAAA-BBBB-CCCC-DDDD",
        1,
        new Date(now.getTime() + 10 * 60_000),
      )).toThrow("superseded");
      expect(appendChatEvent(db, {
        projectId: project.id,
        eventId: crypto.randomUUID(),
        senderDeviceId: member.id,
        content: "Work resumed",
        clientCreatedAt: now.toISOString(),
      }, now).content).toBe("Work resumed");
      expect(db.query(`
        SELECT event_type AS eventType FROM audit_events
        WHERE subject_id = ? AND event_type IN ('project.locked', 'project.unlocked')
        ORDER BY sequence
      `).all(project.id)).toEqual([
        { eventType: "project.locked" },
        { eventType: "project.unlocked" },
      ]);
    } finally {
      db.close();
    }
  });

  test("makes a lock committed on another SQLite connection visible to every write path", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-project-lock-connections-"));
    const databasePath = join(root, "server.sqlite3");
    const writer = openDatabase(databasePath);
    let locker: ReturnType<typeof openDatabase> | undefined;
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const owner = approvedDevice(writer, "Stephen", now);
      const member = approvedDevice(writer, "Kai", now);
      const project = createProject(writer, "Cross-connection lock", owner.id, now);
      addProjectMember(writer, project.id, owner.id, member.id, now);
      locker = openDatabase(databasePath);
      updateProjectLock(locker, owner.id, signedUpdate(owner, {
        projectId: project.id,
        action: "lock",
        expectedRevision: 0,
        reason: "Second connection incident",
        now,
      }), "AAAA-BBBB-CCCC-DDDD", 1, now);

      expect(() => appendChatEvent(writer, {
        projectId: project.id,
        eventId: crypto.randomUUID(),
        senderDeviceId: member.id,
        content: "Must observe the other connection's lock",
        clientCreatedAt: now.toISOString(),
      }, now)).toThrow("PROJECT_LOCKED");
      expect(() => registerAgent(writer, {
        id: crypto.randomUUID(),
        projectId: project.id,
        hostDeviceId: member.id,
        name: "Must not register",
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: null,
        coAgentEffort: null,
        maxConcurrentCoAgents: 0,
      }, now)).toThrow("PROJECT_LOCKED");
      expect(writer.query("SELECT COUNT(*) AS count FROM chat_events WHERE project_id = ?")
        .get(project.id)).toEqual({ count: 0 });
      expect(writer.query("SELECT COUNT(*) AS count FROM agents WHERE project_id = ?")
        .get(project.id)).toEqual({ count: 0 });
    } finally {
      locker?.close();
      writer.close();
      Bun.gc(true);
      await Bun.sleep(100);
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });
});

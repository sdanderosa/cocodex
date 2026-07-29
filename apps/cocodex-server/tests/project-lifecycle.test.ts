import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import {
  projectLifecycleSigningTranscript,
  type ProjectLifecycleAction,
  type ProjectLifecycleUpdateFrame,
} from "@cocodex/protocol";
import { openDatabase } from "../src/database";
import { updateProjectLifecycle } from "../src/project-lifecycle";
import { addProjectMember, appendChatEvent, createProject, listProjects } from "../src/shared-state";

const FINGERPRINT = "AA:BB:CC:DD:EE:FF";
const EPOCH = 3;

function approvedDevice(db: ReturnType<typeof openDatabase>, name: string, now: Date) {
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
  `).run(deviceId, pair.publicKey, randomBytes(32).toString("hex"), name, invitationId, now.toISOString(), now.toISOString());
  return { id: deviceId, privateKey: pair.privateKey };
}

function signedFrame(
  projectId: string,
  actorPrivateKey: string,
  action: ProjectLifecycleAction,
  expectedRevision: number,
  now: Date,
  options: { operationId?: string; name?: string; confirmationName?: string; serverFingerprint?: string } = {},
): ProjectLifecycleUpdateFrame {
  const unsigned = {
    version: 1 as const,
    operationId: options.operationId ?? randomUUID(),
    projectId,
    action,
    expectedRevision,
    ...(options.name !== undefined ? { name: options.name } : {}),
    ...(options.confirmationName !== undefined ? { confirmationName: options.confirmationName } : {}),
    serverFingerprint: options.serverFingerprint ?? FINGERPRINT,
    serverEpoch: EPOCH,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 120_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
  };
  return {
    ...unsigned,
    type: "project.lifecycle.update",
    requestId: randomUUID(),
    signature: sign(null, projectLifecycleSigningTranscript(unsigned), actorPrivateKey).toString("base64url"),
  };
}

describe("authoritative project lifecycle", () => {
  test("refuses lifecycle deletion while a historical migration transaction is active", () => {
    const db = openDatabase(":memory:");
    const now = new Date("2030-01-01T00:00:00.000Z");
    try {
      const owner = approvedDevice(db, "Stephen", now);
      const project = createProject(db, "Legacy archive", owner.id, now);
      appendChatEvent(db, {
        projectId: project.id,
        eventId: randomUUID(),
        senderDeviceId: owner.id,
        content: "historical plaintext canary",
        clientCreatedAt: now.toISOString(),
      }, now);
      db.query(`
        UPDATE projects SET state = 'archived', archived_at = ? WHERE id = ?
      `).run(now.toISOString(), project.id);
      const migrationId = randomUUID();
      db.query(`
        INSERT INTO project_plaintext_migrations (
          migration_id, project_id, key_epoch, owner_device_id, snapshot_digest,
          state, item_count, staged_count, created_at, updated_at
        ) VALUES (?, ?, 1, ?, ?, 'prepared', 0, 0, ?, ?)
      `).run(
        migrationId, project.id, owner.id, randomBytes(32).toString("base64url"),
        now.toISOString(), now.toISOString(),
      );
      const deletion = signedFrame(project.id, owner.privateKey, "delete", 0, now, {
        confirmationName: "Legacy archive",
      });
      expect(() => updateProjectLifecycle(
        db, owner.id, deletion, FINGERPRINT, EPOCH, now,
      )).toThrow("still in progress");
      expect(db.query("SELECT 1 FROM projects WHERE id = ?").get(project.id)).not.toBeNull();
      expect(db.query("SELECT 1 FROM project_lifecycle_operations WHERE operation_id = ?")
        .get(deletion.operationId)).toBeNull();
      expect(db.query("SELECT state FROM project_plaintext_migrations WHERE migration_id = ?")
        .get(migrationId)).toEqual({ state: "prepared" });
    } finally {
      db.close();
    }
  });


  test("signs, authorizes, revisions, archives, restores, and permanently deletes", () => {
    const db = openDatabase(":memory:");
    const now = new Date("2030-01-01T00:00:00.000Z");
    try {
      const owner = approvedDevice(db, "Stephen", now);
      const member = approvedDevice(db, "Kai", now);
      const outsider = approvedDevice(db, "Outsider", now);
      const project = createProject(db, "Nocturne", owner.id, now);
      addProjectMember(db, project.id, owner.id, member.id, now);

      const rename = signedFrame(project.id, owner.privateKey, "rename", 0, now, { name: "Nocturne Next" });
      const renamed = updateProjectLifecycle(db, owner.id, rename, FINGERPRINT, EPOCH, now);
      expect(renamed).toMatchObject({
        created: true,
        project: { name: "Nocturne Next", state: "active", lifecycleRevision: 1 },
        memberDeviceIds: [owner.id, member.id],
        transition: { action: "rename", previousName: "Nocturne", resultingRevision: 1 },
      });
      expect(updateProjectLifecycle(db, owner.id, rename, FINGERPRINT, EPOCH, now).created).toBeFalse();
      expect(() => updateProjectLifecycle(db, owner.id, { ...rename, name: "Conflict" }, FINGERPRINT, EPOCH, now))
        .toThrow("signature");
      expect(() => updateProjectLifecycle(
        db,
        member.id,
        signedFrame(project.id, member.privateKey, "rename", 1, now, { name: "Member edit" }),
        FINGERPRINT,
        EPOCH,
        now,
      )).toThrow("owner");
      expect(() => updateProjectLifecycle(
        db,
        outsider.id,
        signedFrame(project.id, outsider.privateKey, "archive", 1, now),
        FINGERPRINT,
        EPOCH,
        now,
      )).toThrow("owner");
      expect(() => updateProjectLifecycle(
        db,
        owner.id,
        signedFrame(project.id, owner.privateKey, "archive", 1, now),
        FINGERPRINT,
        EPOCH,
        now,
      )).toThrow("Lock the project");

      db.query(`
        UPDATE project_lock_state SET state = 'locked', revision = 1,
          locked_at = ?, locked_by_device_id = ?, reason = 'Owner review', updated_at = ?
        WHERE project_id = ?
      `).run(now.toISOString(), owner.id, now.toISOString(), project.id);
      const archived = updateProjectLifecycle(
        db,
        owner.id,
        signedFrame(project.id, owner.privateKey, "archive", 1, now),
        FINGERPRINT,
        EPOCH,
        now,
      );
      expect(archived.project).toMatchObject({ state: "archived", lifecycleRevision: 2 });
      expect(listProjects(db, member.id)[0]).toMatchObject({ state: "archived", lifecycleRevision: 2 });
      expect(() => appendChatEvent(db, {
        projectId: project.id,
        eventId: randomUUID(),
        senderDeviceId: member.id,
        content: "must not write",
        clientCreatedAt: now.toISOString(),
      }, now)).toThrow("PROJECT_ARCHIVED");

      const restored = updateProjectLifecycle(
        db,
        owner.id,
        signedFrame(project.id, owner.privateKey, "restore", 2, now),
        FINGERPRINT,
        EPOCH,
        now,
      );
      expect(restored.project).toMatchObject({ state: "active", lifecycleRevision: 3, lock: { state: "locked" } });
      expect(() => appendChatEvent(db, {
        projectId: project.id,
        eventId: randomUUID(),
        senderDeviceId: owner.id,
        content: "still locked",
        clientCreatedAt: now.toISOString(),
      }, now)).toThrow("PROJECT_LOCKED");

      updateProjectLifecycle(
        db,
        owner.id,
        signedFrame(project.id, owner.privateKey, "archive", 3, now),
        FINGERPRINT,
        EPOCH,
        now,
      );
      expect(() => updateProjectLifecycle(
        db,
        owner.id,
        signedFrame(project.id, owner.privateKey, "delete", 4, now, { confirmationName: "nocturne next" }),
        FINGERPRINT,
        EPOCH,
        now,
      )).toThrow("exactly match");
      const deletion = signedFrame(project.id, owner.privateKey, "delete", 4, now, {
        confirmationName: "Nocturne Next",
      });
      const deleted = updateProjectLifecycle(db, owner.id, deletion, FINGERPRINT, EPOCH, now);
      expect(deleted).toMatchObject({
        created: true,
        project: null,
        memberDeviceIds: [owner.id, member.id],
        transition: { action: "delete", resultingState: null, resultingRevision: 5 },
      });
      expect(listProjects(db, owner.id)).toEqual([]);
      expect(db.query("SELECT id FROM projects WHERE id = ?").get(project.id)).toBeNull();
      expect(db.query("SELECT project_id FROM project_members WHERE project_id = ?").all(project.id)).toEqual([]);
      expect(db.query("SELECT operation_id AS operationId FROM project_lifecycle_operations WHERE operation_id = ?")
        .get(deletion.operationId)).toEqual({ operationId: deletion.operationId });
      expect(updateProjectLifecycle(db, owner.id, deletion, FINGERPRINT, EPOCH, now))
        .toMatchObject({ created: false, project: null, transition: deleted.transition });
      expect(db.query("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      db.close();
    }
  });

  test("rejects stale revisions, wrong authority, expired requests, and invalid signatures", () => {
    const db = openDatabase(":memory:");
    const now = new Date("2030-01-01T00:00:00.000Z");
    try {
      const owner = approvedDevice(db, "Stephen", now);
      const project = createProject(db, "Security", owner.id, now);
      expect(() => updateProjectLifecycle(
        db, owner.id, signedFrame(project.id, owner.privateKey, "rename", 1, now, { name: "Stale" }),
        FINGERPRINT, EPOCH, now,
      )).toThrow("revision is stale");
      const wrongAuthority = signedFrame(project.id, owner.privateKey, "rename", 0, now, {
        name: "Wrong authority", serverFingerprint: "FF:EE:DD:CC:BB:AA",
      });
      expect(() => updateProjectLifecycle(db, owner.id, wrongAuthority, FINGERPRINT, EPOCH, now))
        .toThrow("different server authority");
      const expiredAt = new Date("2029-12-31T23:50:00.000Z");
      expect(() => updateProjectLifecycle(
        db, owner.id, signedFrame(project.id, owner.privateKey, "rename", 0, expiredAt, { name: "Expired" }),
        FINGERPRINT, EPOCH, now,
      )).toThrow("validity window");
      const valid = signedFrame(project.id, owner.privateKey, "rename", 0, now, { name: "Tamper" });
      expect(() => updateProjectLifecycle(
        db, owner.id, { ...valid, signature: Buffer.alloc(64, 9).toString("base64url") },
        FINGERPRINT, EPOCH, now,
      )).toThrow("signature is invalid");
    } finally {
      db.close();
    }
  });
});

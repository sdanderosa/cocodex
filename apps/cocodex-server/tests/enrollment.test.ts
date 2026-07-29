import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decodeInvitation, enrollmentSigningTranscript } from "@cocodex/protocol";
import { approveDevice, createEnrollmentChallenge, enrollDevice, listDevices, revokeDevice } from "../src/enrollment";
import { openDatabase } from "../src/database";
import { createInvitation } from "../src/invitations";

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    const absolute = resolve(root);
    if (!absolute.startsWith(resolve(tmpdir()))) throw new Error(`Refusing to remove non-temporary path: ${absolute}`);
    for (let attempt = 0; attempt < 40; attempt += 1) {
      try {
        rmSync(absolute, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 39) throw error;
        // Windows may retain a just-closed SQLite handle briefly. Keep cleanup
        // bounded while giving the OS enough time to release that lock.
        await Bun.sleep(100);
      }
    }
  }
});

describe("device enrollment persistence", () => {
  test("stores a token hash, atomically consumes the invite, and requires approval", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-enrollment-"));
    roots.push(root);
    const databasePath = join(root, "state.sqlite3");
    const db = openDatabase(databasePath);
    const pair = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const messaging = generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const code = createInvitation(db, {
      host: "server.example",
      port: 10443,
      serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
      now: new Date("2027-01-01T00:00:00.000Z"),
    });
    const invitation = decodeInvitation(code);
    const stored = db.query("SELECT token_hash AS tokenHash FROM invitations").get() as { tokenHash: string };
    expect(stored.tokenHash).not.toContain(invitation.token);
    expect(readFileSync(databasePath).includes(Buffer.from(invitation.token))).toBeFalse();

    const challenge = createEnrollmentChallenge(
      db,
      invitation,
      pair.publicKey,
      invitation.serverFingerprint,
      new Date("2027-01-01T00:00:30.000Z"),
    );
    const signature = sign(null, enrollmentSigningTranscript({
      serverFingerprint: invitation.serverFingerprint,
      invitationId: invitation.invitationId,
      challengeId: challenge.id,
      challenge: challenge.challenge,
      displayName: "Kai",
      devicePublicKeyPem: pair.publicKey,
      messagingPublicKeyPem: messaging.publicKey,
    }), pair.privateKey).toString("base64url");
    const request = {
      invitation,
      expectedServerFingerprint: invitation.serverFingerprint,
      serverIdentityFingerprint: invitation.serverFingerprint,
      challengeId: challenge.id,
      challenge: challenge.challenge,
      displayName: "Kai",
      devicePublicKeyPem: pair.publicKey,
      messagingPublicKeyPem: messaging.publicKey,
      signature,
    };
    const device = enrollDevice(db, request, new Date("2027-01-01T00:01:00.000Z"));
    expect(device.status).toBe("pending");
    expect(() => enrollDevice(db, request, new Date("2027-01-01T00:02:00.000Z"))).toThrow("already used");
    expect(approveDevice(db, device.fingerprint, new Date("2027-01-01T00:03:00.000Z"))).toBeTrue();
    expect(listDevices(db)[0]?.status).toBe("approved");
    expect(revokeDevice(db, device.fingerprint, new Date("2027-01-01T00:04:00.000Z"))).toBeTrue();
    expect(listDevices(db)[0]?.status).toBe("revoked");
    expect(revokeDevice(db, device.fingerprint, new Date("2027-01-01T00:05:00.000Z"))).toBeFalse();
    db.close();
  });

  test("rolls back device revocation when encrypted-project incident persistence fails", () => {
    const db = openDatabase(":memory:");
    const now = new Date("2027-01-01T00:00:00.000Z");
    const invitationId = randomUUID();
    const deviceId = randomUUID();
    const projectId = randomUUID();
    try {
      db.query(`
        INSERT INTO invitations (id, token_hash, expires_at, consumed_at, created_at)
        VALUES (?, 'rollback-token-hash', ?, ?, ?)
      `).run(invitationId, now.toISOString(), now.toISOString(), now.toISOString());
      db.query(`
        INSERT INTO devices (
          id, public_key_pem, fingerprint, display_name, status,
          invitation_id, enrolled_at, approved_at
        ) VALUES (?, 'rollback-public-key', 'rollback-fingerprint', 'Rollback Device',
          'approved', ?, ?, ?)
      `).run(deviceId, invitationId, now.toISOString(), now.toISOString());
      db.query(`
        INSERT INTO projects (id, name, created_by_device_id, created_at)
        VALUES (?, 'Rollback Project', ?, ?)
      `).run(projectId, deviceId, now.toISOString());
      db.query(`
        INSERT INTO project_members (project_id, device_id, role, joined_at)
        VALUES (?, ?, 'owner', ?)
      `).run(projectId, deviceId, now.toISOString());
      db.query(`
        INSERT INTO shared_chats (
          id, project_id, title, created_by_device_id, state,
          creation_nonce, created_at, updated_at
        ) VALUES (?, ?, 'General', ?, 'active', NULL, ?, ?)
      `).run(projectId, projectId, deviceId, now.toISOString(), now.toISOString());
      db.query(`
        INSERT INTO project_key_epochs (
          project_id, current_epoch, last_rotation_id, updated_by_device_id,
          created_at, updated_at, rotation_required
        ) VALUES (?, 1, NULL, ?, ?, ?, 0)
      `).run(projectId, deviceId, now.toISOString(), now.toISOString());
      db.exec(`
        CREATE TRIGGER reject_revocation_incident
        BEFORE INSERT ON device_revocation_project_incidents
        BEGIN
          SELECT RAISE(ABORT, 'injected incident failure');
        END;
      `);
      expect(() => revokeDevice(db, "rollback-fingerprint", now))
        .toThrow("injected incident failure");
      expect(db.query("SELECT status, revoked_at AS revokedAt FROM devices WHERE id = ?")
        .get(deviceId)).toEqual({ status: "approved", revokedAt: null });
      expect(db.query(`
        SELECT rotation_required AS rotationRequired
        FROM project_key_epochs WHERE project_id = ?
      `).get(projectId)).toEqual({ rotationRequired: 0 });
      expect(db.query(`
        SELECT COUNT(*) AS count FROM device_revocation_project_incidents
      `).get()).toEqual({ count: 0 });
    } finally {
      db.close();
    }
  });
});

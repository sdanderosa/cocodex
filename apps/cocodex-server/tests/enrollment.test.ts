import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
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
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        rmSync(absolute, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 19) throw error;
        await Bun.sleep(25);
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
});

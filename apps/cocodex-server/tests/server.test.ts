import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import { createDefaultConfig } from "../src/config";
import { openDatabase } from "../src/database";
import { approveDevice } from "../src/enrollment";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { startCoCodexServer } from "../src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";
import { decodeInvitation, enrollmentSigningTranscript } from "@cocodex/protocol";

const temporaryRoots: string[] = [];
const runningServers: Array<{ stop: (force?: boolean) => Promise<void> }> = [];
const openDatabases: Database[] = [];

afterEach(async () => {
  await Promise.all(runningServers.splice(0).map(server => server.stop(true)));
  for (const database of new Set(openDatabases.splice(0))) database.close();
  // Under the complete Windows Server suite, SQLite WAL/SHM handles can be
  // released just after close while other Bun workers are still collecting.
  // Keep cleanup exact to this test root, but give handle finalization the
  // same bounded five-second window used by the process-heavy suites.
  Bun.gc(true);
  for (const root of temporaryRoots.splice(0)) {
    let lastError: unknown;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        lastError = undefined;
        break;
      } catch (error) {
        lastError = error;
        await Bun.sleep(50);
      }
    }
    if (lastError) throw lastError;
  }
});

function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cocodex-server-test-"));
  temporaryRoots.push(root);
  return root;
}

function deviceIdentity() {
  const signing = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { ...signing, messagingPublicKey: messaging.publicKey };
}

describe("CoCodex Server enrollment boundary", () => {
  test("a one-time invitation enrolls a proof-owning device pending approval", async () => {
    const paths = serverPaths(temporaryRoot());
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const db = openDatabase(paths.database);
    openDatabases.push(db);
    openDatabases.push(db);
    openDatabases.push(db);
    const invitationCode = createInvitation(db, {
      host: "127.0.0.1",
      port: 443,
      serverFingerprint: tlsCertificateFingerprint(paths.tlsCertificate),
    });
    const invitation = decodeInvitation(invitationCode);
    const pair = deviceIdentity();
    const config = createDefaultConfig(paths, "127.0.0.1", 443, "admin-test-token");
    config.hostname = "127.0.0.1";
    config.port = 0;
    const running = startCoCodexServer(config, db, identity);
    runningServers.push(running);
    const deniedAdmin = await fetch(`https://127.0.0.1:${running.port}/v1/admin/status`, { tls: { rejectUnauthorized: false } });
    expect(deniedAdmin.status).toBe(401);
    const allowedAdmin = await fetch(`https://127.0.0.1:${running.port}/v1/admin/status`, {
      tls: { rejectUnauthorized: false },
      headers: { authorization: "Bearer admin-test-token" },
    });
    expect(allowedAdmin.status).toBe(200);
    expect((await allowedAdmin.json()) as { service: string }).toMatchObject({ service: "cocodex-server" });
    const challengeResponse = await fetch(`https://127.0.0.1:${running.port}/v1/enrollment/challenge`, {
      method: "POST",
      tls: { rejectUnauthorized: false },
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ invitationCode, devicePublicKeyPem: pair.publicKey }),
    });
    expect(challengeResponse.status).toBe(201);
    const challenge = await challengeResponse.json() as { id: string; challenge: string };
    const signature = sign(null, enrollmentSigningTranscript({
      serverFingerprint: invitation.serverFingerprint,
      invitationId: invitation.invitationId,
      challengeId: challenge.id,
      challenge: challenge.challenge,
      displayName: "Kai",
      devicePublicKeyPem: pair.publicKey,
      messagingPublicKeyPem: pair.messagingPublicKey,
    }), pair.privateKey).toString("base64url");
    const enrollmentBody = {
      version: 1,
      invitationCode,
      challengeId: challenge.id,
      challenge: challenge.challenge,
      displayName: "Kai",
      devicePublicKeyPem: pair.publicKey,
      messagingPublicKeyPem: pair.messagingPublicKey,
      signature,
    };

    const response = await fetch(`https://127.0.0.1:${running.port}/v1/enroll`, {
      method: "POST",
      tls: { rejectUnauthorized: false },
      headers: { "content-type": "application/json" },
      body: JSON.stringify(enrollmentBody),
    });
    expect(response.status).toBe(202);
    const result = await response.json() as { device: { fingerprint: string; status: string } };
    expect(result.device.status).toBe("pending");
    expect(approveDevice(db, result.device.fingerprint)).toBe(true);

    const replay = await fetch(`https://127.0.0.1:${running.port}/v1/enroll`, {
      method: "POST",
      tls: { rejectUnauthorized: false },
      headers: { "content-type": "application/json" },
      body: JSON.stringify(enrollmentBody),
    });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "Enrollment challenge is invalid, expired, or already used" });
  });

  test("a device without the matching private key cannot consume an invitation", async () => {
    const paths = serverPaths(temporaryRoot());
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const db = openDatabase(paths.database);
    openDatabases.push(db);
    openDatabases.push(db);
    openDatabases.push(db);
    const invitationCode = createInvitation(db, {
      host: "127.0.0.1",
      port: 443,
      serverFingerprint: tlsCertificateFingerprint(paths.tlsCertificate),
    });
    const invitation = decodeInvitation(invitationCode);
    const claimed = deviceIdentity();
    const attacker = deviceIdentity();
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const running = startCoCodexServer(config, db, identity);
    runningServers.push(running);
    const challengeResponse = await fetch(`https://127.0.0.1:${running.port}/v1/enrollment/challenge`, {
      method: "POST",
      tls: { rejectUnauthorized: false },
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ invitationCode, devicePublicKeyPem: claimed.publicKey }),
    });
    const challenge = await challengeResponse.json() as { id: string; challenge: string };
    const signature = sign(null, enrollmentSigningTranscript({
      serverFingerprint: invitation.serverFingerprint,
      invitationId: invitation.invitationId,
      challengeId: challenge.id,
      challenge: challenge.challenge,
      displayName: "Kai",
      devicePublicKeyPem: claimed.publicKey,
      messagingPublicKeyPem: claimed.messagingPublicKey,
    }), attacker.privateKey).toString("base64url");

    const response = await fetch(`https://127.0.0.1:${running.port}/v1/enroll`, {
      method: "POST",
      tls: { rejectUnauthorized: false },
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        version: 1,
        invitationCode,
        challengeId: challenge.id,
        challenge: challenge.challenge,
        displayName: "Kai",
        devicePublicKeyPem: claimed.publicKey,
        messagingPublicKeyPem: claimed.messagingPublicKey,
        signature,
      }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid enrollment proof" });
  });
});

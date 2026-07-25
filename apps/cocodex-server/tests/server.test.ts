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
const runningServers: Array<{ stop: (force?: boolean) => void }> = [];
const openDatabases: Database[] = [];

afterEach(() => {
  for (const server of runningServers.splice(0)) server.stop(true);
  for (const database of openDatabases.splice(0)) database.close();
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
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
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const running = startCoCodexServer(config, db, identity);
    runningServers.push(running);
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

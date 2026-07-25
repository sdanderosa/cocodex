import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import {
  decodeInvitation,
  enrollmentSigningTranscript,
  projectContentSigningTranscript,
  projectKeyEnvelopeSigningTranscript,
  websocketAuthTranscript,
  type ProjectContentEnvelope,
  type ProjectKeyEnvelope,
} from "@cocodex/protocol";
import { createDefaultConfig } from "../src/config";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { addProjectMember, createProject } from "../src/shared-state";
import { startCoCodexServer } from "../src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";

const roots: string[] = [];
const servers: Array<{ stop(force?: boolean): Promise<void> }> = [];
const databases: Database[] = [];
const sockets: WebSocket[] = [];

afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.close();
  await Promise.all(servers.splice(0).map(server => server.stop(true)));
  for (const database of databases.splice(0)) database.close();
  Bun.gc(true);
  for (const root of roots.splice(0)) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 19) throw error;
        await Bun.sleep(25);
      }
    }
  }
});

interface TestDevice {
  id: string;
  privateKey: string;
  publicKey: string;
}

function approvedDevice(db: Database, fingerprint: string, displayName: string): TestDevice {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messaging = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const invitation = decodeInvitation(createInvitation(db, {
    host: "127.0.0.1",
    port: 443,
    serverFingerprint: fingerprint,
  }));
  const challenge = createEnrollmentChallenge(db, invitation, pair.publicKey, fingerprint);
  const enrollmentSignature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: fingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
  }), pair.privateKey).toString("base64url");
  const device = enrollDevice(db, {
    invitation,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messaging.publicKey,
    signature: enrollmentSignature,
  });
  expect(approveDevice(db, device.fingerprint)).toBeTrue();
  return { id: device.id, privateKey: pair.privateKey, publicKey: pair.publicKey };
}

function nextFrame(
  socket: WebSocket,
  expectedType: string,
  predicate: (frame: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.removeEventListener("message", onMessage);
      reject(new Error(`Timed out waiting for ${expectedType}`));
    }, 5_000);
    const onMessage = (event: MessageEvent) => {
      const frame = JSON.parse(String(event.data)) as Record<string, unknown>;
      if (frame.type === "error") {
        clearTimeout(timeout);
        socket.removeEventListener("message", onMessage);
        reject(new Error(String(frame.error)));
        return;
      }
      if (frame.type !== expectedType || !predicate(frame)) return;
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      resolve(frame);
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", event => reject(new Error(`Socket closed ${event.code}: ${event.reason}`)), { once: true });
  });
}

async function connect(port: number, device: TestDevice, fingerprint: string): Promise<WebSocket> {
  const socket = new WebSocket(
    `wss://127.0.0.1:${port}/v1/connect`,
    { tls: { rejectUnauthorized: false } } as never,
  );
  sockets.push(socket);
  const challenge = await nextFrame(socket, "auth.challenge");
  const requestId = randomUUID();
  const proof = sign(null, websocketAuthTranscript({
    serverFingerprint: fingerprint,
    deviceId: device.id,
    requestId,
    challenge: String(challenge.challenge),
  }), device.privateKey).toString("base64url");
  const authenticated = nextFrame(socket, "auth.ok");
  socket.send(JSON.stringify({ version: 1, type: "auth.response", requestId, deviceId: device.id, signature: proof }));
  await authenticated;
  return socket;
}

function keyEnvelope(projectId: string, sender: TestDevice, recipientDeviceId: string): ProjectKeyEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch: 1,
    recipientDeviceId,
    senderDeviceId: sender.id,
    sealedProjectKey: randomBytes(80).toString("base64url"),
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectKeyEnvelopeSigningTranscript(unsigned), sender.privateKey).toString("base64url"),
  };
}

function contextEnvelope(projectId: string, sender: TestDevice, recordId = randomUUID()): ProjectContentEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch: 1,
    recordType: "shared-context" as const,
    recordId,
    nonce: randomBytes(24).toString("base64url"),
    ciphertext: randomBytes(16).toString("base64url"),
    senderDeviceId: sender.id,
    senderPublicKeyPem: sender.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectContentSigningTranscript(unsigned), sender.privateKey).toString("base64url"),
  };
}

describe("encrypted project WSS routing", () => {
  test("routes opaque keys/context, enforces membership, and rejects stale/replayed writes", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-project-encryption-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const owner = approvedDevice(db, fingerprint, "Stephen");
    const member = approvedDevice(db, fingerprint, "Kai");
    const project = createProject(db, "Encrypted project", owner.id);
    addProjectMember(db, project.id, owner.id, member.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);
    const ownerSocket = await connect(server.port, owner, fingerprint);
    const memberSocket = await connect(server.port, member, fingerprint);

    const initialKeys = nextFrame(memberSocket, "project.key.result");
    memberSocket.send(JSON.stringify({ version: 1, type: "project.key.get", requestId: randomUUID(), projectId: project.id }));
    expect((await initialKeys).envelopes).toEqual([]);

    const key = keyEnvelope(project.id, owner, member.id);
    const keyChanged = nextFrame(memberSocket, "project.key.changed");
    const keyAccepted = nextFrame(ownerSocket, "project.key.accepted");
    const keyRequestId = randomUUID();
    ownerSocket.send(JSON.stringify({ version: 1, type: "project.key.share", requestId: keyRequestId, projectId: project.id, envelope: key }));
    expect(await keyAccepted).toMatchObject({ requestId: keyRequestId, created: true, envelope: key });
    expect(await keyChanged).toMatchObject({ projectId: project.id, envelope: key });
    const keySnapshot = nextFrame(memberSocket, "project.key.result");
    memberSocket.send(JSON.stringify({ version: 1, type: "project.key.get", requestId: randomUUID(), projectId: project.id, keyEpoch: 1 }));
    expect((await keySnapshot).envelopes).toEqual([key]);

    const replayAccepted = nextFrame(ownerSocket, "project.key.accepted");
    ownerSocket.send(JSON.stringify({ version: 1, type: "project.key.share", requestId: randomUUID(), projectId: project.id, envelope: key }));
    expect((await replayAccepted).created).toBeFalse();
    const memberKey = keyEnvelope(project.id, member, owner.id);
    const memberKeyError = nextFrame(memberSocket, "project.key.accepted");
    memberSocket.send(JSON.stringify({ version: 1, type: "project.key.share", requestId: randomUUID(), projectId: project.id, envelope: memberKey }));
    await expect(memberKeyError).rejects.toThrow("Only a project owner");
    const ownerInitialContext = nextFrame(ownerSocket, "project.context.result");
    ownerSocket.send(JSON.stringify({ version: 1, type: "project.context.get", requestId: randomUUID(), projectId: project.id }));
    expect((await ownerInitialContext).revision).toBe(0);
    const initialContext = nextFrame(memberSocket, "project.context.result");
    memberSocket.send(JSON.stringify({ version: 1, type: "project.context.get", requestId: randomUUID(), projectId: project.id }));
    expect(await initialContext).toMatchObject({ projectId: project.id, envelope: null, revision: 0 });
    const firstContext = contextEnvelope(project.id, member);
    const contextChanged = nextFrame(ownerSocket, "project.context.changed");
    const memberContextChanged = nextFrame(memberSocket, "project.context.changed");
    const contextAccepted = nextFrame(memberSocket, "project.context.updated");
    const contextRequestId = randomUUID();
    memberSocket.send(JSON.stringify({
      version: 1,
      type: "project.context.update",
      requestId: contextRequestId,
      projectId: project.id,
      expectedRevision: 0,
      envelope: firstContext,
    }));
    expect(await contextAccepted).toMatchObject({ requestId: contextRequestId, revision: 1, created: true, envelope: firstContext });
    expect(await contextChanged).toMatchObject({ projectId: project.id, revision: 1, envelope: firstContext });
    expect(await memberContextChanged).toMatchObject({ projectId: project.id, revision: 1, envelope: firstContext });

    const staleContext = contextEnvelope(project.id, owner);
    const staleError = nextFrame(ownerSocket, "project.context.updated");
    ownerSocket.send(JSON.stringify({
      version: 1,
      type: "project.context.update",
      requestId: randomUUID(),
      projectId: project.id,
      expectedRevision: 0,
      envelope: staleContext,
    }));
    await expect(staleError).rejects.toThrow("revision conflict");
    const secondContext = contextEnvelope(project.id, owner);
    const secondChanged = nextFrame(memberSocket, "project.context.changed");
    const secondAccepted = nextFrame(ownerSocket, "project.context.updated");
    ownerSocket.send(JSON.stringify({
      version: 1,
      type: "project.context.update",
      requestId: randomUUID(),
      projectId: project.id,
      expectedRevision: 1,
      envelope: secondContext,
    }));
    expect((await secondAccepted).revision).toBe(2);
    expect((await secondChanged).envelope).toEqual(secondContext);
    const replayContext = nextFrame(ownerSocket, "project.context.updated");
    ownerSocket.send(JSON.stringify({
      version: 1,
      type: "project.context.update",
      requestId: randomUUID(),
      projectId: project.id,
      expectedRevision: 1,
      envelope: secondContext,
    }));
    expect((await replayContext).created).toBeFalse();

    const stored = db.query("SELECT envelope_json AS envelopeJson FROM encrypted_project_context WHERE project_id = ?")
      .get(project.id) as { envelopeJson: string };
    expect(stored.envelopeJson).toContain(secondContext.ciphertext);
    expect(stored.envelopeJson).not.toContain("plaintext");
  }, 15_000);
});

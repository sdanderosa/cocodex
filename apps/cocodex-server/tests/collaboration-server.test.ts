import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import {
  agentRequestSigningTranscript,
  decodeInvitation,
  enrollmentSigningTranscript,
  websocketAuthTranscript,
  type ChatEvent,
  publicKeyFingerprint,
} from "@cocodex/protocol";
import { registerAgent } from "../src/agent-routing";
import { createDefaultConfig } from "../src/config";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { addProjectMember, createProject } from "../src/shared-state";
import { startCoCodexServer } from "../src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "../../../src/cocodex/private-messaging";

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
  messagingPrivateKey: string;
  messagingPublicKey: string;
}

function approvedDevice(db: Database, fingerprint: string, displayName: string): TestDevice {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const messagingPair = generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const invitation = decodeInvitation(createInvitation(db, {
    host: "127.0.0.1",
    port: 443,
    serverFingerprint: fingerprint,
  }));
  const challenge = createEnrollmentChallenge(db, invitation, pair.publicKey, fingerprint);
  const signature = sign(null, enrollmentSigningTranscript({
    serverFingerprint: fingerprint,
    invitationId: invitation.invitationId,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messagingPair.publicKey,
  }), pair.privateKey).toString("base64url");
  const device = enrollDevice(db, {
    invitation,
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messagingPair.publicKey,
    signature,
  });
  expect(approveDevice(db, device.fingerprint)).toBeTrue();
  return {
    id: device.id,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    messagingPrivateKey: messagingPair.privateKey,
    messagingPublicKey: messagingPair.publicKey,
  };
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

async function connect(
  port: number,
  device: TestDevice,
  serverFingerprint: string,
  announceAgentReady = true,
): Promise<WebSocket> {
  const socket = new WebSocket(
    `wss://127.0.0.1:${port}/v1/connect`,
    { tls: { rejectUnauthorized: false } } as never,
  );
  sockets.push(socket);
  const challenge = await nextFrame(socket, "auth.challenge");
  const requestId = randomUUID();
  const proof = sign(
    null,
    websocketAuthTranscript({
      serverFingerprint,
      deviceId: device.id,
      requestId,
      challenge: String(challenge.challenge),
    }),
    device.privateKey,
  ).toString("base64url");
  const authenticated = nextFrame(socket, "auth.ok");
  socket.send(JSON.stringify({
    version: 1,
    type: "auth.response",
    requestId,
    deviceId: device.id,
    signature: proof,
  }));
  await authenticated;
  if (announceAgentReady) {
    socket.send(JSON.stringify({
      version: 1,
      type: "agent.ready",
      requestId: randomUUID(),
    }));
  }
  return socket;
}

describe("authenticated WSS collaboration", () => {
  test("two members share authoritative chat order and recover history by cursor", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-collaboration-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const project = createProject(db, "Nocturne Launcher", stephen.id);
    addProjectMember(db, project.id, stephen.id, kai.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    registerAgent(db, {
      id: "local-codex",
      projectId: project.id,
      hostDeviceId: stephen.id,
      name: "Stephen's Codex",
    });
    registerAgent(db, {
      id: "kai-codex",
      projectId: project.id,
      hostDeviceId: kai.id,
      name: "Kai's Codex",
    });

    const stephenSocket = await connect(server.port, stephen, fingerprint);
    const kaiSocket = await connect(server.port, kai, fingerprint);
    for (const socket of [stephenSocket, kaiSocket]) {
      const history = nextFrame(socket, "chat.snapshot");
      socket.send(JSON.stringify({
        version: 1,
        type: "chat.subscribe",
        requestId: randomUUID(),
        projectId: project.id,
        afterSequence: 0,
      }));
      expect((await history).events).toEqual([]);
    }

    const kaiEventId = randomUUID();
    const kaiAtStephen = nextFrame(stephenSocket, "chat.event");
    const kaiAtKai = nextFrame(kaiSocket, "chat.event");
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "chat.send",
      requestId: randomUUID(),
      projectId: project.id,
      eventId: kaiEventId,
      content: "Please inspect authentication.",
      clientCreatedAt: new Date().toISOString(),
    }));
    const first = (await kaiAtKai).event as ChatEvent;
    expect((await kaiAtStephen).event).toEqual(first);

    const stephenAtStephen = nextFrame(stephenSocket, "chat.event");
    const stephenAtKai = nextFrame(kaiSocket, "chat.event");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "chat.send",
      requestId: randomUUID(),
      projectId: project.id,
      eventId: randomUUID(),
      content: "I will review the result.",
      clientCreatedAt: new Date().toISOString(),
    }));
    const second = (await stephenAtStephen).event as ChatEvent;
    expect((await stephenAtKai).event).toEqual(second);
    expect(second.sequence).toBeGreaterThan(first.sequence);

    const privatePlaintext = "Stephen-only recovery phrase";
    const privateMessageId = randomUUID();
    const privateCreatedAt = new Date().toISOString();
    const privateCiphertext = await sealSignedPrivateMessage({
      messageId: privateMessageId,
      senderDeviceId: kai.id,
      recipientDeviceId: stephen.id,
      text: privatePlaintext,
      clientCreatedAt: privateCreatedAt,
    }, kai.privateKey, kai.publicKey, stephen.messagingPublicKey);
    const privateAtStephen = nextFrame(stephenSocket, "private.message");
    const privateAccepted = nextFrame(kaiSocket, "private.accepted");
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "private.send",
      requestId: randomUUID(),
      messageId: privateMessageId,
      recipientDeviceId: stephen.id,
      ciphertext: privateCiphertext,
      clientCreatedAt: privateCreatedAt,
    }));
    const privateEnvelope = (await privateAtStephen).message as {
      messageId: string; senderDeviceId: string; recipientDeviceId: string;
      ciphertext: string; clientCreatedAt: string;
    };
    expect((await privateAccepted).message).toEqual(expect.objectContaining({
      senderDeviceId: kai.id,
      recipientDeviceId: stephen.id,
    }));
    expect((await openSignedPrivateMessage(
      privateEnvelope.ciphertext,
      stephen.messagingPrivateKey,
      stephen.messagingPublicKey,
      privateEnvelope,
      publicKeyFingerprint(kai.publicKey),
    )).text).toBe(privatePlaintext);
    const storedPrivate = db.query("SELECT ciphertext FROM private_messages").get() as { ciphertext: string };
    expect(storedPrivate.ciphertext).toBe(privateCiphertext);
    expect(storedPrivate.ciphertext).not.toContain(privatePlaintext);
    expect(db.query("SELECT 1 FROM chat_events WHERE content = ?").get(privatePlaintext)).toBeNull();

    kaiSocket.close();
    const reconnectedKai = await connect(server.port, kai, fingerprint);
    const recoveredPrivate = nextFrame(reconnectedKai, "private.snapshot");
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "private.subscribe",
      requestId: randomUUID(),
      afterSequence: 0,
    }));
    expect((await recoveredPrivate).messages).toEqual([
      expect.objectContaining({ ciphertext: privateCiphertext }),
    ]);
    const recovered = nextFrame(reconnectedKai, "chat.snapshot");
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "chat.subscribe",
      requestId: randomUUID(),
      projectId: project.id,
      afterSequence: first.sequence,
    }));
    expect((await recovered).events).toEqual([second]);

    const kaiTaskId = randomUUID();
    const kaiIssuedAt = new Date().toISOString();
    const kaiExpiresAt = new Date(Date.now() + 60_000).toISOString();
    const kaiNonce = randomUUID();
    const kaiSignature = sign(null, agentRequestSigningTranscript({
      taskId: kaiTaskId,
      projectId: project.id,
      agentId: "local-codex",
      prompt: "Inspect authentication.",
      nonce: kaiNonce,
      issuedAt: kaiIssuedAt,
      expiresAt: kaiExpiresAt,
    }), kai.privateKey).toString("base64url");
    const taskAtStephen = nextFrame(stephenSocket, "agent.task");
    const acceptedAtKai = nextFrame(reconnectedKai, "agent.accepted");
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "agent.request",
      requestId: randomUUID(),
      taskId: kaiTaskId,
      projectId: project.id,
      agentId: "local-codex",
      prompt: "Inspect authentication.",
      nonce: kaiNonce,
      issuedAt: kaiIssuedAt,
      expiresAt: kaiExpiresAt,
      signature: kaiSignature,
    }));
    expect((await taskAtStephen).task).toMatchObject({
      id: kaiTaskId,
      requesterDeviceId: kai.id,
      targetDeviceId: stephen.id,
    });
    expect((await acceptedAtKai).task).toMatchObject({ id: kaiTaskId, status: "queued" });
    const resultAtKai = nextFrame(reconnectedKai, "agent.result");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.result",
      requestId: randomUUID(),
      taskId: kaiTaskId,
      eventId: randomUUID(),
      content: "Authentication inspection complete.",
      final: true,
      status: "completed",
    }));
    expect(await resultAtKai).toMatchObject({
      taskId: kaiTaskId,
      final: true,
      status: "completed",
      event: { senderDeviceId: stephen.id },
    });

    const stephenTaskId = randomUUID();
    const stephenIssuedAt = new Date().toISOString();
    const stephenExpiresAt = new Date(Date.now() + 1_500).toISOString();
    const stephenNonce = randomUUID();
    const stephenSignature = sign(null, agentRequestSigningTranscript({
      taskId: stephenTaskId,
      projectId: project.id,
      agentId: "kai-codex",
      prompt: "Run the reciprocal check.",
      nonce: stephenNonce,
      issuedAt: stephenIssuedAt,
      expiresAt: stephenExpiresAt,
    }), stephen.privateKey).toString("base64url");
    const taskAtKai = nextFrame(reconnectedKai, "agent.task");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.request",
      requestId: randomUUID(),
      taskId: stephenTaskId,
      projectId: project.id,
      agentId: "kai-codex",
      prompt: "Run the reciprocal check.",
      nonce: stephenNonce,
      issuedAt: stephenIssuedAt,
      expiresAt: stephenExpiresAt,
      signature: stephenSignature,
    }));
    expect((await taskAtKai).task).toMatchObject({
      id: stephenTaskId,
      requesterDeviceId: stephen.id,
      targetDeviceId: kai.id,
    });
    const partialAtStephen = nextFrame(stephenSocket, "agent.result");
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "agent.result",
      requestId: randomUUID(),
      taskId: stephenTaskId,
      eventId: randomUUID(),
      content: "Reciprocal check began.",
      final: false,
      status: "running",
    }));
    expect(await partialAtStephen).toMatchObject({
      taskId: stephenTaskId,
      final: false,
      status: "running",
    });
    await Bun.sleep(1_600);

    for (const socket of sockets.splice(0)) socket.close();
    await Bun.sleep(25);
    const originalPort = server.port;
    expect(servers.pop()).toBe(server);
    await server.stop(true);
    expect(databases.pop()).toBe(db);
    db.close();

    const restartedDb = openDatabase(paths.database);
    databases.push(restartedDb);
    config.port = originalPort;
    const restartedServer = startCoCodexServer(config, restartedDb, identity);
    servers.push(restartedServer);
    const restartedStephen = await connect(restartedServer.port, stephen, fingerprint);
    const restartedKai = await connect(restartedServer.port, kai, fingerprint, false);
    const recoveredRunningTask = nextFrame(restartedKai, "agent.task");
    restartedKai.send(JSON.stringify({
      version: 1,
      type: "agent.ready",
      requestId: randomUUID(),
    }));
    expect((await recoveredRunningTask).task).toMatchObject({
      id: stephenTaskId,
      status: "running",
      targetDeviceId: kai.id,
    });
    const restartedChat = nextFrame(restartedKai, "chat.snapshot");
    restartedKai.send(JSON.stringify({
      version: 1,
      type: "chat.subscribe",
      requestId: randomUUID(),
      projectId: project.id,
      afterSequence: 0,
    }));
    expect(((await restartedChat).events as ChatEvent[]).map(event => event.sequence))
      .toEqual([first.sequence, second.sequence, expect.any(Number), expect.any(Number)]);
    const restartedPrivate = nextFrame(restartedStephen, "private.snapshot");
    restartedStephen.send(JSON.stringify({
      version: 1,
      type: "private.subscribe",
      requestId: randomUUID(),
      afterSequence: 0,
    }));
    expect((await restartedPrivate).messages).toEqual([
      expect.objectContaining({ ciphertext: privateCiphertext }),
    ]);

    const expiringTaskId = randomUUID();
    const expiringIssuedAt = new Date().toISOString();
    const expiringExpiresAt = new Date(Date.now() + 250).toISOString();
    const expiringNonce = randomUUID();
    const expiringSignature = sign(null, agentRequestSigningTranscript({
      taskId: expiringTaskId,
      projectId: project.id,
      agentId: "kai-codex",
      prompt: "This request should expire before execution.",
      nonce: expiringNonce,
      issuedAt: expiringIssuedAt,
      expiresAt: expiringExpiresAt,
    }), stephen.privateKey).toString("base64url");
    const expiringAtKai = nextFrame(restartedKai, "agent.task");
    restartedStephen.send(JSON.stringify({
      version: 1,
      type: "agent.request",
      requestId: randomUUID(),
      taskId: expiringTaskId,
      projectId: project.id,
      agentId: "kai-codex",
      prompt: "This request should expire before execution.",
      nonce: expiringNonce,
      issuedAt: expiringIssuedAt,
      expiresAt: expiringExpiresAt,
      signature: expiringSignature,
    }));
    expect((await expiringAtKai).task).toMatchObject({ id: expiringTaskId, status: "queued" });
    await Bun.sleep(300);
    const expiredAtKai = nextFrame(restartedKai, "agent.result", frame => frame.taskId === expiringTaskId);
    restartedStephen.send(JSON.stringify({
      version: 1,
      type: "project.list",
      requestId: randomUUID(),
    }));
    expect(await expiredAtKai).toMatchObject({
      taskId: expiringTaskId,
      final: true,
      status: "failed",
      event: { content: "Agent request expired before the host client accepted it." },
    });
  }, 15_000);
});

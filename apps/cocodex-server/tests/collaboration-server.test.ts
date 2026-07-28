import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "bun:sqlite";
import * as Y from "yjs";
import {
  agentDefinitionSigningTranscript,
  agentRequestSigningTranscript,
  createDeviceKeyCertificate,
  decodeInvitation,
  enrollmentSigningTranscript,
  usageReportSigningTranscript,
  websocketAuthTranscript,
  type ChatEvent,
  type UsageReport,
  publicKeyFingerprint,
  projectLockSigningTranscript,
  sharedChatCreationSigningTranscript,
} from "@cocodex/protocol";
import { registerAgent } from "../src/agent-routing";
import { createDefaultConfig } from "../src/config";
import { openDatabase } from "../src/database";
import { createEnrollmentChallenge, enrollDevice, revokeDevice } from "../src/enrollment";
import {
  approvePendingDeviceForTest,
  testServerIdentityFingerprint,
} from "./device-approval-fixture";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { addProjectMember, createProject } from "../src/shared-state";
import { startCoCodexServer } from "../src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "../../../src/cocodex/private-messaging";

const roots: string[] = [];
const deferredRoots: string[] = [];
const servers: Array<{ stop(force?: boolean): Promise<void> }> = [];
const databases: Database[] = [];
const sockets: WebSocket[] = [];
const DEFAULT_AGENT_RUNTIME = {
  primaryModel: "gpt-5.6-sol",
  primaryEffort: "medium",
  coAgentModel: null,
  coAgentEffort: null,
  maxConcurrentCoAgents: 0,
} as const;

afterEach(async () => {
  await Promise.all(sockets.splice(0).map(async socket => {
    if (socket.readyState === WebSocket.CLOSED) return;
    const closed = new Promise<void>(resolve => {
      socket.addEventListener("close", () => resolve(), { once: true });
    });
    socket.close();
    await Promise.race([closed, Bun.sleep(500)]);
  }));
  await Promise.all(servers.splice(0).map(server => server.stop(true)));
  for (const database of databases.splice(0)) database.close();

  Bun.gc(true);
  for (const root of roots.splice(0)) {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 99) {
          deferredRoots.push(root);
          break;
        }
        await Bun.sleep(50);
      }
    }
  }
}, 15_000);

afterAll(async () => {
  Bun.gc(true);
  for (const root of deferredRoots.splice(0)) {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 99) throw error;
        await Bun.sleep(50);
      }
    }
  }
}, 15_000);

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
    expectedServerFingerprint: invitation.serverFingerprint,
    serverIdentityFingerprint: testServerIdentityFingerprint(db),
    challengeId: challenge.id,
    challenge: challenge.challenge,
    displayName,
    devicePublicKeyPem: pair.publicKey,
    messagingPublicKeyPem: messagingPair.publicKey,
    signature,
  });
  approvePendingDeviceForTest(db, device, pair.privateKey, invitation.serverFingerprint);
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
      if (frame.type === "error" && expectedType !== "error") {
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
  agentId?: string,
  receivedFrames?: Array<Record<string, unknown>>,
): Promise<WebSocket> {
  const socket = new WebSocket(
    `wss://127.0.0.1:${port}/v1/connect`,
    { tls: { rejectUnauthorized: false } } as never,
  );
  if (receivedFrames) {
    socket.addEventListener("message", event => {
      receivedFrames.push(JSON.parse(String(event.data)) as Record<string, unknown>);
    });
  }
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
      ...(agentId ? { agentId } : {}),
    }));
  }
  return socket;
}

async function waitForCollectedFrame(
  frames: Array<Record<string, unknown>>,
  expectedType: string,
  timeoutMs = 3_000,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  do {
    const frame = frames.find(candidate => candidate.type === expectedType);
    if (frame) return frame;
    await Bun.sleep(10);
  } while (Date.now() < deadline);
  throw new Error(`Timed out waiting for collected ${expectedType}`);
}

function usageReport(deviceId: string, revision = 1): UsageReport {
  return {
    version: 1,
    deviceId,
    revision,
    updatedAt: new Date().toISOString(),
    requests: revision,
    inputTokens: 100 * revision,
    cachedInputTokens: 20 * revision,
    outputTokens: 50 * revision,
    reasoningOutputTokens: 5 * revision,
    activeAgents: revision,
    accountLabel: "Main",
    fiveHourPercent: 68,
    weeklyPercent: 41,
    monthlyPercent: 75,
  };
}

describe("authenticated WSS collaboration", () => {
  test("enforces signed owner project lock across real WSS and server restart", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-project-lock-wss-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const project = createProject(db, "Incident control", stephen.id);
    addProjectMember(db, project.id, stephen.id, kai.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    let server = startCoCodexServer(config, db, identity);
    servers.push(server);
    const stephenFrames: Array<Record<string, unknown>> = [];
    const kaiFrames: Array<Record<string, unknown>> = [];
    const stephenSocket = await connect(server.port, stephen, fingerprint, false, undefined, stephenFrames);
    const kaiSocket = await connect(server.port, kai, fingerprint, false, undefined, kaiFrames);

    const makeUpdate = (
      device: TestDevice,
      action: "lock" | "unlock",
      expectedRevision: number,
      reason: string,
    ) => {
      const issuedAt = new Date().toISOString();
      const unsigned = {
        version: 1 as const,
        operationId: randomUUID(),
        projectId: project.id,
        action,
        expectedRevision,
        reason,
        serverFingerprint: fingerprint,
        serverEpoch: 1,
        issuedAt,
        expiresAt: new Date(Date.now() + 120_000).toISOString(),
        nonce: randomBytes(32).toString("base64url"),
      };
      return {
        ...unsigned,
        type: "project.lock.update",
        requestId: randomUUID(),
        signature: sign(null, projectLockSigningTranscript(unsigned), device.privateKey).toString("base64url"),
      };
    };

    const rejected = nextFrame(kaiSocket, "error");
    kaiSocket.send(JSON.stringify(makeUpdate(kai, "lock", 0, "Member cannot lock")));
    expect(String((await rejected).error)).toContain("owner");

    const ownerAccepted = nextFrame(stephenSocket, "project.lock.updated");
    stephenSocket.send(JSON.stringify(makeUpdate(stephen, "lock", 0, "Security review")));
    expect(await ownerAccepted).toMatchObject({
      created: true,
      transition: {
        projectId: project.id,
        action: "lock",
        state: { state: "locked", revision: 1, reason: "Security review" },
      },
    });
    expect(await waitForCollectedFrame(kaiFrames, "project.lock.changed")).toMatchObject({
      transition: { projectId: project.id, state: { state: "locked", revision: 1 } },
    });
    const blocked = nextFrame(kaiSocket, "error");
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "chat.send",
      requestId: randomUUID(),
      projectId: project.id,
      eventId: randomUUID(),
      content: "Must not persist",
      clientCreatedAt: new Date().toISOString(),
    }));
    expect(String((await blocked).error)).toContain("PROJECT_LOCKED");
    expect(db.query("SELECT COUNT(*) AS count FROM chat_events WHERE project_id = ?").get(project.id))
      .toEqual({ count: 0 });

    await server.stop(true);
    servers.splice(servers.indexOf(server), 1);
    server = startCoCodexServer(config, db, identity);
    servers.push(server);
    const recovered = await connect(server.port, stephen, fingerprint, false);
    const listed = nextFrame(recovered, "project.list.result");
    recovered.send(JSON.stringify({ version: 1, type: "project.list", requestId: randomUUID() }));
    expect(await listed).toMatchObject({
      projects: [{
        id: project.id,
        lock: { state: "locked", revision: 1, reason: "Security review" },
      }],
    });
    const unlocked = nextFrame(recovered, "project.lock.updated");
    recovered.send(JSON.stringify(makeUpdate(stephen, "unlock", 1, "Review complete")));
    expect(await unlocked).toMatchObject({
      transition: { action: "unlock", state: { state: "active", revision: 2 } },
    });
  });

  test("discovers only verified approved private contacts and removes revoked peers", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-private-contacts-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);
    const stephenSocket = await connect(server.port, stephen, fingerprint, false);
    const kaiSocket = await connect(server.port, kai, fingerprint, false);
    const stephenCertificate = createDeviceKeyCertificate(stephen.id, {
      publicKeyPem: stephen.publicKey,
      privateKeyPem: stephen.privateKey,
      messagingPublicKeyPem: stephen.messagingPublicKey,
    });
    const kaiCertificate = createDeviceKeyCertificate(kai.id, {
      publicKeyPem: kai.publicKey,
      privateKeyPem: kai.privateKey,
      messagingPublicKeyPem: kai.messagingPublicKey,
    });
    const stephenSeesKai = nextFrame(stephenSocket, "private.contact.snapshot", frame =>
      (frame.contacts as Array<Record<string, unknown>>)?.some(contact => contact.deviceId === kai.id));
    const kaiSeesStephen = nextFrame(kaiSocket, "private.contact.snapshot", frame =>
      (frame.contacts as Array<Record<string, unknown>>)?.some(contact => contact.deviceId === stephen.id));
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "device.key-certificate.publish",
      requestId: randomUUID(),
      certificate: stephenCertificate,
    }));
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "device.key-certificate.publish",
      requestId: randomUUID(),
      certificate: kaiCertificate,
    }));
    expect((await stephenSeesKai).contacts).toEqual([expect.objectContaining({
      deviceId: kai.id,
      displayName: "Kai",
      fingerprint: publicKeyFingerprint(kai.publicKey),
      deviceKeyCertificate: kaiCertificate,
    })]);
    expect((await kaiSeesStephen).contacts).toEqual([expect.objectContaining({
      deviceId: stephen.id,
      displayName: "Stephen",
      fingerprint: publicKeyFingerprint(stephen.publicKey),
      deviceKeyCertificate: stephenCertificate,
    })]);

    await Bun.sleep(1_050);
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "device.key-certificate.publish",
      requestId: randomUUID(),
      certificate: stephenCertificate,
    }));
    const certificateRateLimited = nextFrame(stephenSocket, "error", frame =>
      String(frame.error).includes("publication rate limit"));
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "device.key-certificate.publish",
      requestId: randomUUID(),
      certificate: stephenCertificate,
    }));
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "device.key-certificate.publish",
      requestId: randomUUID(),
      certificate: stephenCertificate,
    }));
    expect((await certificateRateLimited).error).toContain("publication rate limit");

    const requestId = randomUUID();
    const explicit = nextFrame(stephenSocket, "private.contact.snapshot", frame =>
      frame.requestId === requestId);
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "private.contact.list",
      requestId,
    }));
    expect((await explicit).contacts).toHaveLength(1);

    const removed = nextFrame(stephenSocket, "private.contact.snapshot", frame =>
      Array.isArray(frame.contacts) && frame.contacts.length === 0);
    const kaiClosed = new Promise<CloseEvent>(resolve =>
      kaiSocket.addEventListener("close", event => resolve(event), { once: true }));
    expect(revokeDevice(db, publicKeyFingerprint(kai.publicKey))).toBeTrue();
    const [removedSnapshot, revokedClose] = await Promise.all([removed, kaiClosed]);
    expect(removedSnapshot.contacts).toEqual([]);
    expect(revokedClose.code).toBe(1008);
  });

  test("creates a signed self-hosted agent over WSS and rejects spoofed authority", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-setup-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const outsider = approvedDevice(db, fingerprint, "Outsider");
    const project = createProject(db, "Agent setup", stephen.id);
    addProjectMember(db, project.id, stephen.id, kai.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);
    const stephenSocket = await connect(server.port, stephen, fingerprint, false);
    const outsiderSocket = await connect(server.port, outsider, fingerprint, false);
    const agentId = randomUUID();
    const name = "Lucas";
    const requestId = randomUUID();
    const definition = {
      projectId: project.id,
      agentId,
      name,
      hostDeviceId: stephen.id,
      ...DEFAULT_AGENT_RUNTIME,
    };
    const created = nextFrame(stephenSocket, "agent.created");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.create",
      requestId,
      projectId: project.id,
      agentId,
      name,
      ...DEFAULT_AGENT_RUNTIME,
      signature: sign(null, agentDefinitionSigningTranscript(definition), stephen.privateKey).toString("base64url"),
    }));
    expect(await created).toMatchObject({
      requestId,
      projectId: project.id,
      created: true,
      agent: { id: agentId, hostDeviceId: stephen.id, name },
    });
    const replay = nextFrame(stephenSocket, "agent.created");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.create",
      requestId: randomUUID(),
      projectId: project.id,
      agentId,
      name,
      ...DEFAULT_AGENT_RUNTIME,
      signature: sign(null, agentDefinitionSigningTranscript(definition), stephen.privateKey).toString("base64url"),
    }));
    expect((await replay).created).toBeFalse();
    const outsiderError = nextFrame(outsiderSocket, "agent.created");
    const outsiderAgentId = randomUUID();
    outsiderSocket.send(JSON.stringify({
      version: 1,
      type: "agent.create",
      requestId: randomUUID(),
      projectId: project.id,
      agentId: outsiderAgentId,
      name: "Imposter",
      ...DEFAULT_AGENT_RUNTIME,
      signature: sign(null, agentDefinitionSigningTranscript({
        projectId: project.id,
        agentId: outsiderAgentId,
        name: "Imposter",
        hostDeviceId: outsider.id,
        ...DEFAULT_AGENT_RUNTIME,
      }), outsider.privateKey).toString("base64url"),
    }));
    await expect(outsiderError).rejects.toThrow("approved project member");
    expect(db.query("SELECT host_device_id AS hostDeviceId FROM agents WHERE id = ?").get(agentId))
      .toEqual({ hostDeviceId: stephen.id });

    const angelaId = randomUUID();
    const angelaRuntime = { ...DEFAULT_AGENT_RUNTIME, primaryEffort: "xhigh" as const };
    const angelaDefinition = {
      projectId: project.id,
      agentId: angelaId,
      name: "Angela",
      hostDeviceId: stephen.id,
      ...angelaRuntime,
    };
    const angelaCreated = nextFrame(stephenSocket, "agent.created");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.create",
      requestId: randomUUID(),
      projectId: project.id,
      agentId: angelaId,
      name: angelaDefinition.name,
      ...angelaRuntime,
      signature: sign(null, agentDefinitionSigningTranscript(angelaDefinition), stephen.privateKey).toString("base64url"),
    }));
    expect((await angelaCreated).created).toBeTrue();
    expect(db.query("SELECT primary_effort AS primaryEffort FROM agents WHERE id = ?").get(angelaId))
      .toEqual({ primaryEffort: "xhigh" });

    const lucasWorker = await connect(server.port, stephen, fingerprint, false);
    const angelaWorker = await connect(server.port, stephen, fingerprint, false);
    const lucasReady = nextFrame(lucasWorker, "agent.ready.accepted");
    lucasWorker.send(JSON.stringify({
      version: 1,
      type: "agent.ready",
      requestId: randomUUID(),
      agentId,
    }));
    expect(await lucasReady).toMatchObject({ agentId });
    const angelaReady = nextFrame(angelaWorker, "agent.ready.accepted");
    angelaWorker.send(JSON.stringify({
      version: 1,
      type: "agent.ready",
      requestId: randomUUID(),
      agentId: angelaId,
      ...angelaRuntime,
    }));
    expect(await angelaReady).toMatchObject({ agentId: angelaId });

    const kaiSocket = await connect(server.port, kai, fingerprint, false);
    const taskId = randomUUID();
    const nonce = randomUUID();
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const prompt = "Prove worker result binding.";
    const taskAtLucas = nextFrame(lucasWorker, "agent.task");
    const acceptedAtKai = nextFrame(kaiSocket, "agent.accepted");
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "agent.request",
      requestId: randomUUID(),
      taskId,
      projectId: project.id,
      chatId: project.id,
      agentId,
      prompt,
      nonce,
      issuedAt,
      expiresAt,
      signature: sign(null, agentRequestSigningTranscript({
        taskId,
        projectId: project.id,
        chatId: project.id,
        agentId,
        prompt,
        nonce,
        issuedAt,
        expiresAt,
      }), kai.privateKey).toString("base64url"),
    }));
    await Promise.all([taskAtLucas, acceptedAtKai]);
    const spoofRejected = nextFrame(angelaWorker, "agent.result.accepted");
    angelaWorker.send(JSON.stringify({
      version: 1,
      type: "agent.result",
      requestId: randomUUID(),
      taskId,
      eventId: randomUUID(),
      content: "Wrong worker",
      final: true,
      status: "completed",
    }));
    await expect(spoofRejected).rejects.toThrow("matching ready worker lease");

    const correctResult = nextFrame(lucasWorker, "agent.result.accepted");
    lucasWorker.send(JSON.stringify({
      version: 1,
      type: "agent.result",
      requestId: randomUUID(),
      taskId,
      eventId: randomUUID(),
      content: "Correct worker",
      final: true,
      status: "completed",
    }));
    expect(await correctResult).toMatchObject({ taskId, sequence: 1 });
  });

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
    const agentRoster = nextFrame(stephenSocket, "agent.list.result");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.list",
      requestId: randomUUID(),
      projectId: project.id,
    }));
    const listedAgents = (await agentRoster).agents as Array<Record<string, unknown>>;
    expect(listedAgents).toHaveLength(2);
    expect(listedAgents).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "local-codex", name: "Stephen's Codex", hostDisplayName: "Stephen", status: "available" }),
      expect.objectContaining({ id: "kai-codex", name: "Kai's Codex", hostDisplayName: "Kai", status: "available" }),
    ]));
    const emptyTaskList = nextFrame(stephenSocket, "agent.task.list.result");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.task.list",
      requestId: randomUUID(),
      projectId: project.id,
      chatId: project.id,
    }));
    expect((await emptyTaskList).tasks).toEqual([]);
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

    const contextRequestId = randomUUID();
    const initialContext = nextFrame(stephenSocket, "context.result");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "context.get",
      requestId: contextRequestId,
      projectId: project.id,
    }));
    expect(await initialContext).toMatchObject({
      requestId: contextRequestId,
      context: {
        projectId: project.id,
        finalGoal: "",
        context: {},
        revision: 0,
      },
    });

    const contextChangedAtStephen = nextFrame(stephenSocket, "context.changed");
    const contextChangedAtKai = nextFrame(kaiSocket, "context.changed");
    const contextUpdatedAtKai = nextFrame(kaiSocket, "context.updated");
    const contextUpdateRequestId = randomUUID();
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "context.update",
      requestId: contextUpdateRequestId,
      projectId: project.id,
      expectedRevision: 0,
      finalGoal: "Build the private alpha",
      context: { acceptance: ["enrollment", "reconnect"], owner: "Stephen" },
    }));
    expect(await contextUpdatedAtKai).toMatchObject({
      requestId: contextUpdateRequestId,
      context: {
        projectId: project.id,
        finalGoal: "Build the private alpha",
        context: { acceptance: ["enrollment", "reconnect"], owner: "Stephen" },
        revision: 1,
        updatedByDeviceId: kai.id,
      },
    });
    expect((await contextChangedAtStephen).context).toMatchObject({ revision: 1, updatedByDeviceId: kai.id });
    expect((await contextChangedAtKai).context).toMatchObject({ revision: 1, updatedByDeviceId: kai.id });

    const usageResultAtStephen = nextFrame(stephenSocket, "usage.result");
    const usageResultAtKai = nextFrame(kaiSocket, "usage.result");
    for (const socket of [stephenSocket, kaiSocket]) {
      socket.send(JSON.stringify({
        version: 1,
        type: "usage.get",
        requestId: randomUUID(),
        projectId: project.id,
      }));
    }
    expect((await usageResultAtStephen).reports).toEqual([
      expect.objectContaining({ deviceId: stephen.id, displayName: "Stephen", report: null }),
      expect.objectContaining({ deviceId: kai.id, displayName: "Kai", report: null }),
    ]);
    expect((await usageResultAtKai).reports).toEqual([
      expect.objectContaining({ deviceId: stephen.id, displayName: "Stephen", report: null }),
      expect.objectContaining({ deviceId: kai.id, displayName: "Kai", report: null }),
    ]);
    const stephenUsage = usageReport(stephen.id);
    const usageChangedAtStephen = nextFrame(stephenSocket, "usage.changed");
    const usageChangedAtKai = nextFrame(kaiSocket, "usage.changed");
    const usageAccepted = nextFrame(stephenSocket, "usage.accepted");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "usage.report",
      requestId: randomUUID(),
      report: stephenUsage,
      signature: sign(null, usageReportSigningTranscript(stephenUsage), stephen.privateKey).toString("base64url"),
    }));
    expect((await usageAccepted).report).toMatchObject({ deviceId: stephen.id, report: stephenUsage });
    expect((await usageChangedAtStephen).report).toMatchObject({ deviceId: stephen.id, report: stephenUsage });
    expect((await usageChangedAtKai).report).toMatchObject({ deviceId: stephen.id, report: stephenUsage });
    const storedUsage = db.query("SELECT report_json, report_signature FROM usage_reports WHERE device_id = ?").get(stephen.id) as {
      report_json: string; report_signature: string;
    };
    expect(JSON.parse(storedUsage.report_json)).toEqual(stephenUsage);
    expect(storedUsage.report_signature).toBeString();

    const privateRowsBeforeTyping = db.query("SELECT COUNT(*) AS count FROM private_messages").get();
    const typingAtStephen = nextFrame(stephenSocket, "private.typing");
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "private.typing.send",
      requestId: randomUUID(),
      recipientDeviceId: stephen.id,
      typing: true,
    }));
    expect(await typingAtStephen).toMatchObject({
      senderDeviceId: kai.id,
      recipientDeviceId: stephen.id,
      typing: true,
    });
    expect(db.query("SELECT COUNT(*) AS count FROM private_messages").get()).toEqual(privateRowsBeforeTyping);

    const stoppedTypingAtStephen = nextFrame(stephenSocket, "private.typing");
    kaiSocket.send(JSON.stringify({
      version: 1,
      type: "private.typing.send",
      requestId: randomUUID(),
      recipientDeviceId: stephen.id,
      typing: false,
    }));
    expect(await stoppedTypingAtStephen).toMatchObject({ senderDeviceId: kai.id, typing: false });

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

    const deliveredReceiptAtStephen = nextFrame(stephenSocket, "private.receipt.accepted");
    const deliveredReceiptAtKai = nextFrame(kaiSocket, "private.receipt", frame =>
      (frame.receipt as Record<string, unknown>)?.messageId === privateMessageId,
    );
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "private.receipt.send",
      requestId: randomUUID(),
      messageId: privateMessageId,
      receipt: "delivered",
    }));
    const deliveredFrame = await deliveredReceiptAtStephen;
    expect(deliveredFrame.receipt).toMatchObject({
      messageId: privateMessageId,
      senderDeviceId: kai.id,
      recipientDeviceId: stephen.id,
      receipt: "delivered",
    });
    expect((await deliveredReceiptAtKai).receipt).toMatchObject({ receipt: "delivered" });

    const readReceiptAtKai = nextFrame(kaiSocket, "private.receipt", frame =>
      (frame.receipt as Record<string, unknown>)?.messageId === privateMessageId
        && (frame.receipt as Record<string, unknown>)?.receipt === "read",
    );
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "private.receipt.send",
      requestId: randomUUID(),
      messageId: privateMessageId,
      receipt: "read",
    }));
    expect((await readReceiptAtKai).receipt).toMatchObject({ receipt: "read" });
    expect(db.query("SELECT COUNT(*) AS count FROM private_message_receipts").get()).toEqual({ count: 2 });
    expect(db.query("SELECT ciphertext FROM private_messages WHERE message_id = ?").get(privateMessageId)).toEqual({ ciphertext: privateCiphertext });

    kaiSocket.close();
    const reconnectedKai = await connect(server.port, kai, fingerprint);
    const recoveredUsage = nextFrame(reconnectedKai, "usage.result");
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "usage.get",
      requestId: randomUUID(),
      projectId: project.id,
    }));
    expect((await recoveredUsage).reports).toEqual([
      expect.objectContaining({ deviceId: stephen.id, report: stephenUsage }),
      expect.objectContaining({ deviceId: kai.id, report: null }),
    ]);
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
    expect((await recoveredPrivate).receipts).toEqual([
      expect.objectContaining({ messageId: privateMessageId, receipt: "delivered" }),
      expect.objectContaining({ messageId: privateMessageId, receipt: "read" }),
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
      chatId: project.id,
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
      chatId: project.id,
      agentId: "local-codex",
      prompt: "Inspect authentication.",
      nonce: kaiNonce,
      issuedAt: kaiIssuedAt,
      expiresAt: kaiExpiresAt,
      signature: kaiSignature,
    }));
    expect((await taskAtStephen).task).toMatchObject({
      id: kaiTaskId,
      chatId: project.id,
      requesterDeviceId: kai.id,
      targetDeviceId: stephen.id,
    });
    expect((await acceptedAtKai).task).toMatchObject({
      id: kaiTaskId,
      chatId: project.id,
      status: "queued",
    });
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
    const completedTaskList = nextFrame(stephenSocket, "agent.task.list.result");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "agent.task.list", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
    }));
    expect((await completedTaskList).tasks).toEqual([expect.objectContaining({
      id: kaiTaskId,
      chatId: project.id,
      agentName: "Stephen's Codex",
      status: "completed",
      dependencies: [],
      eventCount: 1,
      encrypted: false,
    })]);

    const artifactId = randomUUID();
    const artifactAccepted = nextFrame(stephenSocket, "artifact.accepted");
    const artifactAtKai = nextFrame(reconnectedKai, "artifact.published");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "artifact.publish",
      requestId: randomUUID(),
      artifactId,
      projectId: project.id,
      taskId: kaiTaskId,
      artifactType: "finding",
      title: "Authentication finding",
      summary: "The refresh token is not persisted after rotation.",
      content: "Persist the rotated token before returning the response.",
      status: "ready",
    }));
    expect((await artifactAccepted).artifact).toMatchObject({ id: artifactId, taskId: kaiTaskId, authorDeviceId: stephen.id });
    expect((await artifactAtKai).artifact).toMatchObject({ id: artifactId, status: "ready" });
    const artifactList = nextFrame(reconnectedKai, "artifact.list.result");
    reconnectedKai.send(JSON.stringify({
      version: 1, type: "artifact.list", requestId: randomUUID(), projectId: project.id,
    }));
    expect((await artifactList).artifacts).toEqual([
      expect.objectContaining({ id: artifactId, content: "Persist the rotated token before returning the response." }),
    ]);
    const stephenTaskId = randomUUID();
    const stephenIssuedAt = new Date().toISOString();
    const stephenExpiresAt = new Date(Date.now() + 1_500).toISOString();
    const stephenNonce = randomUUID();
    const stephenSignature = sign(null, agentRequestSigningTranscript({
      taskId: stephenTaskId,
      projectId: project.id,
      chatId: project.id,
      agentId: "kai-codex",
      prompt: "Run the reciprocal check.",
      nonce: stephenNonce,
      issuedAt: stephenIssuedAt,
      expiresAt: stephenExpiresAt,
      dependencies: [kaiTaskId],
    }), stephen.privateKey).toString("base64url");
    const taskAtKai = nextFrame(reconnectedKai, "agent.task");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.request",
      requestId: randomUUID(),
      taskId: stephenTaskId,
      projectId: project.id,
      chatId: project.id,
      agentId: "kai-codex",
      prompt: "Run the reciprocal check.",
      nonce: stephenNonce,
      issuedAt: stephenIssuedAt,
      expiresAt: stephenExpiresAt,
      dependencies: [kaiTaskId],
      signature: stephenSignature,
    }));
    expect((await taskAtKai).task).toMatchObject({
      id: stephenTaskId,
      chatId: project.id,
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
    const runningTaskList = nextFrame(stephenSocket, "agent.task.list.result");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "agent.task.list", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
    }));
    expect((await runningTaskList).tasks).toEqual(expect.arrayContaining([expect.objectContaining({
      id: stephenTaskId,
      chatId: project.id,
      status: "running",
      dependencies: [kaiTaskId],
      eventCount: 1,
    })]));

    const promptAtStephen = nextFrame(stephenSocket, "prompt.snapshot");
    const promptAtKai = nextFrame(reconnectedKai, "prompt.snapshot");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "prompt.subscribe", requestId: randomUUID(), projectId: project.id,
    }));
    reconnectedKai.send(JSON.stringify({
      version: 1, type: "prompt.subscribe", requestId: randomUUID(), projectId: project.id,
    }));
    const stephenPrompt = new Y.Doc();
    const kaiPrompt = new Y.Doc();
    Y.applyUpdate(stephenPrompt, Buffer.from(String((await promptAtStephen).update), "base64"));
    Y.applyUpdate(kaiPrompt, Buffer.from(String((await promptAtKai).update), "base64"));
    stephenPrompt.getText("prompt").insert(0, "Stephen ");
    kaiPrompt.getText("prompt").insert(0, "Kai ");
    const stephenUpdate = Buffer.from(Y.encodeStateAsUpdate(stephenPrompt)).toString("base64");
    const kaiUpdate = Buffer.from(Y.encodeStateAsUpdate(kaiPrompt)).toString("base64");
    const stephenUpdateId = randomUUID();
    const kaiUpdateId = randomUUID();
    const updates = [
      nextFrame(stephenSocket, "prompt.update", frame => frame.updateId === stephenUpdateId),
      nextFrame(stephenSocket, "prompt.update", frame => frame.updateId === kaiUpdateId),
      nextFrame(reconnectedKai, "prompt.update", frame => frame.updateId === stephenUpdateId),
      nextFrame(reconnectedKai, "prompt.update", frame => frame.updateId === kaiUpdateId),
    ];
    stephenSocket.send(JSON.stringify({
      version: 1, type: "prompt.update", requestId: randomUUID(), projectId: project.id,
      updateId: stephenUpdateId, update: stephenUpdate,
    }));
    reconnectedKai.send(JSON.stringify({
      version: 1, type: "prompt.update", requestId: randomUUID(), projectId: project.id,
      updateId: kaiUpdateId, update: kaiUpdate,
    }));
    await Promise.all(updates);
    Y.applyUpdate(stephenPrompt, Buffer.from(kaiUpdate, "base64"));
    Y.applyUpdate(kaiPrompt, Buffer.from(stephenUpdate, "base64"));
    const sharedPromptText = stephenPrompt.getText("prompt").toString();
    expect(kaiPrompt.getText("prompt").toString()).toBe(sharedPromptText);
    expect(sharedPromptText).toContain("Stephen ");
    expect(sharedPromptText).toContain("Kai ");

    const remotePresence = nextFrame(reconnectedKai, "presence.update", frame => frame.deviceId === stephen.id);
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
      cursor: { x: 0.42, y: 0.73 }, caret: { anchor: 4, head: 9 },
      relativeCaret: { anchor: "AQIDBA==", head: "BQYHCA==" }, typing: true,
    }));
    const presenceUpdate = await remotePresence;
    expect(presenceUpdate.displayName).toBe("Stephen");
    expect(presenceUpdate.cursor).toEqual({ x: 0.42, y: 0.73 });
    expect(presenceUpdate.caret).toEqual({ anchor: 4, head: 9 });
    expect(presenceUpdate.relativeCaret).toEqual({ anchor: "AQIDBA==", head: "BQYHCA==" });
    expect(presenceUpdate.typing).toBe(true);
    const typingOnly = nextFrame(reconnectedKai, "presence.update", frame => frame.deviceId === stephen.id);
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
      cursor: null, caret: null, typing: true,
    }));
    expect(await typingOnly).toMatchObject({
      deviceId: stephen.id, cursor: null, caret: null, typing: true,
    });
    const presenceLeave = nextFrame(reconnectedKai, "presence.leave", frame => frame.deviceId === stephen.id);
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
      cursor: null, caret: null, typing: false,
    }));
    expect(await presenceLeave).toEqual({
      version: 1,
      type: "presence.leave",
      projectId: project.id,
      chatId: project.id,
      deviceId: stephen.id,
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
    const recoveredContext = nextFrame(restartedKai, "context.result");
    restartedKai.send(JSON.stringify({
      version: 1,
      type: "context.get",
      requestId: randomUUID(),
      projectId: project.id,
    }));
    expect((await recoveredContext).context).toMatchObject({
      projectId: project.id,
      finalGoal: "Build the private alpha",
      context: { acceptance: ["enrollment", "reconnect"], owner: "Stephen" },
      revision: 1,
      updatedByDeviceId: kai.id,
    });
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
    const recoveredPrompt = nextFrame(restartedKai, "prompt.snapshot");
    restartedKai.send(JSON.stringify({
      version: 1, type: "prompt.subscribe", requestId: randomUUID(), projectId: project.id,
    }));
    const recoveredPromptDocument = new Y.Doc();
    Y.applyUpdate(recoveredPromptDocument, Buffer.from(String((await recoveredPrompt).update), "base64"));
    expect(recoveredPromptDocument.getText("prompt").toString()).toBe(sharedPromptText);
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
    const restartedStephenChat = nextFrame(restartedStephen, "chat.snapshot");
    restartedStephen.send(JSON.stringify({
      version: 1, type: "chat.subscribe", requestId: randomUUID(), projectId: project.id, afterSequence: 0,
    }));
    await restartedStephenChat;

    const cancelTaskId = randomUUID();
    const cancelIssuedAt = new Date().toISOString();
    const cancelExpiresAt = new Date(Date.now() + 30_000).toISOString();
    const cancelNonce = randomUUID();
    const cancelSignature = sign(null, agentRequestSigningTranscript({
      taskId: cancelTaskId,
      projectId: project.id,
      chatId: project.id,
      agentId: "kai-codex",
      prompt: "This request will be cancelled.",
      nonce: cancelNonce,
      issuedAt: cancelIssuedAt,
      expiresAt: cancelExpiresAt,
    }), stephen.privateKey).toString("base64url");
    const cancellationAtKai = nextFrame(restartedKai, "agent.cancel", frame => frame.taskId === cancelTaskId);
    const cancellationResultAtStephen = nextFrame(restartedStephen, "agent.result", frame => frame.taskId === cancelTaskId);
    restartedStephen.send(JSON.stringify({
      version: 1, type: "agent.request", requestId: randomUUID(), taskId: cancelTaskId,
      projectId: project.id, chatId: project.id, agentId: "kai-codex", prompt: "This request will be cancelled.",
      nonce: cancelNonce, issuedAt: cancelIssuedAt, expiresAt: cancelExpiresAt, signature: cancelSignature,
    }));
    expect((await nextFrame(restartedKai, "agent.task")).task).toMatchObject({ id: cancelTaskId });
    restartedStephen.send(JSON.stringify({
      version: 1, type: "agent.cancel", requestId: randomUUID(), taskId: cancelTaskId,
      reason: "User pressed Stop Agent.",
    }));
    expect(await cancellationAtKai).toMatchObject({ taskId: cancelTaskId, reason: "User pressed Stop Agent." });
    expect(await cancellationResultAtStephen).toMatchObject({
      taskId: cancelTaskId, final: true, status: "failed",
      event: { content: "Agent task cancelled: User pressed Stop Agent." },
    });

    const expiringTaskId = randomUUID();
    const expiringIssuedAt = new Date().toISOString();
    const expiringExpiresAt = new Date(Date.now() + 250).toISOString();
    const expiringNonce = randomUUID();
    const expiringSignature = sign(null, agentRequestSigningTranscript({
      taskId: expiringTaskId,
      projectId: project.id,
      chatId: project.id,
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
      chatId: project.id,
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

  test("paginates 501 chat and private events over the real WSS cursor protocol", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-collaboration-pagination-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const project = createProject(db, "Pagination", stephen.id);
    addProjectMember(db, project.id, stephen.id, kai.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    const stephenSocket = await connect(server.port, stephen, fingerprint, false);
    const kaiSocket = await connect(server.port, kai, fingerprint, false);
    for (let index = 0; index < 501; index += 1) {
      const requestId = randomUUID();
      const accepted = nextFrame(stephenSocket, "chat.accepted", frame => frame.requestId === requestId);
      stephenSocket.send(JSON.stringify({
        version: 1,
        type: "chat.send",
        requestId,
        projectId: project.id,
        eventId: randomUUID(),
        content: `pagination chat ${index}`,
        clientCreatedAt: new Date().toISOString(),
      }));
      await accepted;
    }
    expect((db.query("SELECT COUNT(*) AS count FROM chat_events WHERE project_id = ?").get(project.id) as { count: number }).count)
      .toBe(501);

    for (let index = 0; index < 501; index += 1) {
      const requestId = randomUUID();
      const messageId = randomUUID();
      const clientCreatedAt = new Date().toISOString();
      const ciphertext = await sealSignedPrivateMessage({
        messageId,
        senderDeviceId: stephen.id,
        recipientDeviceId: kai.id,
        text: `pagination private ${index}`,
        clientCreatedAt,
      }, stephen.privateKey, stephen.publicKey, kai.messagingPublicKey);
      const accepted = nextFrame(stephenSocket, "private.accepted", frame => frame.requestId === requestId);
      stephenSocket.send(JSON.stringify({
        version: 1,
        type: "private.send",
        requestId,
        messageId,
        recipientDeviceId: kai.id,
        ciphertext,
        clientCreatedAt,
      }));
      await accepted;
    }
    expect((db.query("SELECT COUNT(*) AS count FROM private_messages WHERE recipient_device_id = ?").get(kai.id) as { count: number }).count)
      .toBe(501);

    kaiSocket.close();
    const reconnectedKai = await connect(server.port, kai, fingerprint, false);
    const firstChatRequest = randomUUID();
    const firstChat = nextFrame(reconnectedKai, "chat.snapshot", frame => frame.requestId === firstChatRequest);
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "chat.subscribe",
      requestId: firstChatRequest,
      projectId: project.id,
      afterSequence: 0,
    }));
    const firstChatFrame = await firstChat;
    const firstChatEvents = firstChatFrame.events as Array<Record<string, unknown>>;
    expect(firstChatEvents).toHaveLength(500);
    expect(firstChatEvents[0]).toMatchObject({ sequence: 1, content: "pagination chat 0" });
    expect(firstChatEvents.at(-1)).toMatchObject({ sequence: 500, content: "pagination chat 499" });

    const secondChatRequest = randomUUID();
    const secondChat = nextFrame(reconnectedKai, "chat.snapshot", frame => frame.requestId === secondChatRequest);
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "chat.subscribe",
      requestId: secondChatRequest,
      projectId: project.id,
      afterSequence: 500,
    }));
    const secondChatFrame = await secondChat;
    expect(secondChatFrame.events).toEqual([expect.objectContaining({ sequence: 501, content: "pagination chat 500" })]);

    const firstPrivateRequest = randomUUID();
    const firstPrivate = nextFrame(reconnectedKai, "private.snapshot", frame => frame.requestId === firstPrivateRequest);
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "private.subscribe",
      requestId: firstPrivateRequest,
      afterSequence: 0,
    }));
    const firstPrivateFrame = await firstPrivate;
    const firstPrivateMessages = firstPrivateFrame.messages as Array<Record<string, unknown>>;
    expect(firstPrivateMessages).toHaveLength(500);
    expect(firstPrivateMessages[0]).toMatchObject({ sequence: 1 });
    expect(firstPrivateMessages.at(-1)).toMatchObject({ sequence: 500 });

    const secondPrivateRequest = randomUUID();
    const secondPrivate = nextFrame(reconnectedKai, "private.snapshot", frame => frame.requestId === secondPrivateRequest);
    reconnectedKai.send(JSON.stringify({
      version: 1,
      type: "private.subscribe",
      requestId: secondPrivateRequest,
      afterSequence: 500,
    }));
    const secondPrivateFrame = await secondPrivate;
    expect(secondPrivateFrame.messages).toEqual([expect.objectContaining({ sequence: 501 })]);
  }, 30_000);

  test("encrypted chat subscriptions also carry independent presence awareness", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-encrypted-presence-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const project = createProject(db, "Encrypted awareness", stephen.id);
    addProjectMember(db, project.id, stephen.id, kai.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    const stephenSocket = await connect(server.port, stephen, fingerprint, false);
    const stephenSnapshot = nextFrame(stephenSocket, "project.chat.snapshot");
    const stephenPresence = nextFrame(stephenSocket, "presence.snapshot");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId: project.id,
      chatId: project.id, afterSequence: 0,
    }));
    expect(await stephenSnapshot).toMatchObject({ chatId: project.id, events: [] });
    expect((await stephenPresence).members).toEqual([]);

    const initialPresence = nextFrame(stephenSocket, "presence.accepted");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
      cursor: { x: 0.18, y: 0.61 }, caret: { anchor: 6, head: 6 }, typing: false,
    }));
    await initialPresence;

    const kaiSocket = await connect(server.port, kai, fingerprint, false);
    const kaiSnapshot = nextFrame(kaiSocket, "project.chat.snapshot");
    const kaiPresence = nextFrame(kaiSocket, "presence.snapshot");
    kaiSocket.send(JSON.stringify({
      version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId: project.id,
      chatId: project.id, afterSequence: 0,
    }));
    expect(await kaiSnapshot).toMatchObject({ chatId: project.id, events: [] });
    expect((await kaiPresence).members).toEqual([expect.objectContaining({
      deviceId: stephen.id,
      cursor: { x: 0.18, y: 0.61 },
      caret: { anchor: 6, head: 6 },
      typing: false,
    })]);

    const typingOnly = nextFrame(kaiSocket, "presence.update", frame => frame.deviceId === stephen.id);
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
      cursor: null, caret: null, typing: true,
    }));
    expect(await typingOnly).toMatchObject({ deviceId: stephen.id, cursor: null, caret: null, typing: true });

    const secondChatId = randomUUID();
    const nonce = randomBytes(32).toString("base64url");
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const chatCreated = nextFrame(stephenSocket, "project.chat.created");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "project.chat.create",
      requestId: randomUUID(),
      projectId: project.id,
      chatId: secondChatId,
      title: "Security review",
      nonce,
      issuedAt,
      expiresAt,
      signature: sign(null, sharedChatCreationSigningTranscript({
        projectId: project.id,
        chatId: secondChatId,
        title: "Security review",
        creatorDeviceId: stephen.id,
        nonce,
        issuedAt,
        expiresAt,
      }), stephen.privateKey).toString("base64url"),
    }));
    expect(await chatCreated).toMatchObject({ chat: { id: secondChatId } });

    const kaiSecondChat = nextFrame(kaiSocket, "project.chat.snapshot");
    const kaiSecondPresence = nextFrame(kaiSocket, "presence.snapshot");
    kaiSocket.send(JSON.stringify({
      version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId: project.id,
      chatId: secondChatId, afterSequence: 0,
    }));
    await kaiSecondChat;
    expect((await kaiSecondPresence).members).toEqual([expect.objectContaining({
      deviceId: stephen.id,
      caret: null,
      relativeCaret: null,
      typing: false,
    })]);

    const foreignPresence: unknown[] = [];
    const collectForeignPresence = (event: MessageEvent) => {
      const frame = JSON.parse(String(event.data));
      if (frame.type === "presence.update" && frame.deviceId === stephen.id) {
        foreignPresence.push(frame);
      }
    };
    kaiSocket.addEventListener("message", collectForeignPresence);
    const crossChatAccepted = nextFrame(stephenSocket, "presence.accepted");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id, cursor: null, caret: { anchor: 2, head: 5 },
      relativeCaret: { anchor: "AQIDBA==", head: "BQYHCA==" }, typing: true,
    }));
    await crossChatAccepted;
    const nullChatRejected = nextFrame(stephenSocket, "error");
    stephenSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: null, cursor: null, caret: { anchor: 2, head: 5 },
      relativeCaret: { anchor: "AQIDBA==", head: "BQYHCA==" }, typing: true,
    }));
    expect((await nullChatRejected).error).toContain("Prompt presence requires a chat");
    await Bun.sleep(100);
    kaiSocket.removeEventListener("message", collectForeignPresence);
    expect(foreignPresence).toEqual([]);
    const kaiGeneralChat = nextFrame(kaiSocket, "project.chat.snapshot");
    const kaiGeneralPresence = nextFrame(kaiSocket, "presence.snapshot");
    kaiSocket.send(JSON.stringify({
      version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId: project.id,
      chatId: project.id, afterSequence: 0,
    }));
    await Promise.all([kaiGeneralChat, kaiGeneralPresence]);

    const duplicateStephen = await connect(server.port, stephen, fingerprint, false);
    const duplicateSnapshot = nextFrame(duplicateStephen, "project.chat.snapshot");
    const duplicatePresence = nextFrame(duplicateStephen, "presence.snapshot");
    duplicateStephen.send(JSON.stringify({
      version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId: project.id,
      chatId: project.id, afterSequence: 0,
    }));
    await duplicateSnapshot;
    expect((await duplicatePresence).members).toEqual([]);
    const originalClosed = new Promise<void>(resolve => stephenSocket.addEventListener("close", () => resolve(), { once: true }));
    stephenSocket.close();
    await originalClosed;
    const retainedPresence = nextFrame(kaiSocket, "presence.snapshot");
    kaiSocket.send(JSON.stringify({
      version: 1, type: "project.chat.subscribe", requestId: randomUUID(), projectId: project.id,
      chatId: project.id, afterSequence: 0,
    }));
    expect((await retainedPresence).members).toEqual([expect.objectContaining({ deviceId: stephen.id, typing: true })]);

    const kaiPresenceUpdate = nextFrame(duplicateStephen, "presence.update", frame => frame.deviceId === kai.id);
    kaiSocket.send(JSON.stringify({
      version: 1, type: "presence.update", requestId: randomUUID(), projectId: project.id,
      chatId: project.id,
      cursor: null, caret: { anchor: 1, head: 4 }, typing: false,
    }));
    expect(await kaiPresenceUpdate).toMatchObject({ deviceId: kai.id, caret: { anchor: 1, head: 4 } });
    const removedAtStephen = nextFrame(duplicateStephen, "project.member.removed", frame => frame.deviceId === kai.id);
    const leaveAtStephen = nextFrame(duplicateStephen, "presence.leave", frame => frame.deviceId === kai.id);
    duplicateStephen.send(JSON.stringify({
      version: 1, type: "project.member.remove", requestId: randomUUID(), projectId: project.id, deviceId: kai.id,
    }));
    await removedAtStephen;
    await leaveAtStephen;
  });

  test("replays unresolved project revocation incidents once per surviving socket and cancels affected workers", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-revocation-incident-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const kai = approvedDevice(db, fingerprint, "Kai");
    const project = createProject(db, "Revocation recovery", stephen.id);
    addProjectMember(db, project.id, stephen.id, kai.id);
    const agentId = randomUUID();
    registerAgent(db, {
      id: agentId,
      projectId: project.id,
      hostDeviceId: kai.id,
      name: "Kai recovery worker",
    });
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    const stephenSocket = await connect(server.port, stephen, fingerprint, false);
    const kaiFrames: Array<Record<string, unknown>> = [];
    const kaiWorker = await connect(server.port, kai, fingerprint, false, undefined, kaiFrames);
    const workerReady = nextFrame(kaiWorker, "agent.ready.accepted");
    kaiWorker.send(JSON.stringify({
      version: 1,
      type: "agent.ready",
      requestId: randomUUID(),
      agentId,
    }));
    await workerReady;

    for (const socket of [stephenSocket, kaiWorker]) {
      const chatSnapshot = nextFrame(socket, "project.chat.snapshot");
      const presenceSnapshot = nextFrame(socket, "presence.snapshot");
      socket.send(JSON.stringify({
        version: 1,
        type: "project.chat.subscribe",
        requestId: randomUUID(),
        projectId: project.id,
        chatId: project.id,
        afterSequence: 0,
      }));
      await Promise.all([chatSnapshot, presenceSnapshot]);
    }
    const presenceAtKai = nextFrame(kaiWorker, "presence.update", frame => frame.deviceId === stephen.id);
    const presenceAccepted = nextFrame(stephenSocket, "presence.accepted");
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "presence.update",
      requestId: randomUUID(),
      projectId: project.id,
      chatId: project.id,
      cursor: { x: 0.25, y: 0.75 },
      caret: null,
      typing: true,
    }));
    await Promise.all([presenceAtKai, presenceAccepted]);

    const taskId = randomUUID();
    const nonce = randomUUID();
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const prompt = "Keep this task in flight until device revocation.";
    const taskAtKai = nextFrame(
      kaiWorker,
      "agent.task",
      frame => (frame.task as Record<string, unknown> | undefined)?.id === taskId,
    );
    const acceptedAtStephen = nextFrame(
      stephenSocket,
      "agent.accepted",
      frame => (frame.task as Record<string, unknown> | undefined)?.id === taskId,
    );
    stephenSocket.send(JSON.stringify({
      version: 1,
      type: "agent.request",
      requestId: randomUUID(),
      taskId,
      projectId: project.id,
      chatId: project.id,
      agentId,
      prompt,
      nonce,
      issuedAt,
      expiresAt,
      signature: sign(null, agentRequestSigningTranscript({
        taskId,
        projectId: project.id,
        chatId: project.id,
        agentId,
        prompt,
        nonce,
        issuedAt,
        expiresAt,
      }), stephen.privateKey).toString("base64url"),
    }));
    await Promise.all([taskAtKai, acceptedAtStephen]);

    const encryptedAt = new Date().toISOString();
    db.query(`
      INSERT INTO project_key_epochs (
        project_id, current_epoch, last_rotation_id, updated_by_device_id,
        created_at, updated_at, rotation_required
      ) VALUES (?, 1, NULL, ?, ?, ?, 0)
    `).run(project.id, stephen.id, encryptedAt, encryptedAt);

    const incidentAtKai = nextFrame(kaiWorker, "project.device-revoked");
    const cancellationAtKai = nextFrame(kaiWorker, "agent.cancel", frame => frame.taskId === taskId);
    const leaveAtKai = nextFrame(kaiWorker, "presence.leave", frame => frame.deviceId === stephen.id);
    const revokedSocketClosed = new Promise<CloseEvent>(resolve => {
      stephenSocket.addEventListener("close", event => resolve(event), { once: true });
    });
    expect(revokeDevice(db, publicKeyFingerprint(stephen.publicKey))).toBeTrue();

    const [incident, cancellation, leave, closeEvent] = await Promise.all([
      incidentAtKai,
      cancellationAtKai,
      leaveAtKai,
      revokedSocketClosed,
    ]);
    expect(incident).toMatchObject({
      projectId: project.id,
      revokedDeviceId: stephen.id,
      currentEpoch: 1,
      promotedOwnerDeviceId: kai.id,
      cancelledTaskCount: 1,
      cancelledTasks: [{ taskId, targetDeviceId: kai.id }],
    });
    expect(cancellation).toMatchObject({ taskId });
    expect(leave).toMatchObject({ projectId: project.id, deviceId: stephen.id });
    expect(closeEvent.code).toBe(1008);

    await Bun.sleep(1_100);
    expect(kaiFrames.filter(frame => frame.type === "project.device-revoked")).toHaveLength(1);
    expect(kaiFrames.filter(frame => frame.type === "agent.cancel" && frame.taskId === taskId)).toHaveLength(1);

    const roster = nextFrame(kaiWorker, "project.member.list.result");
    kaiWorker.send(JSON.stringify({
      version: 1,
      type: "project.member.list",
      requestId: randomUUID(),
      projectId: project.id,
    }));
    expect((await roster).members).toEqual([
      expect.objectContaining({ deviceId: kai.id, role: "owner", status: "approved" }),
      expect.objectContaining({ deviceId: stephen.id, role: "member", status: "revoked" }),
    ]);

    const replayFrames: Array<Record<string, unknown>> = [];
    await connect(server.port, kai, fingerprint, false, undefined, replayFrames);
    const replayedIncident = await waitForCollectedFrame(replayFrames, "project.device-revoked");
    expect(incident.incidentId).toBeString();
    const incidentId = String(incident.incidentId);
    expect(replayedIncident).toMatchObject({ incidentId, projectId: project.id });
    await Bun.sleep(1_100);
    expect(replayFrames.filter(frame => frame.type === "project.device-revoked")).toHaveLength(1);

    db.query(`
      UPDATE device_revocation_project_incidents
      SET status = 'resolved', resolved_at = ?, resolution_rotation_id = ?
      WHERE incident_id = ?
    `).run(new Date().toISOString(), randomUUID(), incidentId);
    const resolvedFrames: Array<Record<string, unknown>> = [];
    await connect(server.port, kai, fingerprint, false, undefined, resolvedFrames);
    await Bun.sleep(1_100);
    expect(resolvedFrames.some(frame => frame.type === "project.device-revoked")).toBeFalse();
  }, 15_000);

  test("closes an authenticated socket after device revocation without waiting for another frame", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-revocation-sweep-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const stephen = approvedDevice(db, fingerprint, "Stephen");
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    const server = startCoCodexServer(config, db, identity);
    servers.push(server);

    const socket = await connect(server.port, stephen, fingerprint, false);
    const closed = new Promise<CloseEvent>(resolve => socket.addEventListener("close", event => resolve(event), { once: true }));
    expect(revokeDevice(db, publicKeyFingerprint(stephen.publicKey))).toBeTrue();
    const event = await Promise.race([
      closed,
      Bun.sleep(3_000).then(() => { throw new Error("revoked socket was not closed by the authorization sweep"); }),
    ]);
    expect(event.code).toBe(1008);
    expect(event.reason).toContain("revoked");
  });
});

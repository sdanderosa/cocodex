import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as Y from "yjs";
import {
  projectContentSigningTranscript,
  projectKeyEnvelopeSigningTranscript,
  projectMigrationEnvelopeDigest,
  projectMigrationManifestSigningTranscript,
  websocketAuthTranscript,
  type ProjectContentEnvelope,
  type ProjectMigrationInventoryItem,
  type ProjectKeyEnvelope,
} from "@cocodex/protocol";
import { createDefaultConfig } from "../src/config";
import { listEncryptedArtifacts } from "../src/encrypted-artifacts";
import { encryptedChatEventsAfter } from "../src/encrypted-chat";
import { encryptedPromptUpdatesAfter } from "../src/encrypted-prompt";
import { openDatabase } from "../src/database";
import { createServerIdentity } from "../src/identity";
import {
  initializeProjectKeyEpoch,
  removeProjectMemberAndInvalidateKeys,
  removeProjectMemberAndRotateKeys,
  rotateProjectKeyEpoch,
} from "../src/project-encryption-storage";
import {
  assertProjectPlaintextMigrationComplete,
  buildProjectPlaintextInventory,
  commitProjectPlaintextMigration,
  prepareProjectPlaintextMigration,
  projectHasLegacyPlaintext,
  projectPlaintextMigrationPage,
  stageProjectPlaintextMigration,
} from "../src/project-plaintext-migration";
import { addProjectMember, createProject } from "../src/shared-state";
import { serverPaths } from "../src/paths";
import { startCoCodexServer } from "../src/server";
import { createTlsIdentity, tlsCertificateFingerprint } from "../src/tls";

const roots: string[] = [];
const servers: Array<{ stop(force?: boolean): Promise<void> }> = [];
const databases: Array<ReturnType<typeof openDatabase>> = [];
const sockets: WebSocket[] = [];
async function closeSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return;
  await new Promise<void>(resolve => {
    const timer = setTimeout(resolve, 1_000);
    socket.addEventListener("close", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
    socket.close();
  });
}

afterEach(async () => {
  await Promise.all(sockets.splice(0).map(closeSocket));
  await Promise.all(servers.splice(0).map(server => server.stop(true)));
  for (const db of databases.splice(0)) db.close();
  Bun.gc(true);
});

afterAll(async () => {
  Bun.gc(true);
  for (const root of roots.splice(0)) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 119) throw error;
        await Bun.sleep(25);
      }
    }
  }
});

interface Device {
  id: string;
  publicKey: string;
  privateKey: string;
}

function database() {
  const root = mkdtempSync(join(tmpdir(), "cocodex-plaintext-migration-"));
  roots.push(root);
  return openDatabase(join(root, "server.sqlite3"));
}

function approvedDevice(db: ReturnType<typeof database>, displayName: string): Device {
  const signing = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const invitationId = randomUUID();
  const deviceId = randomUUID();
  const now = "2028-01-01T00:00:00.000Z";
  db.query(`
    INSERT INTO invitations (id, token_hash, expires_at, consumed_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(invitationId, randomBytes(32).toString("hex"), "2028-01-02T00:00:00.000Z", now, now);
  db.query(`
    INSERT INTO devices (
      id, public_key_pem, fingerprint, display_name, status, invitation_id,
      enrolled_at, approved_at, approval_revision
    ) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, 1)
  `).run(deviceId, signing.publicKey, randomBytes(32).toString("hex"), displayName, invitationId, now, now);
  return { id: deviceId, publicKey: signing.publicKey, privateKey: signing.privateKey };
}

function keyEnvelope(
  projectId: string,
  owner: Device,
  keyEpoch = 1,
  recipientDeviceId = owner.id,
): ProjectKeyEnvelope {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch,
    recipientDeviceId,
    senderDeviceId: owner.id,
    sealedProjectKey: randomBytes(80).toString("base64url"),
    senderPublicKeyPem: owner.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectKeyEnvelopeSigningTranscript(unsigned), owner.privateKey).toString("base64url"),
  };
}

function migratedEnvelope(projectId: string, owner: Device, item: ProjectMigrationInventoryItem): ProjectContentEnvelope {
  const recordType: ProjectContentEnvelope["recordType"] = item.kind === "shared-context" ? "shared-context"
    : item.kind === "shared-prompt" ? "shared-prompt"
      : item.kind === "agent-response" ? "agent-response"
        : item.kind;
  const unsigned = {
    version: 2 as const,
    projectId,
    chatId: item.chatId,
    keyEpoch: 1,
    recordType,
    recordId: item.sourceId,
    nonce: randomBytes(24).toString("base64url"),
    ciphertext: randomBytes(96).toString("base64url"),
    senderDeviceId: owner.id,
    senderPublicKeyPem: owner.publicKey,
  };
  return {
    ...unsigned,
    signature: sign(null, projectContentSigningTranscript(unsigned), owner.privateKey).toString("base64url"),
  };
}

function stageCompleteMigration(
  db: ReturnType<typeof database>,
  projectId: string,
  owner: Device,
) {
  const prepared = prepareProjectPlaintextMigration(db, projectId, owner.id);
  const page = projectPlaintextMigrationPage(db, {
    ...prepared,
    ownerDeviceId: owner.id,
    cursor: 0,
  });
  expect(page.nextCursor).toBeNull();
  const stagedItems = page.items.map(item => ({
    kind: item.kind,
    sourceId: item.sourceId,
    sourceDigest: item.sourceDigest,
    envelope: migratedEnvelope(projectId, owner, item),
  }));
  expect(stageProjectPlaintextMigration(db, {
    ...prepared,
    ownerDeviceId: owner.id,
    items: stagedItems,
  })).toMatchObject({ accepted: stagedItems.length, stagedCount: stagedItems.length });
  const serverFingerprint = randomBytes(32).toString("hex");
  const transcript = projectMigrationManifestSigningTranscript({
    serverFingerprint,
    projectId,
    migrationId: prepared.migrationId,
    keyEpoch: prepared.keyEpoch,
    snapshotDigest: prepared.snapshotDigest,
    ownerDeviceId: owner.id,
    ownerPublicKeyPem: owner.publicKey,
    mappings: stagedItems.map(item => ({
      kind: item.kind,
      sourceId: item.sourceId,
      sourceDigest: item.sourceDigest,
      envelopeDigest: projectMigrationEnvelopeDigest(item.envelope),
    })),
  });
  return {
    prepared,
    page,
    serverFingerprint,
    ownerSignature: sign(null, transcript, owner.privateKey).toString("base64url"),
  };
}

function nextFrame(
  socket: WebSocket,
  expectedType: string,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      socket.removeEventListener("message", onMessage);
      reject(new Error(`Timed out waiting for ${expectedType}`));
    }, 5_000);
    const onMessage = (event: MessageEvent) => {
      const frame = JSON.parse(String(event.data)) as Record<string, unknown>;
      if (frame.type !== expectedType) {
        if (frame.type === "error") {
          clearTimeout(timeout);
          socket.removeEventListener("message", onMessage);
          reject(new Error(String(frame.error)));
        }
        return;
      }
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      resolve(frame);
    };
    socket.addEventListener("message", onMessage);
  });
}

async function connect(port: number, device: Device, serverFingerprint: string): Promise<WebSocket> {
  const socket = new WebSocket(
    `wss://127.0.0.1:${port}/v1/connect`,
    { tls: { rejectUnauthorized: false } } as never,
  );
  const challenge = await nextFrame(socket, "auth.challenge");
  const requestId = randomUUID();
  const signature = sign(null, websocketAuthTranscript({
    serverFingerprint,
    deviceId: device.id,
    requestId,
    challenge: String(challenge.challenge),
  }), device.privateKey).toString("base64url");
  const authenticated = nextFrame(socket, "auth.ok");
  socket.send(JSON.stringify({
    version: 1,
    type: "auth.response",
    requestId,
    deviceId: device.id,
    signature,
  }));
  await authenticated;
  return socket;
}


function seedAllLegacyClasses(db: ReturnType<typeof database>, owner: Device) {
  const now = new Date("2028-01-01T01:00:00.000Z");
  const project = createProject(db, "Legacy project", owner.id, now);
  initializeProjectKeyEpoch(db, project.id, owner.id, randomUUID(), [keyEnvelope(project.id, owner)], now);
  const chatId = project.id;
  db.query(`
    INSERT INTO shared_project_context (
      project_id, chat_id, final_goal, context_json, revision,
      updated_by_device_id, updated_at
    ) VALUES (?, ?, ?, ?, 1, ?, ?)
  `).run(project.id, chatId, "Migrate everything", JSON.stringify({ legacy: true }), owner.id, now.toISOString());

  const plainEventId = randomUUID();
  db.query(`
    INSERT INTO chat_events (
      project_id, chat_id, event_id, sender_device_id, content,
      client_created_at, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(project.id, chatId, plainEventId, owner.id, "legacy chat canary", now.toISOString(), now.toISOString());

  const agentId = randomUUID();
  db.query(`
    INSERT INTO agents (
      id, project_id, host_device_id, name, enabled, created_at,
      primary_model, primary_effort, max_concurrent_coagents
    ) VALUES (?, ?, ?, 'Legacy Agent', 1, ?, 'gpt-5.6-sol', 'medium', 0)
  `).run(agentId, project.id, owner.id, now.toISOString());
  const taskId = randomUUID();
  db.query(`
    INSERT INTO agent_tasks (
      id, project_id, chat_id, requester_device_id, target_device_id, agent_id,
      prompt, nonce, issued_at, expires_at, requester_signature, server_signature,
      status, accepted_at, completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)
  `).run(
    taskId, project.id, chatId, owner.id, owner.id, agentId,
    "legacy task canary", randomBytes(32).toString("base64url"), now.toISOString(),
    "2028-01-01T02:00:00.000Z", randomBytes(64).toString("base64url"),
    randomBytes(64).toString("base64url"), now.toISOString(), now.toISOString(),
  );
  const resultEventId = randomUUID();
  const result = db.query(`
    INSERT INTO chat_events (
      project_id, chat_id, event_id, sender_device_id, content,
      client_created_at, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(project.id, chatId, resultEventId, owner.id, "legacy result canary", now.toISOString(), now.toISOString());
  db.query(`
    INSERT INTO agent_task_events (task_id, chat_sequence, final, status)
    VALUES (?, ?, 1, 'completed')
  `).run(taskId, Number(result.lastInsertRowid));

  const artifactId = randomUUID();
  db.query(`
    INSERT INTO artifacts (
      id, project_id, chat_id, task_id, author_device_id, type,
      title, summary, content, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'finding', ?, ?, ?, 'ready', ?, ?)
  `).run(
    artifactId, project.id, chatId, taskId, owner.id,
    "Legacy artifact", "legacy summary canary", "legacy artifact body canary",
    now.toISOString(), now.toISOString(),
  );

  const document = new Y.Doc();
  document.getText("prompt").insert(0, "legacy prompt canary");
  const update = Y.encodeStateAsUpdate(document);
  document.destroy();
  db.query(`
    INSERT INTO shared_prompt_documents (project_id, chat_id, yjs_state, updated_at)
    VALUES (?, ?, ?, ?)
  `).run(project.id, chatId, update, now.toISOString());
  db.query(`
    INSERT INTO shared_prompt_updates (
      update_id, project_id, chat_id, sender_device_id, update_blob, accepted_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(randomUUID(), project.id, chatId, owner.id, update, now.toISOString());
  return { projectId: project.id, chatId, taskId };
}

describe("owner-attested historical plaintext migration storage", () => {
  test("blocks ordinary rotation but atomically invalidates staging for both member-removal paths", () => {
    const db = database();
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const seeded = seedAllLegacyClasses(db, owner);
      addProjectMember(db, seeded.projectId, owner.id, member.id);
      const rotationEnvelope = keyEnvelope(seeded.projectId, owner, 2);
      const memberRotationEnvelope = keyEnvelope(seeded.projectId, owner, 2, member.id);
      const prepared = prepareProjectPlaintextMigration(db, seeded.projectId, owner.id);
      expect(() => rotateProjectKeyEpoch(
        db, seeded.projectId, owner.id, 1, randomUUID(), [rotationEnvelope, memberRotationEnvelope],
      )).toThrow("still in progress");
      removeProjectMemberAndInvalidateKeys(db, seeded.projectId, owner.id, member.id);
      expect(db.query("SELECT 1 FROM project_members WHERE project_id = ? AND device_id = ?")
        .get(seeded.projectId, member.id)).toBeNull();
      expect(db.query("SELECT state FROM project_plaintext_migrations WHERE migration_id = ?")
        .get(prepared.migrationId)).toEqual({ state: "invalidated" });
      expect(db.query("SELECT 1 FROM project_plaintext_migration_items WHERE migration_id = ?")
        .get(prepared.migrationId)).toBeNull();

      const memberTwo = approvedDevice(db, "Mira");
      const seededTwo = seedAllLegacyClasses(db, owner);
      addProjectMember(db, seededTwo.projectId, owner.id, memberTwo.id);
      const preparedTwo = prepareProjectPlaintextMigration(db, seededTwo.projectId, owner.id);
      const removed = removeProjectMemberAndRotateKeys(
        db, seededTwo.projectId, owner.id, memberTwo.id, 1, randomUUID(),
        [keyEnvelope(seededTwo.projectId, owner, 2)],
      );
      expect(removed).toMatchObject({ created: true, keyEpoch: 2, removedDeviceId: memberTwo.id });
      expect(db.query("SELECT state FROM project_plaintext_migrations WHERE migration_id = ?")
        .get(preparedTwo.migrationId)).toEqual({ state: "invalidated" });
      expect(db.query("SELECT 1 FROM project_plaintext_migration_items WHERE migration_id = ?")
        .get(preparedTwo.migrationId)).toBeNull();
    } finally {
      db.close();
    }
  });


  test("commits over authenticated WSS and broadcasts cursor reset to every connected member", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-plaintext-migration-wss-"));
    roots.push(root);
    const paths = serverPaths(root);
    const identity = createServerIdentity(paths);
    await createTlsIdentity(paths);
    const fingerprint = tlsCertificateFingerprint(paths.tlsCertificate);
    const db = openDatabase(paths.database);
    databases.push(db);
    const owner = approvedDevice(db, "Stephen");
    const member = approvedDevice(db, "Kai");
    const seeded = seedAllLegacyClasses(db, owner);
    addProjectMember(db, seeded.projectId, owner.id, member.id);
    const config = createDefaultConfig(paths, "127.0.0.1", 443);
    config.hostname = "127.0.0.1";
    config.port = 0;
    let server = startCoCodexServer(config, db, identity);
    servers.push(server);
    let ownerSocket: WebSocket | undefined;
    let memberSocket: WebSocket | undefined;
      ownerSocket = await connect(server.port, owner, fingerprint);
      sockets.push(ownerSocket);
      memberSocket = await connect(server.port, member, fingerprint);
      sockets.push(memberSocket);
      const ownerListRequestId = randomUUID();
      const ownerList = nextFrame(ownerSocket, "project.list.result");
      const ownerRequired = nextFrame(ownerSocket, "project.migration.required");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.list",
        requestId: ownerListRequestId,
      }));
      expect(await ownerList).toMatchObject({ requestId: ownerListRequestId });
      expect(await ownerRequired).toMatchObject({
        projectId: seeded.projectId,
        keyEpoch: 1,
        ownerDeviceId: owner.id,
      });
      const memberRequired = nextFrame(memberSocket, "project.migration.required");
      memberSocket.send(JSON.stringify({
        version: 1,
        type: "project.list",
        requestId: randomUUID(),
      }));
      expect(await memberRequired).toMatchObject({
        projectId: seeded.projectId,
        ownerDeviceId: owner.id,
      });

      const prepareRequestId = randomUUID();
      const inventoryFrame = nextFrame(ownerSocket, "project.migration.inventory");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.prepare",
        requestId: prepareRequestId,
        projectId: seeded.projectId,
      }));
      const inventory = await inventoryFrame;
      expect(inventory).toMatchObject({
        requestId: prepareRequestId,
        projectId: seeded.projectId,
        keyEpoch: 1,
        itemCount: 6,
        stagedCount: 0,
      });
      const migrationId = String(inventory.migrationId);
      const snapshotDigest = String(inventory.snapshotDigest);
      const pageRequestId = randomUUID();
      const pageFrame = nextFrame(ownerSocket, "project.migration.page.result");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.page",
        requestId: pageRequestId,
        projectId: seeded.projectId,
        migrationId,
        snapshotDigest,
        cursor: 0,
      }));
      const page = await pageFrame;
      const items = page.items as ProjectMigrationInventoryItem[];
      expect(items).toHaveLength(6);
      expect(page.nextCursor).toBeNull();
      const stagedItems = items.map(item => ({
        kind: item.kind,
        sourceId: item.sourceId,
        sourceDigest: item.sourceDigest,
        envelope: migratedEnvelope(seeded.projectId, owner, item),
      }));
      const firstStageItems = stagedItems.slice(0, 3);
      const firstStagedFrame = nextFrame(ownerSocket, "project.migration.staged");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.stage",
        requestId: randomUUID(),
        projectId: seeded.projectId,
        migrationId,
        snapshotDigest,
        items: firstStageItems,
      }));
      expect(await firstStagedFrame).toMatchObject({ accepted: 3, stagedCount: 3, itemCount: 6 });

      const restartPort = server.port;
      await Promise.all([closeSocket(ownerSocket), closeSocket(memberSocket)]);
      const serverIndex = servers.indexOf(server);
      if (serverIndex >= 0) servers.splice(serverIndex, 1);
      await server.stop(true);
      server = startCoCodexServer({ ...config, port: restartPort }, db, identity);
      servers.push(server);
      ownerSocket = await connect(server.port, owner, fingerprint);
      sockets.push(ownerSocket);
      memberSocket = await connect(server.port, member, fingerprint);
      sockets.push(memberSocket);

      const resumedMemberRequired = nextFrame(memberSocket, "project.migration.required");
      memberSocket.send(JSON.stringify({
        version: 1,
        type: "project.list",
        requestId: randomUUID(),
      }));
      expect(await resumedMemberRequired).toMatchObject({
        projectId: seeded.projectId,
        ownerDeviceId: owner.id,
      });

      const resumedPrepareRequestId = randomUUID();
      const resumedInventoryFrame = nextFrame(ownerSocket, "project.migration.inventory");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.prepare",
        requestId: resumedPrepareRequestId,
        projectId: seeded.projectId,
      }));
      const resumedInventory = await resumedInventoryFrame;
      expect(resumedInventory).toMatchObject({
        requestId: resumedPrepareRequestId,
        projectId: seeded.projectId,
        migrationId,
        snapshotDigest,
        keyEpoch: 1,
        itemCount: 6,
        stagedCount: 3,
      });

      const resumedPageRequestId = randomUUID();
      const resumedPageFrame = nextFrame(ownerSocket, "project.migration.page.result");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.page",
        requestId: resumedPageRequestId,
        projectId: seeded.projectId,
        migrationId,
        snapshotDigest,
        cursor: 0,
      }));
      const resumedPage = await resumedPageFrame;
      const resumedItems = resumedPage.items as ProjectMigrationInventoryItem[];
      expect(resumedItems.filter(item => item.staged)).toHaveLength(3);
      for (const item of resumedItems.filter(item => item.staged)) {
        expect(item.envelopeDigest).toBeString();
      }

      const remainingStagedFrame = nextFrame(ownerSocket, "project.migration.staged");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.stage",
        requestId: randomUUID(),
        projectId: seeded.projectId,
        migrationId,
        snapshotDigest,
        items: stagedItems.slice(3),
      }));
      expect(await remainingStagedFrame).toMatchObject({
        accepted: 3,
        stagedCount: 6,
        itemCount: 6,
      });
      const manifest = projectMigrationManifestSigningTranscript({
        serverFingerprint: fingerprint,
        projectId: seeded.projectId,
        migrationId,
        keyEpoch: 1,
        snapshotDigest,
        ownerDeviceId: owner.id,
        ownerPublicKeyPem: owner.publicKey,
        mappings: stagedItems.map(item => ({
          kind: item.kind,
          sourceId: item.sourceId,
          sourceDigest: item.sourceDigest,
          envelopeDigest: projectMigrationEnvelopeDigest(item.envelope),
        })),
      });
      const commitRequestId = randomUUID();
      const ownerCompleted = nextFrame(ownerSocket, "project.migration.completed");
      const memberCompleted = nextFrame(memberSocket, "project.migration.completed");
      ownerSocket.send(JSON.stringify({
        version: 1,
        type: "project.migration.commit",
        requestId: commitRequestId,
        projectId: seeded.projectId,
        migrationId,
        keyEpoch: 1,
        snapshotDigest,
        ownerPublicKeyPem: owner.publicKey,
        ownerSignature: sign(null, manifest, owner.privateKey).toString("base64url"),
      }));
      expect(await ownerCompleted).toMatchObject({
        requestId: commitRequestId,
        projectId: seeded.projectId,
        migrationId,
        migratedCount: 6,
        resetChatIds: [seeded.chatId],
      });
      expect(await memberCompleted).toMatchObject({
        projectId: seeded.projectId,
        migrationId,
        migratedCount: 6,
        resetChatIds: [seeded.chatId],
      });
      expect(projectHasLegacyPlaintext(db, seeded.projectId)).toBeFalse();
  });


  test("rolls back earlier replacements when a late artifact collision aborts commit", () => {
    const db = database();
    try {
      const owner = approvedDevice(db, "Stephen");
      const seeded = seedAllLegacyClasses(db, owner);
      const staged = stageCompleteMigration(db, seeded.projectId, owner);
      const artifact = staged.page.items.find(item => item.kind === "artifact");
      if (!artifact || artifact.kind !== "artifact") throw new Error("Expected artifact fixture");
      db.query(`
        INSERT INTO project_artifacts (
          id, project_id, chat_id, task_id, author_device_id, envelope_json,
          created_at, updated_at
        ) VALUES (?, ?, ?, NULL, ?, '{}', ?, ?)
      `).run(
        artifact.sourceId, seeded.projectId, seeded.chatId, owner.id,
        artifact.createdAt, artifact.updatedAt,
      );
      expect(() => commitProjectPlaintextMigration(db, {
        projectId: seeded.projectId,
        migrationId: staged.prepared.migrationId,
        ownerDeviceId: owner.id,
        keyEpoch: staged.prepared.keyEpoch,
        snapshotDigest: staged.prepared.snapshotDigest,
        ownerPublicKeyPem: owner.publicKey,
        ownerSignature: staged.ownerSignature,
        serverFingerprint: staged.serverFingerprint,
      })).toThrow("collides");
      expect(projectHasLegacyPlaintext(db, seeded.projectId)).toBeTrue();
      const counts = db.query(`
        SELECT
          (SELECT COUNT(*) FROM chat_events WHERE project_id = ?) AS legacyChat,
          (SELECT COUNT(*) FROM shared_prompt_updates WHERE project_id = ?) AS legacyPrompt,
          (SELECT COUNT(*) FROM artifacts WHERE project_id = ?) AS legacyArtifact,
          (SELECT COUNT(*) FROM project_chat_events WHERE project_id = ?) AS encryptedChat,
          (SELECT COUNT(*) FROM project_prompt_updates WHERE project_id = ?) AS encryptedPrompt
      `).get(...Array(5).fill(seeded.projectId));
      expect(counts).toEqual({
        legacyChat: 2, legacyPrompt: 1, legacyArtifact: 1,
        encryptedChat: 0, encryptedPrompt: 0,
      });
      expect((db.query("SELECT prompt FROM agent_tasks WHERE id = ?").get(seeded.taskId) as { prompt: string }).prompt)
        .toBe("legacy task canary");
      expect((db.query("SELECT state FROM project_plaintext_migrations WHERE migration_id = ?")
        .get(staged.prepared.migrationId) as { state: string }).state).toBe("prepared");
      expect((db.query("SELECT COUNT(*) AS count FROM project_plaintext_migration_items WHERE migration_id = ?")
        .get(staged.prepared.migrationId) as { count: number }).count).toBe(6);
    } finally {
      db.close();
    }
  }, 15_000);


  test("atomically replaces all six plaintext classes with owner-attested encrypted projections", () => {
    const db = database();
    try {
      const owner = approvedDevice(db, "Stephen");
      const seeded = seedAllLegacyClasses(db, owner);
      const staged = stageCompleteMigration(db, seeded.projectId, owner);
      const completedAt = new Date("2028-01-01T01:30:00.000Z");
      const completed = commitProjectPlaintextMigration(db, {
        projectId: seeded.projectId,
        migrationId: staged.prepared.migrationId,
        ownerDeviceId: owner.id,
        keyEpoch: staged.prepared.keyEpoch,
        snapshotDigest: staged.prepared.snapshotDigest,
        ownerPublicKeyPem: owner.publicKey,
        ownerSignature: staged.ownerSignature,
        serverFingerprint: staged.serverFingerprint,
      }, completedAt);
      expect(completed).toMatchObject({
        migratedCount: 6,
        resetChatIds: [seeded.chatId],
        completedAt: completedAt.toISOString(),
      });
      expect(projectHasLegacyPlaintext(db, seeded.projectId)).toBeFalse();
      expect(() => assertProjectPlaintextMigrationComplete(db, seeded.projectId)).not.toThrow();
      const counts = db.query(`
        SELECT
          (SELECT COUNT(*) FROM chat_events WHERE project_id = ?) AS legacyChat,
          (SELECT COUNT(*) FROM shared_prompt_updates WHERE project_id = ?) AS legacyPrompt,
          (SELECT COUNT(*) FROM artifacts WHERE project_id = ?) AS legacyArtifact,
          (SELECT COUNT(*) FROM shared_project_context WHERE project_id = ?) AS legacyContext,
          (SELECT COUNT(*) FROM project_chat_events WHERE project_id = ?) AS encryptedChat,
          (SELECT COUNT(*) FROM project_prompt_updates WHERE project_id = ?) AS encryptedPrompt,
          (SELECT COUNT(*) FROM project_artifacts WHERE project_id = ?) AS encryptedArtifact,
          (SELECT COUNT(*) FROM encrypted_project_context WHERE project_id = ?) AS encryptedContext
      `).get(...Array(8).fill(seeded.projectId));
      expect(counts).toEqual({
        legacyChat: 0, legacyPrompt: 0, legacyArtifact: 0, legacyContext: 0,
        encryptedChat: 2, encryptedPrompt: 1, encryptedArtifact: 1, encryptedContext: 1,
      });
      const migratedChats = encryptedChatEventsAfter(db, seeded.projectId, seeded.chatId, owner.id, 0);
      expect(migratedChats).toHaveLength(2);
      expect(migratedChats.every(event =>
        event.migrationId === staged.prepared.migrationId
        && event.attributedDeviceId === owner.id)).toBeTrue();
      const migratedArtifacts = listEncryptedArtifacts(db, seeded.projectId, seeded.chatId, owner.id);
      expect(migratedArtifacts).toHaveLength(1);
      expect(migratedArtifacts[0]).toMatchObject({
        migrationId: staged.prepared.migrationId,
        attributedDeviceId: owner.id,
      });
      const migratedPrompts = encryptedPromptUpdatesAfter(db, seeded.projectId, seeded.chatId, owner.id, 0);
      expect(migratedPrompts).toHaveLength(1);
      expect(migratedPrompts[0]?.migrationId).toBe(staged.prepared.migrationId);
      const task = db.query("SELECT prompt, prompt_envelope_json AS envelope, migration_id AS migrationId FROM agent_tasks WHERE id = ?")
        .get(seeded.taskId) as { prompt: string; envelope: string | null; migrationId: string | null };
      expect(task).toMatchObject({ prompt: "[encrypted]", migrationId: staged.prepared.migrationId });
      expect(task.envelope).toBeString();
      const migration = db.query(`
        SELECT state, staged_count AS stagedCount, item_count AS itemCount,
          manifest_digest AS manifestDigest, owner_signature AS ownerSignature
        FROM project_plaintext_migrations WHERE migration_id = ?
      `).get(staged.prepared.migrationId);
      expect(migration).toMatchObject({
        state: "completed", stagedCount: 6, itemCount: 6, ownerSignature: staged.ownerSignature,
      });
      expect((migration as { manifestDigest: string }).manifestDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(db.query("SELECT 1 FROM project_plaintext_migration_items WHERE migration_id = ?")
        .get(staged.prepared.migrationId)).toBeNull();
    } finally {
      db.close();
    }
  });


  test("inventories every legacy class, freezes it, pages it, and stages signed owner envelopes idempotently", () => {
    const db = database();
    try {
      const owner = approvedDevice(db, "Stephen");
      const seeded = seedAllLegacyClasses(db, owner);
      expect(projectHasLegacyPlaintext(db, seeded.projectId)).toBeTrue();
      expect(() => assertProjectPlaintextMigrationComplete(db, seeded.projectId)).toThrow("must be migrated");

      const inventory = buildProjectPlaintextInventory(db, seeded.projectId);
      expect(inventory.map(item => item.kind)).toEqual([
        "shared-context", "chat", "agent-response", "shared-prompt", "artifact", "task",
      ]);
      expect(JSON.stringify(inventory)).toContain("legacy chat canary");
      const prompt = inventory.find(item => item.kind === "shared-prompt");
      expect(prompt?.kind).toBe("shared-prompt");
      const promptDocument = new Y.Doc();
      Y.applyUpdate(promptDocument, Buffer.from((prompt as Extract<ProjectMigrationInventoryItem, { kind: "shared-prompt" }>).updateBase64, "base64"));
      expect(promptDocument.getText("prompt").toString()).toBe("legacy prompt canary");
      promptDocument.destroy();
      const prepared = prepareProjectPlaintextMigration(db, seeded.projectId, owner.id);
      expect(prepared.itemCount).toBe(6);
      expect(prepareProjectPlaintextMigration(db, seeded.projectId, owner.id)).toEqual(prepared);

      const page = projectPlaintextMigrationPage(db, {
        ...prepared, ownerDeviceId: owner.id, cursor: 0,
      });
      expect(page.items).toHaveLength(6);
      expect(page.nextCursor).toBeNull();
      expect(page.items.every(item => item.staged === false)).toBeTrue();

      const first = page.items[0]!;
      const stageItem = {
        kind: first.kind,
        sourceId: first.sourceId,
        sourceDigest: first.sourceDigest,
        envelope: migratedEnvelope(seeded.projectId, owner, first),
      };
      const staged = stageProjectPlaintextMigration(db, {
        ...prepared, ownerDeviceId: owner.id, items: [stageItem],
      });
      expect(staged).toMatchObject({ accepted: 1, stagedCount: 1, itemCount: 6 });
      expect(stageProjectPlaintextMigration(db, {
        ...prepared, ownerDeviceId: owner.id, items: [stageItem],
      })).toMatchObject({ accepted: 0, stagedCount: 1 });
      expect(projectPlaintextMigrationPage(db, {
        ...prepared, ownerDeviceId: owner.id, cursor: 0,
      }).items[0]?.staged).toBeTrue();
      expect(() => stageProjectPlaintextMigration(db, {
        ...prepared,
        ownerDeviceId: owner.id,
        items: [{ ...stageItem, envelope: migratedEnvelope(seeded.projectId, owner, first) }],
      })).toThrow("changed");
    } finally {
      db.close();
    }
  });

  test("rejects non-owner preparation, source mutation, and nonterminal legacy tasks", () => {
    const db = database();
    try {
      const owner = approvedDevice(db, "Stephen");
      const member = approvedDevice(db, "Kai");
      const seeded = seedAllLegacyClasses(db, owner);
      addProjectMember(db, seeded.projectId, owner.id, member.id);
      expect(() => prepareProjectPlaintextMigration(db, seeded.projectId, member.id)).toThrow("owner");
      const prepared = prepareProjectPlaintextMigration(db, seeded.projectId, owner.id);
      db.query("UPDATE chat_events SET content = 'changed after prepare' WHERE sequence = (SELECT MIN(sequence) FROM chat_events WHERE project_id = ?)").run(seeded.projectId);
      expect(() => prepareProjectPlaintextMigration(db, seeded.projectId, owner.id)).toThrow("changed");

      db.query("UPDATE agent_tasks SET status = 'running', completed_at = NULL WHERE id = ?").run(seeded.taskId);
      expect(() => buildProjectPlaintextInventory(db, seeded.projectId)).toThrow("terminal");
      const row = db.query("SELECT state FROM project_plaintext_migrations WHERE migration_id = ?")
        .get(prepared.migrationId) as { state: string };
      expect(row.state).toBe("invalidated");
    } finally {
      db.close();
    }
  });
});

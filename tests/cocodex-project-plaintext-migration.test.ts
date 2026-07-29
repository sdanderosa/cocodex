import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, verify } from "node:crypto";
import {
  clientFrameSchema,
  projectMigrationEnvelopeDigest,
  projectMigrationInventoryItemSchema,
  projectMigrationManifestSigningTranscript,
  type ProjectMigrationInventoryItem,
  type ProjectMigrationStageItem,
} from "../packages/cocodex-protocol/src";
import {
  ProjectPlaintextMigrationCoordinator,
  projectMigrationItemPlaintext,
  type ProjectMigrationOwner,
} from "../src/cocodex/project-plaintext-migration";

const digest = (value: string) => createHash("sha256").update(value).digest("base64url");
const timestamp = "2030-01-01T00:00:00.000Z";

function owner(): ProjectMigrationOwner & { projectKey: Buffer } {
  const pair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    deviceId: randomUUID(),
    publicKeyPem: pair.publicKey,
    privateKeyPem: pair.privateKey,
    serverFingerprint: digest("tls certificate"),
    projectKey: randomBytes(32),
  };
}

function inventory(projectId: string, chatId: string, deviceId: string): ProjectMigrationInventoryItem[] {
  const taskId = randomUUID();
  const common = (kind: string) => ({
    kind,
    sourceId: randomUUID(),
    chatId,
    sourceDigest: digest(kind),
    staged: false,
  });
  return [
    projectMigrationInventoryItemSchema.parse({
      ...common("shared-context"),
      revision: 2,
      updatedByDeviceId: deviceId,
      updatedAt: timestamp,
      finalGoal: "Ship CoCodex",
      context: { phase: "migration" },
    }),
    projectMigrationInventoryItemSchema.parse({
      ...common("chat"),
      sourceSequence: 1,
      attributedDeviceId: deviceId,
      clientCreatedAt: timestamp,
      acceptedAt: timestamp,
      content: "legacy chat",
    }),
    projectMigrationInventoryItemSchema.parse({
      ...common("agent-response"),
      sourceSequence: 2,
      attributedDeviceId: deviceId,
      taskId,
      final: true,
      status: "completed",
      clientCreatedAt: timestamp,
      acceptedAt: timestamp,
      content: "legacy result",
    }),
    projectMigrationInventoryItemSchema.parse({
      ...common("shared-prompt"),
      updatedAt: timestamp,
      updateBase64: Buffer.from("yjs update").toString("base64"),
    }),
    projectMigrationInventoryItemSchema.parse({
      ...common("artifact"),
      attributedDeviceId: deviceId,
      taskId,
      artifactType: "finding",
      title: "Legacy finding",
      summary: "Summary",
      content: "Artifact body",
      status: "ready",
      createdAt: timestamp,
      updatedAt: timestamp,
    }),
    projectMigrationInventoryItemSchema.parse({
      ...common("task"),
      attributedDeviceId: deviceId,
      targetDeviceId: deviceId,
      agentId: "agent-1",
      prompt: "legacy task",
      dependencies: [],
      inputArtifactIds: [],
      privateShareMessageId: null,
      status: "completed",
      acceptedAt: timestamp,
      completedAt: timestamp,
    }),
  ];
}

describe("resident owner plaintext migration", () => {
  test("encodes every legacy class in the exact existing encrypted plaintext format", () => {
    const projectId = randomUUID();
    const chatId = randomUUID();
    const localOwner = owner();
    const items = inventory(projectId, chatId, localOwner.deviceId);
    expect(JSON.parse(projectMigrationItemPlaintext(projectId, items[0]!))).toEqual({
      finalGoal: "Ship CoCodex",
      context: { phase: "migration" },
    });
    expect(JSON.parse(projectMigrationItemPlaintext(projectId, items[1]!))).toEqual({ content: "legacy chat" });
    expect(JSON.parse(projectMigrationItemPlaintext(projectId, items[2]!))).toEqual({ content: "legacy result" });
    expect(JSON.parse(projectMigrationItemPlaintext(projectId, items[3]!))).toEqual({
      update: Buffer.from("yjs update").toString("base64"),
    });
    expect(JSON.parse(projectMigrationItemPlaintext(projectId, items[4]!))).toMatchObject({
      id: items[4]!.sourceId,
      projectId,
      chatId,
      type: "finding",
      title: "Legacy finding",
      status: "ready",
    });
    expect(JSON.parse(projectMigrationItemPlaintext(projectId, items[5]!))).toEqual({
      prompt: "legacy task",
      dependencies: [],
      inputArtifactIds: [],
    });
  });

  test("encrypts, stages, signs, commits, and resumes from staged digests after restart", async () => {
    const projectId = randomUUID();
    const chatId = randomUUID();
    const migrationId = randomUUID();
    const snapshotDigest = digest("snapshot");
    const localOwner = owner();
    const items = inventory(projectId, chatId, localOwner.deviceId);
    const sent: Array<Record<string, any>> = [];
    const completed: Array<Record<string, any>> = [];
    const statuses: Array<Record<string, any>> = [];
    const coordinator = new ProjectPlaintextMigrationCoordinator({
      owner: localOwner,
      loadProjectKey: (candidate, epoch) => candidate === projectId && epoch === 1
        ? { keyEpoch: 1, projectKey: localOwner.projectKey }
        : undefined,
      send: frame => sent.push(frame),
      completed: frame => completed.push(frame),
      status: event => statuses.push(event),
    });

    coordinator.required({
      version: 1,
      type: "project.migration.required",
      projectId,
      keyEpoch: 1,
      ownerDeviceId: localOwner.deviceId,
    });
    expect(clientFrameSchema.parse(sent.shift()).type).toBe("project.migration.prepare");
    await coordinator.handle({
      version: 1,
      type: "project.migration.inventory",
      requestId: randomUUID(),
      projectId,
      migrationId,
      keyEpoch: 1,
      snapshotDigest,
      itemCount: items.length,
      stagedCount: 0,
    });
    expect(clientFrameSchema.parse(sent.shift()).type).toBe("project.migration.page");
    await coordinator.handle({
      version: 1,
      type: "project.migration.page.result",
      requestId: randomUUID(),
      projectId,
      migrationId,
      snapshotDigest,
      cursor: 0,
      items,
      nextCursor: null,
    });
    const stage = clientFrameSchema.parse(sent.shift()) as {
      type: "project.migration.stage";
      items: ProjectMigrationStageItem[];
    };
    expect(stage.type).toBe("project.migration.stage");
    expect(stage.items).toHaveLength(6);
    expect(stage.items.map(item => item.envelope.recordType)).toEqual([
      "shared-context", "chat", "agent-response", "shared-prompt", "artifact", "task",
    ]);
    await coordinator.handle({
      version: 1,
      type: "project.migration.staged",
      requestId: randomUUID(),
      projectId,
      migrationId,
      snapshotDigest,
      accepted: 6,
      stagedCount: 6,
      itemCount: 6,
    });
    const commit = clientFrameSchema.parse(sent.shift()) as Record<string, any>;
    expect(commit.type).toBe("project.migration.commit");
    const mappings = stage.items.map(item => ({
      kind: item.kind,
      sourceId: item.sourceId,
      sourceDigest: item.sourceDigest,
      envelopeDigest: projectMigrationEnvelopeDigest(item.envelope),
    }));
    expect(verify(
      null,
      projectMigrationManifestSigningTranscript({
        serverFingerprint: localOwner.serverFingerprint,
        projectId,
        migrationId,
        keyEpoch: 1,
        snapshotDigest,
        ownerDeviceId: localOwner.deviceId,
        ownerPublicKeyPem: localOwner.publicKeyPem,
        mappings,
      }),
      localOwner.publicKeyPem,
      Buffer.from(commit.ownerSignature, "base64url"),
    )).toBeTrue();

    const resumedSent: Array<Record<string, any>> = [];
    const resumed = new ProjectPlaintextMigrationCoordinator({
      owner: localOwner,
      loadProjectKey: () => ({ keyEpoch: 1, projectKey: localOwner.projectKey }),
      send: frame => resumedSent.push(frame),
      completed: frame => completed.push(frame),
      status: event => statuses.push(event),
    });
    resumed.required({
      version: 1,
      type: "project.migration.required",
      projectId,
      keyEpoch: 1,
      ownerDeviceId: localOwner.deviceId,
    });
    resumedSent.shift();
    await resumed.handle({
      version: 1,
      type: "project.migration.inventory",
      requestId: randomUUID(),
      projectId,
      migrationId,
      keyEpoch: 1,
      snapshotDigest,
      itemCount: items.length,
      stagedCount: items.length,
    });
    resumedSent.shift();
    await resumed.handle({
      version: 1,
      type: "project.migration.page.result",
      requestId: randomUUID(),
      projectId,
      migrationId,
      snapshotDigest,
      cursor: 0,
      items: items.map((item, index) => projectMigrationInventoryItemSchema.parse({
        ...item,
        staged: true,
        envelopeDigest: mappings[index]!.envelopeDigest,
      })),
      nextCursor: null,
    });
    expect(resumedSent).toHaveLength(1);
    expect(clientFrameSchema.parse(resumedSent[0]).type).toBe("project.migration.commit");
    expect(resumedSent.some(frame => frame.type === "project.migration.stage")).toBeFalse();

    await resumed.handle({
      version: 1,
      type: "project.migration.completed",
      requestId: String(resumedSent[0]!.requestId),
      projectId,
      migrationId,
      keyEpoch: 1,
      snapshotDigest,
      migratedCount: 6,
      resetChatIds: [chatId],
      completedAt: timestamp,
    });
    expect(completed).toHaveLength(1);
    expect(statuses.at(-1)).toMatchObject({ state: "completed", projectId, stagedCount: 6 });
  });

  test("never sends a stage batch larger than the protocol maximum", async () => {
    const projectId = randomUUID();
    const chatId = randomUUID();
    const migrationId = randomUUID();
    const snapshotDigest = digest("batch snapshot");
    const localOwner = owner();
    const items = Array.from({ length: 17 }, (_, sourceSequence) =>
      projectMigrationInventoryItemSchema.parse({
        kind: "chat",
        sourceId: randomUUID(),
        chatId,
        sourceDigest: digest(String(sourceSequence)),
        sourceSequence,
        attributedDeviceId: localOwner.deviceId,
        clientCreatedAt: timestamp,
        acceptedAt: timestamp,
        content: `message ${sourceSequence}`,
        staged: false,
      }));
    const sent: Array<Record<string, any>> = [];
    const coordinator = new ProjectPlaintextMigrationCoordinator({
      owner: localOwner,
      loadProjectKey: () => ({ keyEpoch: 1, projectKey: localOwner.projectKey }),
      send: frame => sent.push(frame),
      completed: () => {},
      status: () => {},
    });
    coordinator.required({
      version: 1,
      type: "project.migration.required",
      projectId,
      keyEpoch: 1,
      ownerDeviceId: localOwner.deviceId,
    });
    sent.shift();
    await coordinator.handle({
      version: 1,
      type: "project.migration.inventory",
      requestId: randomUUID(),
      projectId,
      migrationId,
      keyEpoch: 1,
      snapshotDigest,
      itemCount: 17,
      stagedCount: 0,
    });
    sent.shift();
    await coordinator.handle({
      version: 1,
      type: "project.migration.page.result",
      requestId: randomUUID(),
      projectId,
      migrationId,
      snapshotDigest,
      cursor: 0,
      items,
      nextCursor: null,
    });
    const first = sent.shift()!;
    expect(first.items).toHaveLength(16);
    await coordinator.handle({
      version: 1,
      type: "project.migration.staged",
      requestId: String(first.requestId),
      projectId,
      migrationId,
      snapshotDigest,
      accepted: 16,
      stagedCount: 16,
      itemCount: 17,
    });
    expect(sent.shift()!.items).toHaveLength(1);
  });
});

import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import {
  clientFrameSchema,
  encryptedArtifactSchema,
  encryptedChatEventSchema,
  encryptedPromptUpdateSchema,
  projectMigrationEnvelopeDigest,
  projectMigrationManifestSigningTranscript,
  projectMigrationPageResultFrameSchema,
  projectMigrationStageFrameSchema,
  projectServerFrameSchema,
  type ProjectContentEnvelope,
} from "../src";

const digest = (value: string) => createHash("sha256").update(value).digest("base64url");

function envelope(projectId: string, chatId: string, senderDeviceId: string, publicKey: string): ProjectContentEnvelope {
  return {
    version: 2,
    projectId,
    chatId,
    keyEpoch: 1,
    recordType: "chat",
    recordId: randomUUID(),
    nonce: randomBytes(24).toString("base64url"),
    ciphertext: randomBytes(64).toString("base64url"),
    senderDeviceId,
    senderPublicKeyPem: publicKey,
    signature: randomBytes(64).toString("base64url"),
  };
}

describe("owner-attested plaintext migration protocol", () => {
  test("requires complete migration attribution on chat and artifacts while marking prompt projections", () => {
    const projectId = randomUUID();
    const chatId = randomUUID();
    const senderDeviceId = randomUUID();
    const migrationId = randomUUID();
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const chatEnvelope = envelope(projectId, chatId, senderDeviceId, signing.publicKey);
    const chatEvent = {
      sequence: 1,
      projectId,
      chatId,
      eventId: chatEnvelope.recordId,
      senderDeviceId,
      envelope: chatEnvelope,
      clientCreatedAt: "2030-01-01T00:00:00.000Z",
      acceptedAt: "2030-01-01T00:00:01.000Z",
      migrationId,
      attributedDeviceId: senderDeviceId,
    };
    expect(encryptedChatEventSchema.parse(chatEvent).migrationId).toBe(migrationId);
    expect(() => encryptedChatEventSchema.parse({
      ...chatEvent,
      attributedDeviceId: undefined,
    })).toThrow("complete");

    const artifactId = randomUUID();
    const artifact = {
      artifactId,
      projectId,
      chatId,
      taskId: null,
      authorDeviceId: senderDeviceId,
      envelope: { ...chatEnvelope, recordType: "artifact" as const, recordId: artifactId },
      createdAt: "2030-01-01T00:00:00.000Z",
      updatedAt: "2030-01-01T00:00:01.000Z",
      migrationId,
      attributedDeviceId: senderDeviceId,
    };
    expect(encryptedArtifactSchema.parse(artifact).attributedDeviceId).toBe(senderDeviceId);
    expect(() => encryptedArtifactSchema.parse({ ...artifact, migrationId: undefined })).toThrow("complete");
    expect(encryptedPromptUpdateSchema.parse({
      sequence: 1,
      projectId,
      chatId,
      updateId: randomUUID(),
      senderDeviceId,
      envelope: { ...chatEnvelope, recordType: "shared-prompt" as const, recordId: randomUUID() },
      acceptedAt: "2030-01-01T00:00:01.000Z",
      migrationId,
    }).migrationId).toBe(migrationId);
  });


  test("strictly bounds prepare, page, stage, commit, and completed frames", () => {
    const projectId = randomUUID();
    const chatId = randomUUID();
    const migrationId = randomUUID();
    const ownerDeviceId = randomUUID();
    const requestId = randomUUID();
    const snapshotDigest = digest("snapshot");
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const contentEnvelope = envelope(projectId, chatId, ownerDeviceId, signing.publicKey);
    const sourceDigest = digest("legacy chat row");

    expect(clientFrameSchema.parse({
      version: 1, type: "project.migration.prepare", requestId, projectId,
    }).type).toBe("project.migration.prepare");
    expect(clientFrameSchema.parse({
      version: 1, type: "project.migration.page", requestId, projectId,
      migrationId, snapshotDigest, cursor: 0,
    }).type).toBe("project.migration.page");
    expect(projectMigrationStageFrameSchema.parse({
      version: 1, type: "project.migration.stage", requestId, projectId,
      migrationId, snapshotDigest,
      items: [{ kind: "chat", sourceId: contentEnvelope.recordId, sourceDigest, envelope: contentEnvelope }],
    }).items).toHaveLength(1);
    expect(clientFrameSchema.parse({
      version: 1, type: "project.migration.commit", requestId, projectId,
      migrationId, keyEpoch: 1, snapshotDigest, ownerPublicKeyPem: signing.publicKey,
      ownerSignature: randomBytes(64).toString("base64url"),
    }).type).toBe("project.migration.commit");

    expect(projectServerFrameSchema.parse({
      version: 1, type: "project.migration.inventory", requestId, projectId,
      migrationId, keyEpoch: 1, snapshotDigest, itemCount: 1, stagedCount: 0,
    }).type).toBe("project.migration.inventory");
    expect(projectMigrationPageResultFrameSchema.parse({
      version: 1, type: "project.migration.page.result", requestId, projectId,
      migrationId, snapshotDigest, cursor: 0, nextCursor: null,
      items: [{
        kind: "chat", sourceId: contentEnvelope.recordId, chatId, sourceDigest,
        sourceSequence: 1, attributedDeviceId: ownerDeviceId,
        clientCreatedAt: "2030-01-01T00:00:00.000Z",
        acceptedAt: "2030-01-01T00:00:01.000Z", content: "legacy", staged: false,
      }],
    }).items[0]?.kind).toBe("chat");
    expect(projectServerFrameSchema.parse({
      version: 1, type: "project.migration.staged", requestId, projectId,
      migrationId, snapshotDigest, accepted: 1, stagedCount: 1, itemCount: 1,
    }).type).toBe("project.migration.staged");
    expect(projectServerFrameSchema.parse({
      version: 1, type: "project.migration.completed", requestId, projectId,
      migrationId, keyEpoch: 1, snapshotDigest, migratedCount: 1,
      resetChatIds: [chatId], completedAt: "2030-01-01T00:00:02.000Z",
    }).type).toBe("project.migration.completed");
    expect(projectServerFrameSchema.parse({
      version: 1, type: "project.migration.required", projectId,
      keyEpoch: 1, ownerDeviceId,
    }).type).toBe("project.migration.required");

    expect(() => projectMigrationStageFrameSchema.parse({
      version: 1, type: "project.migration.stage", requestId, projectId,
      migrationId, snapshotDigest,
      items: [
        { kind: "chat", sourceId: contentEnvelope.recordId, sourceDigest, envelope: contentEnvelope },
        { kind: "chat", sourceId: contentEnvelope.recordId, sourceDigest, envelope: contentEnvelope },
      ],
    })).toThrow("duplicate");
    expect(() => projectMigrationPageResultFrameSchema.parse({
      version: 1, type: "project.migration.page.result", requestId, projectId,
      migrationId, snapshotDigest, cursor: 4, nextCursor: 99, items: [],
    })).toThrow();
    expect(() => clientFrameSchema.parse({
      version: 1, type: "project.migration.prepare", requestId, projectId, extra: true,
    })).toThrow();
  });

  test("manifest transcript binds every authority and source/envelope mapping", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const input = {
      serverFingerprint: "AAAA-BBBB-CCCC-DDDD",
      projectId: randomUUID(),
      migrationId: randomUUID(),
      keyEpoch: 3,
      snapshotDigest: digest("snapshot"),
      ownerDeviceId: randomUUID(),
      ownerPublicKeyPem: signing.publicKey,
      mappings: [
        { kind: "chat" as const, sourceId: randomUUID(), sourceDigest: digest("chat"), envelopeDigest: digest("chat envelope") },
        { kind: "artifact" as const, sourceId: randomUUID(), sourceDigest: digest("artifact"), envelopeDigest: digest("artifact envelope") },
      ],
    };
    const baseline = projectMigrationManifestSigningTranscript(input);
    expect(projectMigrationManifestSigningTranscript({ ...input, mappings: [...input.mappings].reverse() })).toEqual(baseline);
    for (const changed of [
      { ...input, serverFingerprint: "EEEE-FFFF" },
      { ...input, projectId: randomUUID() },
      { ...input, migrationId: randomUUID() },
      { ...input, keyEpoch: 4 },
      { ...input, snapshotDigest: digest("other snapshot") },
      { ...input, ownerDeviceId: randomUUID() },
      { ...input, mappings: input.mappings.map((item, index) => index ? item : { ...item, sourceDigest: digest("other row") }) },
      { ...input, mappings: input.mappings.map((item, index) => index ? item : { ...item, envelopeDigest: digest("other envelope") }) },
    ]) {
      expect(projectMigrationManifestSigningTranscript(changed)).not.toEqual(baseline);
    }
    expect(() => projectMigrationManifestSigningTranscript({
      ...input, mappings: [input.mappings[0]!, input.mappings[0]!],
    })).toThrow("duplicate");
  });

  test("envelope digest is stable across caller key order and changes with ciphertext", () => {
    const signing = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const contentEnvelope = envelope(randomUUID(), randomUUID(), randomUUID(), signing.publicKey);
    const reordered = Object.fromEntries(Object.entries(contentEnvelope).reverse()) as unknown as ProjectContentEnvelope;
    expect(projectMigrationEnvelopeDigest(reordered)).toBe(projectMigrationEnvelopeDigest(contentEnvelope));
    expect(projectMigrationEnvelopeDigest({
      ...contentEnvelope, ciphertext: randomBytes(64).toString("base64url"),
    })).not.toBe(projectMigrationEnvelopeDigest(contentEnvelope));
  });
});

import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { publicKeyFingerprint } from "@cocodex/protocol";
import {
  acknowledgePrivateHistoryEntry,
  emptyPrivateHistory,
  loadPrivateHistory,
  markPrivateHistoryEntryQueued,
  reconcileStagedPrivateHistory,
  recordPrivateHistoryEntry,
  savePrivateHistory,
} from "../src/cocodex/private-history";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "../src/cocodex/private-messaging";

function signingIdentity() {
  return generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function messagingIdentity() {
  return generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

describe("CoCodex encrypted local private history", () => {
  test("stores a sender self-copy as ciphertext and restores it locally", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-private-history-"));
    try {
      const path = join(root, "private-history.json");
      const localDeviceId = randomUUID();
      const peerDeviceId = randomUUID();
      const messageId = randomUUID();
      const createdAt = "2030-01-01T00:00:00.000Z";
      const canary = "LOCAL-HISTORY-PLAINTEXT-CANARY";
      const signing = signingIdentity();
      const messaging = messagingIdentity();
      const localCiphertext = await sealSignedPrivateMessage({
        messageId,
        senderDeviceId: localDeviceId,
        recipientDeviceId: peerDeviceId,
        text: canary,
        clientCreatedAt: createdAt,
      }, signing.privateKey, signing.publicKey, messaging.publicKey);
      let state = recordPrivateHistoryEntry(emptyPrivateHistory(localDeviceId), {
        messageId,
        senderDeviceId: localDeviceId,
        recipientDeviceId: peerDeviceId,
        localCiphertext,
        clientCreatedAt: createdAt,
        deliveryState: "queued",
        serverSequence: null,
        acceptedAt: null,
      });
      savePrivateHistory(path, state);
      expect(readFileSync(path, "utf8")).not.toContain(canary);
      state = acknowledgePrivateHistoryEntry(loadPrivateHistory(path, localDeviceId), {
        messageId,
        senderDeviceId: localDeviceId,
        recipientDeviceId: peerDeviceId,
        clientCreatedAt: createdAt,
        sequence: 7,
        acceptedAt: "2030-01-01T00:00:01.000Z",
      });
      savePrivateHistory(path, state);
      expect(loadPrivateHistory(path, localDeviceId).entries[0]).toMatchObject({
        deliveryState: "accepted",
        serverSequence: 7,
        acceptedAt: "2030-01-01T00:00:01.000Z",
      });
      const opened = await openSignedPrivateMessage(
        localCiphertext,
        messaging.privateKey,
        messaging.publicKey,
        { messageId, senderDeviceId: localDeviceId, recipientDeviceId: peerDeviceId, clientCreatedAt: createdAt },
        publicKeyFingerprint(signing.publicKey),
      );
      expect(opened.text).toBe(canary);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects cross-device entries, conflicting IDs, and acknowledgement changes", () => {
    const localDeviceId = randomUUID();
    const peerDeviceId = randomUUID();
    const messageId = randomUUID();
    const entry = {
      messageId,
      senderDeviceId: localDeviceId,
      recipientDeviceId: peerDeviceId,
      localCiphertext: Buffer.alloc(48, 4).toString("base64url"),
      clientCreatedAt: "2030-01-01T00:00:00.000Z",
      deliveryState: "queued" as const,
      serverSequence: null,
      acceptedAt: null,
    };
    let state = recordPrivateHistoryEntry(emptyPrivateHistory(localDeviceId), entry);
    expect(() => recordPrivateHistoryEntry(state, { ...entry, localCiphertext: Buffer.alloc(48, 5).toString("base64url") }))
      .toThrow("reused with different content");
    expect(() => recordPrivateHistoryEntry(state, {
      ...entry,
      messageId: randomUUID(),
      senderDeviceId: randomUUID(),
      recipientDeviceId: randomUUID(),
    })).toThrow("different device");
    const accepted = {
      messageId,
      senderDeviceId: localDeviceId,
      recipientDeviceId: peerDeviceId,
      clientCreatedAt: entry.clientCreatedAt,
      sequence: 2,
      acceptedAt: "2030-01-01T00:00:01.000Z",
    };
    state = acknowledgePrivateHistoryEntry(state, accepted);
    expect(() => acknowledgePrivateHistoryEntry(state, { ...accepted, sequence: 3 }))
      .toThrow("sequence changed");
  });

  test("bounds local history to the newest 512 ciphertext entries", () => {
    const localDeviceId = randomUUID();
    const peerDeviceId = randomUUID();
    let state = emptyPrivateHistory(localDeviceId);
    for (let index = 0; index < 540; index += 1) {
      state = recordPrivateHistoryEntry(state, {
        messageId: randomUUID(),
        senderDeviceId: localDeviceId,
        recipientDeviceId: peerDeviceId,
        localCiphertext: Buffer.alloc(48, index % 255).toString("base64url"),
        clientCreatedAt: new Date(Date.UTC(2030, 0, 1, 0, 0, index)).toISOString(),
        deliveryState: "accepted",
        serverSequence: index + 1,
        acceptedAt: new Date(Date.UTC(2030, 0, 1, 0, 1, index)).toISOString(),
      });
    }
    expect(state.entries).toHaveLength(512);
  });

  test("never evicts unaccepted messages to make room", () => {
    const localDeviceId = randomUUID();
    const peerDeviceId = randomUUID();
    let state = emptyPrivateHistory(localDeviceId);
    for (let index = 0; index < 512; index += 1) {
      state = recordPrivateHistoryEntry(state, {
        messageId: randomUUID(),
        senderDeviceId: localDeviceId,
        recipientDeviceId: peerDeviceId,
        localCiphertext: Buffer.alloc(48, index % 255).toString("base64url"),
        clientCreatedAt: new Date(Date.UTC(2030, 0, 1, 0, 0, index)).toISOString(),
        deliveryState: "queued",
        serverSequence: null,
        acceptedAt: null,
      });
    }
    expect(() => recordPrivateHistoryEntry(state, {
      ...state.entries[0]!,
      messageId: randomUUID(),
    })).toThrow("full of unaccepted messages");
  });

  test("reconciles staged sends against the durable outbox without replaying ghosts", () => {
    const localDeviceId = randomUUID();
    const peerDeviceId = randomUUID();
    const queuedId = randomUUID();
    const ghostId = randomUUID();
    let state = emptyPrivateHistory(localDeviceId);
    for (const messageId of [queuedId, ghostId]) {
      state = recordPrivateHistoryEntry(state, {
        messageId,
        senderDeviceId: localDeviceId,
        recipientDeviceId: peerDeviceId,
        localCiphertext: Buffer.alloc(48, 8).toString("base64url"),
        clientCreatedAt: "2030-01-01T00:00:00.000Z",
        deliveryState: "staged",
        serverSequence: null,
        acceptedAt: null,
      });
    }
    state = reconcileStagedPrivateHistory(state, new Set([queuedId]));
    expect(state.entries).toEqual([
      expect.objectContaining({ messageId: queuedId, deliveryState: "queued" }),
    ]);
    expect(markPrivateHistoryEntryQueued(state, queuedId)).toBe(state);
  });
});

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  deferPrivateMailboxMessage,
  emptyPrivateMailbox,
  hasPrivateMailboxReceipt,
  loadPrivateMailbox,
  recordPrivateMailboxReceipt,
  recordPrivateMailboxRemoteReceipt,
  savePrivateMailbox,
} from "../src/cocodex/private-mailbox";
import { inboundPrivateEnvelope } from "../src/cocodex/session";

describe("CoCodex private mailbox cursor", () => {
  test("persists an atomic cursor and bounded message receipts", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-private-mailbox-"));
    try {
      const path = join(root, "private-mailbox.json");
      const deviceId = crypto.randomUUID();
      let state = emptyPrivateMailbox(deviceId);
      const first = crypto.randomUUID();
      const second = crypto.randomUUID();
      state = recordPrivateMailboxReceipt(state, { messageId: first, sequence: 4 });
      state = recordPrivateMailboxReceipt(state, { messageId: second, sequence: 9 });
      savePrivateMailbox(path, state);
      expect(loadPrivateMailbox(path, deviceId)).toEqual(state);
      expect(loadPrivateMailbox(path, deviceId).cursor).toBe(9);
      expect(hasPrivateMailboxReceipt(state, first)).toBeTrue();
      expect(recordPrivateMailboxReceipt(state, { messageId: first, sequence: 4 })).toEqual(state);
      expect(() => loadPrivateMailbox(path, crypto.randomUUID())).toThrow("different device");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("keeps only the newest receipts to bound local state", () => {
    const deviceId = crypto.randomUUID();
    let state = emptyPrivateMailbox(deviceId);
    for (let sequence = 1; sequence <= 2_100; sequence += 1) {
      state = recordPrivateMailboxReceipt(state, { messageId: crypto.randomUUID(), sequence });
    }
    expect(state.cursor).toBe(2_100);
    expect(state.receipts).toHaveLength(2_048);
    expect(state.receipts[0]?.sequence).toBe(53);
  });

  test("persists failed deliveries for retry and removes them after decryption", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-private-mailbox-deferred-"));
    try {
      const path = join(root, "private-mailbox.json");
      const deviceId = crypto.randomUUID();
      const message = {
        sequence: 7,
        messageId: crypto.randomUUID(),
        senderDeviceId: crypto.randomUUID(),
        recipientDeviceId: deviceId,
        ciphertext: Buffer.alloc(48, 8).toString("base64url"),
        clientCreatedAt: "2027-01-01T00:00:00.000Z",
        acceptedAt: "2027-01-01T00:00:01.000Z",
      };
      let state = deferPrivateMailboxMessage(emptyPrivateMailbox(deviceId), message);
      expect(state.cursor).toBe(7);
      expect(state.deferred).toEqual([message]);
      savePrivateMailbox(path, state);
      expect(loadPrivateMailbox(path, deviceId).deferred).toEqual([message]);

      state = recordPrivateMailboxReceipt(state, { messageId: message.messageId, sequence: message.sequence });
      expect(state.deferred).toEqual([]);
      expect(hasPrivateMailboxReceipt(state, message.messageId)).toBeTrue();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("bounds deferred ciphertext state", () => {
    const deviceId = crypto.randomUUID();
    let state = emptyPrivateMailbox(deviceId);
    for (let sequence = 1; sequence <= 300; sequence += 1) {
      state = deferPrivateMailboxMessage(state, {
        sequence,
        messageId: crypto.randomUUID(),
        senderDeviceId: crypto.randomUUID(),
        recipientDeviceId: deviceId,
        ciphertext: Buffer.alloc(48, sequence % 255).toString("base64url"),
        clientCreatedAt: "2027-01-01T00:00:00.000Z",
        acceptedAt: "2027-01-01T00:00:01.000Z",
      });
    }
    expect(state.deferred).toHaveLength(256);
    expect(state.deferred[0]?.sequence).toBe(45);
    expect(state.cursor).toBe(300);
  });

  test("recovers sender-visible delivery/read receipts with an independent cursor", () => {
    const deviceId = crypto.randomUUID();
    const messageId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    let state = emptyPrivateMailbox(deviceId);
    const delivered = {
      sequence: 3,
      messageId,
      senderDeviceId: deviceId,
      recipientDeviceId,
      receipt: "delivered" as const,
      acceptedAt: "2027-01-01T00:00:00.000Z",
    };
    const read = { ...delivered, sequence: 4, receipt: "read" as const };
    state = recordPrivateMailboxRemoteReceipt(state, delivered);
    state = recordPrivateMailboxRemoteReceipt(state, read);
    expect(state.receiptCursor).toBe(4);
    expect(state.remoteReceipts).toEqual([delivered, read]);
    expect(recordPrivateMailboxRemoteReceipt(state, read)).toEqual(state);
    expect(() => recordPrivateMailboxRemoteReceipt(state, { ...read, messageId: crypto.randomUUID() })).toThrow("sequence was reused");
  });

  test("does not let a later outbound acknowledgement skip an earlier inbound delivery", () => {
    const deviceId = crypto.randomUUID();
    const peerDeviceId = crypto.randomUUID();
    let state = recordPrivateMailboxReceipt(emptyPrivateMailbox(deviceId), {
      messageId: crypto.randomUUID(),
      sequence: 1,
    });
    const outbound = {
      sequence: 3,
      messageId: crypto.randomUUID(),
      senderDeviceId: deviceId,
      recipientDeviceId: peerDeviceId,
      ciphertext: Buffer.alloc(48, 3).toString("base64url"),
      clientCreatedAt: "2027-01-01T00:00:00.000Z",
      acceptedAt: "2027-01-01T00:00:01.000Z",
    };
    expect(inboundPrivateEnvelope({ type: "private.accepted", message: outbound }))
      .toBeUndefined();
    expect(state.cursor).toBe(1);

    const inbound = {
      ...outbound,
      sequence: 2,
      messageId: crypto.randomUUID(),
      senderDeviceId: peerDeviceId,
      recipientDeviceId: deviceId,
    };
    const delivery = inboundPrivateEnvelope({ type: "private.message", message: inbound });
    expect(delivery).toEqual(inbound);
    state = recordPrivateMailboxReceipt(state, {
      messageId: delivery!.messageId,
      sequence: delivery!.sequence,
    });
    expect(state.cursor).toBe(2);
  });
});

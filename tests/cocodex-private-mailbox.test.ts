import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  emptyPrivateMailbox,
  hasPrivateMailboxReceipt,
  loadPrivateMailbox,
  recordPrivateMailboxReceipt,
  savePrivateMailbox,
} from "../src/cocodex/private-mailbox";

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
});


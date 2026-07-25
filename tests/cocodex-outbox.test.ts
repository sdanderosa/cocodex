import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { clientPaths } from "../src/cocodex/paths";
import { drainDurableOutbox, enqueueDurableEvent, queuedEvents } from "../src/cocodex/outbox";

describe("CoCodex durable offline outbox", () => {
  test("survives reload and drains acknowledged events in original order", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-outbox-"));
    const paths = clientPaths(root);
    try {
      const events = ["first", "second", "third"].map(content => ({
        version: 1 as const,
        type: "chat.send" as const,
        requestId: randomUUID(),
        projectId: randomUUID(),
        eventId: randomUUID(),
        content,
        clientCreatedAt: new Date().toISOString(),
      }));
      for (const event of events) enqueueDurableEvent(paths, event);
      expect(queuedEvents(clientPaths(root)).map(event => event.requestId))
        .toEqual(events.map(event => event.requestId));

      const delivered: string[] = [];
      await expect(drainDurableOutbox(paths, async frame => {
        if (frame.requestId === events[2]!.requestId) throw new Error("offline");
        delivered.push(frame.requestId);
      })).rejects.toThrow("offline");
      expect(delivered).toEqual(events.slice(0, 2).map(event => event.requestId));
      expect(queuedEvents(clientPaths(root))).toEqual([events[2]]);

      await drainDurableOutbox(clientPaths(root), async frame => {
        delivered.push(frame.requestId);
      });
      expect(delivered).toEqual(events.map(event => event.requestId));
      expect(queuedEvents(paths)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("does not erase an event enqueued while an earlier acknowledgement is pending", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-outbox-race-"));
    const paths = clientPaths(root);
    try {
      const projectId = randomUUID();
      const event = (content: string) => ({
        version: 1 as const, type: "chat.send" as const, requestId: randomUUID(),
        projectId, eventId: randomUUID(), content, clientCreatedAt: new Date().toISOString(),
      });
      const first = event("first");
      const second = event("second");
      enqueueDurableEvent(paths, first);
      let release!: () => void;
      const delayed = new Promise<void>(resolve => { release = resolve; });
      const delivered: string[] = [];
      const draining = drainDurableOutbox(paths, async frame => {
        delivered.push(frame.requestId);
        if (frame.requestId === first.requestId) await delayed;
      });
      await Bun.sleep(10);
      enqueueDurableEvent(paths, second);
      release();
      await draining;
      expect(delivered).toEqual([first.requestId, second.requestId]);
      expect(queuedEvents(paths)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { clientPaths } from "../src/cocodex/paths";
import { drainDurableOutbox, enqueueDurableEvent, flushDurableOutbox, queuedEvents } from "../src/cocodex/outbox";

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

  test("persists Yjs prompt updates while the collaboration server is offline", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-prompt-outbox-"));
    const paths = clientPaths(root);
    const update = {
      version: 1 as const,
      type: "prompt.update" as const,
      requestId: randomUUID(),
      projectId: randomUUID(),
      updateId: randomUUID(),
      update: "AQID",
    };
    try {
      expect(enqueueDurableEvent(paths, update)).toEqual(update);
      expect(queuedEvents(clientPaths(root))).toEqual([update]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("persists project-context updates while the collaboration server is offline", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-context-outbox-"));
    const paths = clientPaths(root);
    const update = {
      version: 1 as const,
      type: "context.update" as const,
      requestId: randomUUID(),
      projectId: randomUUID(),
      expectedRevision: 0,
      finalGoal: "Complete the private alpha",
      context: { source: "offline" },
    };
    try {
      expect(enqueueDurableEvent(paths, update)).toEqual(update);
      expect(queuedEvents(clientPaths(root))).toEqual([update]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("persists only the sealed file-reference envelope while offline", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-file-reference-outbox-"));
    const paths = clientPaths(root);
    const projectId = randomUUID();
    const referenceId = randomUUID();
    const deviceId = randomUUID();
    const frame = {
      version: 1 as const,
      type: "project.file-reference.publish" as const,
      requestId: randomUUID(),
      referenceId,
      projectId,
      artifactId: randomUUID(),
      envelope: {
        version: 1 as const,
        projectId,
        keyEpoch: 1,
        recordType: "file-reference" as const,
        recordId: referenceId,
        nonce: Buffer.alloc(24, 1).toString("base64url"),
        ciphertext: Buffer.alloc(64, 2).toString("base64url"),
        senderDeviceId: deviceId,
        senderPublicKeyPem: "P".repeat(64),
        signature: Buffer.alloc(64, 3).toString("base64url"),
      },
    };
    try {
      expect(enqueueDurableEvent(paths, frame)).toEqual(frame);
      const serialized = JSON.stringify(queuedEvents(clientPaths(root)));
      expect(serialized).toContain(frame.envelope.ciphertext);
      expect(serialized).not.toContain("C:\\Users\\Stephen\\private.txt");
      expect(serialized).not.toContain("private file bytes");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("does not let a stale project-context update block future outbox work", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-context-conflict-"));
    const paths = clientPaths(root);
    const update = {
      version: 1 as const,
      type: "context.update" as const,
      requestId: randomUUID(),
      projectId: randomUUID(),
      expectedRevision: 0,
      finalGoal: "Stale write",
      context: {},
    };
    class ErrorSocket {
      readyState = 1;
      private readonly listeners = new Map<string, Set<(event: unknown) => void>>();
      addEventListener(type: string, listener: (event: unknown) => void): void {
        const listeners = this.listeners.get(type) ?? new Set<(event: unknown) => void>();
        listeners.add(listener);
        this.listeners.set(type, listeners);
      }
      removeEventListener(type: string, listener: (event: unknown) => void): void {
        this.listeners.get(type)?.delete(listener);
      }
      send(value: string): void {
        const requestId = (JSON.parse(value) as { requestId: string }).requestId;
        setTimeout(() => {
          for (const listener of this.listeners.get("message") ?? []) {
            listener({ data: JSON.stringify({ type: "error", requestId, error: "Shared project context revision conflict" }) });
          }
        }, 0);
      }
    }
    try {
      enqueueDurableEvent(paths, update);
      await expect(flushDurableOutbox(new ErrorSocket() as unknown as WebSocket, paths))
        .rejects.toThrow("revision conflict");
      expect(queuedEvents(paths)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

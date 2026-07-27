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

  test("persists atomic member removal until a strict key-rotation acknowledgement", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-member-removal-outbox-"));
    const paths = clientPaths(root);
    const projectId = randomUUID();
    const frame = {
      version: 1 as const,
      type: "project.member.remove-and-rotate" as const,
      requestId: randomUUID(),
      projectId,
      deviceId: randomUUID(),
      expectedEpoch: 1,
      envelopes: [{
        version: 1 as const,
        projectId,
        keyEpoch: 2,
        recipientDeviceId: randomUUID(),
        senderDeviceId: randomUUID(),
        sealedProjectKey: Buffer.alloc(80, 1).toString("base64url"),
        senderPublicKeyPem: "P".repeat(64),
        signature: Buffer.alloc(64, 2).toString("base64url"),
      }],
    };
    class Socket {
      constructor(private readonly mismatch?: "project" | "epoch" | "envelope") {}
      private listeners = new Set<(event: MessageEvent) => void>();
      addEventListener(type: string, listener: (event: MessageEvent) => void) {
        if (type === "message") this.listeners.add(listener);
      }
      removeEventListener(type: string, listener: (event: MessageEvent) => void) {
        if (type === "message") this.listeners.delete(listener);
      }
      send(value: string) {
        const sent = JSON.parse(value) as typeof frame;
        const envelopes = this.mismatch === "envelope"
          ? sent.envelopes.map(envelope => ({
            ...envelope,
            sealedProjectKey: Buffer.alloc(80, 9).toString("base64url"),
          }))
          : sent.envelopes;
        queueMicrotask(() => this.listeners.forEach(listener => listener({
          data: JSON.stringify({
            version: 1,
            type: "project.key.rotated",
            requestId: sent.requestId,
            projectId: this.mismatch === "project" ? randomUUID() : sent.projectId,
            keyEpoch: this.mismatch === "epoch" ? 3 : 2,
            envelopes,
            created: true,
          }),
        } as MessageEvent)));
      }
    }
    try {
      expect(enqueueDurableEvent(paths, frame)).toEqual(frame);
      expect(queuedEvents(clientPaths(root))).toEqual([frame]);
      for (const mismatch of ["project", "epoch", "envelope"] as const) {
        await expect(flushDurableOutbox(new Socket(mismatch) as unknown as WebSocket, paths))
          .rejects.toThrow("did not match");
        expect(queuedEvents(paths)).toEqual([frame]);
      }
      expect(await flushDurableOutbox(new Socket() as unknown as WebSocket, paths)).toBe(1);
      expect(queuedEvents(paths)).toEqual([]);
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

  test("discards a terminal file-reference error so later durable work can drain", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-file-reference-terminal-"));
    const paths = clientPaths(root);
    const projectId = randomUUID();
    const referenceId = randomUUID();
    const reference = {
      version: 1 as const, type: "project.file-reference.publish" as const,
      requestId: randomUUID(), referenceId, projectId, artifactId: randomUUID(),
      envelope: {
        version: 1 as const, projectId, keyEpoch: 1, recordType: "file-reference" as const,
        recordId: referenceId, nonce: Buffer.alloc(24, 1).toString("base64url"),
        ciphertext: Buffer.alloc(64, 2).toString("base64url"), senderDeviceId: randomUUID(),
        senderPublicKeyPem: "P".repeat(64), signature: Buffer.alloc(64, 3).toString("base64url"),
      },
    };
    const chat = {
      version: 1 as const, type: "chat.send" as const, requestId: randomUUID(),
      projectId, eventId: randomUUID(), content: "next", clientCreatedAt: new Date().toISOString(),
    };
    class Socket {
      private listeners = new Set<(event: MessageEvent) => void>();
      addEventListener(type: string, listener: (event: MessageEvent) => void) { if (type === "message") this.listeners.add(listener); }
      removeEventListener(type: string, listener: (event: MessageEvent) => void) { if (type === "message") this.listeners.delete(listener); }
      send(value: string) {
        const sent = JSON.parse(value) as { requestId: string; type: string };
        const response = sent.type === "project.file-reference.publish"
          ? { type: "error", requestId: sent.requestId, error: "File-reference artifact is not in this project" }
          : { type: "chat.accepted", requestId: sent.requestId };
        queueMicrotask(() => this.listeners.forEach(listener => listener({ data: JSON.stringify(response) } as MessageEvent)));
      }
    }
    try {
      enqueueDurableEvent(paths, reference);
      enqueueDurableEvent(paths, chat);
      const socket = new Socket() as unknown as WebSocket;
      await expect(flushDurableOutbox(socket, paths)).rejects.toThrow("File-reference artifact");
      expect(queuedEvents(paths)).toEqual([chat]);
      expect(await flushDurableOutbox(socket, paths)).toBe(1);
      expect(queuedEvents(paths)).toEqual([]);
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

  test("purges every queued write for an authoritatively revoked project", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-revoked-project-outbox-"));
    const paths = clientPaths(root);
    const revokedProjectId = randomUUID();
    const retainedProjectId = randomUUID();
    const makeChat = (projectId: string, content: string) => ({
      version: 1 as const,
      type: "chat.send" as const,
      requestId: randomUUID(),
      projectId,
      eventId: randomUUID(),
      content,
      clientCreatedAt: new Date().toISOString(),
    });
    const revokedFirst = makeChat(revokedProjectId, "queued before revocation");
    const revokedSecond = makeChat(revokedProjectId, "also terminal");
    const retained = makeChat(retainedProjectId, "other project remains durable");
    class RevokedSocket {
      private listeners = new Set<(event: MessageEvent) => void>();
      addEventListener(type: string, listener: (event: MessageEvent) => void) {
        if (type === "message") this.listeners.add(listener);
      }
      removeEventListener(type: string, listener: (event: MessageEvent) => void) {
        if (type === "message") this.listeners.delete(listener);
      }
      send(value: string) {
        const sent = JSON.parse(value) as { requestId: string };
        queueMicrotask(() => this.listeners.forEach(listener => listener({
          data: JSON.stringify({
            type: "error",
            requestId: sent.requestId,
            error: "Device is not an approved project member",
          }),
        } as MessageEvent)));
      }
    }
    try {
      enqueueDurableEvent(paths, revokedFirst);
      enqueueDurableEvent(paths, revokedSecond);
      enqueueDurableEvent(paths, retained);
      await expect(flushDurableOutbox(new RevokedSocket() as unknown as WebSocket, paths))
        .rejects.toThrow("not an approved project member");
      expect(queuedEvents(paths)).toEqual([retained]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects only a revoked-recipient private send and continues draining later work", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-revoked-private-outbox-"));
    const paths = clientPaths(root);
    const privateFrame = {
      version: 1 as const,
      type: "private.send" as const,
      requestId: randomUUID(),
      messageId: randomUUID(),
      recipientDeviceId: randomUUID(),
      ciphertext: Buffer.alloc(80, 7).toString("base64url"),
      clientCreatedAt: "2030-01-01T00:00:00.000Z",
    };
    const chatFrame = {
      version: 1 as const,
      type: "chat.send" as const,
      requestId: randomUUID(),
      projectId: randomUUID(),
      eventId: randomUUID(),
      content: "later durable work",
      clientCreatedAt: "2030-01-01T00:00:01.000Z",
    };
    const rejected: Array<{ requestId: string; reason: string }> = [];
    class Socket {
      private listeners = new Set<(event: MessageEvent) => void>();
      addEventListener(type: string, listener: (event: MessageEvent) => void) {
        if (type === "message") this.listeners.add(listener);
      }
      removeEventListener(type: string, listener: (event: MessageEvent) => void) {
        if (type === "message") this.listeners.delete(listener);
      }
      send(value: string) {
        const sent = JSON.parse(value) as { type: string; requestId: string };
        queueMicrotask(() => this.listeners.forEach(listener => listener({
          data: JSON.stringify(sent.type === "private.send"
            ? {
              version: 1,
              type: "error",
              requestId: sent.requestId,
              error: "Private-message device is not approved",
            }
            : {
              version: 1,
              type: "chat.accepted",
              requestId: sent.requestId,
            }),
        } as MessageEvent)));
      }
    }
    try {
      enqueueDurableEvent(paths, privateFrame);
      enqueueDurableEvent(paths, chatFrame);
      expect(await flushDurableOutbox(new Socket() as unknown as WebSocket, paths, {
        onTerminalRejection: (frame, reason) => rejected.push({ requestId: frame.requestId, reason }),
      })).toBe(1);
      expect(rejected).toEqual([{
        requestId: privateFrame.requestId,
        reason: "Private-message device is not approved",
      }]);
      expect(queuedEvents(paths)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { clientPaths } from "../src/cocodex/paths";
import {
  enqueueDurableEvent,
  flushDurableOutbox,
  queuedEvents,
} from "../src/cocodex/outbox";

function leaveFrame(projectId = randomUUID()) {
  return {
    version: 1 as const,
    type: "project.member.leave" as const,
    requestId: randomUUID(),
    projectId,
    serverFingerprint: "AA:BB:CC:DD:EE:FF",
    serverEpoch: 4,
    issuedAt: "2030-01-01T00:00:00.000Z",
    expiresAt: "2030-01-01T00:02:00.000Z",
    nonce: randomBytes(32).toString("base64url"),
    signature: randomBytes(64).toString("base64url"),
  };
}

class Socket {
  private listeners = new Set<(event: MessageEvent) => void>();
  constructor(private readonly response: (frame: ReturnType<typeof leaveFrame>) => object) {}
  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    if (type === "message") this.listeners.add(listener);
  }
  removeEventListener(type: string, listener: (event: MessageEvent) => void) {
    if (type === "message") this.listeners.delete(listener);
  }
  send(value: string) {
    const sent = JSON.parse(value) as ReturnType<typeof leaveFrame>;
    queueMicrotask(() => this.listeners.forEach(listener => listener({
      data: JSON.stringify(this.response(sent)),
    } as MessageEvent)));
  }
}

describe("durable project leave", () => {
  test("persists until a strict matching Server leave acknowledgement", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-project-leave-outbox-"));
    const paths = clientPaths(root);
    const frame = leaveFrame();
    try {
      expect(enqueueDurableEvent(paths, frame)).toEqual(frame);
      const socket = new Socket(sent => ({
        version: 1,
        type: "project.member.leave-requested",
        requestId: sent.requestId,
        projectId: sent.projectId,
        deviceId: randomUUID(),
        requestedAt: "2030-01-01T00:00:01.000Z",
        created: true,
      }));
      expect(await flushDurableOutbox(socket as unknown as WebSocket, paths)).toBe(1);
      expect(queuedEvents(paths)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects mismatched acknowledgements and drops terminal pending conflicts", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-project-leave-outbox-errors-"));
    const paths = clientPaths(root);
    const frame = leaveFrame();
    try {
      enqueueDurableEvent(paths, frame);
      const mismatch = new Socket(sent => ({
        version: 1,
        type: "project.member.leave-requested",
        requestId: sent.requestId,
        projectId: randomUUID(),
        deviceId: randomUUID(),
        requestedAt: "2030-01-01T00:00:01.000Z",
        created: true,
      }));
      await expect(flushDurableOutbox(mismatch as unknown as WebSocket, paths))
        .rejects.toThrow("did not match");
      expect(queuedEvents(paths)).toEqual([frame]);

      const terminal = new Socket(sent => ({
        version: 1,
        type: "error",
        requestId: sent.requestId,
        error: "A different project-leave request is already pending",
      }));
      await expect(flushDurableOutbox(terminal as unknown as WebSocket, paths))
        .rejects.toThrow("already pending");
      expect(queuedEvents(paths)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

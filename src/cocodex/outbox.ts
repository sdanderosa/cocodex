import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { clientFrameSchema, type ClientFrame } from "@cocodex/protocol";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import type { ClientPaths } from "./paths";

type DurableFrame = Extract<ClientFrame, { type: "chat.send" | "private.send" | "agent.request" }>;

interface OutboxFile {
  version: 1;
  events: DurableFrame[];
}

function parseOutbox(path: string): OutboxFile {
  if (!existsSync(path)) return { version: 1, events: [] };
  hardenSecretPath(path, { required: true });
  const value = JSON.parse(readFileSync(path, "utf8")) as { version?: unknown; events?: unknown };
  if (value.version !== 1 || !Array.isArray(value.events)) throw new Error("Invalid CoCodex outbox");
  const events = value.events.map(event => {
    const frame = clientFrameSchema.parse(event);
    if (frame.type !== "chat.send" && frame.type !== "private.send" && frame.type !== "agent.request") {
      throw new Error("Unsupported durable CoCodex event");
    }
    return frame;
  });
  return { version: 1, events };
}

function saveOutbox(path: string, events: DurableFrame[]): void {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({ version: 1, events }, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function queuedEvents(paths: ClientPaths): DurableFrame[] {
  return parseOutbox(paths.outbox).events;
}

export function enqueueDurableEvent(paths: ClientPaths, value: unknown): DurableFrame {
  const frame = clientFrameSchema.parse(value);
  if (frame.type !== "chat.send" && frame.type !== "private.send" && frame.type !== "agent.request") {
    throw new Error("Only chat, private-message, and agent requests can be queued durably");
  }
  const events = parseOutbox(paths.outbox).events;
  const duplicate = events.find(event => event.requestId === frame.requestId);
  if (duplicate) {
    if (JSON.stringify(duplicate) !== JSON.stringify(frame)) {
      throw new Error("Outbox request ID was reused with different content");
    }
    return duplicate;
  }
  events.push(frame);
  saveOutbox(paths.outbox, events);
  return frame;
}

export async function drainDurableOutbox(
  paths: ClientPaths,
  deliver: (frame: DurableFrame) => Promise<void>,
): Promise<number> {
  let delivered = 0;
  while (true) {
    const next = parseOutbox(paths.outbox).events[0];
    if (!next) break;
    await deliver(next);
    const current = parseOutbox(paths.outbox).events;
    const index = current.findIndex(event => event.requestId === next.requestId);
    if (index < 0) continue;
    current.splice(index, 1);
    saveOutbox(paths.outbox, current);
    delivered += 1;
  }
  return delivered;
}

export async function flushDurableOutbox(socket: WebSocket, paths: ClientPaths): Promise<number> {
  return drainDurableOutbox(paths, frame => new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error("Timed out waiting for outbox acknowledgement")), 10_000);
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
      error ? reject(error) : resolve();
    };
    const onClose = () => finish(new Error("Connection closed while draining outbox"));
    const onMessage = (event: MessageEvent) => {
      const response = JSON.parse(String(event.data)) as Record<string, unknown>;
      if (response.requestId !== frame.requestId) return;
      if (response.type === "error") finish(new Error(String(response.error)));
      else if (response.type === "chat.accepted" || response.type === "private.accepted"
        || response.type === "agent.accepted") finish();
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
    socket.send(JSON.stringify(frame));
  }));
}

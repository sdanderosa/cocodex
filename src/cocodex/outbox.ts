import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  clientFrameSchema,
  projectKeyRotatedFrameSchema,
  projectMemberLeaveRequestedFrameSchema,
  type ClientFrame,
} from "../../packages/cocodex-protocol/src/index.ts";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import type { ClientPaths } from "./paths";

type DurableFrame = Extract<ClientFrame, { type: "chat.send" | "project.chat.send" | "private.send" | "private.receipt.send" | "agent.request" | "project.agent.request" | "prompt.update" | "project.prompt.update" | "artifact.publish" | "project.artifact.publish" | "project.file-reference.publish" | "context.update" | "project.context.update" | "project.member.remove-and-rotate" | "project.member.leave" }>;

export interface FlushDurableOutboxOptions {
  onTerminalRejection?: (frame: DurableFrame, reason: string) => void;
}

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
    if (frame.type !== "chat.send" && frame.type !== "project.chat.send" && frame.type !== "private.send" && frame.type !== "private.receipt.send" && frame.type !== "agent.request" && frame.type !== "project.agent.request"
      && frame.type !== "prompt.update" && frame.type !== "project.prompt.update" && frame.type !== "artifact.publish" && frame.type !== "project.artifact.publish" && frame.type !== "context.update"
      && frame.type !== "project.file-reference.publish" && frame.type !== "project.context.update"
      && frame.type !== "project.member.remove-and-rotate" && frame.type !== "project.member.leave") {
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

function discardQueuedEvent(path: string, requestId: string): void {
  const events = parseOutbox(path).events;
  const index = events.findIndex(event => event.requestId === requestId);
  if (index < 0) return;
  events.splice(index, 1);
  saveOutbox(path, events);
}

export function discardQueuedProjectEvents(paths: ClientPaths, projectId: string): number {
  const events = parseOutbox(paths.outbox).events;
  const retained = events.filter(event => !("projectId" in event) || event.projectId !== projectId);
  const removed = events.length - retained.length;
  if (removed > 0) saveOutbox(paths.outbox, retained);
  return removed;
}

function sameEnvelopeSet(
  left: readonly { recipientDeviceId: string }[],
  right: readonly { recipientDeviceId: string }[],
): boolean {
  if (left.length !== right.length) return false;
  const canonical = (values: readonly { recipientDeviceId: string }[]) =>
    values.map(value => JSON.stringify(value)).sort();
  const expected = canonical(left);
  const actual = canonical(right);
  return expected.every((value, index) => value === actual[index]);
}

export function queuedEvents(paths: ClientPaths): DurableFrame[] {
  return parseOutbox(paths.outbox).events;
}

export function enqueueDurableEvent(paths: ClientPaths, value: unknown): DurableFrame {
  const frame = clientFrameSchema.parse(value);
  if (frame.type !== "chat.send" && frame.type !== "project.chat.send" && frame.type !== "private.send" && frame.type !== "private.receipt.send" && frame.type !== "agent.request" && frame.type !== "project.agent.request"
      && frame.type !== "prompt.update" && frame.type !== "project.prompt.update" && frame.type !== "artifact.publish" && frame.type !== "project.artifact.publish" && frame.type !== "context.update"
      && frame.type !== "project.file-reference.publish" && frame.type !== "project.context.update"
      && frame.type !== "project.member.remove-and-rotate" && frame.type !== "project.member.leave") {
    throw new Error("Only supported collaboration updates and atomic member-removal rotations can be queued durably");
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

export async function flushDurableOutbox(
  socket: WebSocket,
  paths: ClientPaths,
  options: FlushDurableOutboxOptions = {},
): Promise<number> {
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
      let response: Record<string, unknown>;
      try { response = JSON.parse(String(event.data)) as Record<string, unknown>; }
      catch { return; }
      if (response.requestId !== frame.requestId) return;
      if (response.type === "error") {
        const message = String(response.error);
        const normalizedMessage = message.toLowerCase();
        // An optimistic context write cannot ever succeed on a retry once the
        // server has advanced the revision. Keep transient failures durable,
        // but discard this non-retryable event so it cannot block later work.
        if ("projectId" in frame
          && normalizedMessage.includes("device is not an approved project member")) {
          discardQueuedProjectEvents(paths, frame.projectId);
        } else if ("projectId" in frame && message.startsWith("PROJECT_LOCKED:")) {
          // A lock is an authoritative execution freeze. Never replay a
          // pre-lock mutation after unlock; the user must explicitly resubmit
          // it against the newly observed project state.
          discardQueuedEvent(paths.outbox, frame.requestId);
          options.onTerminalRejection?.(frame, message);
          finish();
          return;
        } else if (frame.type === "private.send"
          && normalizedMessage.includes("private-message device is not approved")) {
          // A revoked or deleted recipient can never accept this immutable
          // ciphertext envelope. Drop only this message and continue draining
          // later durable work instead of permanently head-of-line blocking it.
          discardQueuedEvent(paths.outbox, frame.requestId);
          options.onTerminalRejection?.(frame, message);
          finish();
          return;
        } else if ((frame.type === "context.update" || frame.type === "project.context.update") && message.includes("revision conflict")) {
          discardQueuedEvent(paths.outbox, frame.requestId);
        } else if (frame.type === "project.context.update" && message.includes("replay conflict")) {
          // Two clients may race the deterministic legacy-context migration;
          // the first accepted envelope is authoritative and this retry is
          // terminal rather than an outbox head-of-line blocker.
          discardQueuedEvent(paths.outbox, frame.requestId);
        } else if (frame.type === "project.file-reference.publish"
          && (normalizedMessage.includes("file-reference artifact")
            || normalizedMessage.includes("artifact host")
            || normalizedMessage.includes("file-reference id")
            || normalizedMessage.includes("file-reference record id")
            || normalizedMessage.includes("file-reference project limit")
            || normalizedMessage.includes("file-reference envelope must use the current"))) {
          discardQueuedEvent(paths.outbox, frame.requestId);
        } else if ((frame.type === "project.member.remove-and-rotate"
          || frame.type === "project.member.leave")
          && (normalizedMessage.includes("project member removal")
            || normalizedMessage.includes("project key rotation conflict")
            || normalizedMessage.includes("project-leave")
            || normalizedMessage.includes("project leave")
            || normalizedMessage.includes("leave request")
            || normalizedMessage.includes("device is not a project member")
            || normalizedMessage.includes("project owner"))) {
          // Membership/epoch/recipient-set conflicts cannot become valid by
          // replaying the same sealed batch. Drop this exact operation so the
          // owner can refresh the authoritative roster and retry safely.
          discardQueuedEvent(paths.outbox, frame.requestId);
        } else if (message.includes("Project requires encrypted content frames")
          || message.includes("Project key rotation is required")) {
          // A legacy queued event cannot be safely replayed after a project
          // enters encrypted mode or awaits key rotation. Drop only this
          // terminal event so it cannot block later durable work.
          discardQueuedEvent(paths.outbox, frame.requestId);
        }
        finish(new Error(message));
      }
      else if (response.type === "project.key.rotated" && frame.type === "project.member.remove-and-rotate") {
        const parsed = projectKeyRotatedFrameSchema.safeParse(response);
        if (!parsed.success) return;
        if (parsed.data.projectId !== frame.projectId
          || parsed.data.keyEpoch !== frame.expectedEpoch + 1
          || !sameEnvelopeSet(parsed.data.envelopes, frame.envelopes)) {
          finish(new Error("Project member removal acknowledgement did not match the queued operation"));
          return;
        }
        finish();
      }
      else if (response.type === "project.member.leave-requested" && frame.type === "project.member.leave") {
        const parsed = projectMemberLeaveRequestedFrameSchema.safeParse(response);
        if (!parsed.success) return;
        if (parsed.data.projectId !== frame.projectId) {
          finish(new Error("Project-leave acknowledgement did not match the queued request"));
          return;
        }
        finish();
      }
      else if (response.type === "chat.accepted" || response.type === "project.chat.accepted" || response.type === "private.accepted" || response.type === "private.receipt.accepted"
        || response.type === "agent.accepted" || response.type === "project.agent.accepted" || response.type === "prompt.accepted" || response.type === "project.prompt.accepted"
        || response.type === "artifact.accepted" || response.type === "project.artifact.accepted" || response.type === "context.updated"
        || response.type === "project.context.updated" || response.type === "project.file-reference.accepted") finish();
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
    socket.send(JSON.stringify(frame));
  }));
}

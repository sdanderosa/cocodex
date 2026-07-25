import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { attachLocalAgentBridge } from "./agent-bridge";
import { loadLocalAgentPolicy } from "./agent-policy";
import { CodexAgentAdapter, type CodexUsage } from "./codex-agent-adapter";
import { loadClientConnection, maintainAuthenticatedClient, sendAgentRequest } from "./client";
import { loadOrCreateClientIdentity } from "./identity";
import { enqueueDurableEvent, flushDurableOutbox } from "./outbox";
import type { ClientPaths } from "./paths";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "./private-messaging";

interface ControlCommand extends Record<string, unknown> {
  id?: string;
  type: string;
}

export interface JsonLineSessionOptions {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  errorOutput?: NodeJS.WritableStream;
}

export async function runJsonLineSession(
  paths: ClientPaths,
  options: JsonLineSessionOptions = {},
): Promise<void> {
  const output = options.output ?? process.stdout;
  const errorOutput = options.errorOutput ?? process.stderr;
  const connection = loadClientConnection(paths);
  const identity = loadOrCreateClientIdentity(paths);
  const controller = new AbortController();
  const chatCursors = new Map<string, number>();
  let privateCursor = 0;
  let socket: WebSocket | undefined;
  let flushChain = Promise.resolve(0);
  const emit = (value: unknown) => output.write(`${JSON.stringify(value)}\n`);
  const emitError = (value: unknown) => errorOutput.write(`${JSON.stringify(value)}\n`);
  const send = (frame: unknown) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) throw new Error("CoCodex Server is offline");
    socket.send(JSON.stringify(frame));
  };
  const flush = () => {
    if (!socket || socket.readyState !== WebSocket.OPEN) return Promise.resolve(0);
    flushChain = flushChain.then(() => flushDurableOutbox(socket!, paths));
    return flushChain;
  };

  const session = maintainAuthenticatedClient(paths, async connected => {
    socket = connected;
    const listener = (event: MessageEvent) => {
      const frame = JSON.parse(String(event.data)) as Record<string, any>;
      if (frame.type === "chat.snapshot") {
        const latest = frame.events?.at(-1)?.sequence;
        if (typeof latest === "number") chatCursors.set(frame.projectId, latest);
      } else if (frame.type === "chat.event" || frame.type === "agent.result") {
        const item = frame.event;
        if (item?.projectId && typeof item.sequence === "number") {
          chatCursors.set(item.projectId, Math.max(chatCursors.get(item.projectId) ?? 0, item.sequence));
        }
      } else if (frame.type === "private.snapshot") {
        const latest = frame.messages?.at(-1)?.sequence;
        if (typeof latest === "number") privateCursor = Math.max(privateCursor, latest);
      } else if (frame.type === "private.message" && typeof frame.message?.sequence === "number") {
        privateCursor = Math.max(privateCursor, frame.message.sequence);
        if (frame.message.recipientDeviceId === connection.deviceId) {
          const policy = existsSync(paths.agentPolicy) ? loadLocalAgentPolicy(paths.agentPolicy) : undefined;
          const trusted = policy?.trustedRequesterFingerprints[frame.message.senderDeviceId];
          void openSignedPrivateMessage(
            frame.message.ciphertext,
            identity.messagingPrivateKeyPem,
            identity.messagingPublicKeyPem,
            frame.message,
            trusted,
          ).then(opened => emit({
            source: "private",
            message: { ...frame.message, ciphertext: undefined, text: opened.text },
          })).catch(error => emitError({
            source: "private",
            error: error instanceof Error ? error.message : String(error),
          }));
        }
      }
      emit({ source: "server", frame });
    };
    connected.addEventListener("message", listener);
    const flushedEvents = await flush();
    for (const [projectId, afterSequence] of chatCursors) {
      send({ version: 1, type: "chat.subscribe", requestId: randomUUID(), projectId, afterSequence });
    }
    send({ version: 1, type: "private.subscribe", requestId: randomUUID(), afterSequence: privateCursor });
    let detachAgent: (() => void) | undefined;
    if (existsSync(paths.agentPolicy)) {
      const policy = loadLocalAgentPolicy(paths.agentPolicy);
      const onUsage = (usage: CodexUsage) => emit({
        source: "local-usage",
        deviceId: connection.deviceId,
        usage,
      });
      detachAgent = attachLocalAgentBridge(connected, new CodexAgentAdapter({
        projectId: policy.projectId,
        agentId: policy.agentId,
        workspaceRoot: policy.workspaceRoot,
        sandbox: policy.sandbox,
        onUsage,
      }), {
        localDeviceId: connection.deviceId,
        serverPublicKeyPem: connection.serverIdentityPublicKeyPem,
        trustedRequesterFingerprints: new Map(Object.entries(policy.trustedRequesterFingerprints)),
      });
    }
    emit({ source: "session", state: "connected", deviceId: connection.deviceId, flushedEvents });
    return () => {
      connected.removeEventListener("message", listener);
      detachAgent?.();
      if (socket === connected) socket = undefined;
      emit({ source: "session", state: "disconnected", deviceId: connection.deviceId });
    };
  }, {
    signal: controller.signal,
    onConnectionError: error => emitError({ source: "session", state: "retrying", error: error.message }),
  });

  const lines = createInterface({
    input: options.input ?? process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  });
  try {
    for await (const raw of lines) {
      let command: ControlCommand | undefined;
      try {
        command = JSON.parse(raw) as ControlCommand;
        if (!command || typeof command.type !== "string") throw new Error("Command type is required");
        if (command.type === "shutdown") {
          emit({ source: "control", id: command.id, ok: true });
          controller.abort();
          socket?.close();
          break;
        }
        if (command.type === "project.list") {
          send({ version: 1, type: "project.list", requestId: command.id ?? randomUUID() });
        } else if (command.type === "chat.subscribe") {
          const projectId = String(command.projectId);
          const afterSequence = Number(command.afterSequence ?? chatCursors.get(projectId) ?? 0);
          chatCursors.set(projectId, afterSequence);
          send({
            version: 1,
            type: "chat.subscribe",
            requestId: command.id ?? randomUUID(),
            projectId,
            afterSequence,
          });
        } else if (command.type === "chat.send") {
          const eventId = String(command.eventId ?? randomUUID());
          enqueueDurableEvent(paths, {
            version: 1,
            type: "chat.send",
            requestId: command.id ?? randomUUID(),
            projectId: String(command.projectId),
            eventId,
            content: String(command.content),
            clientCreatedAt: String(command.clientCreatedAt ?? new Date().toISOString()),
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, eventId });
        } else if (command.type === "agent.request") {
          if (!socket) throw new Error("CoCodex Server is offline");
          const taskId = sendAgentRequest(
            socket,
            String(command.projectId),
            String(command.agentId),
            String(command.prompt),
            paths,
          );
          emit({ source: "control", id: command.id, ok: true, taskId });
        } else if (command.type === "private.send") {
          const messageId = String(command.messageId ?? randomUUID());
          const clientCreatedAt = String(command.clientCreatedAt ?? new Date().toISOString());
          const recipientDeviceId = String(command.recipientDeviceId);
          const ciphertext = await sealSignedPrivateMessage({
            messageId,
            senderDeviceId: connection.deviceId,
            recipientDeviceId,
            text: String(command.text),
            clientCreatedAt,
          }, identity.privateKeyPem, identity.publicKeyPem, String(command.recipientMessagingPublicKeyPem));
          enqueueDurableEvent(paths, {
            version: 1,
            type: "private.send",
            requestId: command.id ?? randomUUID(),
            messageId,
            recipientDeviceId,
            ciphertext,
            clientCreatedAt,
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, messageId });
        } else {
          throw new Error(`Unknown control command: ${command.type}`);
        }
      } catch (error) {
        emit({
          source: "control",
          id: command?.id,
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  } finally {
    controller.abort();
    socket?.close();
    lines.close();
    await session;
  }
}

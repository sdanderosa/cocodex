import { randomUUID } from "node:crypto";
import type { AgentTask } from "@cocodex/protocol";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { attachLocalAgentBridge } from "./agent-bridge";
import { loadLocalAgentPolicy } from "./agent-policy";
import { CodexAgentAdapter, type CodexUsage } from "./codex-agent-adapter";
import { createAgentRequest, loadClientConnection, maintainAuthenticatedClient } from "./client";
import { loadOrCreateClientIdentity, verifyDeviceKeyCertificate } from "./identity";
import { enqueueDurableEvent, flushDurableOutbox } from "./outbox";
import type { ClientPaths } from "./paths";
import { openSignedPrivateMessage, sealSignedPrivateMessage } from "./private-messaging";
import { loadTrustedDevices, trustDevice } from "./trusted-devices";

interface ControlCommand extends Record<string, unknown> {
  id?: string;
  type: string;
}

function controlRequestId(value: unknown): string {
  return typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    ? value
    : randomUUID();
}

const SNAPSHOT_PAGE_SIZE = 500;

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
  const promptSubscriptions = new Set<string>();
  const contextSubscriptions = new Set<string>();
  let privateCursor = 0;
  let socket: WebSocket | undefined;
  let flushChain = Promise.resolve(0);
  const pendingAgentApprovals = new Map<string, (approved: boolean) => void>();
  const emit = (value: unknown) => output.write(`${JSON.stringify(value)}\n`);
  const emitError = (value: unknown) => errorOutput.write(`${JSON.stringify(value)}\n`);
  const send = (frame: unknown) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) throw new Error("CoCodex Server is offline");
    socket.send(JSON.stringify(frame));
  };
  const flush = () => {
    if (!socket || socket.readyState !== WebSocket.OPEN) return Promise.resolve(0);
    // A connection can disappear while an outbox flush is in flight. Recover
    // the serialization chain so that a transient failure cannot permanently
    // prevent later reconnects from draining durable events.
    flushChain = flushChain.catch(() => 0).then(() => flushDurableOutbox(socket!, paths));
    return flushChain;
  };
  const authorizeAgentTask = (task: AgentTask, signal?: AbortSignal): Promise<boolean> => new Promise(resolve => {
    if (pendingAgentApprovals.has(task.id) || signal?.aborted) return resolve(false);
    const finish = (approved: boolean) => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", onAbort);
      pendingAgentApprovals.delete(task.id);
      emit({ source: "agent-approval", approvalState: "resolved", taskId: task.id, approved });
      resolve(approved);
    };
    const timeout = setTimeout(() => finish(false), 5 * 60_000);
    const onAbort = () => finish(false);
    pendingAgentApprovals.set(task.id, finish);
    signal?.addEventListener("abort", onAbort, { once: true });
    emit({
      source: "agent-approval",
      approvalState: "pending",
      task: {
        id: task.id,
        projectId: task.projectId,
        agentId: task.agentId,
        requesterDeviceId: task.requesterDeviceId,
        prompt: task.prompt,
      },
    });
  });
  const openPrivateEnvelope = (message: {
    messageId: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    clientCreatedAt: string;
    ciphertext: string;
    sequence?: number;
  }) => {
    if (message.recipientDeviceId !== connection.deviceId) return;
    const trusted = loadTrustedDevices(paths.trustedDevices)[message.senderDeviceId];
    if (!trusted) {
      emitError({
        source: "private",
        error: `Private-message sender ${message.senderDeviceId} is not an approved device`,
      });
      return;
    }
    void openSignedPrivateMessage(
      message.ciphertext,
      identity.messagingPrivateKeyPem,
      identity.messagingPublicKeyPem,
      message,
      trusted,
    ).then(opened => emit({
      source: "private",
      message: { ...message, ciphertext: undefined, text: opened.text },
    })).catch(error => emitError({
      source: "private",
      error: error instanceof Error ? error.message : String(error),
    }));
  };

  const session = maintainAuthenticatedClient(paths, async connected => {
    socket = connected;
    const listener = (event: MessageEvent) => {
      let frame: Record<string, any>;
      try { frame = JSON.parse(String(event.data)) as Record<string, any>; }
      catch { return; }
      if (frame.type === "chat.snapshot") {
        const events = Array.isArray(frame.events) ? frame.events : [];
        const latest = events.at(-1)?.sequence;
        if (typeof latest === "number") chatCursors.set(frame.projectId, latest);
        if (events.length === SNAPSHOT_PAGE_SIZE && typeof latest === "number") {
          send({
            version: 1,
            type: "chat.subscribe",
            requestId: randomUUID(),
            projectId: frame.projectId,
            afterSequence: latest,
          });
        }
      } else if (frame.type === "chat.event" || frame.type === "agent.result") {
        const item = frame.event;
        if (item?.projectId && typeof item.sequence === "number") {
          chatCursors.set(item.projectId, Math.max(chatCursors.get(item.projectId) ?? 0, item.sequence));
        }
      } else if (frame.type === "private.snapshot") {
        const messages = Array.isArray(frame.messages) ? frame.messages : [];
        for (const message of messages) openPrivateEnvelope(message);
        const latest = messages.at(-1)?.sequence;
        if (typeof latest === "number") privateCursor = Math.max(privateCursor, latest);
        if (messages.length === SNAPSHOT_PAGE_SIZE && typeof latest === "number") {
          send({
            version: 1,
            type: "private.subscribe",
            requestId: randomUUID(),
            afterSequence: latest,
          });
        }
      } else if (frame.type === "private.message" && typeof frame.message?.sequence === "number") {
        privateCursor = Math.max(privateCursor, frame.message.sequence);
        openPrivateEnvelope(frame.message);
      }
      emit({ source: "server", frame });
    };
    connected.addEventListener("message", listener);
    const flushedEvents = await flush();
    for (const [projectId, afterSequence] of chatCursors) {
      send({ version: 1, type: "chat.subscribe", requestId: randomUUID(), projectId, afterSequence });
    }
    for (const projectId of promptSubscriptions) {
      send({ version: 1, type: "prompt.subscribe", requestId: randomUUID(), projectId });
    }
    for (const projectId of contextSubscriptions) {
      send({ version: 1, type: "context.get", requestId: randomUUID(), projectId });
    }
    send({ version: 1, type: "private.subscribe", requestId: randomUUID(), afterSequence: privateCursor });
    let detachAgent: (() => void | Promise<void>) | undefined;
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
        authorizeTask: policy.approvalMode === "always" ? authorizeAgentTask : () => true,
      }), {
        localDeviceId: connection.deviceId,
        serverPublicKeyPem: connection.serverIdentityPublicKeyPem,
        trustedRequesterFingerprints: new Map(Object.entries(policy.trustedRequesterFingerprints)),
        journalPath: paths.agentJournal,
      });
    }
    emit({ source: "session", state: "connected", deviceId: connection.deviceId, flushedEvents });
    return async () => {
      connected.removeEventListener("message", listener);
      await detachAgent?.();
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
          send({ version: 1, type: "project.list", requestId: controlRequestId(command.id) });
        } else if (command.type === "chat.subscribe") {
          const projectId = String(command.projectId);
          const afterSequence = Number(command.afterSequence ?? chatCursors.get(projectId) ?? 0);
          chatCursors.set(projectId, afterSequence);
          send({
            version: 1,
            type: "chat.subscribe",
            requestId: controlRequestId(command.id),
            projectId,
            afterSequence,
          });
        } else if (command.type === "prompt.subscribe") {
          const projectId = String(command.projectId);
          promptSubscriptions.add(projectId);
          send({
            version: 1,
            type: "prompt.subscribe",
            requestId: controlRequestId(command.id),
            projectId,
          });
        } else if (command.type === "context.get") {
          const projectId = String(command.projectId);
          contextSubscriptions.add(projectId);
          send({
            version: 1,
            type: "context.get",
            requestId: controlRequestId(command.id),
            projectId,
          });
        } else if (command.type === "context.update") {
          const projectId = String(command.projectId);
          contextSubscriptions.add(projectId);
          enqueueDurableEvent(paths, {
            version: 1,
            type: "context.update",
            requestId: controlRequestId(command.id),
            projectId,
            expectedRevision: Number(command.expectedRevision ?? 0),
            finalGoal: String(command.finalGoal ?? ""),
            context: command.context ?? {},
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, projectId });
        } else if (command.type === "prompt.update") {
          const updateId = String(command.updateId ?? randomUUID());
          enqueueDurableEvent(paths, {
            version: 1,
            type: "prompt.update",
            requestId: controlRequestId(command.id),
            projectId: String(command.projectId),
            updateId,
            update: String(command.update),
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, updateId });
        } else if (command.type === "chat.send") {
          const eventId = String(command.eventId ?? randomUUID());
          enqueueDurableEvent(paths, {
            version: 1,
            type: "chat.send",
            requestId: controlRequestId(command.id),
            projectId: String(command.projectId),
            eventId,
            content: String(command.content),
            clientCreatedAt: String(command.clientCreatedAt ?? new Date().toISOString()),
          });
          const delivered = await flush();
          emit({ source: "control", id: command.id, ok: true, queued: delivered === 0, eventId });
        } else if (command.type === "agent.request") {
          const request = createAgentRequest(
            String(command.projectId),
            String(command.agentId),
            String(command.prompt),
            paths,
            Array.isArray(command.dependencies) ? command.dependencies.map(String) : [],
          );
          enqueueDurableEvent(paths, {
            ...request,
          });
          const delivered = await flush();
          emit({
            source: "control",
            id: command.id,
            ok: true,
            queued: delivered === 0,
            taskId: request.taskId,
          });
        } else if (command.type === "agent.approval") {
          const taskId = String(command.taskId);
          const pending = pendingAgentApprovals.get(taskId);
          if (!pending) throw new Error("Agent task is not awaiting local approval");
          pending(command.approved === true);
          emit({ source: "control", id: command.id, ok: true, taskId, approved: command.approved === true });
        } else if (command.type === "agent.cancel") {
          send({
            version: 1,
            type: "agent.cancel",
            requestId: controlRequestId(command.id),
            taskId: String(command.taskId),
            reason: String(command.reason ?? "Cancelled by the host user."),
          });
          emit({ source: "control", id: command.id, ok: true, taskId: String(command.taskId) });
        } else if (command.type === "presence.update") {
          send({
            version: 1,
            type: "presence.update",
            requestId: controlRequestId(command.id),
            projectId: String(command.projectId),
            cursor: command.cursor ?? null,
            caret: command.caret ?? null,
          });
          emit({ source: "control", id: command.id, ok: true });
        } else if (command.type === "device.trust") {
          const deviceId = String(command.deviceId);
          const fingerprint = String(command.fingerprint);
          trustDevice(paths.trustedDevices, deviceId, fingerprint);
          emit({ source: "control", id: command.id, ok: true, deviceId });
        } else if (command.type === "private.send") {
          const messageId = String(command.messageId ?? randomUUID());
          const clientCreatedAt = String(command.clientCreatedAt ?? new Date().toISOString());
          const recipientDeviceId = String(command.recipientDeviceId);
          const certificate = verifyDeviceKeyCertificate(String(command.recipientKeyCertificate), recipientDeviceId);
          const trustedFingerprint = loadTrustedDevices(paths.trustedDevices)[recipientDeviceId];
          if (!trustedFingerprint || trustedFingerprint !== certificate.fingerprint) {
            throw new Error("Recipient device key certificate does not match the trusted fingerprint");
          }
          const ciphertext = await sealSignedPrivateMessage({
            messageId,
            senderDeviceId: connection.deviceId,
            recipientDeviceId,
            text: String(command.text),
            clientCreatedAt,
          }, identity.privateKeyPem, identity.publicKeyPem, certificate.messagingPublicKeyPem);
          enqueueDurableEvent(paths, {
            version: 1,
            type: "private.send",
            requestId: controlRequestId(command.id),
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
    for (const finish of pendingAgentApprovals.values()) finish(false);
    controller.abort();
    socket?.close();
    lines.close();
    await session;
  }
}

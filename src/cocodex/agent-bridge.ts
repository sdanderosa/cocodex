import { createPublicKey, randomUUID, verify } from "node:crypto";
import {
  agentDispatchSigningTranscript,
  agentCancelFrameSchema,
  agentRequestSigningTranscript,
  agentTaskFrameSchema,
  publicKeyFingerprint,
  type AgentTask,
} from "@cocodex/protocol";
import {
  acknowledgeAgentResult,
  appendAgentResult,
  beginAgentTask,
  pendingAgentResults,
  type DurableAgentResult,
} from "./agent-journal";

export interface LocalAgentAdapter {
  authorize(task: AgentTask, signal?: AbortSignal): boolean | Promise<boolean>;
  execute(task: AgentTask, signal?: AbortSignal): AsyncIterable<string>;
}

export interface AgentBridgeSecurity {
  localDeviceId: string;
  serverPublicKeyPem: string;
  trustedRequesterFingerprints: ReadonlyMap<string, string>;
  journalPath?: string;
  now?: () => Date;
}

function verifyTask(task: AgentTask, security: AgentBridgeSecurity): boolean {
  if (task.targetDeviceId !== security.localDeviceId
    || (task.status !== "queued" && task.status !== "running")) return false;
  const now = (security.now ?? (() => new Date()))().getTime();
  if ((task.status === "queued" && Date.parse(task.expiresAt) <= now)
    || Date.parse(task.issuedAt) > now + 60_000) return false;
  const trusted = security.trustedRequesterFingerprints.get(task.requesterDeviceId);
  if (!trusted || trusted !== publicKeyFingerprint(task.requesterPublicKeyPem)) return false;
  const requestValid = verify(null, agentRequestSigningTranscript({
    taskId: task.id,
    projectId: task.projectId,
    agentId: task.agentId,
    prompt: task.prompt,
    nonce: task.nonce,
    issuedAt: task.issuedAt,
    expiresAt: task.expiresAt,
  }), createPublicKey(task.requesterPublicKeyPem), Buffer.from(task.requesterSignature, "base64url"));
  if (!requestValid) return false;
  return verify(null, agentDispatchSigningTranscript({
    taskId: task.id,
    projectId: task.projectId,
    agentId: task.agentId,
    prompt: task.prompt,
    nonce: task.nonce,
    issuedAt: task.issuedAt,
    expiresAt: task.expiresAt,
    requesterDeviceId: task.requesterDeviceId,
    targetDeviceId: task.targetDeviceId,
    requesterSignature: task.requesterSignature,
    requesterPublicKeyPem: task.requesterPublicKeyPem,
  }), createPublicKey(security.serverPublicKeyPem), Buffer.from(task.serverSignature, "base64url"));
}

function deliverResult(socket: WebSocket, result: DurableAgentResult): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error("Timed out waiting for agent result acknowledgement")), 10_000);
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
      error ? reject(error) : resolve();
    };
    const onClose = () => finish(new Error("Connection closed while delivering agent result"));
    const onMessage = (event: MessageEvent) => {
      let frame: Record<string, unknown>;
      try { frame = JSON.parse(String(event.data)) as Record<string, unknown>; }
      catch { return; }
      if (frame.requestId !== result.requestId) return;
      if (frame.type === "agent.result.accepted") finish();
      else if (frame.type === "error") finish(new Error(String(frame.error)));
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
    socket.send(JSON.stringify(result));
  });
}

async function sendResult(
  socket: WebSocket,
  security: AgentBridgeSecurity,
  taskId: string,
  content: string,
  final: boolean,
  status: "running" | "completed" | "failed",
): Promise<void> {
  const result: DurableAgentResult = { version: 1, type: "agent.result", requestId: randomUUID(), taskId,
    eventId: randomUUID(), content, final, status };
  if (security.journalPath) appendAgentResult(security.journalPath, taskId, result);
  await deliverResult(socket, result);
  if (security.journalPath) acknowledgeAgentResult(security.journalPath, taskId, result.eventId);
}

async function recoverTask(socket: WebSocket, security: AgentBridgeSecurity, taskId: string): Promise<void> {
  if (!security.journalPath) {
    await sendResult(socket, security, taskId, "Local agent execution was interrupted and was not rerun.", true, "failed");
    return;
  }
  let pending = pendingAgentResults(security.journalPath, taskId);
  if (!pending.some(result => result.final)) {
    const interrupted: DurableAgentResult = {
      version: 1, type: "agent.result", requestId: randomUUID(), taskId,
      eventId: randomUUID(), content: "Local agent execution was interrupted and was not rerun.",
      final: true, status: "failed",
    };
    appendAgentResult(security.journalPath, taskId, interrupted);
    pending = [...pending, interrupted];
  }
  for (const result of pending) {
    await deliverResult(socket, result);
    acknowledgeAgentResult(security.journalPath, taskId, result.eventId);
  }
}

function chunks(value: string): string[] {
  const result: string[] = [];
  for (let offset = 0; offset < value.length; offset += 32_768) result.push(value.slice(offset, offset + 32_768));
  return result;
}

async function executeTask(
  socket: WebSocket,
  adapter: LocalAgentAdapter,
  task: AgentTask,
  security: AgentBridgeSecurity,
  signal: AbortSignal,
): Promise<void> {
  if (!await adapter.authorize(task, signal)) {
    await sendResult(socket, security, task.id, "Local execution policy rejected this task.", true, "failed");
    return;
  }
  try {
    let pending: string | undefined;
    for await (const output of adapter.execute(task, signal)) {
      for (const chunk of chunks(output)) {
        if (pending !== undefined) await sendResult(socket, security, task.id, pending, false, "running");
        pending = chunk;
      }
    }
    if (signal.aborted) return;
    await sendResult(socket, security, task.id, pending ?? "Task completed without textual output.", true, "completed");
  } catch {
    if (signal.aborted) return;
    try {
      await sendResult(socket, security, task.id, "Local agent execution failed. Review the host client logs.", true, "failed");
    } catch {
      // The durable journal will replay the final result after reconnect.
    }
  }
}

export function attachLocalAgentBridge(
  socket: WebSocket,
  adapter: LocalAgentAdapter,
  security: AgentBridgeSecurity,
): () => Promise<void> {
  const activeTasks = new Set<string>();
  const executionControllers = new Map<string, AbortController>();
  const MAX_LOCAL_AGENT_QUEUE = 8;
  let executionChain = Promise.resolve();
  const listener = (event: MessageEvent) => {
    let raw: unknown;
    try {
      raw = JSON.parse(String(event.data));
    } catch {
      return;
    }
    const parsed = agentTaskFrameSchema.safeParse(raw);
    const cancellation = agentCancelFrameSchema.safeParse(raw);
    if (cancellation.success) {
      executionControllers.get(cancellation.data.taskId)?.abort();
      return;
    }
    if (!parsed.success) return;
    const task = parsed.data.task;
    if (activeTasks.has(task.id) || !verifyTask(task, security)) return;
    const executionController = new AbortController();
    executionControllers.set(task.id, executionController);
    if (activeTasks.size >= MAX_LOCAL_AGENT_QUEUE) {
      activeTasks.add(task.id);
      const journalState = security.journalPath ? beginAgentTask(security.journalPath, task.id) : "new";
      const mustRecover = task.status === "running" || journalState === "started";
      executionChain = executionChain
        .catch(() => undefined)
        .then(() => mustRecover
          ? recoverTask(socket, security, task.id)
          : journalState === "new"
            ? sendResult(socket, security, task.id, "Local execution queue is full.", true, "failed")
            : undefined)
        .finally(() => {
          executionControllers.delete(task.id);
          activeTasks.delete(task.id);
        });
      return;
    }
    activeTasks.add(task.id);
    const journalState = security.journalPath ? beginAgentTask(security.journalPath, task.id) : "new";
    const mustRecover = task.status === "running" || journalState === "started";
    executionChain = executionChain
      .catch(() => undefined)
      .then(() => mustRecover
        ? recoverTask(socket, security, task.id)
        : journalState === "new"
          ? executeTask(socket, adapter, task, security, executionController.signal)
          : undefined)
      .finally(() => {
        executionControllers.delete(task.id);
        activeTasks.delete(task.id);
      });
  };
  socket.addEventListener("message", listener);
  socket.send(JSON.stringify({
    version: 1,
    type: "agent.ready",
    requestId: randomUUID(),
  }));
  return async () => {
    socket.removeEventListener("message", listener);
    for (const controller of executionControllers.values()) controller.abort();
    await executionChain.catch(() => undefined);
  };
}

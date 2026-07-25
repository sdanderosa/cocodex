import { createPublicKey, randomUUID, verify } from "node:crypto";
import {
  agentEncryptedDispatchSigningTranscript,
  agentDispatchSigningTranscript,
  agentCancelFrameSchema,
  agentRequestSigningTranscript,
  agentTaskFrameSchema,
  encryptedAgentTaskFrameSchema,
  publicKeyFingerprint,
  type AgentTask,
  type EncryptedAgentTask,
  type ProjectContentEnvelope,
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
  agentId?: string;
  serverPublicKeyPem: string;
  trustedRequesterFingerprints: ReadonlyMap<string, string>;
  journalPath?: string;
  onActiveAgents?: (count: number) => void;
  now?: () => Date;
  decryptTaskPrompt?: (task: EncryptedAgentTask) => Promise<string>;
  encryptResult?: (result: DurableAgentResult) => Promise<ProjectContentEnvelope | undefined>;
  /** Local host safety state. A remote task never overrides this callback. */
  isExecutionAllowed?: () => boolean;
}

export type LocalAgentBridgeHandle = (() => Promise<void>) & {
  emergencyStop: (reason?: string) => void;
  resume: () => void;
  isEmergencyStopped: () => boolean;
};

async function verifyTask(task: AgentTask | EncryptedAgentTask, security: AgentBridgeSecurity): Promise<AgentTask | null> {
  if (task.targetDeviceId !== security.localDeviceId
    || (security.agentId !== undefined && task.agentId !== security.agentId)
    || (task.status !== "queued" && task.status !== "running")) return null;
  const now = (security.now ?? (() => new Date()))().getTime();
  if ((task.status === "queued" && Date.parse(task.expiresAt) <= now)
    || Date.parse(task.issuedAt) > now + 60_000) return null;
  const trusted = security.trustedRequesterFingerprints.get(task.requesterDeviceId);
  if (!trusted || trusted !== publicKeyFingerprint(task.requesterPublicKeyPem)) return null;
  if ("promptEnvelope" in task) {
    if (!security.decryptTaskPrompt) return null;
    const requestValid = verify(null, agentEncryptedDispatchSigningTranscript({
      taskId: task.id,
      projectId: task.projectId,
      agentId: task.agentId,
      nonce: task.nonce,
      issuedAt: task.issuedAt,
      expiresAt: task.expiresAt,
      dependencies: task.dependencies,
      inputArtifactIds: task.inputArtifactIds,
      privateShareMessageId: task.privateShareMessageId,
      requesterDeviceId: task.requesterDeviceId,
      targetDeviceId: task.targetDeviceId,
      envelopeProjectId: task.promptEnvelope.projectId,
      envelopeKeyEpoch: task.promptEnvelope.keyEpoch,
      envelopeRecordId: task.promptEnvelope.recordId,
      envelopeNonce: task.promptEnvelope.nonce,
      envelopeCiphertext: task.promptEnvelope.ciphertext,
      envelopeSenderDeviceId: task.promptEnvelope.senderDeviceId,
      envelopeSenderPublicKeyPem: task.promptEnvelope.senderPublicKeyPem,
      envelopeSignature: task.promptEnvelope.signature,
    }), createPublicKey(security.serverPublicKeyPem), Buffer.from(task.serverSignature, "base64url"));
    if (!requestValid) return null;
    let prompt: string;
    try { prompt = await security.decryptTaskPrompt(task); }
    catch { return null; }
    if (prompt.length < 1 || Buffer.byteLength(prompt, "utf8") > 300_000) return null;
    return requestValid ? { ...task, prompt } as AgentTask : null;
  }
  const requestValid = verify(null, agentRequestSigningTranscript({
    taskId: task.id,
    projectId: task.projectId,
    agentId: task.agentId,
    prompt: task.prompt,
    nonce: task.nonce,
    issuedAt: task.issuedAt,
    expiresAt: task.expiresAt,
    dependencies: task.dependencies,
    inputArtifactIds: task.inputArtifactIds,
    privateShareMessageId: task.privateShareMessageId,
  }), createPublicKey(task.requesterPublicKeyPem), Buffer.from(task.requesterSignature, "base64url"));
  if (!requestValid) return null;
  const dispatchValid = verify(null, agentDispatchSigningTranscript({
    taskId: task.id,
    projectId: task.projectId,
    agentId: task.agentId,
    prompt: task.prompt,
    nonce: task.nonce,
    issuedAt: task.issuedAt,
    expiresAt: task.expiresAt,
    dependencies: task.dependencies,
    inputArtifactIds: task.inputArtifactIds,
    privateShareMessageId: task.privateShareMessageId,
    requesterDeviceId: task.requesterDeviceId,
    targetDeviceId: task.targetDeviceId,
    requesterSignature: task.requesterSignature,
    requesterPublicKeyPem: task.requesterPublicKeyPem,
  }), createPublicKey(security.serverPublicKeyPem), Buffer.from(task.serverSignature, "base64url"));
  return dispatchValid ? task : null;
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
      if (frame.type === "agent.result.accepted" || frame.type === "project.agent.result.accepted") finish();
      else if (frame.type === "error") finish(new Error(String(frame.error)));
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
    socket.send(JSON.stringify(result.projectEnvelope ? {
      version: 1,
      type: "project.agent.result",
      requestId: result.requestId,
      taskId: result.taskId,
      eventId: result.eventId,
      envelope: result.projectEnvelope,
      final: result.final,
      status: result.status,
    } : result));
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
  if (security.encryptResult) {
    const envelope = await security.encryptResult(result);
    if (envelope) result.projectEnvelope = envelope;
  }
  if (security.journalPath) appendAgentResult(security.journalPath, taskId, result);
  await deliverResult(socket, result);
  if (security.journalPath) acknowledgeAgentResult(security.journalPath, taskId, result.eventId);
}

async function recoverTask(socket: WebSocket, security: AgentBridgeSecurity, taskId: string, encrypted: boolean): Promise<void> {
  if (!security.journalPath) {
    await sendResult(socket, security, taskId, "Local agent execution was interrupted and was not rerun.", true, "failed");
    return;
  }
  let pending = pendingAgentResults(security.journalPath, taskId);
  if (!pending.some(result => result.final)) {
    if (encrypted) {
      await sendResult(socket, security, taskId, "Local agent execution was interrupted and was not rerun.", true, "failed");
      return;
    }
    const interrupted: DurableAgentResult = {
      version: 1, type: "agent.result", requestId: randomUUID(), taskId,
      eventId: randomUUID(), content: "Local agent execution was interrupted and was not rerun.",
      final: true, status: "failed",
    };
    appendAgentResult(security.journalPath, taskId, interrupted);
    pending = [...pending, interrupted];
  }
  for (const result of pending) {
    if (encrypted && !result.projectEnvelope) throw new Error("Encrypted agent result journal entry has no envelope");
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
  encrypted: boolean,
  wasCancelled: () => boolean,
  sendCancellation: () => Promise<void>,
  executionAllowed: () => boolean,
): Promise<void> {
  if (encrypted && wasCancelled()) {
    await sendCancellation();
    return;
  }
  if (!executionAllowed()) {
    if (wasCancelled()) await sendCancellation();
    else await sendResult(socket, security, task.id, "Local execution is disabled by the host safety control.", true, "failed");
    return;
  }
  if (!await adapter.authorize(task, signal)) {
    if (encrypted && wasCancelled()) await sendCancellation();
    else await sendResult(socket, security, task.id, "Local execution policy rejected this task.", true, "failed");
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
    if (signal.aborted) {
      if (encrypted && wasCancelled()) await sendCancellation();
      return;
    }
    await sendResult(socket, security, task.id, pending ?? "Task completed without textual output.", true, "completed");
  } catch {
    if (signal.aborted) {
      if (encrypted && wasCancelled()) {
        try { await sendCancellation(); } catch { /* journal replays the final event after reconnect */ }
      }
      return;
    }
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
): LocalAgentBridgeHandle {
  const activeTasks = new Set<string>();
  const executionControllers = new Map<string, AbortController>();
  const taskModes = new Map<string, boolean>();
  const pendingCancellations = new Set<string>();
  const cancelledEncryptedTasks = new Set<string>();
  const cancellationResultsSent = new Set<string>();
  const emergencyCancelledTasks = new Set<string>();
  const MAX_LOCAL_AGENT_QUEUE = 8;
  let emergencyStopped = false;
  let executionChain = Promise.resolve();
  const reportActiveAgents = () => security.onActiveAgents?.(activeTasks.size);
  const sendCancellation = (taskId: string): Promise<void> => {
    if (cancellationResultsSent.has(taskId)) return Promise.resolve();
    cancellationResultsSent.add(taskId);
    if (security.journalPath && pendingAgentResults(security.journalPath, taskId).some(result => result.final)) {
      return Promise.resolve();
    }
    return sendResult(socket, security, taskId, "Agent task cancelled by a trusted device.", true, "failed")
      .catch(() => undefined);
  };
  const listener = (event: MessageEvent) => {
    let raw: unknown;
    try {
      raw = JSON.parse(String(event.data));
    } catch {
      return;
    }
    const parsed = agentTaskFrameSchema.safeParse(raw);
    const encryptedParsed = encryptedAgentTaskFrameSchema.safeParse(raw);
    const cancellation = agentCancelFrameSchema.safeParse(raw);
    if (cancellation.success) {
      const knownMode = taskModes.get(cancellation.data.taskId);
      if (knownMode === true) cancelledEncryptedTasks.add(cancellation.data.taskId);
      else if (knownMode === undefined) pendingCancellations.add(cancellation.data.taskId);
      executionControllers.get(cancellation.data.taskId)?.abort();
      return;
    }
    const wireTask = parsed.success ? parsed.data.task : encryptedParsed.success ? encryptedParsed.data.task : undefined;
    if (!wireTask) return;
    void (async () => {
      const task = await verifyTask(wireTask, security);
      if (!task || activeTasks.has(task.id)) return;
      const encrypted = encryptedParsed.success;
      taskModes.set(task.id, encrypted);
      if (pendingCancellations.delete(task.id) && encrypted) cancelledEncryptedTasks.add(task.id);
      const executionController = new AbortController();
      executionControllers.set(task.id, executionController);
      const cancelled = () => (encrypted && cancelledEncryptedTasks.has(task.id)) || emergencyCancelledTasks.has(task.id);
      const executionAllowed = () => !emergencyStopped && (security.isExecutionAllowed?.() ?? true);
      if (activeTasks.size >= MAX_LOCAL_AGENT_QUEUE) {
        activeTasks.add(task.id);
        reportActiveAgents();
        const journalState = security.journalPath ? beginAgentTask(security.journalPath, task.id) : "new";
        const mustRecover = task.status === "running" || journalState === "started";
        executionChain = executionChain
          .catch(() => undefined)
          .then(() => cancelled()
            ? sendCancellation(task.id)
            : !executionAllowed()
              ? sendResult(socket, security, task.id, "Local execution is disabled by the host safety control.", true, "failed")
            : mustRecover
              ? recoverTask(socket, security, task.id, encrypted)
              : journalState === "new"
                ? sendResult(socket, security, task.id, "Local execution queue is full.", true, "failed")
                : undefined)
          .finally(() => {
            executionControllers.delete(task.id);
            activeTasks.delete(task.id);
            taskModes.delete(task.id);
            pendingCancellations.delete(task.id);
            cancelledEncryptedTasks.delete(task.id);
            emergencyCancelledTasks.delete(task.id);
            cancellationResultsSent.delete(task.id);
            reportActiveAgents();
          });
        return;
      }
      activeTasks.add(task.id);
      reportActiveAgents();
      const journalState = security.journalPath ? beginAgentTask(security.journalPath, task.id) : "new";
      const mustRecover = task.status === "running" || journalState === "started";
      executionChain = executionChain
        .catch(() => undefined)
          .then(() => cancelled()
            ? sendCancellation(task.id)
            : !executionAllowed()
              ? sendResult(socket, security, task.id, "Local execution is disabled by the host safety control.", true, "failed")
            : mustRecover
            ? recoverTask(socket, security, task.id, encrypted)
            : journalState === "new"
                ? executeTask(socket, adapter, task, security, executionController.signal, encrypted, cancelled, () => sendCancellation(task.id), executionAllowed)
              : undefined)
        .finally(() => {
          executionControllers.delete(task.id);
          activeTasks.delete(task.id);
          taskModes.delete(task.id);
          pendingCancellations.delete(task.id);
          cancelledEncryptedTasks.delete(task.id);
          emergencyCancelledTasks.delete(task.id);
          cancellationResultsSent.delete(task.id);
          reportActiveAgents();
        });
    })().catch(() => undefined);
  };
  socket.addEventListener("message", listener);
  socket.send(JSON.stringify({
    version: 1,
    type: "agent.ready",
    requestId: randomUUID(),
    ...(security.agentId ? { agentId: security.agentId } : {}),
  }));
  const emergencyStop = (_reason?: string) => {
    emergencyStopped = true;
    for (const taskId of executionControllers.keys()) emergencyCancelledTasks.add(taskId);
    for (const controller of executionControllers.values()) controller.abort();
  };
  const resume = () => { emergencyStopped = false; };
  const detach = async () => {
    socket.removeEventListener("message", listener);
    for (const controller of executionControllers.values()) controller.abort();
    await executionChain.catch(() => undefined);
  };
  Object.assign(detach, {
    emergencyStop,
    resume,
    isEmergencyStopped: () => emergencyStopped,
  });
  return detach as LocalAgentBridgeHandle;
}

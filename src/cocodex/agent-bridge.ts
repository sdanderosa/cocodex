import { createPublicKey, randomUUID, verify } from "node:crypto";
import {
  agentDispatchSigningTranscript,
  agentRequestSigningTranscript,
  agentTaskFrameSchema,
  publicKeyFingerprint,
  type AgentTask,
} from "@cocodex/protocol";

export interface LocalAgentAdapter {
  authorize(task: AgentTask): boolean | Promise<boolean>;
  execute(task: AgentTask): AsyncIterable<string>;
}

export interface AgentBridgeSecurity {
  localDeviceId: string;
  serverPublicKeyPem: string;
  trustedRequesterFingerprints: ReadonlyMap<string, string>;
  now?: () => Date;
}

function verifyTask(task: AgentTask, security: AgentBridgeSecurity): boolean {
  if (task.targetDeviceId !== security.localDeviceId || task.status !== "queued") return false;
  const now = (security.now ?? (() => new Date()))().getTime();
  if (Date.parse(task.expiresAt) <= now || Date.parse(task.issuedAt) > now + 60_000) return false;
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

function sendResult(socket: WebSocket, taskId: string, content: string, final: boolean, status: "running" | "completed" | "failed"): void {
  socket.send(JSON.stringify({ version: 1, type: "agent.result", requestId: randomUUID(), taskId,
    eventId: randomUUID(), content, final, status }));
}

function chunks(value: string): string[] {
  const result: string[] = [];
  for (let offset = 0; offset < value.length; offset += 32_768) result.push(value.slice(offset, offset + 32_768));
  return result;
}

async function executeTask(socket: WebSocket, adapter: LocalAgentAdapter, task: AgentTask): Promise<void> {
  if (!await adapter.authorize(task)) {
    sendResult(socket, task.id, "Local execution policy rejected this task.", true, "failed");
    return;
  }
  try {
    let pending: string | undefined;
    for await (const output of adapter.execute(task)) {
      for (const chunk of chunks(output)) {
        if (pending !== undefined) sendResult(socket, task.id, pending, false, "running");
        pending = chunk;
      }
    }
    sendResult(socket, task.id, pending ?? "Task completed without textual output.", true, "completed");
  } catch {
    sendResult(socket, task.id, "Local agent execution failed. Review the host client logs.", true, "failed");
  }
}

export function attachLocalAgentBridge(
  socket: WebSocket,
  adapter: LocalAgentAdapter,
  security: AgentBridgeSecurity,
): () => void {
  const activeTasks = new Set<string>();
  const listener = (event: MessageEvent) => {
    let raw: unknown;
    try {
      raw = JSON.parse(String(event.data));
    } catch {
      return;
    }
    const parsed = agentTaskFrameSchema.safeParse(raw);
    if (!parsed.success) return;
    const task = parsed.data.task;
    if (activeTasks.has(task.id) || !verifyTask(task, security)) return;
    activeTasks.add(task.id);
    void executeTask(socket, adapter, task).finally(() => activeTasks.delete(task.id));
  };
  socket.addEventListener("message", listener);
  return () => socket.removeEventListener("message", listener);
}
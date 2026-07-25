import { randomUUID } from "node:crypto";
import type { AgentTask } from "@cocodex/protocol";

export interface LocalAgentAdapter {
  authorize(task: AgentTask): boolean | Promise<boolean>;
  execute(task: AgentTask): AsyncIterable<string>;
}

function sendResult(
  socket: WebSocket,
  taskId: string,
  content: string,
  final: boolean,
  status: "running" | "completed" | "failed",
): void {
  socket.send(JSON.stringify({
    version: 1,
    type: "agent.result",
    requestId: randomUUID(),
    taskId,
    eventId: randomUUID(),
    content,
    final,
    status,
  }));
}

async function executeTask(socket: WebSocket, adapter: LocalAgentAdapter, task: AgentTask): Promise<void> {
  if (!await adapter.authorize(task)) {
    sendResult(socket, task.id, "Local execution policy rejected this task.", true, "failed");
    return;
  }
  try {
    let pending: string | undefined;
    for await (const chunk of adapter.execute(task)) {
      const bounded = chunk.slice(0, 32_768);
      if (!bounded) continue;
      if (pending !== undefined) sendResult(socket, task.id, pending, false, "running");
      pending = bounded;
    }
    sendResult(socket, task.id, pending ?? "Task completed without textual output.", true, "completed");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    sendResult(socket, task.id, `Local agent failed: ${message}`.slice(0, 32_768), true, "failed");
  }
}

export function attachLocalAgentBridge(socket: WebSocket, adapter: LocalAgentAdapter): () => void {
  const activeTasks = new Set<string>();
  const listener = (event: MessageEvent) => {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(String(event.data)) as Record<string, unknown>;
    } catch {
      return;
    }
    if (frame.type !== "agent.task") return;
    const task = frame.task as AgentTask;
    if (!task?.id || activeTasks.has(task.id)) return;
    activeTasks.add(task.id);
    void executeTask(socket, adapter, task).finally(() => activeTasks.delete(task.id));
  };
  socket.addEventListener("message", listener);
  return () => socket.removeEventListener("message", listener);
}

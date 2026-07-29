import { randomUUID, sign } from "node:crypto";
import {
  agentExecutionSigningTranscript,
  type AgentTask,
} from "../../packages/cocodex-protocol/src/index.ts";
import type { ClientIdentity } from "./identity";
import type { TaskWorkspace } from "./task-worktree";

export function reportAgentExecution(
  socket: WebSocket,
  identity: ClientIdentity,
  task: AgentTask,
  workspace: TaskWorkspace,
): Promise<void> {
  const requestId = randomUUID();
  const unsigned = {
    taskId: task.id,
    projectId: task.projectId,
    chatId: task.chatId ?? task.projectId,
    agentId: task.agentId,
    workspaceMode: workspace.mode,
    workspaceRef: workspace.workspaceRef,
    branch: workspace.branch,
    baseCommit: workspace.baseCommit,
    mergeTarget: workspace.mergeTarget,
    startedAt: new Date().toISOString(),
  };
  const signature = sign(
    null,
    agentExecutionSigningTranscript(unsigned),
    identity.privateKeyPem,
  ).toString("base64url");
  return new Promise((resolve, reject) => {
    let finished = false;
    const finish = (error?: Error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
      error ? reject(error) : resolve();
    };
    const timeout = setTimeout(
      () => finish(new Error("Timed out waiting for agent execution acknowledgement")),
      10_000,
    );
    const onClose = () => finish(new Error("Connection closed before agent execution was acknowledged"));
    const onMessage = (event: MessageEvent) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(String(event.data)) as Record<string, unknown>;
      } catch {
        return;
      }
      if (frame.requestId !== requestId) return;
      if (frame.type === "agent.execution.accepted" && frame.taskId === task.id) finish();
      else if (frame.type === "error") finish(new Error(String(frame.error)));
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose, { once: true });
    try {
      socket.send(JSON.stringify({
        version: 1,
        type: "agent.execution.report",
        requestId,
        ...unsigned,
        signature,
      }));
    } catch (error) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

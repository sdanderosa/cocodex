import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { LanguageProvider } from "../src/i18n/provider";
import { TaskDependencyGraph, type AgentTaskView } from "../src/pages/CoCodex";

function task(overrides: Partial<AgentTaskView> & Pick<AgentTaskView, "id" | "agentId" | "agentName" | "status">): AgentTaskView {
  return {
    projectId: "project",
    chatId: "chat",
    requesterDeviceId: "stephen",
    targetDeviceId: "stephen",
    dependencies: [],
    inputArtifactIds: [],
    workspaceMode: "git-worktree",
    workspaceRef: "worktree",
    branch: "cocodex/chat/agent/task",
    baseCommit: "abcdef1234567890",
    mergeTarget: "main",
    acceptedAt: "2026-07-28T10:00:00.000Z",
    startedAt: null,
    completedAt: null,
    lastActivityAt: "2026-07-28T10:00:00.000Z",
    eventCount: 1,
    encrypted: true,
    ...overrides,
  };
}

test("renders authoritative dependency and artifact handoff state as a compact graph", () => {
  const previousNavigator = Reflect.get(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { language: "en-US" } });
  let html: string;
  try {
    html = renderToStaticMarkup(<LanguageProvider><TaskDependencyGraph
      tasks={[
        task({ id: "lucas-task", agentId: "lucas", agentName: "Lucas", status: "completed", completedAt: "2026-07-28T10:01:00.000Z" }),
        task({
          id: "angela-task",
          agentId: "angela",
          agentName: "Angela",
          status: "queued",
          dependencies: ["lucas-task"],
          inputArtifactIds: ["accepted-result"],
          acceptedAt: "2026-07-28T10:02:00.000Z",
        }),
      ]}
      artifacts={[{
        id: "accepted-result",
        projectId: "project",
        chatId: "chat",
        taskId: "lucas-task",
        authorDeviceId: "stephen",
        type: "handoff",
        title: "Accepted result",
        summary: "Ready for Angela",
        content: "bounded content",
        status: "accepted",
        createdAt: "2026-07-28T10:01:00.000Z",
        updatedAt: "2026-07-28T10:01:00.000Z",
      }]}
    /></LanguageProvider>);
  } finally {
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: previousNavigator });
  }

  expect(html).toContain('role="list"');
  expect(html).toContain('data-state="ready"');
  expect(html).toContain('data-layer="1"');
  expect(html).toContain("Angela");
  expect(html).toContain("Lucas");
  expect(html).toContain("Accepted result");
  expect(html).toContain("Consumes 1 artifact inputs");
});

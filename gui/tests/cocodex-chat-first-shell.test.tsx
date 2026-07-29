import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { LanguageProvider } from "../src/i18n/provider";
import {
  ChatTimeline,
  PrivateTypingIndicator,
  WorkspaceRailTabs,
} from "../src/pages/CoCodex";
import { executableLocalAgentIds, stopEveryLocalAgent } from "../src/cocodex-agent-safety-state";

test("chat-first right rail exposes one selected workspace detail tab", () => {
  const previousNavigator = Reflect.get(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { language: "en-US" },
  });
  let html: string;
  try {
    html = renderToStaticMarkup(
      <LanguageProvider>
        <WorkspaceRailTabs active="agents" onChange={() => {}} />
      </LanguageProvider>,
    );
  } finally {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: previousNavigator,
    });
  }

  expect(html).toContain('role="tablist"');
  expect(html).toContain('aria-label="Workspace details"');
  expect(html).toContain('aria-selected="true"');
  expect((html.match(/role="tab"/g) ?? []).length).toBe(4);
  expect((html.match(/aria-selected="true"/g) ?? []).length).toBe(1);
});

test("private typing indicator is accessible, animated by three dots, and absent when idle", () => {
  const active = renderToStaticMarkup(<PrivateTypingIndicator active label="Kai is typing…" />);
  expect(active).toContain('role="status"');
  expect(active).toContain('aria-live="polite"');
  expect(active).toContain("Kai is typing");
  expect((active.match(/<i/g) ?? []).length).toBe(3);
  expect(renderToStaticMarkup(<PrivateTypingIndicator active={false} label="Kai is typing…" />)).toBe("");
});

test("global emergency stop targets every and only executing local agent", async () => {
  const ids = executableLocalAgentIds([
    { agentId: "lucas", executionEnabled: true },
    { agentId: "angela", executionEnabled: false },
    { agentId: "sue", executionEnabled: true },
  ]);
  const stopped: string[] = [];

  await stopEveryLocalAgent(ids, async agentId => { stopped.push(agentId); });

  expect(ids).toEqual(["lucas", "sue"]);
  expect(stopped).toEqual(["lucas", "sue"]);
});

test("global emergency stop attempts every agent and reports every rejected stop", async () => {
  const stopped: string[] = [];

  await expect(stopEveryLocalAgent(["lucas", "sue", "angela"], async agentId => {
    stopped.push(agentId);
    if (agentId !== "sue") throw new Error("host rejected stop");
  })).rejects.toThrow("Emergency stop was rejected for: lucas, angela");

  expect(stopped).toEqual(["lucas", "sue", "angela"]);
});

test("shared timeline interleaves expandable agent activity with server-accepted chat", () => {
  const previousNavigator = Reflect.get(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { language: "en-US" } });
  let html: string;
  try {
    html = renderToStaticMarkup(<LanguageProvider><div className="cocodex-message-list">
      <ChatTimeline
        localDeviceId="stephen-device"
        members={[{
          deviceId: "kai-device",
          displayName: "Kai",
          fingerprint: "kai-fingerprint",
          role: "member",
          trusted: true,
        }]}
        messages={[{
          sequence: 7,
          projectId: "project",
          chatId: "chat",
          eventId: "message-7",
          senderDeviceId: "kai-device",
          content: "Please verify the accepted artifact.",
          acceptedAt: "2026-07-28T10:00:02.000Z",
        }]}
        tasks={[{
          id: "task-lucas-123456",
          projectId: "project",
          chatId: "chat",
          agentId: "lucas",
          agentName: "Lucas",
          requesterDeviceId: "stephen-device",
          targetDeviceId: "stephen-device",
          status: "running",
          dependencies: ["task-angela"],
          inputArtifactIds: ["artifact-tests"],
          workspaceMode: "git-worktree",
          workspaceRef: "lucas-worktree",
          branch: "cocodex/chat/lucas/task",
          baseCommit: "abcdef1234567890",
          mergeTarget: "main",
          acceptedAt: "2026-07-28T10:00:01.000Z",
          startedAt: "2026-07-28T10:00:01.500Z",
          completedAt: null,
          lastActivityAt: "2026-07-28T10:00:01.900Z",
          eventCount: 4,
          encrypted: true,
        }]}
      />
    </div></LanguageProvider>);
  } finally {
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: previousNavigator });
  }

  expect(html.indexOf("Lucas")).toBeLessThan(html.indexOf("Please verify the accepted artifact."));
  expect(html).toContain("<details open=\"\"");
  expect(html).toContain("4 events");
  expect(html).toContain("Kai");
  expect(html).toContain("cocodex/chat/lucas/task");
  expect(html).toContain("encrypted");
});

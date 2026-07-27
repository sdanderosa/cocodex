import { describe, expect, test } from "bun:test";
import { buildCoCodexComposerSubmission } from "../src/cocodex-composer-state";

describe("CoCodex shared composer submission", () => {
  test("routes the exact merged shared prompt to the selected agent", () => {
    const submission = buildCoCodexComposerSubmission({
      projectId: "project-1",
      chatId: "chat-1",
      agentId: "  stephen-agent  ",
      chatDraft: "private chat draft that must not be dispatched",
      sharedPrompt: "  jointly edited agent instruction  ",
      inputArtifactIds: ["artifact-1"],
    });

    expect(submission).toEqual({
      source: "shared-prompt",
      submittedValue: "  jointly edited agent instruction  ",
      command: {
        type: "agent.request",
        projectId: "project-1",
        chatId: "chat-1",
        agentId: "stephen-agent",
        prompt: "jointly edited agent instruction",
        inputArtifactIds: ["artifact-1"],
      },
    });
  });

  test("keeps ordinary project chat on its independent local draft", () => {
    const submission = buildCoCodexComposerSubmission({
      projectId: "project-1",
      chatId: "chat-1",
      agentId: "",
      chatDraft: "  chronological chat message  ",
      sharedPrompt: "shared prompt must remain untouched",
      inputArtifactIds: ["artifact-1"],
    });

    expect(submission).toEqual({
      source: "chat-draft",
      submittedValue: "  chronological chat message  ",
      command: {
        type: "chat.send",
        projectId: "project-1",
        chatId: "chat-1",
        content: "chronological chat message",
      },
    });
  });

  test("rejects missing scope and the selected source when it is blank", () => {
    const base = {
      projectId: "project-1",
      chatId: "chat-1",
      agentId: "stephen-agent",
      chatDraft: "chat does not substitute for an empty shared prompt",
      sharedPrompt: "   ",
      inputArtifactIds: [] as string[],
    };
    expect(buildCoCodexComposerSubmission(base)).toBeNull();
    expect(buildCoCodexComposerSubmission({ ...base, projectId: "" })).toBeNull();
    expect(buildCoCodexComposerSubmission({
      ...base,
      agentId: "",
      chatDraft: "",
      sharedPrompt: "agent text is irrelevant without a selected agent",
    })).toBeNull();
  });

  test("copies the artifact selection so later UI changes cannot mutate a dispatch", () => {
    const selected = ["artifact-1"];
    const submission = buildCoCodexComposerSubmission({
      projectId: "project-1",
      chatId: "chat-1",
      agentId: "agent-1",
      chatDraft: "",
      sharedPrompt: "inspect the selected artifact",
      inputArtifactIds: selected,
    });
    selected.push("artifact-2");

    expect(submission?.command.inputArtifactIds).toEqual(["artifact-1"]);
  });
});

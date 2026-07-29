export interface CoCodexComposerSubmission {
  source: "chat-draft" | "shared-prompt";
  submittedValue: string;
  command: {
    type: "chat.send" | "agent.request";
    projectId: string;
    chatId: string;
    content?: string;
    agentId?: string;
    prompt?: string;
    inputArtifactIds?: string[];
  };
}

export function buildCoCodexComposerSubmission(options: {
  projectId: string;
  chatId: string;
  agentId: string;
  chatDraft: string;
  sharedPrompt: string;
  finalGoal?: string;
  inputArtifactIds: string[];
}): CoCodexComposerSubmission | null {
  if (!options.projectId || !options.chatId) return null;
  const agentId = options.agentId.trim();
  const submittedValue = agentId ? options.sharedPrompt : options.chatDraft;
  const content = submittedValue.trim();
  if (!content) return null;
  return agentId
    ? {
        source: "shared-prompt",
        submittedValue,
        command: {
          type: "agent.request",
          projectId: options.projectId,
          chatId: options.chatId,
          agentId,
          prompt: options.finalGoal?.trim()
            ? `<cocodex_final_goal>${JSON.stringify(options.finalGoal.trim())}</cocodex_final_goal>\n\n${content}`
            : content,
          inputArtifactIds: [...options.inputArtifactIds],
        },
      }
    : {
        source: "chat-draft",
        submittedValue,
        command: {
          type: "chat.send",
          projectId: options.projectId,
          chatId: options.chatId,
          content,
        },
      };
}

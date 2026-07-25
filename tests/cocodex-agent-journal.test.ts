import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acknowledgeAgentResult,
  appendAgentResult,
  beginAgentTask,
  pendingAgentResults,
} from "../src/cocodex/agent-journal";

describe("CoCodex local execution journal", () => {
  test("distinguishes interrupted work from an acknowledged finished task", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-journal-"));
    const path = join(root, "journal.json");
    const taskId = crypto.randomUUID();
    const result = {
      version: 1 as const,
      type: "agent.result" as const,
      requestId: crypto.randomUUID(),
      taskId,
      eventId: crypto.randomUUID(),
      content: "complete",
      final: true,
      status: "completed" as const,
    };
    try {
      expect(beginAgentTask(path, taskId)).toBe("new");
      expect(beginAgentTask(path, taskId)).toBe("started");
      appendAgentResult(path, taskId, result);
      expect(beginAgentTask(path, taskId)).toBe("finished");
      expect(pendingAgentResults(path, taskId)).toEqual([result]);
      acknowledgeAgentResult(path, taskId, result.eventId);
      expect(beginAgentTask(path, taskId)).toBe("finished");
      expect(pendingAgentResults(path, taskId)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

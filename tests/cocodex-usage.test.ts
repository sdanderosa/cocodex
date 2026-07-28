import { describe, expect, test } from "bun:test";
import { addAgentUsage, emptyUsageReport } from "../src/cocodex/usage";

describe("CoCodex per-agent usage", () => {
  test("tracks cache reads independently for each local agent", () => {
    const report = emptyUsageReport("11111111-1111-4111-8111-111111111111");
    report.agents = addAgentUsage(report, "planner", {
      inputTokens: 100,
      cachedInputTokens: 60,
      outputTokens: 10,
      reasoningOutputTokens: 4,
    });
    report.agents = addAgentUsage(report, "planner", {
      inputTokens: 50,
      cachedInputTokens: 40,
      outputTokens: 5,
      reasoningOutputTokens: 2,
    });
    report.agents = addAgentUsage(report, "reviewer", {
      inputTokens: 20,
      cachedInputTokens: 0,
      outputTokens: 3,
    });

    expect(report.agents).toEqual([
      {
        agentId: "reviewer",
        requests: 1,
        inputTokens: 20,
        cachedInputTokens: 0,
        outputTokens: 3,
        reasoningOutputTokens: 0,
      },
      {
        agentId: "planner",
        requests: 2,
        inputTokens: 150,
        cachedInputTokens: 100,
        outputTokens: 15,
        reasoningOutputTokens: 6,
      },
    ]);
  });
});

import { z } from "zod";

const boundedCounter = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const boundedPercent = z.number().finite().min(0).max(100);

export const usageWindowSchema = z.object({
  label: z.string().trim().min(1).max(80),
  percent: boundedPercent,
  resetAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
}).strict();

export const agentUsageSchema = z.object({
  agentId: z.string().trim().min(1).max(120),
  requests: boundedCounter,
  inputTokens: boundedCounter,
  cachedInputTokens: boundedCounter,
  outputTokens: boundedCounter,
  reasoningOutputTokens: boundedCounter,
}).strict();

export const usageReportSchema = z.object({
  version: z.literal(1),
  deviceId: z.uuid(),
  revision: boundedCounter,
  updatedAt: z.iso.datetime(),
  requests: boundedCounter,
  inputTokens: boundedCounter,
  cachedInputTokens: boundedCounter,
  outputTokens: boundedCounter,
  reasoningOutputTokens: boundedCounter,
  activeAgents: z.number().int().nonnegative().max(256),
  accountLabel: z.string().trim().max(80).optional(),
  fiveHourPercent: boundedPercent.optional(),
  fiveHourResetAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  weeklyPercent: boundedPercent.optional(),
  weeklyResetAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  monthlyPercent: boundedPercent.optional(),
  monthlyResetAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  customWindows: z.array(usageWindowSchema).max(8).optional(),
  agents: z.array(agentUsageSchema).max(8).optional(),
}).strict().superRefine((value, refinement) => {
  if (value.agents && new Set(value.agents.map(agent => agent.agentId)).size !== value.agents.length) {
    refinement.addIssue({ code: "custom", path: ["agents"], message: "Agent usage IDs must be unique" });
  }
  try {
    if (Buffer.byteLength(JSON.stringify(value), "utf8") > 16 * 1024) {
      refinement.addIssue({ code: "custom", message: "Usage report is too large" });
    }
  } catch {
    refinement.addIssue({ code: "custom", message: "Usage report must be JSON-serializable" });
  }
});

export type UsageReport = z.infer<typeof usageReportSchema>;
export type AgentUsage = z.infer<typeof agentUsageSchema>;

export interface UsageReportView {
  deviceId: string;
  displayName: string;
  report: UsageReport | null;
  acceptedAt: string | null;
}

function lengthPrefix(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.byteLength);
  return Buffer.concat([length, data]);
}

/**
 * Stable signed representation. Optional fields are represented by an empty
 * string and custom windows are serialized in their validated input order.
 */
export function usageReportSigningTranscript(report: UsageReport): Buffer {
  const values = [
    "1",
    report.deviceId,
    String(report.revision),
    report.updatedAt,
    String(report.requests),
    String(report.inputTokens),
    String(report.cachedInputTokens),
    String(report.outputTokens),
    String(report.reasoningOutputTokens),
    String(report.activeAgents),
    report.accountLabel ?? "",
    report.fiveHourPercent === undefined ? "" : String(report.fiveHourPercent),
    report.fiveHourResetAt === undefined ? "" : String(report.fiveHourResetAt),
    report.weeklyPercent === undefined ? "" : String(report.weeklyPercent),
    report.weeklyResetAt === undefined ? "" : String(report.weeklyResetAt),
    report.monthlyPercent === undefined ? "" : String(report.monthlyPercent),
    report.monthlyResetAt === undefined ? "" : String(report.monthlyResetAt),
    JSON.stringify(report.customWindows ?? []),
  ];
  // Reports created before per-agent accounting must retain their original
  // signing transcript. New reports bind the optional breakdown at the end.
  if (report.agents !== undefined) values.push(JSON.stringify(report.agents));
  return Buffer.concat([
    Buffer.from("COCODEX-USAGE-REPORT\u0000", "utf8"),
    ...values.map(lengthPrefix),
  ]);
}

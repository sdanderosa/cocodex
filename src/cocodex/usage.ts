import { sign } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  usageReportSchema,
  usageReportSigningTranscript,
  type UsageReport,
} from "../../packages/cocodex-protocol/src/index.ts";
import type { ClientIdentity } from "./identity";
import type { CodexUsage } from "./codex-agent-adapter";
import { hardenSecretPath } from "../lib/windows-secret-acl";

export function emptyUsageReport(deviceId: string): UsageReport {
  return {
    version: 1,
    deviceId,
    revision: 0,
    updatedAt: new Date(0).toISOString(),
    requests: 0,
    inputTokens: 0,
    cachedInputTokens: 0,
    outputTokens: 0,
    reasoningOutputTokens: 0,
    activeAgents: 0,
  };
}

export function loadUsageReport(path: string, deviceId: string): UsageReport {
  if (!existsSync(path)) return emptyUsageReport(deviceId);
  hardenSecretPath(path, { required: true });
  try {
    const report = usageReportSchema.parse(JSON.parse(readFileSync(path, "utf8")));
    if (report.deviceId !== deviceId) return emptyUsageReport(deviceId);
    return report;
  } catch {
    return emptyUsageReport(deviceId);
  }
}

export function saveUsageReport(path: string, report: UsageReport): void {
  usageReportSchema.parse(report);
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  hardenSecretPath(path, { required: true });
}

export function signUsageReport(report: UsageReport, identity: ClientIdentity): string {
  return sign(null, usageReportSigningTranscript(report), identity.privateKeyPem).toString("base64url");
}

export function addAgentUsage(
  report: UsageReport,
  agentId: string,
  usage: CodexUsage,
): NonNullable<UsageReport["agents"]> {
  const existing = report.agents?.find(agent => agent.agentId === agentId);
  const next = {
    agentId,
    requests: (existing?.requests ?? 0) + 1,
    inputTokens: (existing?.inputTokens ?? 0) + (usage.inputTokens ?? 0),
    cachedInputTokens: (existing?.cachedInputTokens ?? 0) + (usage.cachedInputTokens ?? 0),
    outputTokens: (existing?.outputTokens ?? 0) + (usage.outputTokens ?? 0),
    reasoningOutputTokens: (existing?.reasoningOutputTokens ?? 0) + (usage.reasoningOutputTokens ?? 0),
  };
  return [next, ...(report.agents ?? []).filter(agent => agent.agentId !== agentId)].slice(0, 8);
}

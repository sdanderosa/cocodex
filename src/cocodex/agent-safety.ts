import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import type { LocalAgentPolicy } from "./agent-policy";

const safetySchema = z.object({
  version: z.literal(1),
  executionEnabled: z.boolean(),
  fullComputerEnabled: z.boolean(),
  updatedAt: z.string().datetime({ offset: true }),
  reason: z.string().trim().max(500).optional(),
}).strict();

export type LocalAgentSafetyState = z.infer<typeof safetySchema>;

function defaultSafety(policy: LocalAgentPolicy): LocalAgentSafetyState {
  return {
    version: 1,
    executionEnabled: false,
    fullComputerEnabled: false,
    updatedAt: new Date().toISOString(),
    reason: `Safety state is missing for agent ${policy.agentId}; execution is disabled.`,
  };
}

function writeAtomic(path: string, value: LocalAgentSafetyState): LocalAgentSafetyState {
  const absolute = resolve(path);
  const directory = dirname(absolute);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${absolute}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, absolute);
  hardenSecretPath(absolute, { required: true });
  return value;
}

export function loadAgentSafety(path: string, policy: LocalAgentPolicy): LocalAgentSafetyState {
  if (!existsSync(path)) return defaultSafety(policy);
  hardenSecretPath(path, { required: true });
  const parsed = safetySchema.parse(JSON.parse(readFileSync(path, "utf8")));
  // A project-only policy can never be widened by a stale safety file. This
  // keeps an old opt-in from surviving a later policy downgrade.
  return policy.accessProfile === "full-computer" && policy.fullComputerOptIn
    ? parsed
    : { ...parsed, fullComputerEnabled: false };
}

export function saveAgentSafety(path: string, state: Omit<LocalAgentSafetyState, "version" | "updatedAt">): LocalAgentSafetyState {
  return writeAtomic(path, safetySchema.parse({
    ...state,
    version: 1,
    updatedAt: new Date().toISOString(),
  }));
}

export function configureAgentSafety(path: string, policy: LocalAgentPolicy): LocalAgentSafetyState {
  return saveAgentSafety(path, {
    executionEnabled: true,
    fullComputerEnabled: false,
    reason: policy.accessProfile === "full-computer"
      ? "Full-computer access requires a separate local enable action."
      : undefined,
  });
}

export function emergencyStopAgent(path: string, reason = "Stopped by the local host user."): LocalAgentSafetyState {
  if (existsSync(path)) safetySchema.parse(JSON.parse(readFileSync(path, "utf8")));
  return saveAgentSafety(path, { executionEnabled: false, fullComputerEnabled: false, reason });
}

export function resumeAgent(path: string, policy: LocalAgentPolicy): LocalAgentSafetyState {
  const current = loadAgentSafety(path, policy);
  return saveAgentSafety(path, { executionEnabled: true, fullComputerEnabled: current.fullComputerEnabled, reason: undefined });
}

export function setFullComputerEnabled(path: string, policy: LocalAgentPolicy, enabled: boolean): LocalAgentSafetyState {
  if (enabled && (policy.accessProfile !== "full-computer" || !policy.fullComputerOptIn)) {
    throw new Error("Full-computer access is not explicitly enabled in the local agent policy");
  }
  const current = loadAgentSafety(path, policy);
  return saveAgentSafety(path, { executionEnabled: current.executionEnabled, fullComputerEnabled: enabled, reason: enabled ? undefined : "Full-computer access disabled locally." });
}

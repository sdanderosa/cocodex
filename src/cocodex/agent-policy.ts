import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const policySchema = z.object({
  version: z.literal(1),
  projectId: z.uuid(),
  agentId: z.string().trim().min(1).max(120),
  workspaceRoot: z.string().min(1),
  workspaceMode: z.enum(["shared", "git-worktree"]).default("shared"),
  sandbox: z.enum(["read-only", "workspace-write"]),
  /**
   * `project-only` is the safe default. `full-computer` is an explicit local
   * opt-in that maps to Codex's supported `danger-full-access` sandbox.
   */
  accessProfile: z.enum(["project-only", "full-computer"]).default("project-only"),
  fullComputerOptIn: z.boolean().default(false),
  approvalMode: z.enum(["trusted-device", "always"]).default("trusted-device"),
  trustedRequesterFingerprints: z.record(z.uuid(), z.string().min(16).max(256)),
}).strict().superRefine((value, context) => {
  if (value.accessProfile === "full-computer" && !value.fullComputerOptIn) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["fullComputerOptIn"],
      message: "Full-computer access requires an explicit local opt-in",
    });
  }
});

const policyStoreSchema = z.object({
  version: z.literal(2),
  agents: z.array(policySchema).min(1).max(8),
}).strict().superRefine((value, context) => {
  const ids = new Set<string>();
  for (const [index, policy] of value.agents.entries()) {
    if (ids.has(policy.agentId)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["agents", index, "agentId"],
        message: "Local agent IDs must be unique",
      });
    }
    ids.add(policy.agentId);
  }
});

export type LocalAgentPolicy = z.infer<typeof policySchema>;
export interface LocalAgentPolicyStore {
  version: 1 | 2;
  agents: LocalAgentPolicy[];
}

export function validateLocalAgentPolicy(policy: LocalAgentPolicy): LocalAgentPolicy {
  return policySchema.parse({ ...policy, workspaceRoot: resolve(policy.workspaceRoot) });
}

function writePolicyFile(path: string, value: LocalAgentPolicy | z.infer<typeof policyStoreSchema>): void {
  mkdirSync(dirname(path), { recursive: true });
  hardenSecretDir(dirname(path), { required: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function saveLocalAgentPolicy(path: string, policy: LocalAgentPolicy): LocalAgentPolicy {
  const parsed = validateLocalAgentPolicy(policy);
  writePolicyFile(path, parsed);
  return parsed;
}

export function loadLocalAgentPolicyStore(path: string): LocalAgentPolicyStore {
  hardenSecretPath(path, { required: true });
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const legacy = policySchema.safeParse(raw);
  if (legacy.success) return { version: 1, agents: [legacy.data] };
  const store = policyStoreSchema.parse(raw);
  return { version: 2, agents: store.agents };
}

export function loadLocalAgentPolicies(path: string): LocalAgentPolicy[] {
  return loadLocalAgentPolicyStore(path).agents;
}

export function loadLocalAgentPolicy(path: string, agentId?: string): LocalAgentPolicy {
  const policies = loadLocalAgentPolicies(path);
  if (agentId) {
    const selected = policies.find(policy => policy.agentId === agentId);
    if (!selected) throw new Error("No local policy is configured for this agent");
    return selected;
  }
  if (policies.length !== 1) throw new Error("Multiple local agents are configured; specify an agent ID");
  return policies[0];
}

export function saveLocalAgentPolicies(path: string, policies: LocalAgentPolicy[]): LocalAgentPolicy[] {
  const parsed = policyStoreSchema.parse({
    version: 2,
    agents: policies.map(validateLocalAgentPolicy),
  });
  writePolicyFile(path, parsed);
  return parsed.agents;
}

export function upsertLocalAgentPolicy(path: string, policy: LocalAgentPolicy): LocalAgentPolicy[] {
  const parsed = validateLocalAgentPolicy(policy);
  const current = existsSync(path) ? loadLocalAgentPolicies(path) : [];
  const index = current.findIndex(candidate => candidate.agentId === parsed.agentId);
  const next = index < 0
    ? [...current, parsed]
    : current.map((candidate, candidateIndex) => candidateIndex === index ? parsed : candidate);
  return saveLocalAgentPolicies(path, next);
}

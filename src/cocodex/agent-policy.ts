import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

export type LocalAgentPolicy = z.infer<typeof policySchema>;

export function saveLocalAgentPolicy(path: string, policy: LocalAgentPolicy): LocalAgentPolicy {
  const parsed = policySchema.parse({ ...policy, workspaceRoot: resolve(policy.workspaceRoot) });
  mkdirSync(dirname(path), { recursive: true });
  hardenSecretDir(dirname(path), { required: true });
  writeFileSync(path, `${JSON.stringify(parsed, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  hardenSecretPath(path, { required: true });
  return parsed;
}

export function loadLocalAgentPolicy(path: string): LocalAgentPolicy {
  hardenSecretPath(path, { required: true });
  return policySchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

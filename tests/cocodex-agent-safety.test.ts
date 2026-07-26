import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { emergencyStopAgent, configureAgentSafety, loadAgentSafety, resumeAgent, setFullComputerEnabled } from "../src/cocodex/agent-safety";
import {
  loadLocalAgentPolicies,
  loadLocalAgentPolicy,
  loadLocalAgentPolicyStore,
  saveLocalAgentPolicy,
  upsertLocalAgentPolicy,
} from "../src/cocodex/agent-policy";

const projectId = "bd5b929c-1024-4a0b-bbd7-fc246a84de89";
const deviceId = "51f90a90-2168-4fc6-8abf-c5cda3a0a9df";

function policy(root: string, accessProfile: "project-only" | "full-computer", fullComputerOptIn: boolean) {
  return saveLocalAgentPolicy(join(root, "policy.json"), {
    version: 1,
    projectId,
    agentId: "local-codex",
    workspaceRoot: root,
    sandbox: "workspace-write",
    accessProfile,
    fullComputerOptIn,
    approvalMode: "trusted-device",
    trustedRequesterFingerprints: { [deviceId]: "A".repeat(32) },
  });
}

describe("CoCodex local agent safety controls", () => {
  test("persist atomically, fail closed on downgrade, and require explicit full-computer confirmation", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-safety-"));
    const safetyPath = join(root, "local-agent-safety.json");
    try {
      const full = policy(root, "full-computer", true);
      expect(configureAgentSafety(safetyPath, full)).toMatchObject({
        executionEnabled: true,
        fullComputerEnabled: false,
      });
      const initialRaw = readFileSync(safetyPath, "utf8");
      expect(JSON.parse(initialRaw).version).toBe(1);

      const stopped = emergencyStopAgent(safetyPath, "Incident response");
      expect(stopped).toMatchObject({ executionEnabled: false, fullComputerEnabled: false, reason: "Incident response" });
      expect(loadAgentSafety(safetyPath, full).executionEnabled).toBeFalse();
      expect(resumeAgent(safetyPath, full)).toMatchObject({ executionEnabled: true, fullComputerEnabled: false });
      expect(setFullComputerEnabled(safetyPath, full, true).fullComputerEnabled).toBeTrue();

      const projectOnly = policy(root, "project-only", false);
      expect(loadAgentSafety(safetyPath, projectOnly).fullComputerEnabled).toBeFalse();
      expect(() => setFullComputerEnabled(safetyPath, projectOnly, true)).toThrow("not explicitly enabled");
      expect(loadAgentSafety(join(root, "missing.json"), projectOnly)).toMatchObject({
        executionEnabled: false,
        fullComputerEnabled: false,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects a full-computer policy without an explicit opt-in", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-policy-reject-"));
    try {
      expect(() => policy(root, "full-computer", false)).toThrow("explicit local opt-in");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("migrates one legacy policy into a bounded multi-agent store without overwriting it", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-policy-store-"));
    const policyPath = join(root, "policy.json");
    try {
      const first = policy(root, "project-only", false);
      expect(loadLocalAgentPolicyStore(policyPath)).toMatchObject({ version: 1, agents: [first] });
      const second = { ...first, agentId: randomUUID(), workspaceRoot: join(root, "second") };
      upsertLocalAgentPolicy(policyPath, second);
      expect(loadLocalAgentPolicyStore(policyPath).version).toBe(2);
      expect(loadLocalAgentPolicies(policyPath).map(item => item.agentId)).toEqual([first.agentId, second.agentId]);
      expect(loadLocalAgentPolicy(policyPath, second.agentId)).toMatchObject(second);
      expect(() => loadLocalAgentPolicy(policyPath)).toThrow("Multiple local agents");

      let latest = second;
      for (let index = 3; index <= 8; index += 1) {
        latest = { ...first, agentId: randomUUID(), workspaceRoot: join(root, `agent-${index}`) };
        upsertLocalAgentPolicy(policyPath, latest);
      }
      expect(loadLocalAgentPolicies(policyPath)).toHaveLength(8);
      expect(() => upsertLocalAgentPolicy(policyPath, {
        ...latest,
        agentId: randomUUID(),
        workspaceRoot: join(root, "agent-9"),
      })).toThrow();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects aggregate local agent definitions above the device thread budget", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-thread-budget-"));
    const policyPath = join(root, "policy.json");
    try {
      const first = saveLocalAgentPolicy(policyPath, {
        version: 1,
        projectId,
        agentId: randomUUID(),
        workspaceRoot: root,
        sandbox: "workspace-write",
        primaryModel: "gpt-5.6-sol",
        primaryEffort: "medium",
        coAgentModel: "gpt-5.6-luna",
        coAgentEffort: "medium",
        maxConcurrentCoAgents: 8,
        accessProfile: "project-only",
        fullComputerOptIn: false,
        approvalMode: "trusted-device",
        trustedRequesterFingerprints: { [deviceId]: "A".repeat(32) },
      });
      expect(() => upsertLocalAgentPolicy(policyPath, {
        ...first,
        agentId: randomUUID(),
        workspaceRoot: join(root, "second"),
        maxConcurrentCoAgents: 7,
      })).toThrow("thread device budget");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

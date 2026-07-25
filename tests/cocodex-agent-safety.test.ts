import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emergencyStopAgent, configureAgentSafety, loadAgentSafety, resumeAgent, setFullComputerEnabled } from "../src/cocodex/agent-safety";
import { saveLocalAgentPolicy } from "../src/cocodex/agent-policy";

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
        fullComputerEnabled: true,
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
        executionEnabled: true,
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
});

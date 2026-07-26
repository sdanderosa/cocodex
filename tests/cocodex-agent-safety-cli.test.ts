import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const bun = join(import.meta.dir, "..", "node_modules", "bun", "bin", "bun.exe");

function runClient(cli: string, args: string[]): { exitCode: number | null; stdout: string; stderr: string } {
  const child = spawnSync(bun, [cli, ...args], {
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
  });
  if (process.platform === "win32") Bun.sleepSync(1_000);
  return {
    exitCode: child.status,
    stdout: child.stdout.trim(),
    stderr: `${child.stderr}${child.error ? `\n${child.error.message}` : ""}`.trim(),
  };
}

describe("CoCodex agent safety CLI", () => {
  test("configures, stops, resumes, and separately enables full-computer access", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-safety-cli-"));
    const workspace = join(root, "workspace");
    mkdirSync(workspace, { recursive: true });
    const cli = join(import.meta.dir, "..", "src", "cocodex", "cli.ts");
    const projectId = "bd5b929c-1024-4a0b-bbd7-fc246a84de89";
    const deviceId = "51f90a90-2168-4fc6-8abf-c5cda3a0a9df";
    const fingerprint = "A".repeat(32);
    try {
      // The path is created by the test so the adapter's workspace check is real.
      await Bun.write(join(workspace, "README.md"), "local");
      const configured = await runClient(cli, [
        "configure-agent", "--project", projectId, "--agent", "local-codex", "--workspace", workspace,
        "--trust-device", deviceId, "--trust-fingerprint", fingerprint,
        "--access", "full-computer", "--confirm-full-computer", "--state-root", root,
      ]);
      expect(configured.exitCode).toBe(0);
      expect(JSON.parse(configured.stdout)).toMatchObject({ configured: true, accessProfile: "full-computer" });

      const initial = await runClient(cli, ["agent-safety-status", "--state-root", root]);
      expect(JSON.parse(initial.stdout).safety).toMatchObject({ executionEnabled: true, fullComputerEnabled: false });

      const stopped = await runClient(cli, ["emergency-stop", "--reason", "CLI incident", "--state-root", root]);
      expect(stopped.exitCode).toBe(0);
      expect(JSON.parse(stopped.stdout).safety).toEqual([{
        agentId: "local-codex",
        state: expect.objectContaining({
          executionEnabled: false,
          fullComputerEnabled: false,
          reason: "CLI incident",
        }),
      }]);

      const unconfirmed = await runClient(cli, ["full-computer-enable", "--state-root", root]);
      expect(unconfirmed.exitCode).not.toBe(0);
      expect(unconfirmed.stderr).toContain("--confirm");

      const resumed = await runClient(cli, ["emergency-resume", "--state-root", root]);
      expect(JSON.parse(resumed.stdout).safety).toMatchObject({ executionEnabled: true, fullComputerEnabled: false });
      const enabled = await runClient(cli, ["full-computer-enable", "--confirm", "--state-root", root]);
      expect(JSON.parse(enabled.stdout).safety).toMatchObject({ executionEnabled: true, fullComputerEnabled: true });
      const disabled = await runClient(cli, ["full-computer-disable", "--state-root", root]);
      expect(JSON.parse(disabled.stdout).safety.fullComputerEnabled).toBeFalse();
    } finally {
      rmSync(root, { recursive: true, force: true });
      if (process.platform === "win32") await Bun.sleep(1_000);
    }
  }, 60_000);
});

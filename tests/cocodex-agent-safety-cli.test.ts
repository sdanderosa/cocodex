import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function runClient(cli: string, args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, cli, ...args], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout: stdout.trim(), stderr: stderr.trim() };
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
      expect(JSON.parse(initial.stdout).safety).toMatchObject({ executionEnabled: true, fullComputerEnabled: true });

      const stopped = await runClient(cli, ["emergency-stop", "--reason", "CLI incident", "--state-root", root]);
      expect(stopped.exitCode).toBe(0);
      expect(JSON.parse(stopped.stdout).safety).toMatchObject({ executionEnabled: false, fullComputerEnabled: false, reason: "CLI incident" });

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
    }
  }, 20_000);
});

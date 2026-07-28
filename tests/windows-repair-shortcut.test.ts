import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const scriptPath = resolve(import.meta.dir, "../bin/repair-codex.ps1");

describe("Windows Codex safe-repair shortcut contract", () => {
  test("backs up before repair, requires readiness, and preserves unknown listeners", () => {
    const script = readFileSync(scriptPath, "utf8");
    expect(script).toContain("[IO.File]::Copy($configPath, $candidate, $false)");
    expect(script).toContain("Get-NetTCPConnection -LocalPort $port -State Listen");
    expect(script).toContain("never stops or adopts an unknown listener");
    expect(script).toContain("$ready.checks.credentials -eq $true");
    expect(script).toContain('Invoke-Ocx @(\"restore\")');
    expect(script).toContain('Invoke-Ocx @(\"service\", \"start\")');
    expect(script).toContain('Invoke-Ocx @(\"ensure\")');
    expect(script).toContain('$health = Get-JsonEndpoint "/healthz" 1');
    expect(script).not.toMatch(/Stop-Process|taskkill\.exe|sc\.exe\s+delete/i);
  });

  test("supports a no-change dry run for the desktop shortcut", () => {
    const script = readFileSync(scriptPath, "utf8");
    expect(script).toContain("[switch]$DryRun");
    expect(script).toContain("would run ocx restore; no configuration or process will be changed");
    expect(script).toContain("would run ocx ensure; no configuration or process will be changed");
  });
});

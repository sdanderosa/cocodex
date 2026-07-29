import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertDirectServerOwnership } from "../src/process-ownership";
import { createDefaultConfig, saveConfig } from "../src/config";
import { serverPaths } from "../src/paths";
import { tryAutomaticPortMapping } from "../src/port-mapping";
import {
  SUNSHINE_PROTECTED_PORT_MAX,
  SUNSHINE_PROTECTED_PORT_MIN,
  assertSunshinePortsUntouched,
  isSunshineProtectedPort,
} from "../src/protected-host-services";

const roots: string[] = [];

function sourceTreeText(root: string): string {
  return readdirSync(root, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(root, entry.name);
      if (entry.isDirectory()) return [sourceTreeText(path)];
      if (!entry.isFile() || !/\.(?:ts|tsx|js|mjs|cjs)$/u.test(entry.name)) return [];
      return [readFileSync(path, "utf8")];
    })
    .join("\n");
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("Sunshine host-service protection", () => {
  test("rejects every Sunshine port before binding, mapping, or firewall setup", async () => {
    for (let port = SUNSHINE_PROTECTED_PORT_MIN; port <= SUNSHINE_PROTECTED_PORT_MAX; port += 1) {
      expect(isSunshineProtectedPort(port)).toBe(true);
      expect(() => assertSunshinePortsUntouched(port)).toThrow("Sunshine");
      expect(() => createDefaultConfig(serverPaths("unused"), "127.0.0.1", port)).toThrow("Sunshine");
    }

    expect(isSunshineProtectedPort(SUNSHINE_PROTECTED_PORT_MIN - 1)).toBe(false);
    expect(isSunshineProtectedPort(SUNSHINE_PROTECTED_PORT_MAX + 1)).toBe(false);

    const previous = process.env.COCODEX_DISABLE_PORT_MAPPING;
    process.env.COCODEX_DISABLE_PORT_MAPPING = "1";
    try {
      await expect(tryAutomaticPortMapping(47_990)).rejects.toThrow("Sunshine");
    } finally {
      if (previous === undefined) delete process.env.COCODEX_DISABLE_PORT_MAPPING;
      else process.env.COCODEX_DISABLE_PORT_MAPPING = previous;
    }
  });

  test("signals only the exact healthy CoCodex Server process", async () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-host-protection-"));
    roots.push(root);
    const paths = serverPaths(root);
    saveConfig(paths, createDefaultConfig(paths, "127.0.0.1", 19_463));

    const fetchFor = (body: Record<string, unknown>) => (async () => new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;

    await expect(assertDirectServerOwnership(paths, 41_001, fetchFor({
      ok: true,
      service: "cocodex-server",
      protocol: 1,
      processId: 41_001,
    }))).resolves.toBeUndefined();

    await expect(assertDirectServerOwnership(paths, 11_100, fetchFor({
      ok: true,
      service: "cocodex-server",
      protocol: 1,
      processId: 41_001,
    }))).rejects.toThrow("no foreign process (including Sunshine) was stopped");

    await expect(assertDirectServerOwnership(paths, 11_100, fetchFor({
      ok: true,
      service: "sunshine",
      protocol: 1,
      processId: 11_100,
    }))).rejects.toThrow("no foreign process (including Sunshine) was stopped");
  });

  test("ownership proof precedes every stop/restart signal and Sunshine IP, ports, service, and process remain read-only", () => {
    const source = readFileSync(join(import.meta.dir, "../src/cli.ts"), "utf8");
    for (const marker of ['case "stop"', 'case "restart"']) {
      const command = source.slice(source.indexOf(marker), source.indexOf("case ", source.indexOf(marker) + marker.length));
      expect(command.indexOf("await assertDirectServerOwnership(paths, pid)")).toBeGreaterThanOrEqual(0);
      expect(command.indexOf("await assertDirectServerOwnership(paths, pid)")).toBeLessThan(command.indexOf('process.kill(pid, "SIGTERM")'));
    }

    const serverSource = sourceTreeText(join(import.meta.dir, "../src"));
    for (const forbidden of [
      "netsh interface ip",
      "netsh interface ipv4",
      "netsh interface ipv6",
      "Set-NetIPAddress",
      "New-NetIPAddress",
      "Remove-NetIPAddress",
      "Set-NetIPInterface",
      "Stop-Service Sunshine",
      "Restart-Service Sunshine",
      "sc stop Sunshine",
      "taskkill /IM sunshine",
    ]) {
      expect(serverSource.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
  });
});

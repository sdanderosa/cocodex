import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectCodexBrowserCapability,
  openOfficialCodexApp,
  type CodexBrowserCapabilityDeps,
} from "../src/cocodex/codex-browser-capability";

function deps(outputs: Record<string, { status: number; stdout?: string }>, calls: string[][] = []): CodexBrowserCapabilityDeps {
  return {
    platform: "linux",
    resolveRuntime: () => ({
      runtime: { command: "/opt/codex", version: "0.146.0-alpha.3.1", source: "app" },
      failures: [],
    }),
    probe: (_file, args) => {
      calls.push([...args]);
      const result = outputs[args.join(" ")] ?? { status: 1 };
      return { status: result.status, stdout: Buffer.from(result.stdout ?? ""), stderr: Buffer.alloc(0) };
    },
  };
}

describe("official Codex browser capability", () => {
  test("reports the installed desktop Browser honestly without claiming codex exec support", () => {
    const capability = detectCodexBrowserCapability(deps({
      "features list": { status: 0, stdout: "browser_use stable true\nbrowser_use_external stable true\nbrowser_use_full_cdp_access stable false\n" },
      "plugin list": { status: 0, stdout: "browser@openai-bundled  installed, enabled  26.721\n" },
      "app --help": { status: 0 },
    }));
    expect(capability).toEqual({
      version: 1,
      executionSurface: "codex-exec",
      runtimeVersion: "0.146.0-alpha.3.1",
      agentBrowserAvailable: false,
      officialAppAvailable: true,
      browserPluginInstalled: true,
      browserFeatureEnabled: true,
      externalBrowserFeatureEnabled: true,
      fullCdpFeatureEnabled: false,
      status: "official-app-only",
      reason: expect.stringContaining("official Codex app"),
    });
  });

  test("fails closed for missing flags, plugin, app command, or runtime", () => {
    expect(detectCodexBrowserCapability(deps({
      "features list": { status: 0, stdout: "browser_use stable false\n" },
      "plugin list": { status: 0, stdout: "browser@openai-bundled  not installed\n" },
      "app --help": { status: 1 },
    }))).toMatchObject({ agentBrowserAvailable: false, officialAppAvailable: false, status: "unavailable" });
    expect(detectCodexBrowserCapability({ resolveRuntime: () => { throw new Error("missing"); } }))
      .toMatchObject({ runtimeVersion: null, officialAppAvailable: false, status: "unavailable" });
  });

  test("opens only the configured workspace through shell-free official app argv", () => {
    const root = mkdtempSync(join(tmpdir(), "cocodex-browser-open-"));
    const calls: string[][] = [];
    try {
      const capability = openOfficialCodexApp(root, deps({
        "features list": { status: 0, stdout: "browser_use stable true\nbrowser_use_external stable true\n" },
        "plugin list": { status: 0, stdout: "browser@openai-bundled  installed, enabled  26.721\n" },
        "app --help": { status: 0 },
        [`app ${root}`]: { status: 0 },
      }, calls));
      expect(capability.officialAppAvailable).toBeTrue();
      expect(calls.at(-1)).toEqual(["app", root]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

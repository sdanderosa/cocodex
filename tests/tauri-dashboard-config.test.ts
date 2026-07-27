import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";

const repoRoot = resolve(import.meta.dir, "..");

function readJson(relativePath: string): Record<string, any> {
  return JSON.parse(readFileSync(resolve(repoRoot, relativePath), "utf8")) as Record<string, any>;
}

describe("CoCodex Tauri dashboard configuration", () => {
  test("wraps the shared Vite build without granting native shell access", () => {
    const config = readJson("gui/src-tauri/tauri.conf.json");
    const capabilities = readJson("gui/src-tauri/capabilities/default.json");

    expect(config.productName).toBe("CoCodex");
    expect(config.identifier).toBe("com.cocodex.desktop");
    expect(config.build.frontendDist).toBe("../dist");
    expect(config.build.devUrl).toBe("http://127.0.0.1:4179");
    expect(config.build.beforeDevCommand).toContain("dev-tauri.ts");
    expect(config.build.beforeBuildCommand).toBe("bun run build");
    expect(config.app.windows).toHaveLength(1);
    expect(config.app.windows[0].label).toBe("main");
    for (const icon of config.bundle.icon as string[]) {
      expect(existsSync(resolve(repoRoot, "gui/src-tauri", icon))).toBe(true);
    }
    expect(capabilities.windows).toEqual(["main"]);
    expect(capabilities.permissions).toEqual(["core:default"]);
  });
});

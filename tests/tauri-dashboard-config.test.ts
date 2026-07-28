import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  parseRustHostTriple,
  sidecarOutputPath,
  validateTargetTriple,
} from "../scripts/build-tauri-sidecar";

const repoRoot = resolve(import.meta.dir, "..");

function readJson(relativePath: string): Record<string, any> {
  return JSON.parse(readFileSync(resolve(repoRoot, relativePath), "utf8")) as Record<string, any>;
}

describe("CoCodex Tauri dashboard configuration", () => {
  test("bundles the managed runtime without granting webview shell access", () => {
    const config = readJson("gui/src-tauri/tauri.conf.json");
    const capabilities = readJson("gui/src-tauri/capabilities/default.json");
    const cargoManifest = readFileSync(resolve(repoRoot, "gui/src-tauri/Cargo.toml"), "utf8");
    const nativeMain = readFileSync(resolve(repoRoot, "gui/src-tauri/src/main.rs"), "utf8");

    expect(config.productName).toBe("CoCodex");
    expect(config.identifier).toBe("com.cocodex.desktop");
    expect(config.build.frontendDist).toBe("../dist");
    expect(config.build.devUrl).toBe("http://127.0.0.1:4179");
    expect(config.build.beforeDevCommand).toContain("dev-tauri.ts");
    expect(config.build.beforeBuildCommand).toContain("build-tauri-frontend.ts");
    expect(config.app.windows).toHaveLength(1);
    expect(config.app.windows[0].label).toBe("main");
    expect(config.app.windows[0].visible).toBe(false);
    expect(config.bundle.externalBin).toEqual(["binaries/cocodex-runtime"]);
    for (const icon of config.bundle.icon as string[]) {
      expect(existsSync(resolve(repoRoot, "gui/src-tauri", icon))).toBe(true);
    }
    expect(capabilities.windows).toEqual(["main"]);
    expect(capabilities.permissions).toEqual(["core:default"]);
    expect(cargoManifest).toContain('tauri-plugin-shell = "2"');
    expect(nativeMain).toContain('.sidecar("cocodex-runtime")');
    expect(nativeMain).toContain("stop_owned_runtime");
    expect(nativeMain).toContain("window.location.hash = '#cocodex'");
  });

  test("derives the external-binary filename from a validated Rust target", () => {
    expect(parseRustHostTriple("rustc 1.97.1\nhost: x86_64-pc-windows-msvc\n")).toBe(
      "x86_64-pc-windows-msvc",
    );
    expect(validateTargetTriple("aarch64-apple-darwin")).toBe("aarch64-apple-darwin");
    expect(() => validateTargetTriple("../escape")).toThrow("invalid Rust target triple");
    expect(sidecarOutputPath("x86_64-pc-windows-msvc")).toEndWith(
      "cocodex-runtime-x86_64-pc-windows-msvc.exe",
    );
  });
});

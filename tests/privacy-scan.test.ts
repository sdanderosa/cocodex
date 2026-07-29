import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");

describe("repository privacy scan", () => {
  test("accepts the required Tauri high-DPI icon without weakening the scan", () => {
    const config = readFileSync(resolve(root, "gui/src-tauri/tauri.conf.json"), "utf8");
    expect(config).toContain(["128x128", "2x.png"].join("@"));

    const result = Bun.spawnSync([process.execPath, "scripts/privacy-scan.ts"], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(new TextDecoder().decode(result.stdout)).toContain("Privacy scan passed");
    expect(result.exitCode).toBe(0);
  }, 15_000);
});

import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { backupConfigBeforeUpdate } from "../src/config";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("pre-update OpenCodex config backup", () => {
  test("copies exact bytes without overwriting an existing snapshot", () => {
    const root = mkdtempSync(join(tmpdir(), "ocx-update-backup-"));
    roots.push(root);
    const configPath = join(root, "config.json");
    const bytes = '{\n  "providers": {"openai": {"codexAccountMode": "direct"}}\n}\n';
    writeFileSync(configPath, bytes);
    const first = backupConfigBeforeUpdate(configPath, 1234);
    const second = backupConfigBeforeUpdate(configPath, 1234);

    expect(first).toBe(`${configPath}.pre-update.1234.bak`);
    expect(second).toBe(`${configPath}.pre-update.1234-1.bak`);
    expect(readFileSync(first!, "utf8")).toBe(bytes);
    expect(readFileSync(second!, "utf8")).toBe(bytes);
  });

  test("is a no-op when no persisted config exists", () => {
    const root = mkdtempSync(join(tmpdir(), "ocx-update-backup-"));
    roots.push(root);
    expect(backupConfigBeforeUpdate(join(root, "missing.json"), 1234)).toBeNull();
    expect(existsSync(join(root, "missing.json.pre-update.1234.bak"))).toBe(false);
  });

  test("the npm launcher backs up before stopping or replacing the package", () => {
    const source = readFileSync(new URL("../bin/ocx.mjs", import.meta.url), "utf8");
    const backupAt = source.indexOf("const configBackup = backupConfigBeforeUpdate()");
    const stopAt = source.indexOf("Stopping the running proxy before updating");
    const replaceAt = source.indexOf("npm} install -g");
    expect(backupAt).toBeGreaterThan(-1);
    expect(stopAt).toBeGreaterThan(backupAt);
    expect(replaceAt).toBeGreaterThan(backupAt);
    expect(source).toContain("fsConstants.COPYFILE_EXCL");
  });});

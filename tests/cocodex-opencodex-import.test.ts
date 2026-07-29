import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyOpenCodexImport,
  createOpenCodexImportPlan,
  listOpenCodexImportBackups,
  rollbackOpenCodexImport,
  summarizeOpenCodexImportPlan,
} from "../src/cocodex/opencodex-import";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture(): { source: string; codex: string; state: string } {
  const root = mkdtempSync(join(tmpdir(), "cocodex-opencodex-import-"));
  const source = join(root, "opencodex");
  const codex = join(root, "codex");
  const state = join(root, "cocodex");
  roots.push(root);
  mkdirSync(source, { recursive: true });
  mkdirSync(codex, { recursive: true });
  mkdirSync(state, { recursive: true });
  writeFileSync(join(source, "config.json"), JSON.stringify({
    providers: { openai: { baseUrl: "https://example.invalid", apiKey: "do-not-print" } },
    defaultProvider: "openai",
  }));
  writeFileSync(join(codex, "opencodex-catalog.json"), JSON.stringify({ models: ["gpt-5.6-sol"] }));
  writeFileSync(join(source, "usage.jsonl"), '{"model":"gpt-5.6-sol","inputTokens":4}\n');
  writeFileSync(join(source, "auth.json"), '{"refreshToken":"must-stay-out"}\n');
  writeFileSync(join(source, "codex-accounts.json"), '{"main":{"refreshToken":"must-stay-out"}}\n');
  writeFileSync(join(source, "ocx.pid"), "1234\n");
  return { source, codex, state };
}

describe("CoCodex OpenCodex import flow", () => {
  test("previews an allowlisted plan without exposing provider secret values", () => {
    const { source, codex, state } = fixture();
    const plan = createOpenCodexImportPlan({
      sourceOpenCodexHome: source,
      targetOpenCodexHome: join(state, "opencodex"),
      sourceCodexHome: codex,
      targetCodexHome: join(state, "codex"),
      includeSecrets: true,
    });
    const config = plan.files.find(file => file.relativePath === "config.json");
    expect(config?.status).toBe("available");
    expect(config?.sensitive).toBeTrue();
    expect(plan.files.find(file => file.relativePath === "auth.json")?.status).toBe("excluded");
    expect(plan.files.find(file => file.relativePath === "codex-accounts.json")?.status).toBe("excluded");
    expect(summarizeOpenCodexImportPlan(plan).available).toBe(3);
    expect(JSON.stringify(plan)).not.toContain("do-not-print");
  });

  test("applies atomically, preserves source and client authentication, and records backups", () => {
    const { source, codex, state } = fixture();
    const target = join(state, "opencodex");
    const existingConfig = join(target, "config.json");
    const existingAuth = join(target, "auth.json");
    mkdirForTest(target);
    writeFileSync(existingConfig, '{"providers":{"old":{"baseUrl":"https://old.invalid"}}}\n');
    writeFileSync(existingAuth, '{"refreshToken":"existing-auth"}\n');
    const existingConfigContent = readFileSync(existingConfig, "utf8");
    const sourceConfig = readFileSync(join(source, "config.json"), "utf8");
    const plan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, sourceCodexHome: codex, targetCodexHome: join(state, "codex"), includeSecrets: true });
    const result = applyOpenCodexImport(plan, new Date("2026-01-02T03:04:05.000Z"));
    expect(readFileSync(existingConfig, "utf8")).toBe(sourceConfig);
    expect(readFileSync(existingAuth, "utf8")).toBe('{"refreshToken":"existing-auth"}\n');
    expect(result.imported.map(file => file.relativePath)).toContain("config.json");
    expect(listOpenCodexImportBackups(target)).toHaveLength(1);
    expect(readFileSync(join(source, "auth.json"), "utf8")).toContain("must-stay-out");
    expect(result.backupDirectory).toContain(".cocodex-import-backups");
    expect(readFileSync(join(result.backupDirectory, "manifest.json"), "utf8")).toContain("config.json");
    const rollback = rollbackOpenCodexImport(result.backupDirectory, target, join(state, "codex"));
    expect(rollback.restored).toBe(1);
    expect(rollback.removed).toBe(2);
    expect(readFileSync(existingConfig, "utf8")).toBe(existingConfigContent);
    expect(readFileSync(existingAuth, "utf8")).toBe('{"refreshToken":"existing-auth"}\n');
  });

  test("rollback removes only the imported bundle and leaves the source untouched", () => {
    const { source, codex, state } = fixture();
    const target = join(state, "opencodex");
    const plan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, sourceCodexHome: codex, targetCodexHome: join(state, "codex"), includeSecrets: true });
    const manifest = applyOpenCodexImport(plan);
    const result = rollbackOpenCodexImport(manifest.backupDirectory, target, join(state, "codex"));
    expect(result.rolledBack).toBeTrue();
    expect(existsSync(join(target, "usage.jsonl"))).toBeFalse();
    expect(readFileSync(join(source, "config.json"), "utf8")).toContain("do-not-print");
    expect(readFileSync(join(source, "auth.json"), "utf8")).toContain("must-stay-out");
  });

  test("refuses a source that changes after preview before publishing a bundle", () => {
    const { source, codex, state } = fixture();
    writeFileSync(join(source, "config.json"), "not-json\n");
    const target = join(state, "opencodex");
    const plan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, sourceCodexHome: codex, targetCodexHome: join(state, "codex"), includeSecrets: true });
    writeFileSync(join(source, "usage.jsonl"), "changed\n");
    expect(() => applyOpenCodexImport(plan)).toThrow("Source changed before import");
    expect(existsSync(join(target, "config.json"))).toBeFalse();
  });

  test("refuses rollback after an imported destination is edited", () => {
    const { source, codex, state } = fixture();
    const target = join(state, "opencodex");
    const plan = createOpenCodexImportPlan({
      sourceOpenCodexHome: source,
      targetOpenCodexHome: target,
      sourceCodexHome: codex,
      targetCodexHome: join(state, "codex"),
      includeSecrets: true,
    });
    const result = applyOpenCodexImport(plan);
    writeFileSync(join(target, "usage.jsonl"), "edited after import\n");
    expect(() => rollbackOpenCodexImport(result.backupDirectory, target, join(state, "codex"))).toThrow("destination was edited");
    expect(readFileSync(join(target, "usage.jsonl"), "utf8")).toBe("edited after import\n");
  });
});

function mkdirForTest(path: string): void {
  mkdirSync(path, { recursive: true });
}

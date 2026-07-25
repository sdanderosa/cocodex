import { describe, expect, test } from "bun:test";
import { globSync, readFileSync } from "node:fs";
import { join } from "node:path";

describe("server trust boundary", () => {
  test("does not import OpenCodex credentials, providers, management, or execution", () => {
    const sourceRoot = join(import.meta.dir, "..");
    const sourceFiles = globSync("src/**/*.ts", { cwd: sourceRoot }).map((file) => join(sourceRoot, file));
    const forbidden = [
      new RegExp(String.raw`from\s+["'][^"']*src/server`),
      new RegExp(String.raw`from\s+["'][^"']*src/providers`),
      new RegExp(String.raw`from\s+["'][^"']*src/codex`),
      new RegExp(String.raw`from\s+["'][^"']*management-api`),
      new RegExp(String.raw`from\s+["'][^"']*native-exec`),
    ];
    for (const file of sourceFiles) {
      const source = readFileSync(file, "utf8");
      for (const pattern of forbidden) expect(source).not.toMatch(pattern);
    }
  });
});

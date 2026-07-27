import { expect, test } from "bun:test";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

test("compiled CoCodex embeds its audited DPAPI addon", () => {
  if (process.platform !== "win32") return;
  const root = mkdtempSync(join(tmpdir(), "cocodex-compiled-dpapi-"));
  const stagedLib = join(root, "src", "lib");
  const source = join(root, "entry.ts");
  const executable = join(root, "dpapi-smoke.exe");
  const protectedPath = join(root, "protected.json");
  const implementation = join(stagedLib, "local-protected-secret.ts");
  const architecture = process.arch === "arm64" ? "win32-arm64" : "win32-x64";
  const sourceAddon = join(
    import.meta.dir,
    "..",
    "node_modules",
    "@primno",
    "dpapi",
    "prebuilds",
    architecture,
    "@primno+dpapi.node",
  );
  const stagedAddon = join(
    root,
    "node_modules",
    "@primno",
    "dpapi",
    "prebuilds",
    architecture,
    "@primno+dpapi.node",
  );
  try {
    mkdirSync(stagedLib, { recursive: true });
    mkdirSync(dirname(stagedAddon), { recursive: true });
    copyFileSync(
      join(import.meta.dir, "..", "src", "lib", "local-protected-secret.ts"),
      implementation,
    );
    copyFileSync(
      join(import.meta.dir, "..", "src", "lib", "windows-secret-acl.ts"),
      join(stagedLib, "windows-secret-acl.ts"),
    );
    copyFileSync(sourceAddon, stagedAddon);
    writeFileSync(source, [
      `import { writeProtectedSecret } from ${JSON.stringify(implementation)};`,
      `writeProtectedSecret(process.argv.at(-1)!, "cocodex.test.compiled", "COMPILED-DPAPI-CANARY");`,
    ].join("\n"));
    const built = Bun.spawnSync([
      process.execPath,
      "build",
      source,
      "--compile",
      "--outfile",
      executable,
    ], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(built.exitCode).toBe(0);
    const binary = readFileSync(executable);
    expect(binary.includes(Buffer.from("CryptProtectData"))).toBe(true);
    expect(binary.includes(Buffer.from("CryptUnprotectData"))).toBe(true);

    rmSync(join(root, "node_modules"), { recursive: true, force: true });
    rmSync(join(root, "src"), { recursive: true, force: true });
    const ran = Bun.spawnSync([executable, protectedPath], {
      cwd: root,
      env: { ...process.env, NODE_PATH: "" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(ran.exitCode).toBe(0);
    const stored = readFileSync(protectedPath, "utf8");
    expect(stored).not.toContain("COMPILED-DPAPI-CANARY");
    expect(stored).toContain('"protection":"windows-dpapi-current-user"');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 60_000);

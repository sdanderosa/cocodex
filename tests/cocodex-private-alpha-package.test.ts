import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sourcePackage from "../package.json";
import {
  assertShrinkwrap,
  privateAlphaPackageJson,
} from "../scripts/build-cocodex-private-alpha";
import { windowsTestProcessEnvironment } from "../scripts/test";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("CoCodex private-alpha distribution", () => {
  test("creates a branded local package without changing inherited runtime dependencies", () => {
    const packaged = privateAlphaPackageJson(sourcePackage, "0.1.0-alpha.1");
    expect(packaged).toMatchObject({
      name: "@sdanderosa/cocodex",
      version: "0.1.0-alpha.1",
      repository: { url: "git+https://github.com/sdanderosa/cocodex.git" },
      bin: {
        cocodex: "./bin/ccx.mjs",
        ccx: "./bin/ccx.mjs",
        "cocodex-server": "./bin/ccx-server.mjs",
        "ccx-server": "./bin/ccx-server.mjs",
        ocx: "./bin/ocx.mjs",
      },
      scripts: {},
      engines: { node: ">=22.12.0" },
    });
    expect(packaged.dependencies).toEqual({
      "@bufbuild/protobuf": "2.12.1",
      "@modelcontextprotocol/sdk": "1.29.0",
      "@primno/dpapi": "2.0.1",
      bun: "1.3.14",
      "libsodium-wrappers-sumo": "0.8.2",
      selfsigned: "5.5.0",
      yjs: "13.6.31",
      zod: "4.4.3",
    });
    expect(packaged.workspaces).toBeUndefined();
    expect(packaged.devDependencies).toBeUndefined();
    expect(packaged.overrides["@hono/node-server"]).toBe("1.19.14");
    expect(packaged.private).toBeUndefined();
    expect(packaged.files).toContain("gui/dist");
    expect(packaged.files).toContain("apps/cocodex-server/src");
    expect(packaged.files).toContain("packages/cocodex-protocol/src");
    expect(packaged.files).toContain("npm-shrinkwrap.json");
    expect(() => assertShrinkwrap(packaged, "0.1.0-alpha.1")).not.toThrow();
    const shrinkwrap = JSON.parse(readFileSync(
      join(import.meta.dir, "..", "scripts", "private-alpha", "npm-shrinkwrap.json"),
      "utf8",
    ));
    expect(shrinkwrap.packages[""].dependencies).toEqual(packaged.dependencies);
    for (const [path, entry] of Object.entries<any>(shrinkwrap.packages)) {
      if (!path) continue;
      expect(entry.version).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
      expect(entry.resolved).toStartWith("https://registry.npmjs.org/");
      expect(entry.integrity).toMatch(/^sha512-/);
    }
  });

  test("verifies the exact archive checksum before invoking npm", () => {
    const source = readFileSync(join(import.meta.dir, "..", "scripts", "Install-CoCodex.ps1"), "utf8");
    expect(source).not.toContain("Get-FileHash");
    expect(source).toContain("[System.Security.Cryptography.SHA256]::Create()");
    expect(source).toContain("[System.IO.File]::OpenRead($Path)");
    const checksumAt = source.indexOf('$verifiedHash = Assert-BundleFileChecksum $archive $checksum "package archive"');
    const installAt = source.indexOf("& $npm install --prefix");
    expect(checksumAt).toBeGreaterThan(-1);
    expect(installAt).toBeGreaterThan(checksumAt);
    expect(source).toContain("[IO.FileAttributes]::ReparsePoint");
    expect(source).toContain("Assert-ReleaseArchive");
    expect(source).toContain("Assert-InstalledPackage");
    expect(source).toContain("Assert-CoCodexStopped");
    expect(source).toContain("$ancestor.ParentProcessId");
    expect(source).toContain('"powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe"');
    expect(source).toContain("must contain exactly one SHA-256 entry");
    expect(source).toContain("checksum file exceeds the 65536-byte validation limit");
    expect(source).toContain('$Action -eq "Install" -and');
    expect(source).toContain("cocodex-private-alpha-install-root");
    expect(source).toContain('Join-Path $Prefix "node_modules\\.bin"');
    expect(source).toContain('Read-TarTextEntry $Archive "package/package.json"');
    expect(source).toContain("Client state (~\\.cocodex), Server state (~\\.cocodex-server)");
    expect(source).not.toContain("Remove-Item");
  });

  test("rejects a modified archive before any installation attempt", async () => {
    if (process.platform !== "win32") return;
    const root = mkdtempSync(join(tmpdir(), "cocodex-package-tamper-"));
    roots.push(root);
    const archive = join(root, "sdanderosa-cocodex-0.1.0-alpha.1.tgz");
    const checksums = join(root, "SHA256SUMS.txt");
    const release = join(root, "RELEASE.json");
    writeFileSync(archive, "modified archive");
    writeFileSync(checksums, `${"0".repeat(64)} *${archive.split(/[\\/]/).at(-1)}\n`);
    writeFileSync(release, "{}\n");
    const child = Bun.spawn([
      `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`,
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      join(import.meta.dir, "..", "scripts", "Install-CoCodex.ps1"),
      "-Action",
      "Install",
      "-PackagePath",
      archive,
      "-ChecksumPath",
      checksums,
      "-ReleaseManifestPath",
      release,
      "-NpmPrefix",
      join(root, "prefix"),
      "-SkipPathUpdate",
    ], {
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
      env: windowsTestProcessEnvironment(),
    });
    const [exitCode, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
    ]);
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("checksum verification failed");
  }, 20_000);

  test("rejects a checksum-valid archive with the wrong package identity before npm", async () => {
    if (process.platform !== "win32") return;
    const root = mkdtempSync(join(tmpdir(), "cocodex-package-identity-"));
    roots.push(root);
    const packageRoot = join(root, "package");
    mkdirSync(packageRoot);
    const shrinkwrapText = `${JSON.stringify({
      name: "@evil/wrong",
      version: "0.1.0-alpha.1",
      lockfileVersion: 3,
      packages: { "": { name: "@evil/wrong", version: "0.1.0-alpha.1", dependencies: {} } },
    }, null, 2)}\n`;
    writeFileSync(join(packageRoot, "package.json"), `${JSON.stringify({
      name: "@evil/wrong",
      version: "0.1.0-alpha.1",
      scripts: {},
    }, null, 2)}\n`);
    writeFileSync(join(packageRoot, "npm-shrinkwrap.json"), shrinkwrapText);
    const archive = join(root, "sdanderosa-cocodex-0.1.0-alpha.1.tgz");
    const packed = Bun.spawnSync(["tar.exe", "-czf", archive, "-C", root, "package"], {
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
    });
    expect(packed.exitCode).toBe(0);
    const sha = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
    const release = join(root, "RELEASE.json");
    writeFileSync(release, `${JSON.stringify({
      product: "CoCodex",
      channel: "private-alpha",
      version: "0.1.0-alpha.1",
      packageName: "@sdanderosa/cocodex",
      archive: archive.split(/[\\/]/).at(-1),
      sha256: sha(archive),
      sourceCommit: "1".repeat(40),
      sourceTree: "2".repeat(40),
      guiSha256: "3".repeat(64),
      shrinkwrapSha256: createHash("sha256").update(shrinkwrapText).digest("hex"),
      requiredNodeVersion: "22.12.0",
      requiredNpmMajor: 10,
      commands: ["cocodex", "ccx", "cocodex-server", "ccx-server", "ocx"],
    }, null, 2)}\n`);
    const installer = join(import.meta.dir, "..", "scripts", "Install-CoCodex.ps1");
    const checksums = join(root, "SHA256SUMS.txt");
    writeFileSync(checksums, [
      `${sha(archive)} *${archive.split(/[\\/]/).at(-1)}`,
      `${sha(release)} *RELEASE.json`,
      `${sha(installer)} *Install-CoCodex.ps1`,
      "",
    ].join("\n"));
    const child = Bun.spawn([
      `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`,
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      installer,
      "-Action",
      "Install",
      "-PackagePath",
      archive,
      "-ChecksumPath",
      checksums,
      "-ReleaseManifestPath",
      release,
      "-NpmPrefix",
      join(root, "prefix"),
      "-SkipPathUpdate",
    ], {
      stdout: "pipe",
      stderr: "pipe",
      windowsHide: true,
      env: windowsTestProcessEnvironment(),
    });
    const [exitCode, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
    ]);
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("package identity/version does not match");
  }, 20_000);

  test("blocks private-alpha installs from the upstream OpenCodex registry update path", () => {
    const launcher = readFileSync(join(import.meta.dir, "..", "bin", "ocx.mjs"), "utf8");
    const packageGate = launcher.indexOf("installedPackage !== PKG");
    const registryQuery = launcher.indexOf('["view", `${PKG}@${tag}`, "version"]');
    expect(packageGate).toBeGreaterThan(-1);
    expect(registryQuery).toBeGreaterThan(packageGate);
    expect(launcher).toContain("Install-CoCodex.ps1");
    const repairGate = launcher.indexOf("currentPackageMetadata().name !== PKG");
    const lazyInstaller = launcher.indexOf("spawnSync(process.execPath, [installJs]");
    expect(repairGate).toBeGreaterThan(-1);
    expect(lazyInstaller).toBeGreaterThan(repairGate);
    const builder = readFileSync(
      join(import.meta.dir, "..", "scripts", "build-cocodex-private-alpha.ts"),
      "utf8",
    );
    expect(builder).toContain('["status", "--porcelain=v1", "--untracked-files=all"]');
    expect(builder).toContain("GITHUB_SHA does not match the checked-out commit");
    expect(builder).toContain("entry.hasInstallScript === true");
    expect(builder).toContain('path === "node_modules/bun"');
    expect(builder).toContain('path === "node_modules/@primno/dpapi"');
    expect(builder).toContain("Shrinkwrap dependency does not match bun.lock");
    expect(builder).toContain("Source provenance changed while building the private-alpha GUI");
  });

  test("publishes verified artifacts only from an explicit audited workflow dispatch", () => {
    const workflow = readFileSync(
      join(import.meta.dir, "..", ".github", "workflows", "cocodex-private-alpha.yml"),
      "utf8",
    );
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).toContain("expected-sha:");
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("bun run test:batched");
    expect(workflow).toContain("scripts/verify-cocodex-private-alpha-install.ts");
    expect(workflow).toContain('scripts/private-alpha/**');
    expect(workflow).toContain('scripts/generate-cocodex-private-alpha-shrinkwrap.ts');
    expect(workflow).toContain('assets/**');
    expect(workflow).toContain("minimum-runtime:");
    expect(workflow).toContain('node-version: "22.12.0"');
    expect(workflow).toContain("needs: minimum-runtime");
    expect(workflow).toContain("node-version: 24");
    const verifier = readFileSync(
      join(import.meta.dir, "..", "scripts", "verify-cocodex-private-alpha-install.ts"),
      "utf8",
    );
    expect(verifier).toContain('option("--node-command")');
    expect(verifier).toContain(
      "for (const directory of [clientHome, serverHome, openCodexHome, codexHome])",
    );
    expect(verifier).toContain("signal: AbortSignal.timeout(1_000)");
    expect(workflow).toContain("if: ${{ github.event_name == 'workflow_dispatch' }}");
    expect(workflow).toContain(
      "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    );
  });
});

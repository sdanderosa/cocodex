import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { serverPaths } from "../src/paths";
import {
  checkServerUpdate,
  inspectServerUpdateBundle,
  serverUpdateReadiness,
  type ServerUpdateBundle,
} from "../src/server-update";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    const absolute = resolve(root);
    if (!absolute.startsWith(resolve(tmpdir()))) throw new Error(`Refusing cleanup outside temp: ${absolute}`);
    rmSync(absolute, { recursive: true, force: true });
  }
});

function sha(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function fixture(): { root: string; bundle: string; packageStart: string; release: Record<string, unknown> } {
  const root = mkdtempSync(join(tmpdir(), "cocodex-update-"));
  roots.push(root);
  const bundle = join(root, "bundle");
  const packageRoot = join(root, "application", "node_modules", "@sdanderosa", "cocodex");
  const packageStart = join(packageRoot, "apps", "cocodex-server", "src");
  mkdirSync(bundle, { recursive: true });
  mkdirSync(packageStart, { recursive: true });
  writeFileSync(join(packageRoot, "package.json"), JSON.stringify({
    name: "@sdanderosa/cocodex",
    version: "0.1.0-alpha.1",
  }));

  const archiveName = "sdanderosa-cocodex-0.2.0-alpha.1.tgz";
  const archive = Buffer.from("TEST-ARCHIVE");
  const installer = "param()\nWrite-Output 'test'\n";
  const release = {
    product: "CoCodex",
    channel: "private-alpha",
    version: "0.2.0-alpha.1",
    packageName: "@sdanderosa/cocodex",
    archive: archiveName,
    sha256: sha(archive),
    sourceCommit: "a".repeat(40),
    requiredNodeVersion: "22.12.0",
    requiredNpmMajor: 10,
  };
  const releaseText = JSON.stringify(release);
  writeFileSync(join(bundle, archiveName), archive);
  writeFileSync(join(bundle, "Install-CoCodex.ps1"), installer);
  writeFileSync(join(bundle, "RELEASE.json"), releaseText);
  writeFileSync(join(bundle, "SHA256SUMS.txt"), [
    `${sha(archive)} *${archiveName}`,
    `${sha(releaseText)} *RELEASE.json`,
    `${sha(installer)} *Install-CoCodex.ps1`,
    "",
  ].join("\n"));
  return { root, bundle, packageStart, release };
}

function accepted(bundle: ServerUpdateBundle, prefix: string): Record<string, unknown> {
  return {
    verified: true,
    packageName: bundle.packageName,
    version: bundle.version,
    sha256: bundle.sha256,
    applicationPrefix: prefix,
    blockingProcesses: [],
    readyForUpdate: true,
  };
}

describe("CoCodex Server verified update bundle", () => {
  test("verifies every release input and projects bounded metadata", () => {
    const value = fixture();
    const bundle = inspectServerUpdateBundle(value.bundle);
    expect(bundle).toMatchObject({
      packageName: "@sdanderosa/cocodex",
      version: "0.2.0-alpha.1",
      sourceCommit: "a".repeat(40),
      sha256: value.release.sha256,
    });
    expect(bundle.installer).toBe(join(value.bundle, "Install-CoCodex.ps1"));
    expect(bundle.archive).toEndWith(".tgz");
  });

  test("fails closed for archive, manifest, installer, and checksum tampering", () => {
    for (const name of [
      "sdanderosa-cocodex-0.2.0-alpha.1.tgz",
      "RELEASE.json",
      "Install-CoCodex.ps1",
      "SHA256SUMS.txt",
    ]) {
      const value = fixture();
      const path = join(value.bundle, name);
      writeFileSync(path, Buffer.concat([readFileSync(path), Buffer.from("tamper")]));
      expect(() => inspectServerUpdateBundle(value.bundle)).toThrow();
    }
  });

  test("rejects wrong package identity, path traversal, and duplicate checksums", () => {
    const wrong = fixture();
    const releasePath = join(wrong.bundle, "RELEASE.json");
    const changed = { ...wrong.release, packageName: "@evil/not-cocodex" };
    const text = JSON.stringify(changed);
    writeFileSync(releasePath, text);
    expect(() => inspectServerUpdateBundle(wrong.bundle)).toThrow(/not a CoCodex package/);

    const traversal = fixture();
    writeFileSync(join(traversal.bundle, "RELEASE.json"), JSON.stringify({
      ...traversal.release,
      archive: "../outside.tgz",
    }));
    expect(() => inspectServerUpdateBundle(traversal.bundle)).toThrow(/release archive is invalid/);

    const duplicate = fixture();
    const sums = join(duplicate.bundle, "SHA256SUMS.txt");
    const first = readFileSync(sums, "utf8").split("\n")[0];
    writeFileSync(sums, `${readFileSync(sums, "utf8")}${first}\n`);
    expect(() => inspectServerUpdateBundle(duplicate.bundle)).toThrow(/duplicate filename/);
  });
});

describe("CoCodex Server update readiness", () => {
  test("reports a verified stopped-service update plan as argv, never a shell command", () => {
    const value = fixture();
    const paths = serverPaths(join(value.root, "server-state"));
    const result = checkServerUpdate(paths, value.bundle, {
      platform: "win32",
      packageStart: value.packageStart,
      serviceState: () => "stopped",
      runInstallerCheck: accepted,
    });

    expect(result).toMatchObject({
      verified: true,
      currentVersion: "0.1.0-alpha.1",
      targetVersion: "0.2.0-alpha.1",
      sourceCommit: "a".repeat(40),
      readiness: {
        ready: true,
        directServerPid: null,
        serviceState: "stopped",
        blockers: [],
      },
      apply: {
        updatesSharedApplicationFiles: true,
        preservesStateRoots: ["~/.cocodex", "~/.cocodex-server", "~/.opencodex", "~/.codex"],
      },
    });
    expect(result.applicationPrefix).toBe(join(value.root, "application"));
    expect(result.apply.executable.toLowerCase()).toContain("powershell");
    expect(result.apply.arguments).toContain("Update");
    expect(result.apply.arguments).toContain(result.applicationPrefix);
    expect(JSON.stringify(result.apply)).not.toContain("cmd.exe");
  });

  test("blocks a direct process, running service, and unknown SCM state", () => {
    const paths = serverPaths(fixture().root);
    writeFileSync(paths.pid, `${process.pid}\n`);
    expect(serverUpdateReadiness(paths, "started")).toMatchObject({
      ready: false,
      directServerPid: process.pid,
      serviceState: "started",
    });
    expect(serverUpdateReadiness(paths, "started").blockers).toHaveLength(2);
    rmSync(paths.pid);
    expect(serverUpdateReadiness(paths, "stopped", [{ processId: 4242, name: "cocodex.exe" }])).toMatchObject({
      ready: false,
      applicationProcesses: [{ processId: 4242, name: "cocodex.exe" }],
      blockers: ["Close CoCodex process 4242 (cocodex.exe)"],
    });
    expect(serverUpdateReadiness(paths, "unknown")).toMatchObject({
      ready: false,
      blockers: ["Repair or verify the CoCodex Server Windows service state"],
    });
  });

  test("rejects a source checkout that is not under the installed scoped-package layout", () => {
    const value = fixture();
    const sourceRoot = join(value.root, "source-checkout");
    mkdirSync(join(sourceRoot, "apps", "cocodex-server", "src"), { recursive: true });
    writeFileSync(join(sourceRoot, "package.json"), JSON.stringify({
      name: "@sdanderosa/cocodex",
      version: "0.1.0-alpha.1",
    }));
    expect(() => checkServerUpdate(serverPaths(join(value.root, "server")), value.bundle, {
      platform: "win32",
      packageStart: join(sourceRoot, "apps", "cocodex-server", "src"),
      serviceState: () => "nonexistent",
      runInstallerCheck: accepted,
    })).toThrow(/verified installed package layout/);
  });
  test("rejects inconsistent installer output and non-Windows execution", () => {
    const value = fixture();
    const paths = serverPaths(join(value.root, "server"));
    expect(() => checkServerUpdate(paths, value.bundle, {
      platform: "linux",
      packageStart: value.packageStart,
    })).toThrow(/only on Windows/);
    expect(() => checkServerUpdate(paths, value.bundle, {
      platform: "win32",
      packageStart: value.packageStart,
      serviceState: () => "nonexistent",
      runInstallerCheck: () => ({
        verified: true,
        packageName: "@sdanderosa/cocodex",
        version: "9.9.9",
        sha256: value.release.sha256,
      }),
    })).toThrow(/inconsistent release metadata/);
  });
});

describe("CoCodex Server update CLI boundary", () => {
  test("update-check help exits successfully without creating state", async () => {
    const value = fixture();
    const stateRoot = join(value.root, "unused-state");
    const cli = join(import.meta.dir, "..", "src", "cli.ts");
    const child = Bun.spawn([
      process.execPath, cli, "update-check", "--help", "--state-root", stateRoot,
    ], { stdout: "pipe", stderr: "pipe" });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("cocodex-server update-check --bundle DIRECTORY");
    expect(stderr).toBe("");
    expect(existsSync(stateRoot)).toBeFalse();
  });
});
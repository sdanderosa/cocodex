import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  verifyInjectionReadiness,
  type InjectionSafetyDeps,
} from "../src/codex/injection-guard";
import type { ServiceDiagnostic } from "../src/service";
import type { OcxConfig } from "../src/types";

const temporaryRoots: string[] = [];
const config = {
  port: 10100,
  hostname: "127.0.0.1",
  codexAutoStart: true,
  providers: {},
  defaultProvider: "openai",
} as OcxConfig;

const viableService: ServiceDiagnostic = {
  supported: true,
  installed: true,
  enabled: true,
  running: true,
  viable: true,
  startable: true,
  stale: false,
  conflict: false,
  backend: "scheduler",
  summary: "installed and running",
};

function dependencies(overrides: Partial<InjectionSafetyDeps> = {}): InjectionSafetyDeps {
  return {
    proxyIdentityAt: async () => ({ pid: 1234 }),
    verifyPidIdentity: pid => pid,
    diagnoseService: () => viableService,
    diagnoseCodexShim: () => ({ installed: false, healthy: false, summary: "not installed" }),
    ...overrides,
  };
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("fail-safe Codex injection readiness", () => {
  test("rejects a stopped service when no operational shim exists", async () => {
    const readiness = await verifyInjectionReadiness(10100, config, dependencies({
      diagnoseService: () => ({
        ...viableService,
        running: false,
        viable: false,
        summary: "installed but stopped",
      }),
    }));

    expect(readiness.ok).toBe(false);
    expect(readiness.protection).toBeNull();
    expect(readiness.message).toContain("installed but stopped");
  });

  test("accepts a healthy reboot-persistent service", async () => {
    const readiness = await verifyInjectionReadiness(10100, config, dependencies());
    expect(readiness).toMatchObject({
      ok: true,
      protection: "service",
      expectedPort: 10100,
      checkedPort: 10100,
    });
    expect(readiness.message).toContain("reboot-persistent");
  });

  test("rejects port 10100 when its health responder is owned by another process", async () => {
    const readiness = await verifyInjectionReadiness(10100, config, dependencies({
      proxyIdentityAt: async () => ({ pid: 9876 }),
      verifyPidIdentity: () => null,
    }));
    expect(readiness.ok).toBe(false);
    expect(readiness.message).toContain("not owned by the expected");
  });

  test("fails closed when /healthz times out", async () => {
    const readiness = await verifyInjectionReadiness(10100, config, dependencies({
      proxyIdentityAt: async () => null,
    }));
    expect(readiness.ok).toBe(false);
    expect(readiness.message).toContain("/healthz");
  });

  test("rejects an occupied configured port instead of persisting a fallback port", async () => {
    let healthChecks = 0;
    const readiness = await verifyInjectionReadiness(10101, config, dependencies({
      proxyIdentityAt: async () => {
        healthChecks++;
        return { pid: 1234 };
      },
    }));

    expect(readiness.ok).toBe(false);
    expect(readiness.message).toContain("fallback port 10101");
    expect(healthChecks).toBe(0);
  });

  test("rejects stale service assets and a shim with a missing executable", async () => {
    const readiness = await verifyInjectionReadiness(10100, config, dependencies({
      diagnoseService: () => ({
        ...viableService,
        viable: false,
        stale: true,
        summary: "missing service executable",
      }),
      diagnoseCodexShim: () => ({
        installed: true,
        healthy: false,
        summary: "wrapper target executable missing",
      }),
    }));

    expect(readiness.ok).toBe(false);
    expect(readiness.message).toContain("missing service executable");
    expect(readiness.message).toContain("wrapper target executable missing");
  });

  test("accepts a healthy enabled shim when no service is installed", async () => {
    const readiness = await verifyInjectionReadiness(10100, config, dependencies({
      diagnoseService: () => ({
        ...viableService,
        installed: false,
        enabled: false,
        running: false,
        viable: false,
        backend: null,
        summary: "not installed",
      }),
      diagnoseCodexShim: () => ({ installed: true, healthy: true, summary: "healthy" }),
    }));
    expect(readiness.ok).toBe(true);
    expect(readiness.protection).toBe("shim");
  });

  test("restores native Codex when the proxy crashes during injection", () => {
    const root = join(import.meta.dir, `.tmp-injection-guard-${process.pid}-${randomUUID()}`);
    temporaryRoots.push(root);
    const codexHome = join(root, "codex");
    const opencodexHome = join(root, "opencodex");
    mkdirSync(codexHome, { recursive: true });
    mkdirSync(opencodexHome, { recursive: true });
    const original = 'model = "gpt-5.5"\n';
    writeFileSync(join(codexHome, "config.toml"), original, "utf8");
    writeFileSync(join(opencodexHome, "config.json"), JSON.stringify(config), "utf8");

    const code = `
      const { injectCodexConfig } = await import(${JSON.stringify(new URL("../src/codex/inject.ts", import.meta.url).href)});
      let checks = 0;
      const service = ${JSON.stringify(viableService)};
      const result = await injectCodexConfig(10100, ${JSON.stringify(config)}, {
        catalogPath: null,
        safetyDeps: {
          proxyIdentityAt: async () => ++checks === 1 ? { pid: 1234 } : null,
          verifyPidIdentity: pid => pid,
          diagnoseService: () => service,
          diagnoseCodexShim: () => ({ installed: false, healthy: false, summary: "not installed" }),
        },
      });
      console.log(JSON.stringify(result));
    `;
    const child = Bun.spawnSync([process.execPath, "-e", code], {
      cwd: join(import.meta.dir, ".."),
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        OPENCODEX_HOME: opencodexHome,
        COCODEX_HOME: join(root, "cocodex"),
      },
      stdout: "pipe",
      stderr: "pipe",
    });

    expect(child.exitCode).toBe(0);
    const output = child.stdout.toString().trim().split(/\r?\n/).at(-1) ?? "";
    expect(JSON.parse(output)).toMatchObject({
      success: false,
      message: expect.stringContaining("post-injection verification failed"),
    });
    expect(readFileSync(join(codexHome, "config.toml"), "utf8")).toBe(original);
    expect(readFileSync(join(codexHome, "config.toml"), "utf8")).not.toContain("localhost:10100");
    expect(existsSync(join(codexHome, "opencodex-journal.json"))).toBe(false);
  }, 30_000);

  test("atomically restores every existing Codex setting when a configuration write fails", () => {
    const root = join(import.meta.dir, `.tmp-injection-write-failure-${process.pid}-${randomUUID()}`);
    temporaryRoots.push(root);
    const codexHome = join(root, "codex");
    const opencodexHome = join(root, "opencodex");
    mkdirSync(codexHome, { recursive: true });
    mkdirSync(opencodexHome, { recursive: true });
    const original = ['model = "gpt-5.5"', 'personality = "pragmatic"', "", "[tools]", "web_search = true", ""].join("\n");
    writeFileSync(join(codexHome, "config.toml"), original, "utf8");
    writeFileSync(join(opencodexHome, "config.json"), JSON.stringify(config), "utf8");

    const code = `
      const { injectCodexConfig } = await import(${JSON.stringify(new URL("../src/codex/inject.ts", import.meta.url).href)});
      const service = ${JSON.stringify(viableService)};
      const result = await injectCodexConfig(10100, ${JSON.stringify(config)}, {
        catalogPath: null,
        atomicWrite: () => { throw new Error("simulated disk failure"); },
        safetyDeps: {
          proxyIdentityAt: async () => ({ pid: 1234 }),
          verifyPidIdentity: pid => pid,
          diagnoseService: () => service,
          diagnoseCodexShim: () => ({ installed: false, healthy: false, summary: "not installed" }),
        },
      });
      console.log(JSON.stringify(result));
    `;
    const child = Bun.spawnSync([process.execPath, "-e", code], {
      cwd: join(import.meta.dir, ".."),
      env: { ...process.env, CODEX_HOME: codexHome, OPENCODEX_HOME: opencodexHome, COCODEX_HOME: join(root, "cocodex") },
      stdout: "pipe",
      stderr: "pipe",
    });

    expect(child.exitCode).toBe(0);
    expect(JSON.parse(child.stdout.toString().trim().split(/\r?\n/).at(-1) ?? "{}")).toMatchObject({
      success: false,
      message: expect.stringContaining("atomic configuration write failed"),
    });
    expect(readFileSync(join(codexHome, "config.toml"), "utf8")).toBe(original);
    expect(existsSync(join(codexHome, "opencodex-journal.json"))).toBe(false);
  }, 30_000);
});

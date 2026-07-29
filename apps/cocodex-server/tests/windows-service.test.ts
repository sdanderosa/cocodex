import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { serverPaths } from "../src/paths";
import {
  COCODEX_SERVER_SERVICE_ID,
  SERVER_WINSW_SHA256,
  buildWindowsServerServiceXml,
  ensureWindowsServerServiceBinary,
  installWindowsServerService,
  parseScmServiceConfig,
  parseScmQueryState,
  parseServerServiceStatus,
  probeServerServiceRegistration,
  serviceUsesCurrentUser,
  startWindowsServerService,
  uninstallWindowsServerService,
  windowsServerServiceStatus,
  type ScmServiceConfig,
  type ServerServiceDeps,
  type ServerServiceState,
} from "../src/windows-service";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    const absolute = resolve(root);
    if (!absolute.startsWith(resolve(tmpdir()))) throw new Error(`Refusing to remove non-temporary path: ${absolute}`);
    rmSync(absolute, { recursive: true, force: true });
  }
});

function temporaryPaths() {
  const root = mkdtempSync(join(tmpdir(), "cocodex-service-"));
  roots.push(root);
  return serverPaths(root);
}

function applied(paths = temporaryPaths()): ScmServiceConfig {
  return {
    binaryPath: `"${paths.serviceExecutable}"`,
    startType: "2   AUTO_START",
    startName: `${process.env.USERDOMAIN ?? "."}\\${process.env.USERNAME ?? "tester"}`,
  };
}

function depsFor(
  paths: ReturnType<typeof serverPaths>,
  state: ServerServiceState,
  calls: string[][] = [],
): ServerServiceDeps {
  return {
    platform: "win32",
    privateStateAccessible: () => {},
    ensureBinary: async () => paths.serviceExecutable,
    status: () => state,
    scmConfig: () => applied(paths),
    writeXml: (_path, xml) => { calls.push(["xml", xml]); },
    interactive: (_paths, args) => { calls.push(["interactive", ...args]); },
    run: (_paths, args) => { calls.push(["run", ...args]); return ""; },
    waitReady: async () => {},
    waitStopped: async () => {},
    healthReady: async () => true,
  };
}

describe("CoCodex Server Windows service manifest", () => {
  test("is a separate same-user automatic service with no password or proxy coupling", () => {
    const paths = temporaryPaths();
    const xml = buildWindowsServerServiceXml(
      paths,
      { executable: "C:\\runtime & tools\\bun.exe", cliScript: "C:\\Co Codex\\cli.ts" },
      { USERDOMAIN: "WORKGROUP", USERNAME: "Stephen" },
    );

    expect(xml).toContain(`<id>${COCODEX_SERVER_SERVICE_ID}</id>`);
    expect(xml).toContain("<name>CoCodex Server</name>");
    expect(xml).toContain("<domain>WORKGROUP</domain>");
    expect(xml).toContain("<user>Stephen</user>");
    expect(xml).toContain("<startmode>Automatic</startmode>");
    expect(xml).toContain("<delayedAutoStart>true</delayedAutoStart>");
    expect(xml).toContain("<onfailure action=\"restart\" delay=\"5 sec\"/>");
    expect(xml).toContain("&amp; tools");
    expect(xml).toContain("&quot;C:\\Co Codex\\cli.ts&quot; start --state-root");
    expect(xml).toContain(`value="${paths.root}"`);
    expect(xml).not.toContain("<password>");
    expect(xml.toLowerCase()).not.toContain("localsystem");
    expect(xml).not.toContain("opencodex");
    expect(xml).not.toContain("10100");
  });

  test("parses WinSW and SCM output without treating unknown output as absence", () => {
    expect(parseServerServiceStatus("Started")).toBe("started");
    expect(parseServerServiceStatus("Stopped")).toBe("stopped");
    expect(parseServerServiceStatus("NonExistent")).toBe("nonexistent");
    expect(parseServerServiceStatus("localized mystery")).toBe("unknown");
    expect(parseScmQueryState("STATE : 4  RUNNING")).toBe("started");
    expect(parseScmQueryState("STATE : 1  STOPPED")).toBe("stopped");
    expect(parseScmQueryState("STATE : 2  START_PENDING")).toBe("unknown");
    expect(parseScmServiceConfig(`
      BINARY_PATH_NAME   : C:\\state\\cocodex-server.exe
      START_TYPE         : 2   AUTO_START
      SERVICE_START_NAME : DESKTOP\\Stephen
    `)).toEqual({
      binaryPath: "C:\\state\\cocodex-server.exe",
      startType: "2   AUTO_START",
      startName: "DESKTOP\\Stephen",
    });
  });

  test("accepts only the current user and rejects built-in service identities", () => {
    const env = { USERNAME: "Stephen", USERDOMAIN: "DESKTOP" };
    expect(serviceUsesCurrentUser({ ...applied(), startName: "DESKTOP\\Stephen" }, env)).toBeTrue();
    expect(serviceUsesCurrentUser({ ...applied(), startName: ".\\Stephen" }, env)).toBeTrue();
    expect(serviceUsesCurrentUser({ ...applied(), startName: "LocalSystem" }, env)).toBeFalse();
    expect(serviceUsesCurrentUser({ ...applied(), startName: "DESKTOP\\Kai" }, env)).toBeFalse();
    expect(serviceUsesCurrentUser({ ...applied(), startName: "OTHERDOMAIN\\Stephen" }, env)).toBeFalse();
  });

  test("SCM absence requires error 1060; access failures remain unknown", () => {
    expect(probeServerServiceRegistration(() => "RUNNING")).toBeTrue();
    expect(probeServerServiceRegistration(() => {
      const error = new Error("OpenService FAILED 1060") as Error & { status: number };
      error.status = 1;
      throw error;
    })).toBeFalse();
    expect(probeServerServiceRegistration(() => {
      const error = new Error("Access denied") as Error & { status: number };
      error.status = 5;
      throw error;
    })).toBe("error");
  });

  test("rejects a downloaded binary with the wrong pinned digest", async () => {
    const paths = temporaryPaths();
    await expect(ensureWindowsServerServiceBinary(
      paths,
      (async () => new Response(new Uint8Array([1, 2, 3]))) as unknown as typeof fetch,
    )).rejects.toThrow(/SHA-256 verification/);
    expect(existsSync(paths.serviceExecutable)).toBeFalse();
    expect(SERVER_WINSW_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("CoCodex Server Windows service lifecycle", () => {
  test("fresh install prompts, verifies autostart, starts, and reports readiness", async () => {
    const paths = temporaryPaths();
    const calls: string[][] = [];
    const status = await installWindowsServerService(paths, { executable: "C:\\bun.exe", cliScript: "C:\\cli.ts" }, depsFor(paths, "nonexistent", calls));

    expect(calls.map(call => call[0])).toEqual(["xml", "interactive", "run"]);
    expect(calls[1]).toEqual(["interactive", "install", "/p"]);
    expect(calls[2]).toEqual(["run", "start"]);
    expect(status).toMatchObject({
      serviceId: "cocodex-server",
      state: "started",
      installed: true,
      sameUser: true,
      automaticStart: true,
      binaryPathMatches: true,
      ready: true,
    });
  });

  test("unknown SCM state fails closed before registration or startup", async () => {
    const paths = temporaryPaths();
    const calls: string[][] = [];
    await expect(installWindowsServerService(
      paths,
      { executable: "C:\\bun.exe" },
      depsFor(paths, "unknown", calls),
    )).rejects.toThrow(/Cannot verify/);
    expect(calls).toEqual([]);
  });

  test("an existing service from another state root cannot be rebound", async () => {
    const paths = temporaryPaths();
    const calls: string[][] = [];
    const deps = depsFor(paths, "stopped", calls);
    deps.scmConfig = () => ({ ...applied(paths), binaryPath: "C:\\other-root\\cocodex-server.exe" });
    await expect(installWindowsServerService(paths, { executable: "C:\\bun.exe" }, deps))
      .rejects.toThrow(/another state root/);
    expect(calls).toEqual([]);
  });

  test("rejects a binary path that only contains the expected path as a prefix", async () => {
    const paths = temporaryPaths();
    const deps = depsFor(paths, "stopped");
    deps.scmConfig = () => ({ ...applied(paths), binaryPath: `${paths.serviceExecutable}.unexpected` });
    await expect(installWindowsServerService(paths, { executable: "C:\\bun.exe" }, deps))
      .rejects.toThrow(/another state root/);
  });
  test("readiness failure rolls back a fresh registration and leaves the port owner alive", async () => {
    const paths = temporaryPaths();
    const calls: string[][] = [];
    const blocker = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
    const port = blocker.port;
    const deps = depsFor(paths, "nonexistent", calls);
    deps.waitReady = async () => { throw new Error(`occupied port ${port}`); };
    try {
      await expect(installWindowsServerService(paths, { executable: "C:\\bun.exe" }, deps))
        .rejects.toThrow(/occupied port/);
      expect(calls.slice(1)).toEqual([
        ["interactive", "install", "/p"],
        ["run", "start"],
        ["run", "stopwait"],
        ["run", "uninstall"],
      ]);
      expect(blocker.port).toBe(port);
    } finally {
      blocker.stop(true);
    }
  });

  test("a stopped service recovers through verified start without touching direct processes", async () => {
    const paths = temporaryPaths();
    const calls: string[][] = [];
    const status = await startWindowsServerService(paths, depsFor(paths, "stopped", calls));
    expect(calls).toEqual([["run", "start"]]);
    expect(status).toMatchObject({ state: "started", ready: true, automaticStart: true });
  });

  test("direct PID ownership blocks service start", async () => {
    const paths = temporaryPaths();
    writeFileSync(paths.pid, `${process.pid}\n`);
    const calls: string[][] = [];
    await expect(startWindowsServerService(paths, depsFor(paths, "stopped", calls)))
      .rejects.toThrow(/direct CoCodex Server process/);
    expect(calls).toEqual([]);
  });

  test("uninstall removes only registration and preserves Server state and service assets", async () => {
    const paths = temporaryPaths();
    writeFileSync(paths.config, "STATE-CANARY");
    mkdirSync(paths.serviceDirectory, { recursive: true });
    writeFileSync(paths.serviceExecutable, "ASSET-CANARY");
    let query = 0;
    const calls: string[][] = [];
    const deps = depsFor(paths, "stopped", calls);
    deps.status = () => query++ === 0 ? "stopped" : "nonexistent";
    const status = await uninstallWindowsServerService(paths, deps);

    expect(calls).toEqual([["run", "uninstall"]]);
    expect(status).toMatchObject({ state: "nonexistent", installed: false });
    expect(readFileSync(paths.config, "utf8")).toBe("STATE-CANARY");
    expect(readFileSync(paths.serviceExecutable, "utf8")).toBe("ASSET-CANARY");
  });

  test("status exposes bounded lifecycle facts and no Server secrets", async () => {
    const paths = temporaryPaths();
    const value = await windowsServerServiceStatus(paths, depsFor(paths, "stopped"));
    expect(value).toEqual({
      serviceId: "cocodex-server",
      state: "stopped",
      installed: true,
      stateRoot: paths.root,
      sameUser: true,
      automaticStart: true,
      binaryPathMatches: true,
      pid: null,
      ready: false,
    });
    expect(JSON.stringify(value)).not.toContain("adminToken");
  });
});


describe("CoCodex Server Windows service repair transaction", () => {
  test("failed repair restores the prior XML and restarts a previously running service", async () => {
    const paths = temporaryPaths();
    mkdirSync(paths.serviceDirectory, { recursive: true });
    writeFileSync(paths.serviceConfig, "PREVIOUS-SERVICE-XML");
    const calls: string[][] = [];
    const deps = depsFor(paths, "started", calls);
    let readinessChecks = 0;
    deps.waitReady = async () => {
      readinessChecks += 1;
      if (readinessChecks === 1) throw new Error("replacement readiness failed");
    };

    await expect(installWindowsServerService(paths, { executable: "C:\\bun.exe" }, deps))
      .rejects.toThrow(/replacement readiness failed/);

    expect(calls.map(call => call[0])).toEqual([
      "run", "xml", "run", "run", "xml", "run",
    ]);
    expect(calls[0]).toEqual(["run", "stopwait"]);
    expect(calls[2]).toEqual(["run", "start"]);
    expect(calls[3]).toEqual(["run", "stopwait"]);
    expect(calls[4]).toEqual(["xml", "PREVIOUS-SERVICE-XML"]);
    expect(calls[5]).toEqual(["run", "start"]);
    expect(readinessChecks).toBe(2);
  });

  test("a rollback failure is surfaced and never reported as a clean repair", async () => {
    const paths = temporaryPaths();
    mkdirSync(paths.serviceDirectory, { recursive: true });
    writeFileSync(paths.serviceConfig, "PREVIOUS-SERVICE-XML");
    const calls: string[][] = [];
    const deps = depsFor(paths, "stopped", calls);
    deps.waitReady = async () => { throw new Error("replacement readiness failed"); };
    deps.writeXml = (_path, xml) => {
      calls.push(["xml", xml]);
      if (xml === "PREVIOUS-SERVICE-XML") throw new Error("restore denied");
    };

    await expect(installWindowsServerService(paths, { executable: "C:\\bun.exe" }, deps))
      .rejects.toThrow(/rollback also failed.*restore denied/i);
  });
});


describe("CoCodex Server service CLI boundary", () => {
  test("service help is side-effect-free and exits successfully", async () => {
    const paths = temporaryPaths();
    const cli = join(import.meta.dir, "..", "src", "cli.ts");
    const child = Bun.spawn([
      process.execPath,
      cli,
      "service",
      "--help",
      "--state-root",
      paths.root,
    ], { stdout: "pipe", stderr: "pipe" });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("cocodex-server service install|start|stop|status|uninstall");
    expect(stderr).toBe("");
    expect(existsSync(paths.serviceDirectory)).toBeFalse();
    expect(existsSync(paths.config)).toBeFalse();
  });
});

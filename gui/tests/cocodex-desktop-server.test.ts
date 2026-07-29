import { afterEach, describe, expect, test } from "bun:test";
import {
  bootstrapApproveDesktopDevice,
  desktopServerNetworkGuidance,
  isDesktopServerAvailable,
  parseDesktopServerStatus,
  prepareDesktopServer,
  readDesktopServerStatus,
} from "../src/cocodex-desktop-server";

const previousWindow = Reflect.get(globalThis, "window");

afterEach(() => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: previousWindow,
  });
});

function installInvoke(invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown>) {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __TAURI_INTERNALS__: { invoke } },
  });
}

const status = {
  initialized: true,
  running: true,
  pid: 4242,
  publicHost: "cocodex.example.net",
  port: 19463,
  authority: "active",
  serverFingerprint: "SERVER-FINGERPRINT",
};

describe("CoCodex native desktop server bridge", () => {
  test("detects native availability and strictly parses server status", async () => {
    installInvoke(async command => {
      expect(command).toBe("desktop_server_status");
      return status;
    });
    expect(isDesktopServerAvailable()).toBe(true);
    expect(await readDesktopServerStatus()).toEqual(status);
    expect(() => parseDesktopServerStatus({ ...status, pid: 0 })).toThrow();
  });

  test("prepares a server with structured arguments and preserves network diagnostics", async () => {
    const calls: Array<[string, Record<string, unknown> | undefined]> = [];
    installInvoke(async (command, args) => {
      calls.push([command, args]);
      return {
        initializedNow: true,
        status,
        invitation: "secure-one-time-invitation",
        network: {
          firewall: "manual-required",
          portMapping: { method: "upnp", mapped: false },
          diagnostic: { state: "manual-forwarding-required" },
          manualPortForwarding: { protocol: "TCP", port: 19463 },
        },
      };
    });
    const result = await prepareDesktopServer({
      publicHost: "cocodex.example.net",
      port: 19463,
    });
    expect(calls).toEqual([[
      "desktop_server_prepare",
      { request: { publicHost: "cocodex.example.net", port: 19463 } },
    ]]);
    expect(result.invitation).toBe("secure-one-time-invitation");
    expect(result.status.running).toBe(true);
    expect(result.network.firewall).toBe("manual-required");
  });

  test("preserves automatic readiness and manual network follow-up", () => {
    expect(desktopServerNetworkGuidance({
      firewall: "created",
      portMapping: { status: "mapped" },
      diagnostic: { status: "ready", message: "Direct hosting is ready." },
      manualPortForwarding: null,
    })).toEqual({
      manualRequired: false,
      message: "Direct hosting is ready.",
    });
    expect(desktopServerNetworkGuidance({
      firewall: "manual-required",
      portMapping: { status: "unavailable" },
      diagnostic: {
        status: "manual-forwarding-required",
        message: "Forward one TCP port manually.",
      },
      manualPortForwarding: { protocol: "TCP", port: 19463 },
    })).toEqual({
      manualRequired: true,
      message: "Forward one TCP port manually.",
    });
  });

  test("bootstrap approval sends only the enrolled fingerprint", async () => {
    const fingerprint = Array.from({ length: 16 }, () => "ABCD").join("-");
    installInvoke(async (command, args) => {
      expect(command).toBe("desktop_server_bootstrap_approve");
      expect(args).toEqual({ fingerprint });
      return { approved: true };
    });
    await bootstrapApproveDesktopDevice(fingerprint);
  });

  test("browser builds cannot start or approve a local server", async () => {
    Object.defineProperty(globalThis, "window", { configurable: true, value: {} });
    expect(isDesktopServerAvailable()).toBe(false);
    await expect(readDesktopServerStatus()).rejects.toThrow("desktop app");
    await expect(bootstrapApproveDesktopDevice("fingerprint")).rejects.toThrow("desktop app");
  });
});

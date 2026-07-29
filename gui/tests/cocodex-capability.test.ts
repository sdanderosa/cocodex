import { beforeEach, expect, test } from "bun:test";
import {
  cocodexApiJson,
  resetCocodexCapabilityForTests,
} from "../src/cocodex-capability";

beforeEach(() => resetCocodexCapabilityForTests());

test("reacquires a per-process capability once after runtime restart", async () => {
  const calls: Array<{ path: string; capability: string | null }> = [];
  let issued = 0;
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const capability = new Headers(init?.headers).get("X-CoCodex-Capability");
    calls.push({ path: url.pathname, capability });
    if (url.pathname.endsWith("/capability")) {
      issued += 1;
      return Response.json({ capability: issued === 1 ? "old-process" : "new-process" });
    }
    if (capability === "old-process") return Response.json({ error: "CoCodex GUI capability required" }, { status: 403 });
    return Response.json({ state: "not-configured" });
  };

  const value = await cocodexApiJson<{ state: string }>(
    "http://127.0.0.1:10101",
    "http://127.0.0.1:10101/api/cocodex/status",
    undefined,
    fetchImpl,
  );

  expect(value.state).toBe("not-configured");
  expect(calls).toEqual([
    { path: "/api/cocodex/capability", capability: null },
    { path: "/api/cocodex/status", capability: "old-process" },
    { path: "/api/cocodex/capability", capability: null },
    { path: "/api/cocodex/status", capability: "new-process" },
  ]);
});

test("does not permanently cache a rejected capability acquisition", async () => {
  let attempts = 0;
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/capability")) {
      attempts += 1;
      return attempts === 1
        ? Response.json({ error: "runtime starting" }, { status: 503 })
        : Response.json({ capability: "recovered" });
    }
    return Response.json({
      capability: new Headers(init?.headers).get("X-CoCodex-Capability"),
    });
  };

  await expect(cocodexApiJson(
    "http://127.0.0.1:10101",
    "http://127.0.0.1:10101/api/cocodex/status",
    undefined,
    fetchImpl,
  )).rejects.toThrow("runtime starting");

  expect(await cocodexApiJson<{ capability: string }>(
    "http://127.0.0.1:10101",
    "http://127.0.0.1:10101/api/cocodex/status",
    undefined,
    fetchImpl,
  )).toEqual({ capability: "recovered" });
});

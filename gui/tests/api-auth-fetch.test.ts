import { beforeEach, expect, test } from "bun:test";
import { installApiAuthFetch, isManagedProxyRequest, resetApiAuthFetchForTests } from "../src/api";

beforeEach(() => resetApiAuthFetchForTests());

test("API authentication never crosses the GUI origin", async () => {
  const storage = new Map<string, string>([["opencodex-api-token", "local-secret"]]);
  const calls: Array<{ url: string; token: string | null }> = [];
  let promptCount = 0;
  const location = new URL("http://127.0.0.1:3000/");
  const fakeWindow = {
    location,
    prompt: () => {
      promptCount += 1;
      return "replacement-secret";
    },
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      calls.push({ url, token: headers.get("X-OpenCodex-API-Key") });
      return new Response(null, { status: url.includes("evil.example") ? 401 : 200 });
    },
  };
  Object.defineProperties(globalThis, {
    window: { configurable: true, value: fakeWindow },
    sessionStorage: {
      configurable: true,
      value: {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
        removeItem: (key: string) => storage.delete(key),
      },
    },
  });

  installApiAuthFetch();
  await fakeWindow.fetch("/api/status");
  await fakeWindow.fetch("https://evil.example/api/collect");

  expect(calls).toEqual([
    { url: "/api/status", token: "local-secret" },
    { url: "https://evil.example/api/collect", token: null },
  ]);
  expect(promptCount).toBe(0);
  expect(isManagedProxyRequest("http://127.0.0.1:10100/healthz")).toBe(true);
  expect(isManagedProxyRequest("http://127.0.0.1:10101/healthz")).toBe(false);
});

test("Tauri rejects loopback proxy fetches until Rust proves child ownership", async () => {
  const calls: string[] = [];
  const fakeWindow = {
    location: new URL("tauri://localhost/"),
    __TAURI_INTERNALS__: {
      invoke: async () => ({ state: "foreign-listener", owned: false, pid: 23976 }),
    },
    prompt: () => null,
    fetch: async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response(null, { status: 200 });
    },
  };
  Object.defineProperty(globalThis, "window", { configurable: true, value: fakeWindow });
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  });

  installApiAuthFetch();
  const response = await fakeWindow.fetch("http://127.0.0.1:10100/healthz");

  expect(response.status).toBe(503);
  expect(calls).toEqual([]);
});

import { expect, test } from "bun:test";
import { installApiAuthFetch } from "../src/api";

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
  Object.assign(globalThis, {
    window: fakeWindow,
    sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
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
});

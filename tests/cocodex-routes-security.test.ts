import { describe, expect, test } from "bun:test";
import { getDefaultConfig } from "../src/config";
import { handleCoCodexRoutes } from "../src/server/management/cocodex-routes";
import type { ManagementContext } from "../src/server/management/context";

function context(req: Request): ManagementContext {
  return {
    req,
    url: new URL(req.url),
    config: getDefaultConfig(),
    deps: {},
    refreshCodexCatalogBestEffort: async () => {},
    syncClaudeAgentDefsBestEffort: async () => {},
  };
}

describe("CoCodex GUI route security", () => {
  test("issues a per-launch capability only to the exact UI origin and requires it thereafter", async () => {
    const crossOrigin = new Request("http://127.0.0.1:10100/api/cocodex/capability", {
      headers: { Origin: "http://127.0.0.1:9999", "Sec-Fetch-Site": "same-site" },
    });
    expect((await handleCoCodexRoutes(context(crossOrigin)))?.status).toBe(403);

    const sameOrigin = new Request("http://127.0.0.1:10100/api/cocodex/capability", {
      headers: { Origin: "http://127.0.0.1:10100", "Sec-Fetch-Site": "same-origin" },
    });
    const issued = await handleCoCodexRoutes(context(sameOrigin));
    expect(issued?.status).toBe(200);
    const capability = String((await issued!.json()).capability);
    expect(capability.length).toBeGreaterThan(32);

    const missing = new Request("http://127.0.0.1:10100/api/cocodex/status", {
      headers: { Origin: "http://127.0.0.1:10100" },
    });
    expect((await handleCoCodexRoutes(context(missing)))?.status).toBe(403);

    const authorized = new Request("http://127.0.0.1:10100/api/cocodex/status", {
      headers: {
        Origin: "http://127.0.0.1:10100",
        "X-CoCodex-Capability": capability,
      },
    });
    expect((await handleCoCodexRoutes(context(authorized)))?.status).toBe(200);
  });
});
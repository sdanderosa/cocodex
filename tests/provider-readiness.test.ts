import { describe, expect, test } from "bun:test";
import {
  assessOpenAiProviderReadiness,
  proxyReadinessAt,
  type ProviderReadinessDeps,
} from "../src/server/readiness";
import type { OcxConfig } from "../src/types";

function config(mode: "direct" | "pool", accounts: OcxConfig["codexAccounts"] = []): OcxConfig {
  return {
    port: 10100,
    hostname: "127.0.0.1",
    defaultProvider: "openai",
    providers: {
      openai: {
        adapter: "openai-responses",
        baseUrl: "https://chatgpt.com/backend-api/codex",
        authMode: "forward",
        codexAccountMode: mode,
      },
    },
    codexAccounts: accounts,
  };
}

function deps(overrides: Partial<ProviderReadinessDeps> = {}): ProviderReadinessDeps {
  return {
    getMainAccountToken: () => ({ accessToken: "test-token", chatgptAccountId: "test-account" }),
    isMainAccountTokenLive: () => true,
    isCodexAccountUsable: () => true,
    isCodexAccountInCooldown: () => false,
    isCodexAccountSoftAvoided: () => false,
    getValidCodexToken: async () => ({
      generation: 1,
      accessToken: "managed-test-token",
      chatgptAccountId: "managed-test-account",
      expiresAt: Date.now() + 60_000,
      refreshToken: "managed-refresh",
    }),
    ...overrides,
  };
}

describe("OpenAI provider readiness", () => {
  test("accepts Direct only with a live native Codex credential", async () => {
    expect(await assessOpenAiProviderReadiness(config("direct"), deps())).toMatchObject({
      ok: true,
      accountMode: "direct",
      code: "ready",
    });
  });

  test("rejects Direct when the native credential is missing", async () => {
    const result = await assessOpenAiProviderReadiness(config("direct"), deps({
      getMainAccountToken: () => null,
      isMainAccountTokenLive: () => false,
    }));
    expect(result).toMatchObject({ ok: false, code: "credential_missing" });
  });

  test("rejects Direct when the native credential is expired", async () => {
    const result = await assessOpenAiProviderReadiness(config("direct"), deps({
      isMainAccountTokenLive: () => false,
    }));
    expect(result).toMatchObject({ ok: false, code: "credential_expired" });
  });

  test("rejects Pool with no usable credential and offers a safe cancel path", async () => {
    const result = await assessOpenAiProviderReadiness(config("pool"), deps({
      getMainAccountToken: () => null,
      isMainAccountTokenLive: () => false,
      isCodexAccountUsable: () => false,
    }));
    expect(result).toMatchObject({
      ok: false,
      accountMode: "pool",
      code: "pool_no_usable_account",
      canUseDirect: false,
    });
    expect(result.message).toContain("cancel proxy injection");
  });

  test("refresh-validates a managed Pool credential instead of trusting its presence", async () => {
    let refreshChecks = 0;
    const result = await assessOpenAiProviderReadiness(
      config("pool", [{ id: "managed", label: "Managed" }]),
      deps({
        getMainAccountToken: () => null,
        isMainAccountTokenLive: () => false,
        isCodexAccountUsable: (_config, id) => id === "managed",
        getValidCodexToken: async () => {
          refreshChecks += 1;
          return {
            generation: 2,
            accessToken: "managed-test-token",
            chatgptAccountId: "managed-test-account",
            expiresAt: Date.now() + 60_000,
            refreshToken: "managed-refresh",
          };
        },
      }),
    );
    expect(result).toMatchObject({ ok: true, accountMode: "pool", code: "ready" });
    expect(refreshChecks).toBe(1);
  });
});

describe("/readyz client proof", () => {
  test("accepts only a successful OpenCodex readiness document", async () => {
    const result = await proxyReadinessAt(10100, {
      fetchFn: async () => new Response(JSON.stringify({
        status: "ok",
        service: "opencodex",
        pid: 42,
        provider: "openai",
        accountMode: "direct",
        code: "ready",
        message: "ready",
        canUseDirect: true,
      }), { status: 200, headers: { "content-type": "application/json" } }),
    });
    expect(result).toMatchObject({ pid: 42, accountMode: "direct", code: "ready" });
  });

  test("rejects a healthy HTTP responder whose credentials are not ready", async () => {
    const result = await proxyReadinessAt(10100, {
      fetchFn: async () => new Response(JSON.stringify({
        status: "not_ready",
        service: "opencodex",
        pid: 42,
        provider: "openai",
        accountMode: "pool",
        code: "pool_no_usable_account",
      }), { status: 503, headers: { "content-type": "application/json" } }),
    });
    expect(result).toMatchObject({ ok: false, code: "pool_no_usable_account" });
  });
});

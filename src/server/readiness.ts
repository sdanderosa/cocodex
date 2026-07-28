import type { CodexAccountMode, OcxConfig } from "../types";
import { getValidCodexToken } from "../codex/account-store";
import { isCodexAccountUsable } from "../codex/account-usability";
import { getMainAccountToken, isMainAccountTokenLive, MAIN_CODEX_ACCOUNT_ID } from "../codex/main-account";
import { isCodexAccountInCooldown, isCodexAccountSoftAvoided } from "../codex/routing";
import { isCanonicalOpenAiForwardProvider } from "../providers/openai-tiers";
import { providerCodexAccountMode } from "../providers/registry";

export type ProxyReadinessCode =
  | "ready"
  | "configuration_invalid"
  | "configuration_mismatch"
  | "provider_missing"
  | "provider_disabled"
  | "provider_invalid"
  | "credential_missing"
  | "credential_expired"
  | "pool_no_usable_account";

export interface ProviderReadiness {
  ok: boolean;
  provider: "openai";
  accountMode: CodexAccountMode | null;
  code: ProxyReadinessCode;
  message: string;
  canUseDirect: boolean;
}

export interface ProviderReadinessDeps {
  getMainAccountToken: typeof getMainAccountToken;
  isMainAccountTokenLive: typeof isMainAccountTokenLive;
  isCodexAccountUsable: typeof isCodexAccountUsable;
  isCodexAccountInCooldown: typeof isCodexAccountInCooldown;
  isCodexAccountSoftAvoided: typeof isCodexAccountSoftAvoided;
  getValidCodexToken: typeof getValidCodexToken;
}

const DEFAULT_PROVIDER_DEPS: ProviderReadinessDeps = {
  getMainAccountToken,
  isMainAccountTokenLive,
  isCodexAccountUsable,
  isCodexAccountInCooldown,
  isCodexAccountSoftAvoided,
  getValidCodexToken,
};

function failure(
  code: Exclude<ProxyReadinessCode, "ready">,
  message: string,
  accountMode: CodexAccountMode | null,
  canUseDirect: boolean,
): ProviderReadiness {
  return { ok: false, provider: "openai", accountMode, code, message, canUseDirect };
}

/**
 * Resolve an actually usable credential for the canonical OpenAI route.
 *
 * Direct mode proves that the native Codex login exists and is not locally
 * known to be expired. Pool mode tries every eligible configured credential;
 * managed accounts pass through the normal refresh/generation checks instead
 * of being accepted merely because an encrypted record exists on disk.
 */
export async function assessOpenAiProviderReadiness(
  config: OcxConfig,
  deps: ProviderReadinessDeps = DEFAULT_PROVIDER_DEPS,
): Promise<ProviderReadiness> {
  const provider = config.providers.openai;
  const mainToken = deps.getMainAccountToken();
  const directUsable = !!mainToken && deps.isMainAccountTokenLive();
  if (!provider) return failure("provider_missing", "OpenAI provider is not configured", null, directUsable);
  if (provider.disabled === true) return failure("provider_disabled", "OpenAI provider is disabled", null, directUsable);
  if (!isCanonicalOpenAiForwardProvider(provider)) {
    return failure("provider_invalid", "OpenAI provider configuration is not the canonical Codex forward provider", null, directUsable);
  }

  const accountMode = providerCodexAccountMode("openai", provider) ?? "pool";
  if (accountMode === "direct") {
    if (!mainToken) {
      return failure("credential_missing", "Direct mode requires a native Codex login", accountMode, false);
    }
    if (!directUsable) {
      return failure("credential_expired", "Direct mode native Codex credential is expired", accountMode, false);
    }
    return {
      ok: true,
      provider: "openai",
      accountMode,
      code: "ready",
      message: "OpenAI Direct credential is usable",
      canUseDirect: true,
    };
  }

  if (
    directUsable
    && deps.isCodexAccountUsable(config, MAIN_CODEX_ACCOUNT_ID)
    && !deps.isCodexAccountInCooldown(MAIN_CODEX_ACCOUNT_ID)
    && !deps.isCodexAccountSoftAvoided(MAIN_CODEX_ACCOUNT_ID)
  ) {
    return {
      ok: true,
      provider: "openai",
      accountMode,
      code: "ready",
      message: "OpenAI Pool has a usable account credential",
      canUseDirect: true,
    };
  }

  for (const account of config.codexAccounts ?? []) {
    if (account.isMain || !deps.isCodexAccountUsable(config, account.id)) continue;
    if (deps.isCodexAccountInCooldown(account.id) || deps.isCodexAccountSoftAvoided(account.id)) continue;
    try {
      await deps.getValidCodexToken(account.id);
      if (deps.isCodexAccountUsable(config, account.id)) {
        return {
          ok: true,
          provider: "openai",
          accountMode,
          code: "ready",
          message: "OpenAI Pool has a usable account credential",
          canUseDirect: directUsable,
        };
      }
    } catch {
      // Try the remaining accounts. Never expose token or account details here.
    }
  }

  return failure(
    "pool_no_usable_account",
    directUsable
      ? "OpenAI Pool has no usable account; switch to Direct mode or cancel proxy injection"
      : "OpenAI Pool has no usable account; cancel proxy injection and sign in or add an account",
    accountMode,
    directUsable,
  );
}

export interface RemoteProxyReadiness {
  ok: boolean;
  pid: number;
  provider: string;
  accountMode: CodexAccountMode | null;
  code: ProxyReadinessCode;
  message: string;
  canUseDirect: boolean;
}

export async function proxyReadinessAt(
  port: number,
  options: { hostname?: string; timeoutMs?: number; fetchFn?: typeof fetch } = {},
): Promise<RemoteProxyReadiness | null> {
  const hostname = (options.hostname ?? "127.0.0.1").trim().toLowerCase();
  const host = hostname === "::1" || hostname === "[::1]" ? "[::1]" : "127.0.0.1";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 2_000);
  try {
    const response = await (options.fetchFn ?? fetch)(`http://${host}:${port}/readyz`, { signal: controller.signal });
    const body = await response.json() as Record<string, unknown>;
    if (body.service !== "opencodex") return null;
    if (typeof body.pid !== "number" || !Number.isInteger(body.pid) || body.pid <= 0) return null;
    if (body.provider !== "openai" || typeof body.code !== "string") return null;
    const allowedCodes: ProxyReadinessCode[] = [
      "ready",
      "configuration_invalid",
      "configuration_mismatch",
      "provider_missing",
      "provider_disabled",
      "provider_invalid",
      "credential_missing",
      "credential_expired",
      "pool_no_usable_account",
    ];
    if (!allowedCodes.includes(body.code as ProxyReadinessCode)) return null;
    const accountMode = body.accountMode === "direct" || body.accountMode === "pool" ? body.accountMode : null;
    const ok = response.ok && body.status === "ok" && body.code === "ready" && accountMode !== null;
    return {
      ok,
      pid: body.pid,
      provider: body.provider,
      accountMode,
      code: body.code as ProxyReadinessCode,
      message: typeof body.message === "string" ? body.message : (ok ? "provider credential verified" : "provider authentication is not ready"),
      canUseDirect: body.canUseDirect === true,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}

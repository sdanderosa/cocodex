import { codexAutoStartEnabled } from "../config";
import type { ServiceDiagnostic } from "../service";
import type { OcxConfig } from "../types";
import type { CodexShimDiagnostic } from "./shim";
import type { RemoteProxyReadiness } from "../server/readiness";

export type InjectionProtection = "service" | "shim";

export interface InjectionReadiness {
  ok: boolean;
  protection: InjectionProtection | null;
  message: string;
  expectedPort: number;
  checkedPort: number;
}

export interface InjectionSafetyDeps {
  proxyIdentityAt?: (
    port: number,
    options: { hostname?: string },
  ) => Promise<{ pid: number | null } | null>;
  proxyReadinessAt?: (
    port: number,
    options: { hostname?: string },
  ) => Promise<RemoteProxyReadiness | null>;
  diagnoseService?: () => ServiceDiagnostic;
  diagnoseCodexShim?: () => CodexShimDiagnostic;
  verifyPidIdentity?: (candidatePid: number) => number | null;
}

function expectedConfiguredPort(config: Pick<OcxConfig, "port">): number {
  const configured = config.port;
  return typeof configured === "number" && Number.isInteger(configured) && configured > 0 && configured <= 65_535
    ? configured
    : 10_100;
}

function unavailableService(): ServiceDiagnostic {
  return {
    supported: false,
    installed: false,
    enabled: false,
    running: false,
    viable: false,
    startable: false,
    stale: false,
    conflict: false,
    backend: null,
    summary: "service diagnostics unavailable",
  };
}

function unavailableShim(): CodexShimDiagnostic {
  return {
    installed: false,
    healthy: false,
    summary: "shim diagnostics unavailable",
  };
}

/**
 * Fail-closed proof that Codex may safely depend on the local proxy.
 *
 * The live port must equal the configured/autostart port. An interactive
 * fallback listener is useful for the dashboard, but it is not reboot-safe
 * and must never be written into Codex's persistent config.
 */
export async function verifyInjectionReadiness(
  port: number,
  config: Pick<OcxConfig, "port" | "hostname" | "codexAutoStart">,
  deps: InjectionSafetyDeps = {},
): Promise<InjectionReadiness> {
  const expectedPort = expectedConfiguredPort(config);
  const base = { expectedPort, checkedPort: port };
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    return { ...base, ok: false, protection: null, message: "proxy port is invalid" };
  }
  if (port !== expectedPort) {
    return {
      ...base,
      ok: false,
      protection: null,
      message: `proxy is healthy on fallback port ${port}, but autostart is configured for ${expectedPort}`,
    };
  }

  const proxyIdentityAt = deps.proxyIdentityAt
    ?? (await import("../server/proxy-liveness")).proxyIdentityAt;
  const identity = await proxyIdentityAt(port, { hostname: config.hostname }).catch(() => null);
  if (!identity) {
    return {
      ...base,
      ok: false,
      protection: null,
      message: `proxy health verification failed at /healthz on port ${port}`,
    };
  }
  if (typeof identity.pid !== "number") {
    return {
      ...base,
      ok: false,
      protection: null,
      message: `proxy health response on port ${port} did not identify its owning process`,
    };
  }
  const verifyPidIdentity = deps.verifyPidIdentity
    ?? (await import("../config")).verifyPidIdentity;
  if (verifyPidIdentity(identity.pid) !== identity.pid) {
    return {
      ...base,
      ok: false,
      protection: null,
      message: `port ${port} is not owned by the expected CoCodex/OpenCodex process`,
    };
  }

  const proxyReadinessAt = deps.proxyReadinessAt
    ?? (await import("../server/readiness")).proxyReadinessAt;
  const providerReadiness = await proxyReadinessAt(port, { hostname: config.hostname }).catch(() => null);
  if (!providerReadiness) {
    return {
      ...base,
      ok: false,
      protection: null,
      message: `proxy provider/authentication readiness verification failed at /readyz on port ${port}`,
    };
  }
  if (providerReadiness.pid !== identity.pid) {
    return {
      ...base,
      ok: false,
      protection: null,
      message: `proxy /healthz and /readyz process identities do not match on port ${port}`,
    };
  }
  if (!providerReadiness.ok) {
    return {
      ...base,
      ok: false,
      protection: null,
      message: providerReadiness.message,
    };
  }

  let service = unavailableService();
  let shim = unavailableShim();
  try {
    const diagnoseService = deps.diagnoseService ?? (await import("../service")).diagnoseService;
    service = diagnoseService();
  } catch {
    // A diagnostic failure is not evidence of restart protection.
  }
  try {
    const diagnoseCodexShim = deps.diagnoseCodexShim ?? (await import("./shim")).diagnoseCodexShim;
    shim = diagnoseCodexShim();
  } catch {
    // A diagnostic failure is not evidence of restart protection.
  }

  const serviceOperational = service.installed
    && service.enabled
    && service.running
    && service.viable
    && !service.stale
    && !service.conflict;
  if (serviceOperational) {
    return {
      ...base,
      ok: true,
      protection: "service",
      message: "proxy health and reboot-persistent service verified",
    };
  }

  const shimOperational = codexAutoStartEnabled(config) && shim.installed && shim.healthy;
  if (shimOperational) {
    return {
      ...base,
      ok: true,
      protection: "shim",
      message: "proxy health and Codex autostart shim verified",
    };
  }

  const serviceDetail = service.installed ? service.summary : "service not installed";
  const shimDetail = shim.installed
    ? shim.summary
    : codexAutoStartEnabled(config)
      ? "shim not installed"
      : "shim disabled by codexAutoStart=false";
  return {
    ...base,
    ok: false,
    protection: null,
    message: `no operational autostart protection (${serviceDetail}; ${shimDetail})`,
  };
}

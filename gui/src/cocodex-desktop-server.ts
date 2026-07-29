export const DEFAULT_COCODEX_SERVER_PORT = 19463;

type TauriInternals = {
  invoke?: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
};

export interface DesktopServerStatus {
  initialized: boolean;
  running: boolean;
  pid: number | null;
  publicHost: string | null;
  port: number | null;
  authority: string | null;
  serverFingerprint: string | null;
}

export interface DesktopServerPrepareResult {
  initializedNow: boolean;
  status: DesktopServerStatus;
  invitation: string;
  network: {
    firewall: unknown;
    portMapping: unknown;
    diagnostic: unknown;
    manualPortForwarding: unknown;
  };
}

function desktopInvoke(): TauriInternals["invoke"] {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return undefined;
  return (window as Window & { __TAURI_INTERNALS__?: TauriInternals })
    .__TAURI_INTERNALS__?.invoke;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("CoCodex desktop returned an invalid server response.");
  }
  return value as Record<string, unknown>;
}

export function parseDesktopServerStatus(value: unknown): DesktopServerStatus {
  const candidate = record(value);
  const pid = candidate.pid === null ? null : Number(candidate.pid);
  const port = candidate.port === null ? null : Number(candidate.port);
  if (
    typeof candidate.initialized !== "boolean"
    || typeof candidate.running !== "boolean"
    || (pid !== null && (!Number.isInteger(pid) || pid <= 0))
    || (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535))
  ) {
    throw new Error("CoCodex desktop returned an invalid server status.");
  }
  return {
    initialized: candidate.initialized,
    running: candidate.running,
    pid,
    publicHost: typeof candidate.publicHost === "string" ? candidate.publicHost : null,
    port,
    authority: typeof candidate.authority === "string" ? candidate.authority : null,
    serverFingerprint: typeof candidate.serverFingerprint === "string"
      ? candidate.serverFingerprint
      : null,
  };
}

export function isDesktopServerAvailable(): boolean {
  return typeof desktopInvoke() === "function";
}

async function invokeDesktop(command: string, args?: Record<string, unknown>): Promise<unknown> {
  const invoke = desktopInvoke();
  if (!invoke) throw new Error("Hosting is available in the CoCodex desktop app.");
  return invoke(command, args);
}

export async function readDesktopServerStatus(): Promise<DesktopServerStatus> {
  return parseDesktopServerStatus(await invokeDesktop("desktop_server_status"));
}

export async function prepareDesktopServer(input: {
  publicHost: string;
  port: number;
}): Promise<DesktopServerPrepareResult> {
  const candidate = record(await invokeDesktop("desktop_server_prepare", { request: input }));
  const invitation = typeof candidate.invitation === "string" ? candidate.invitation.trim() : "";
  if (!invitation || invitation.length > 16 * 1024) {
    throw new Error("CoCodex desktop returned an invalid server invitation.");
  }
  const network = record(candidate.network);
  return {
    initializedNow: candidate.initializedNow === true,
    status: parseDesktopServerStatus(candidate.status),
    invitation,
    network: {
      firewall: network.firewall,
      portMapping: network.portMapping,
      diagnostic: network.diagnostic,
      manualPortForwarding: network.manualPortForwarding,
    },
  };
}

export function desktopServerNetworkGuidance(
  network: DesktopServerPrepareResult["network"],
): { manualRequired: boolean; message: string | null } {
  const diagnostic = network.diagnostic && typeof network.diagnostic === "object"
    ? network.diagnostic as Record<string, unknown>
    : {};
  const status = typeof diagnostic.status === "string" ? diagnostic.status : null;
  const message = typeof diagnostic.message === "string" && diagnostic.message.trim()
    ? diagnostic.message.trim()
    : null;
  return {
    manualRequired: network.firewall === "manual-required" || status !== "ready",
    message,
  };
}

export async function bootstrapApproveDesktopDevice(fingerprint: string): Promise<void> {
  const response = record(await invokeDesktop("desktop_server_bootstrap_approve", { fingerprint }));
  if (response.approved !== true) throw new Error("CoCodex Server did not approve this device.");
}

import { loadConfig } from "./config";
import type { ServerPaths } from "./paths";

function localHealthHost(hostname: string): string {
  if (hostname === "0.0.0.0" || hostname === "::") return "127.0.0.1";
  return hostname;
}

export async function assertDirectServerOwnership(
  paths: ServerPaths,
  pid: number,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  try {
    const config = loadConfig(paths);
    const endpoint = "https://" + localHealthHost(config.hostname) + ":" + config.port + "/healthz";
    const response = await fetchImpl(endpoint, {
      signal: AbortSignal.timeout(1_000),
      tls: { rejectUnauthorized: false },
    });
    const body = await response.json() as Record<string, unknown>;
    if (response.ok
      && body.ok === true
      && body.service === "cocodex-server"
      && body.protocol === 1
      && body.processId === pid) return;
  } catch {
    // A missing, foreign, or unhealthy endpoint never grants signal authority.
  }
  throw new Error(
    "Refusing to signal PID " + pid + ": exact CoCodex Server ownership could not be proven; "
      + "no foreign process (including Sunshine) was stopped",
  );
}

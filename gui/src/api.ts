const TOKEN_KEY = "opencodex-api-token";
const MANAGED_PORT_START = 10101;
const MANAGED_PORT_END = 10120;
const MANAGED_FALLBACK_BASE = `http://127.0.0.1:${MANAGED_PORT_START}`;

let installed = false;
let promptInFlight: Promise<string | null> | null = null;

type TauriInternals = {
  invoke?: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
};

type ManagedRuntimeStatus = {
  state: string;
  owned: boolean;
  pid: number | null;
  port: number;
  baseUrl: string;
};

function tauriInternals(): TauriInternals | null {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return null;
  return (window as Window & { __TAURI_INTERNALS__?: TauriInternals }).__TAURI_INTERNALS__ ?? null;
}

function apiUrl(input: RequestInfo | URL): URL | null {
  try {
    const raw = input instanceof Request ? input.url : String(input);
    return new URL(raw, window.location.href);
  } catch {
    return null;
  }
}

function needsApiAuth(input: RequestInfo | URL): boolean {
  const url = apiUrl(input);
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) return false;
  if (url.origin !== window.location.origin) return false;
  return url.pathname.startsWith("/api/") || url.pathname.startsWith("/v1/");
}

function managedPort(url: URL): number | null {
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1") return null;
  const port = Number(url.port);
  return Number.isInteger(port) && port >= MANAGED_PORT_START && port <= MANAGED_PORT_END
    ? port
    : null;
}

export function isManagedProxyRequest(input: RequestInfo | URL): boolean {
  const url = apiUrl(input);
  return Boolean(url && managedPort(url) !== null);
}

function parseManagedStatus(value: unknown): ManagedRuntimeStatus | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Record<string, unknown>;
  const port = Number(candidate.port);
  const baseUrl = typeof candidate.baseUrl === "string" ? candidate.baseUrl : "";
  if (!Number.isInteger(port) || port < MANAGED_PORT_START || port > MANAGED_PORT_END) return null;
  try {
    const parsed = new URL(baseUrl);
    if (managedPort(parsed) !== port || parsed.origin !== baseUrl || parsed.pathname !== "/") return null;
  } catch {
    return null;
  }
  return {
    state: typeof candidate.state === "string" ? candidate.state : "error",
    owned: candidate.owned === true,
    pid: Number.isInteger(Number(candidate.pid)) && Number(candidate.pid) > 0 ? Number(candidate.pid) : null,
    port,
    baseUrl,
  };
}

async function readManagedRuntimeStatus(): Promise<ManagedRuntimeStatus | null> {
  const invoke = tauriInternals()?.invoke;
  if (!invoke) return null;
  try {
    return parseManagedStatus(await invoke("managed_runtime_status"));
  } catch {
    return null;
  }
}

export async function resolveManagedApiBase(configuredBase: string): Promise<string> {
  if (!tauriInternals()) return configuredBase;
  const status = await readManagedRuntimeStatus();
  return status?.baseUrl ?? MANAGED_FALLBACK_BASE;
}

function rewriteManagedRequest(input: RequestInfo | URL, baseUrl: string): RequestInfo | URL {
  const source = apiUrl(input);
  if (!source) return input;
  const target = new URL(`${source.pathname}${source.search}${source.hash}`, baseUrl);
  if (input instanceof Request) return new Request(target, input);
  if (input instanceof URL) return target;
  return target.href;
}

function readToken(): string | null {
  try {
    const token = sessionStorage.getItem(TOKEN_KEY)?.trim();
    return token || null;
  } catch {
    return null;
  }
}

function storeToken(token: string): void {
  try { sessionStorage.setItem(TOKEN_KEY, token); } catch { /* session storage may be disabled */ }
}

function clearToken(): void {
  try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* session storage may be disabled */ }
}

function withToken(input: RequestInfo | URL, init: RequestInit | undefined, token: string): [RequestInfo | URL, RequestInit | undefined] {
  const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
  headers.set("X-OpenCodex-API-Key", token);
  if (input instanceof Request) return [new Request(input, { headers }), init ? { ...init, headers } : undefined];
  return [input, { ...init, headers }];
}

async function promptForToken(): Promise<string | null> {
  if (promptInFlight) return promptInFlight;
  promptInFlight = Promise.resolve()
    .then(() => window.prompt("OpenCodex API token")?.trim() || null)
    .finally(() => { promptInFlight = null; });
  return promptInFlight;
}

export function installApiAuthFetch(): void {
  if (installed) return;
  installed = true;
  const originalFetch = window.fetch.bind(window);
  window.fetch = async (requestedInput: RequestInfo | URL, init?: RequestInit) => {
    let input = requestedInput;
    if (tauriInternals() && isManagedProxyRequest(input)) {
      const status = await readManagedRuntimeStatus();
      if (!status?.owned || status.state !== "ready" || status.pid === null) {
        return Response.json(
          { error: "CoCodex managed runtime is unavailable." },
          { status: 503 },
        );
      }
      input = rewriteManagedRequest(input, status.baseUrl);
    }
    if (!needsApiAuth(input)) return originalFetch(input, init);

    const token = readToken();
    const [firstInput, firstInit] = token ? withToken(input, init, token) : [input, init];
    const response = await originalFetch(firstInput, firstInit);
    if (response.status !== 401) return response;

    if (token) clearToken();
    const nextToken = await promptForToken();
    if (!nextToken) return response;

    storeToken(nextToken);
    const [retryInput, retryInit] = withToken(input, init, nextToken);
    const retry = await originalFetch(retryInput, retryInit);
    if (retry.status === 401) clearToken();
    return retry;
  };
}

export function resetApiAuthFetchForTests(): void {
  installed = false;
  promptInFlight = null;
}

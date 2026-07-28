const TOKEN_KEY = "opencodex-api-token";

let installed = false;
let promptInFlight: Promise<string | null> | null = null;

type TauriInternals = {
  invoke?: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
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

export function isManagedProxyRequest(input: RequestInfo | URL): boolean {
  const url = apiUrl(input);
  return url?.protocol === "http:"
    && url.hostname === "127.0.0.1"
    && url.port === "10100";
}

async function managedRuntimeOwnsProxy(): Promise<boolean> {
  const invoke = tauriInternals()?.invoke;
  if (!invoke) return true;
  try {
    const status = await invoke("managed_runtime_status");
    return Boolean(status && typeof status === "object" && (status as { owned?: unknown }).owned === true);
  } catch {
    return false;
  }
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
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    if (isManagedProxyRequest(input) && !(await managedRuntimeOwnsProxy())) {
      return Response.json(
        { error: "CoCodex managed runtime is unavailable or port 10100 is owned by another process." },
        { status: 503 },
      );
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

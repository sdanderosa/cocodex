type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const capabilityPromises = new Map<string, Promise<string>>();

async function responseJson<T>(response: Response): Promise<T> {
  const body = await response.json();
  if (!response.ok) {
    const message = body && typeof body === "object" && "error" in body
      ? String((body as { error?: unknown }).error ?? response.status)
      : String(response.status);
    throw new Error(message);
  }
  return body as T;
}

function capabilityFor(apiBase: string, fetchImpl: FetchLike): Promise<string> {
  let pending = capabilityPromises.get(apiBase);
  if (!pending) {
    pending = fetchImpl(`${apiBase}/api/cocodex/capability`)
      .then(responseJson<{ capability: string }>)
      .then(value => value.capability);
    capabilityPromises.set(apiBase, pending);
    void pending.catch(() => {
      if (capabilityPromises.get(apiBase) === pending) capabilityPromises.delete(apiBase);
    });
  }
  return pending;
}

export async function cocodexApiJson<T>(
  apiBase: string,
  url: string,
  init?: RequestInit,
  fetchImpl: FetchLike = fetch,
): Promise<T> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const headers = new Headers(init?.headers);
    headers.set("X-CoCodex-Capability", await capabilityFor(apiBase, fetchImpl));
    const response = await fetchImpl(url, { ...init, headers });
    if (attempt === 0 && (response.status === 401 || response.status === 403)) {
      capabilityPromises.delete(apiBase);
      continue;
    }
    return responseJson<T>(response);
  }
  throw new Error("CoCodex capability retry exhausted");
}

export function resetCocodexCapabilityForTests(): void {
  capabilityPromises.clear();
}

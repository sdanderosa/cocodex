import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { hardenSecretPath } from "../lib/windows-secret-acl";
import { PROJECT_KEY_BYTES, PROJECT_KEY_EPOCH_MAX } from "@cocodex/protocol";

const STORE_VERSION = 1 as const;

export interface StoredProjectKeyStore {
  version: typeof STORE_VERSION;
  projects: Record<string, Record<string, string>>;
}

function emptyStore(): StoredProjectKeyStore {
  return { version: STORE_VERSION, projects: {} };
}

function decodeKey(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== PROJECT_KEY_BYTES || decoded.toString("base64url") !== value) return undefined;
  return decoded;
}

function validateStore(value: unknown): StoredProjectKeyStore {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Project key store is invalid");
  const record = value as Record<string, unknown>;
  if (record.version !== STORE_VERSION || !record.projects || typeof record.projects !== "object" || Array.isArray(record.projects)) {
    throw new Error("Project key store has an unsupported version");
  }
  const projects: Record<string, Record<string, string>> = {};
  for (const [projectId, rawEpochs] of Object.entries(record.projects as Record<string, unknown>)) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(projectId)) {
      throw new Error("Project key store contains an invalid project ID");
    }
    if (!rawEpochs || typeof rawEpochs !== "object" || Array.isArray(rawEpochs)) {
      throw new Error("Project key store contains invalid epochs");
    }
    const epochs: Record<string, string> = {};
    for (const [epoch, encoded] of Object.entries(rawEpochs as Record<string, unknown>)) {
      const numericEpoch = Number(epoch);
      if (!Number.isSafeInteger(numericEpoch) || numericEpoch < 1 || numericEpoch > PROJECT_KEY_EPOCH_MAX
        || typeof encoded !== "string" || !decodeKey(encoded)) {
        throw new Error("Project key store contains an invalid key");
      }
      epochs[String(numericEpoch)] = encoded;
    }
    projects[projectId] = epochs;
  }
  return { version: STORE_VERSION, projects };
}

export function loadProjectKeyStore(path: string): StoredProjectKeyStore {
  if (!existsSync(path)) return emptyStore();
  hardenSecretPath(path, { required: true });
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("Project key store could not be read");
  }
  return validateStore(parsed);
}

export function saveProjectKeyStore(path: string, store: StoredProjectKeyStore): void {
  const validated = validateStore(store);
  writeFileSync(path, `${JSON.stringify(validated, null, 2)}\n`, {
    encoding: "utf8",
    flag: "w",
    mode: 0o600,
  });
  hardenSecretPath(path, { required: true });
}

export function storeProjectKey(path: string, projectId: string, keyEpoch: number, projectKey: Uint8Array): void {
  if (!Number.isSafeInteger(keyEpoch) || keyEpoch < 1 || keyEpoch > PROJECT_KEY_EPOCH_MAX) {
    throw new Error("Project key epoch is invalid");
  }
  const key = Buffer.from(projectKey);
  if (key.byteLength !== PROJECT_KEY_BYTES) throw new Error("Project encryption key has an invalid length");
  const store = loadProjectKeyStore(path);
  const projects = { ...store.projects };
  projects[projectId] = { ...(projects[projectId] ?? {}), [String(keyEpoch)]: key.toString("base64url") };
  saveProjectKeyStore(path, { version: STORE_VERSION, projects });
}

export function loadProjectKey(path: string, projectId: string, keyEpoch?: number): { keyEpoch: number; projectKey: Buffer } | undefined {
  const store = loadProjectKeyStore(path);
  const epochs = store.projects[projectId];
  if (!epochs) return undefined;
  const selectedEpoch = keyEpoch ?? Math.max(...Object.keys(epochs).map(Number));
  const encoded = epochs[String(selectedEpoch)];
  if (!encoded) return undefined;
  const projectKey = decodeKey(encoded);
  if (!projectKey) throw new Error("Project key store contains an invalid key");
  return { keyEpoch: selectedEpoch, projectKey };
}

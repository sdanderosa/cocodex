import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { hardenSecretPath } from "../lib/windows-secret-acl";
import { PROJECT_KEY_BYTES, PROJECT_KEY_EPOCH_MAX } from "@cocodex/protocol";

const STORE_VERSION = 1 as const;

export interface StoredProjectKeyStore {
  version: typeof STORE_VERSION;
  projects: Record<string, Record<string, string>>;
  states?: Record<string, StoredProjectKeyState>;
}

/**
 * Local authorization state for a project key ring.
 *
 * `currentEpoch` is the newest epoch accepted by this client. Older epochs
 * remain in `projects` so historical records can still be opened, but only
 * the current epoch is eligible for new encrypted records. Revocation is
 * deliberately sticky until an explicitly newer key is installed through
 * `restoreProjectKeyAccess`.
 */
export interface StoredProjectKeyState {
  currentEpoch: number | null;
  rotationRequired: boolean;
  revoked: boolean;
  revokedAtEpoch?: number;
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

function validateProjectId(projectId: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(projectId)) {
    throw new Error("Project key store contains an invalid project ID");
  }
}

function validateKeyEpoch(keyEpoch: number): void {
  if (!Number.isSafeInteger(keyEpoch) || keyEpoch < 1 || keyEpoch > PROJECT_KEY_EPOCH_MAX) {
    throw new Error("Project key epoch is invalid");
  }
}

function highestEpoch(epochs: Record<string, string> | undefined): number | null {
  if (!epochs) return null;
  const values = Object.keys(epochs).map(Number);
  return values.length === 0 ? null : Math.max(...values);
}

function defaultProjectKeyState(epochs: Record<string, string> | undefined): StoredProjectKeyState {
  return {
    currentEpoch: highestEpoch(epochs),
    rotationRequired: false,
    revoked: false,
  };
}

function cloneProjectKeyState(state: StoredProjectKeyState): StoredProjectKeyState {
  return state.revokedAtEpoch === undefined
    ? { currentEpoch: state.currentEpoch, rotationRequired: state.rotationRequired, revoked: state.revoked }
    : {
        currentEpoch: state.currentEpoch,
        rotationRequired: state.rotationRequired,
        revoked: state.revoked,
        revokedAtEpoch: state.revokedAtEpoch,
      };
}

function readProjectKeyState(store: StoredProjectKeyStore, projectId: string): StoredProjectKeyState | undefined {
  const raw = store.states?.[projectId];
  if (!raw) {
    return store.projects[projectId] ? defaultProjectKeyState(store.projects[projectId]) : undefined;
  }
  const derivedCurrentEpoch = highestEpoch(store.projects[projectId]);
  // A key inserted by an older client may predate the state metadata. Never
  // let stale metadata move the current epoch backwards.
  const currentEpoch = derivedCurrentEpoch === null
    ? raw.currentEpoch
    : Math.max(raw.currentEpoch ?? 0, derivedCurrentEpoch);
  return cloneProjectKeyState({ ...raw, currentEpoch });
}

function writeProjectKeyState(
  store: StoredProjectKeyStore,
  projectId: string,
  state: StoredProjectKeyState,
): StoredProjectKeyStore {
  return {
    version: STORE_VERSION,
    projects: store.projects,
    states: {
      ...(store.states ?? {}),
      [projectId]: cloneProjectKeyState(state),
    },
  };
}

function validateProjectKeyState(value: unknown): StoredProjectKeyState {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Project key store contains invalid state");
  }
  const record = value as Record<string, unknown>;
  const currentEpoch = record.currentEpoch;
  if (currentEpoch !== null && (typeof currentEpoch !== "number" || !Number.isSafeInteger(currentEpoch)
    || currentEpoch < 1 || currentEpoch > PROJECT_KEY_EPOCH_MAX)) {
    throw new Error("Project key store contains invalid state");
  }
  if (typeof record.rotationRequired !== "boolean" || typeof record.revoked !== "boolean") {
    throw new Error("Project key store contains invalid state");
  }
  const revokedAtEpoch = record.revokedAtEpoch;
  if (revokedAtEpoch !== undefined) validateKeyEpoch(revokedAtEpoch as number);
  return {
    currentEpoch: currentEpoch as number | null,
    rotationRequired: record.rotationRequired,
    revoked: record.revoked,
    ...(revokedAtEpoch === undefined ? {} : { revokedAtEpoch: revokedAtEpoch as number }),
  };
}

function validateStore(value: unknown): StoredProjectKeyStore {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Project key store is invalid");
  const record = value as Record<string, unknown>;
  if (record.version !== STORE_VERSION || !record.projects || typeof record.projects !== "object" || Array.isArray(record.projects)) {
    throw new Error("Project key store has an unsupported version");
  }
  const projects: Record<string, Record<string, string>> = {};
  for (const [projectId, rawEpochs] of Object.entries(record.projects as Record<string, unknown>)) {
    validateProjectId(projectId);
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
  const states: Record<string, StoredProjectKeyState> = {};
  if (record.states !== undefined) {
    if (!record.states || typeof record.states !== "object" || Array.isArray(record.states)) {
      throw new Error("Project key store contains invalid state");
    }
    for (const [projectId, rawState] of Object.entries(record.states as Record<string, unknown>)) {
      validateProjectId(projectId);
      states[projectId] = validateProjectKeyState(rawState);
    }
  }
  return Object.keys(states).length === 0
    ? { version: STORE_VERSION, projects }
    : { version: STORE_VERSION, projects, states };
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
  validateProjectId(projectId);
  validateKeyEpoch(keyEpoch);
  const key = Buffer.from(projectKey);
  if (key.byteLength !== PROJECT_KEY_BYTES) throw new Error("Project encryption key has an invalid length");
  const store = loadProjectKeyStore(path);
  const state = readProjectKeyState(store, projectId) ?? defaultProjectKeyState(undefined);
  if (state.revoked) throw new Error("Project key access has been revoked");
  const existingEncoded = store.projects[projectId]?.[String(keyEpoch)];
  if (existingEncoded !== undefined) {
    const existing = decodeKey(existingEncoded);
    if (!existing) throw new Error("Project key store contains an invalid key");
    if (!existing.equals(key)) throw new Error("Project key epoch already contains a different key");
    return;
  }
  if (state.currentEpoch !== null && keyEpoch < state.currentEpoch) {
    throw new Error(`Project key epoch ${keyEpoch} is stale; current epoch is ${state.currentEpoch}`);
  }
  const projects = { ...store.projects };
  projects[projectId] = { ...(projects[projectId] ?? {}), [String(keyEpoch)]: key.toString("base64url") };
  const isNewerEpoch = state.currentEpoch === null || keyEpoch > state.currentEpoch;
  const nextState: StoredProjectKeyState = {
    ...state,
    currentEpoch: Math.max(state.currentEpoch ?? keyEpoch, keyEpoch),
    rotationRequired: isNewerEpoch ? false : state.rotationRequired,
  };
  saveProjectKeyStore(path, writeProjectKeyState({ ...store, projects }, projectId, nextState));
}

/** Remove one locally staged key after its server transaction was rejected. */
export function removeProjectKey(path: string, projectId: string, keyEpoch: number): void {
  validateProjectId(projectId);
  validateKeyEpoch(keyEpoch);
  const store = loadProjectKeyStore(path);
  const epochs = store.projects[projectId];
  if (!epochs || epochs[String(keyEpoch)] === undefined) return;
  const nextEpochs = { ...epochs };
  delete nextEpochs[String(keyEpoch)];
  const projects = { ...store.projects };
  const states = { ...(store.states ?? {}) };
  if (Object.keys(nextEpochs).length === 0) {
    delete projects[projectId];
    delete states[projectId];
  } else {
    projects[projectId] = nextEpochs;
    const state = readProjectKeyState(store, projectId);
    if (state) states[projectId] = {
      ...state,
      currentEpoch: Math.max(...Object.keys(nextEpochs).map(Number)),
    };
  }
  saveProjectKeyStore(path, {
    version: STORE_VERSION,
    projects,
    ...(Object.keys(states).length > 0 ? { states } : {}),
  });
}

export function loadProjectKey(path: string, projectId: string, keyEpoch?: number): { keyEpoch: number; projectKey: Buffer } | undefined {
  validateProjectId(projectId);
  if (keyEpoch !== undefined) validateKeyEpoch(keyEpoch);
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

/** Return local rotation/revocation state without exposing key bytes. */
export function loadProjectKeyState(path: string, projectId: string): StoredProjectKeyState | undefined {
  validateProjectId(projectId);
  return readProjectKeyState(loadProjectKeyStore(path), projectId);
}

/** Mark the local key ring unusable for new writes until a newer epoch arrives. */
export function markProjectKeyRotationRequired(path: string, projectId: string): StoredProjectKeyState {
  validateProjectId(projectId);
  const store = loadProjectKeyStore(path);
  const state = readProjectKeyState(store, projectId) ?? defaultProjectKeyState(undefined);
  const nextState = { ...state, rotationRequired: true } satisfies StoredProjectKeyState;
  saveProjectKeyStore(path, writeProjectKeyState(store, projectId, nextState));
  return nextState;
}

/** Revoke this device's local project-key access while retaining history for audit/decryption. */
export function revokeProjectKey(path: string, projectId: string, revokedAtEpoch?: number): StoredProjectKeyState {
  validateProjectId(projectId);
  if (revokedAtEpoch !== undefined) validateKeyEpoch(revokedAtEpoch);
  const store = loadProjectKeyStore(path);
  const state = readProjectKeyState(store, projectId) ?? defaultProjectKeyState(undefined);
  const nextRevokedAt = revokedAtEpoch === undefined
    ? state.revokedAtEpoch ?? state.currentEpoch ?? undefined
    : Math.max(state.revokedAtEpoch ?? 0, revokedAtEpoch);
  const nextState: StoredProjectKeyState = {
    ...state,
    rotationRequired: true,
    revoked: true,
    ...(nextRevokedAt === undefined ? {} : { revokedAtEpoch: nextRevokedAt }),
  };
  saveProjectKeyStore(path, writeProjectKeyState(store, projectId, nextState));
  return nextState;
}

/**
 * Install a strictly newer key after an explicit server-approved re-enrollment.
 * This is the only operation that clears a sticky local revocation flag.
 */
export function restoreProjectKeyAccess(
  path: string,
  projectId: string,
  keyEpoch: number,
  projectKey: Uint8Array,
): StoredProjectKeyState {
  validateProjectId(projectId);
  validateKeyEpoch(keyEpoch);
  const key = Buffer.from(projectKey);
  if (key.byteLength !== PROJECT_KEY_BYTES) throw new Error("Project encryption key has an invalid length");
  const store = loadProjectKeyStore(path);
  const state = readProjectKeyState(store, projectId) ?? defaultProjectKeyState(undefined);
  const minimumEpoch = Math.max(state.currentEpoch ?? 0, state.revokedAtEpoch ?? 0);
  if (state.revoked && keyEpoch <= minimumEpoch) {
    throw new Error(`Project key epoch ${keyEpoch} is not newer than revoked epoch ${minimumEpoch}`);
  }
  if (!state.revoked && state.currentEpoch !== null && keyEpoch < state.currentEpoch) {
    throw new Error(`Project key epoch ${keyEpoch} is stale; current epoch is ${state.currentEpoch}`);
  }
  const existingEncoded = store.projects[projectId]?.[String(keyEpoch)];
  if (existingEncoded !== undefined) {
    const existing = decodeKey(existingEncoded);
    if (!existing) throw new Error("Project key store contains an invalid key");
    if (!existing.equals(key)) throw new Error("Project key epoch already contains a different key");
  }
  const projects = { ...store.projects };
  projects[projectId] = { ...(projects[projectId] ?? {}), [String(keyEpoch)]: key.toString("base64url") };
  const nextState: StoredProjectKeyState = {
    currentEpoch: Math.max(state.currentEpoch ?? keyEpoch, keyEpoch),
    rotationRequired: false,
    revoked: false,
  };
  saveProjectKeyStore(path, writeProjectKeyState({ ...store, projects }, projectId, nextState));
  return nextState;
}

/** Rotate to a newer epoch without changing the revocation state. */
export function rotateProjectKey(
  path: string,
  projectId: string,
  keyEpoch: number,
  projectKey: Uint8Array,
): StoredProjectKeyState {
  validateProjectId(projectId);
  validateKeyEpoch(keyEpoch);
  const state = loadProjectKeyState(path, projectId);
  if (state?.revoked) throw new Error("Project key access has been revoked");
  if (state?.currentEpoch !== null && state?.currentEpoch !== undefined && keyEpoch <= state.currentEpoch) {
    throw new Error(`Project key epoch ${keyEpoch} is not newer than current epoch ${state.currentEpoch}`);
  }
  storeProjectKey(path, projectId, keyEpoch, projectKey);
  return loadProjectKeyState(path, projectId)!;
}

/** Load only the current, non-revoked epoch for creating new encrypted records. */
export function loadProjectKeyForEncryption(
  path: string,
  projectId: string,
  keyEpoch?: number,
): { keyEpoch: number; projectKey: Buffer } | undefined {
  const state = loadProjectKeyState(path, projectId);
  if (!state || state.revoked || state.rotationRequired || state.currentEpoch === null) return undefined;
  if (keyEpoch !== undefined && keyEpoch !== state.currentEpoch) return undefined;
  return loadProjectKey(path, projectId, state.currentEpoch);
}

/** Load the current key for an owner preparing a server-approved rotation. */
export function loadProjectKeyForRotation(
  path: string,
  projectId: string,
): { keyEpoch: number; projectKey: Buffer } | undefined {
  const state = loadProjectKeyState(path, projectId);
  if (!state || state.revoked || state.currentEpoch === null) return undefined;
  return loadProjectKey(path, projectId, state.currentEpoch);
}

export function canEncryptProject(path: string, projectId: string): boolean {
  return loadProjectKeyForEncryption(path, projectId) !== undefined;
}

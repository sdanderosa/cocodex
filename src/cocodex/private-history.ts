import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const MAX_HISTORY_ENTRIES = 512;
const MAX_HISTORY_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PRIVATE_CIPHERTEXT_BYTES = 72 * 1024;

const localCiphertextSchema = z.string().min(64).max(96_000).superRefine((value, refinement) => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    refinement.addIssue({ code: "custom", message: "Private-history ciphertext must be canonical base64url" });
    return;
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value || decoded.byteLength < 48
    || decoded.byteLength > MAX_PRIVATE_CIPHERTEXT_BYTES) {
    refinement.addIssue({ code: "custom", message: "Private-history ciphertext is outside the supported bounds" });
  }
});

const privateHistoryEntrySchema = z.object({
  messageId: z.uuid(),
  senderDeviceId: z.uuid(),
  recipientDeviceId: z.uuid(),
  localCiphertext: localCiphertextSchema,
  clientCreatedAt: z.iso.datetime(),
  deliveryState: z.enum(["staged", "queued", "accepted"]),
  serverSequence: z.number().int().positive().nullable(),
  acceptedAt: z.iso.datetime().nullable(),
}).strict();

const privateHistoryFileSchema = z.object({
  version: z.literal(1),
  deviceId: z.uuid(),
  entries: z.array(privateHistoryEntrySchema).max(MAX_HISTORY_ENTRIES),
}).strict();

export interface PrivateHistoryEntry {
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  localCiphertext: string;
  clientCreatedAt: string;
  deliveryState: "staged" | "queued" | "accepted";
  serverSequence: number | null;
  acceptedAt: string | null;
}

export interface PrivateHistoryState {
  version: 1;
  deviceId: string;
  entries: PrivateHistoryEntry[];
}

export interface PrivateHistoryServerEnvelope {
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  clientCreatedAt: string;
  sequence: number;
  acceptedAt: string;
}

export function emptyPrivateHistory(deviceId: string): PrivateHistoryState {
  return { version: 1, deviceId, entries: [] };
}

function validateHistoryOwnership(state: PrivateHistoryState): void {
  for (const entry of state.entries) {
    if (entry.senderDeviceId !== state.deviceId && entry.recipientDeviceId !== state.deviceId) {
      throw new Error("Private history contains a message for a different device");
    }
  }
}

export function loadPrivateHistory(path: string, deviceId: string): PrivateHistoryState {
  if (!existsSync(path)) return emptyPrivateHistory(deviceId);
  hardenSecretPath(path, { required: true });
  if (statSync(path).size > MAX_HISTORY_FILE_BYTES) throw new Error("Private history file is too large");
  const parsed = privateHistoryFileSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  if (parsed.deviceId !== deviceId) throw new Error("Private history belongs to a different device");
  validateHistoryOwnership(parsed);
  return parsed;
}

export function savePrivateHistory(path: string, state: PrivateHistoryState): void {
  const parsed = privateHistoryFileSchema.parse(state);
  validateHistoryOwnership(parsed);
  const serialized = `${JSON.stringify(parsed, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_HISTORY_FILE_BYTES) {
    throw new Error("Private history file is too large");
  }
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function recordPrivateHistoryEntry(
  state: PrivateHistoryState,
  entry: PrivateHistoryEntry,
): PrivateHistoryState {
  const parsed = privateHistoryEntrySchema.parse(entry);
  if (parsed.senderDeviceId !== state.deviceId && parsed.recipientDeviceId !== state.deviceId) {
    throw new Error("Private history entry belongs to a different device");
  }
  const existing = state.entries.find(item => item.messageId === parsed.messageId);
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(parsed)) {
      throw new Error("Private history message ID was reused with different content");
    }
    return state;
  }
  const entries = [...state.entries, parsed];
  if (entries.length > MAX_HISTORY_ENTRIES) {
    const acceptedIndex = entries.findIndex(item => item.deliveryState === "accepted");
    if (acceptedIndex < 0) {
      throw new Error("Private history is full of unaccepted messages");
    }
    entries.splice(acceptedIndex, 1);
  }
  return {
    ...state,
    entries,
  };
}

export function acknowledgePrivateHistoryEntry(
  state: PrivateHistoryState,
  envelope: PrivateHistoryServerEnvelope,
): PrivateHistoryState {
  const index = state.entries.findIndex(item => item.messageId === envelope.messageId);
  if (index < 0) return state;
  const existing = state.entries[index]!;
  if (existing.senderDeviceId !== envelope.senderDeviceId
    || existing.recipientDeviceId !== envelope.recipientDeviceId
    || existing.clientCreatedAt !== envelope.clientCreatedAt) {
    throw new Error("Private-history acknowledgement does not match the local message");
  }
  if (existing.serverSequence !== null && existing.serverSequence !== envelope.sequence) {
    throw new Error("Private-history server sequence changed");
  }
  if (existing.acceptedAt !== null && existing.acceptedAt !== envelope.acceptedAt) {
    throw new Error("Private-history acceptance time changed");
  }
  if (existing.serverSequence === envelope.sequence && existing.acceptedAt === envelope.acceptedAt) return state;
  const entries = [...state.entries];
  entries[index] = {
    ...existing,
    deliveryState: "accepted",
    serverSequence: envelope.sequence,
    acceptedAt: envelope.acceptedAt,
  };
  return { ...state, entries };
}

export function markPrivateHistoryEntryQueued(
  state: PrivateHistoryState,
  messageId: string,
): PrivateHistoryState {
  const index = state.entries.findIndex(entry => entry.messageId === messageId);
  if (index < 0) throw new Error("Private history message does not exist");
  const existing = state.entries[index]!;
  if (existing.deliveryState === "accepted" || existing.deliveryState === "queued") return state;
  if (existing.senderDeviceId !== state.deviceId) {
    throw new Error("Only a local outgoing private message can be queued");
  }
  const entries = [...state.entries];
  entries[index] = { ...existing, deliveryState: "queued" };
  return { ...state, entries };
}

export function reconcileStagedPrivateHistory(
  state: PrivateHistoryState,
  queuedMessageIds: ReadonlySet<string>,
): PrivateHistoryState {
  let changed = false;
  const entries: PrivateHistoryEntry[] = [];
  for (const entry of state.entries) {
    if (entry.deliveryState !== "staged") {
      entries.push(entry);
      continue;
    }
    changed = true;
    if (entry.senderDeviceId === state.deviceId && queuedMessageIds.has(entry.messageId)) {
      entries.push({ ...entry, deliveryState: "queued" });
    }
  }
  return changed ? { ...state, entries } : state;
}

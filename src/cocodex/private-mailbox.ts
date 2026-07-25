import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";

const privateMailboxReceiptSchema = z.object({
  messageId: z.uuid(),
  sequence: z.number().int().positive(),
}).strict();

const privateMailboxFileSchema = z.object({
  version: z.literal(1),
  deviceId: z.uuid(),
  cursor: z.number().int().nonnegative(),
  receipts: z.array(privateMailboxReceiptSchema).max(2_048),
}).strict();

export interface PrivateMailboxReceipt {
  messageId: string;
  sequence: number;
}

export interface PrivateMailboxState {
  version: 1;
  deviceId: string;
  cursor: number;
  receipts: PrivateMailboxReceipt[];
}

export function emptyPrivateMailbox(deviceId: string): PrivateMailboxState {
  return { version: 1, deviceId, cursor: 0, receipts: [] };
}

export function loadPrivateMailbox(path: string, deviceId: string): PrivateMailboxState {
  if (!existsSync(path)) return emptyPrivateMailbox(deviceId);
  hardenSecretPath(path, { required: true });
  const parsed = privateMailboxFileSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  if (parsed.deviceId !== deviceId) throw new Error("Private mailbox belongs to a different device");
  return parsed;
}

export function savePrivateMailbox(path: string, state: PrivateMailboxState): void {
  const parsed = privateMailboxFileSchema.parse(state);
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(parsed, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function hasPrivateMailboxReceipt(state: PrivateMailboxState, messageId: string): boolean {
  return state.receipts.some(receipt => receipt.messageId === messageId);
}

export function recordPrivateMailboxReceipt(
  state: PrivateMailboxState,
  receipt: PrivateMailboxReceipt,
): PrivateMailboxState {
  if (hasPrivateMailboxReceipt(state, receipt.messageId)) return state;
  const receipts = [...state.receipts, receipt];
  return {
    ...state,
    cursor: Math.max(state.cursor, receipt.sequence),
    receipts: receipts.length > 2_048 ? receipts.slice(-2_048) : receipts,
  };
}

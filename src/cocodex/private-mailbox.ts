import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";
import { z } from "zod";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import { renameAtomicFile } from "../config";

const privateMailboxReceiptSchema = z.object({
  messageId: z.uuid(),
  sequence: z.number().int().positive(),
}).strict();

const privateMailboxDeferredMessageSchema = z.object({
  sequence: z.number().int().positive(),
  messageId: z.uuid(),
  senderDeviceId: z.uuid(),
  recipientDeviceId: z.uuid(),
  ciphertext: z.string().min(64).max(96_000).regex(/^[A-Za-z0-9_-]+$/),
  clientCreatedAt: z.iso.datetime(),
  acceptedAt: z.iso.datetime(),
}).strict();

const privateMailboxRemoteReceiptSchema = z.object({
  sequence: z.number().int().positive(),
  messageId: z.uuid(),
  senderDeviceId: z.uuid(),
  recipientDeviceId: z.uuid(),
  receipt: z.enum(["delivered", "read"]),
  acceptedAt: z.iso.datetime(),
}).strict();

const privateMailboxFileSchema = z.object({
  version: z.literal(1),
  deviceId: z.uuid(),
  cursor: z.number().int().nonnegative(),
  receipts: z.array(privateMailboxReceiptSchema).max(2_048),
  deferred: z.array(privateMailboxDeferredMessageSchema).max(256).default([]),
  receiptCursor: z.number().int().nonnegative().default(0),
  remoteReceipts: z.array(privateMailboxRemoteReceiptSchema).max(2_048).default([]),
}).strict();

export interface PrivateMailboxMessage {
  sequence: number;
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  ciphertext: string;
  clientCreatedAt: string;
  acceptedAt: string;
}

export interface PrivateMailboxReceipt {
  messageId: string;
  sequence: number;
}

export interface PrivateMailboxRemoteReceipt {
  sequence: number;
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  receipt: "delivered" | "read";
  acceptedAt: string;
}

export interface PrivateMailboxState {
  version: 1;
  deviceId: string;
  cursor: number;
  receipts: PrivateMailboxReceipt[];
  deferred: PrivateMailboxMessage[];
  receiptCursor: number;
  remoteReceipts: PrivateMailboxRemoteReceipt[];
}

export function emptyPrivateMailbox(deviceId: string): PrivateMailboxState {
  return { version: 1, deviceId, cursor: 0, receipts: [], deferred: [], receiptCursor: 0, remoteReceipts: [] };
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
  renameAtomicFile(temporary, path);
  hardenSecretPath(path, { required: true });
}

export function hasPrivateMailboxReceipt(state: PrivateMailboxState, messageId: string): boolean {
  return state.receipts.some(receipt => receipt.messageId === messageId);
}

export function recordPrivateMailboxReceipt(
  state: PrivateMailboxState,
  receipt: PrivateMailboxReceipt,
): PrivateMailboxState {
  const deferred = state.deferred.filter(message => message.messageId !== receipt.messageId);
  if (hasPrivateMailboxReceipt(state, receipt.messageId)) {
    return deferred.length === state.deferred.length ? state : { ...state, deferred };
  }
  const receipts = [...state.receipts, receipt];
  return {
    ...state,
    cursor: Math.max(state.cursor, receipt.sequence),
    receipts: receipts.length > 2_048 ? receipts.slice(-2_048) : receipts,
    deferred,
  };
}

/**
 * Advance the server cursor without acknowledging a message that could not
 * yet be opened. The protected local mailbox keeps the ciphertext so a later
 * trust/key update can retry it without asking the server to redeliver it.
 */
export function deferPrivateMailboxMessage(
  state: PrivateMailboxState,
  message: PrivateMailboxMessage,
): PrivateMailboxState {
  if (hasPrivateMailboxReceipt(state, message.messageId)) return state;
  const deferred = [...state.deferred.filter(item => item.messageId !== message.messageId), message];
  return {
    ...state,
    cursor: Math.max(state.cursor, message.sequence),
    deferred: deferred.length > 256 ? deferred.slice(-256) : deferred,
  };
}

/** Store sender-visible delivery/read state with an independent cursor. */
export function recordPrivateMailboxRemoteReceipt(
  state: PrivateMailboxState,
  receipt: PrivateMailboxRemoteReceipt,
): PrivateMailboxState {
  const existing = state.remoteReceipts.find(item => item.sequence === receipt.sequence);
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(receipt)) {
      throw new Error("Private receipt sequence was reused with different content");
    }
    return state.receiptCursor >= receipt.sequence ? state : { ...state, receiptCursor: Math.max(state.receiptCursor, receipt.sequence) };
  }
  const remoteReceipts = [...state.remoteReceipts, receipt];
  return {
    ...state,
    receiptCursor: Math.max(state.receiptCursor, receipt.sequence),
    remoteReceipts: remoteReceipts.length > 2_048 ? remoteReceipts.slice(-2_048) : remoteReceipts,
  };
}

import { createPublicKey, verify } from "node:crypto";
import type { Database } from "bun:sqlite";
import {
  canonicalEd25519PublicKey,
  sharedChatCreationSigningTranscript,
  sharedChatSchema,
  type SharedChat,
} from "../../../packages/cocodex-protocol/src/index.ts";
import { requireProjectMembership } from "./shared-state";

const MAX_CLOCK_SKEW_MS = 60_000;
const MAX_CREATE_LIFETIME_MS = 5 * 60_000;
const MAX_CHATS_PER_PROJECT = 64;

interface SharedChatRow {
  id: string;
  projectId: string;
  title: string;
  createdByDeviceId: string;
  state: "active" | "archived";
  creationNonce: string | null;
  createdAt: string;
  updatedAt: string;
}

function fromRow(row: SharedChatRow): SharedChat {
  return sharedChatSchema.parse({
    id: row.id,
    projectId: row.projectId,
    title: row.title,
    createdByDeviceId: row.createdByDeviceId,
    state: row.state,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

function readSharedChat(db: Database, chatId: string): SharedChatRow | null {
  return db.query(`
    SELECT id, project_id AS projectId, title,
      created_by_device_id AS createdByDeviceId, state,
      creation_nonce AS creationNonce, created_at AS createdAt, updated_at AS updatedAt
    FROM shared_chats WHERE id = ?
  `).get(chatId) as SharedChatRow | null;
}

export function requireSharedChat(
  db: Database,
  projectId: string,
  chatId: string,
  deviceId: string,
  options: { allowArchived?: boolean } = {},
): SharedChat {
  requireProjectMembership(db, projectId, deviceId);
  let row = readSharedChat(db, chatId);
  if (!row && chatId === projectId) {
    const project = db.query(`
      SELECT created_by_device_id AS ownerDeviceId, created_at AS createdAt
      FROM projects WHERE id = ?
    `).get(projectId) as { ownerDeviceId: string; createdAt: string } | null;
    if (project) {
      db.query(`
        INSERT OR IGNORE INTO shared_chats (
          id, project_id, title, created_by_device_id, state,
          creation_nonce, created_at, updated_at
        ) VALUES (?, ?, 'General', ?, 'active', NULL, ?, ?)
      `).run(projectId, projectId, project.ownerDeviceId, project.createdAt, project.createdAt);
      row = readSharedChat(db, chatId);
    }
  }
  if (!row || row.projectId !== projectId) throw new Error("Shared chat was not found in this project");
  if (!options.allowArchived && row.state !== "active") throw new Error("Shared chat is archived");
  return fromRow(row);
}

export function generalSharedChat(db: Database, projectId: string): SharedChat {
  const row = readSharedChat(db, projectId);
  if (!row || row.projectId !== projectId) throw new Error("Project General chat is missing");
  return fromRow(row);
}

export function insertGeneralSharedChat(
  db: Database,
  projectId: string,
  ownerDeviceId: string,
  timestamp: string,
): SharedChat {
  db.query(`
    INSERT INTO shared_chats (
      id, project_id, title, created_by_device_id, state,
      creation_nonce, created_at, updated_at
    ) VALUES (?, ?, 'General', ?, 'active', NULL, ?, ?)
  `).run(projectId, projectId, ownerDeviceId, timestamp, timestamp);
  return generalSharedChat(db, projectId);
}

export function listSharedChats(
  db: Database,
  projectId: string,
  deviceId: string,
): SharedChat[] {
  requireProjectMembership(db, projectId, deviceId);
  const rows = db.query(`
    SELECT id, project_id AS projectId, title,
      created_by_device_id AS createdByDeviceId, state,
      creation_nonce AS creationNonce, created_at AS createdAt, updated_at AS updatedAt
    FROM shared_chats
    WHERE project_id = ?
    ORDER BY CASE WHEN id = project_id THEN 0 ELSE 1 END, created_at, id
    LIMIT ?
  `).all(projectId, MAX_CHATS_PER_PROJECT) as SharedChatRow[];
  return rows.map(fromRow);
}

export interface CreateSharedChatInput {
  projectId: string;
  chatId: string;
  title: string;
  creatorDeviceId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export function createSharedChat(
  db: Database,
  input: CreateSharedChatInput,
  now = new Date(),
): { chat: SharedChat; created: boolean } {
  requireProjectMembership(db, input.projectId, input.creatorDeviceId);
  const title = input.title.trim();
  if (title.length < 1 || title.length > 120) throw new Error("Shared chat title must be 1-120 characters");
  const issuedAt = Date.parse(input.issuedAt);
  const expiresAt = Date.parse(input.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) throw new Error("Invalid shared-chat creation lifetime");
  if (issuedAt > now.getTime() + MAX_CLOCK_SKEW_MS
    || expiresAt <= now.getTime()
    || expiresAt - issuedAt > MAX_CREATE_LIFETIME_MS) {
    throw new Error("Shared-chat creation is expired or lives too long");
  }
  const device = db.query(`
    SELECT public_key_pem AS publicKeyPem
    FROM devices WHERE id = ? AND status = 'approved'
  `).get(input.creatorDeviceId) as { publicKeyPem: string } | null;
  if (!device) throw new Error("Approved shared-chat creator key was not found");
  let creatorKey: string;
  try { creatorKey = canonicalEd25519PublicKey(device.publicKeyPem); }
  catch { throw new Error("Shared-chat creator key is invalid"); }
  let valid = false;
  try {
    valid = verify(
      null,
      sharedChatCreationSigningTranscript({
        projectId: input.projectId,
        chatId: input.chatId,
        title,
        creatorDeviceId: input.creatorDeviceId,
        nonce: input.nonce,
        issuedAt: input.issuedAt,
        expiresAt: input.expiresAt,
      }),
      createPublicKey(creatorKey),
      Buffer.from(input.signature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Shared-chat creation signature is invalid");

  return db.transaction(() => {
    const existing = readSharedChat(db, input.chatId);
    if (existing) {
      if (existing.projectId !== input.projectId
        || existing.title !== title
        || existing.createdByDeviceId !== input.creatorDeviceId
        || existing.creationNonce !== input.nonce) {
        throw new Error("Shared chat ID was already used with different content");
      }
      return { chat: fromRow(existing), created: false };
    }
    const replay = db.query(`
      SELECT id FROM shared_chats
      WHERE creation_nonce = ?
    `).get(input.nonce) as { id: string } | null;
    if (replay) throw new Error("Shared-chat creation nonce was already used");
    const count = db.query(`
      SELECT COUNT(*) AS count FROM shared_chats WHERE project_id = ?
    `).get(input.projectId) as { count: number };
    if (count.count >= MAX_CHATS_PER_PROJECT) throw new Error("Shared-chat project limit reached");
    const timestamp = now.toISOString();
    db.query(`
      INSERT INTO shared_chats (
        id, project_id, title, created_by_device_id, state,
        creation_nonce, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
    `).run(
      input.chatId,
      input.projectId,
      title,
      input.creatorDeviceId,
      input.nonce,
      timestamp,
      timestamp,
    );
    return { chat: fromRow(readSharedChat(db, input.chatId)!), created: true };
  }).immediate();
}

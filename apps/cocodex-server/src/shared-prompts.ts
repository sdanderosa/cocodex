import type { Database } from "bun:sqlite";
import * as Y from "yjs";
import { requireProjectMembership } from "./shared-state";

const MAX_PROMPT_UPDATE_BYTES = 128 * 1024;
const MAX_PROMPT_STATE_BYTES = 512 * 1024;
const MAX_PROMPT_TEXT_LENGTH = 32_768;

function decodeUpdate(value: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_PROMPT_UPDATE_BYTES) {
    throw new Error("Shared prompt update is empty or too large");
  }
  return bytes;
}

function loadDocument(db: Database, projectId: string): Y.Doc {
  const row = db.query(`SELECT yjs_state AS state FROM shared_prompt_documents WHERE project_id = ?`)
    .get(projectId) as { state: Uint8Array } | null;
  const document = new Y.Doc();
  if (row) Y.applyUpdate(document, new Uint8Array(row.state));
  return document;
}

export function sharedPromptSnapshot(db: Database, projectId: string, deviceId: string): string {
  requireProjectMembership(db, projectId, deviceId);
  return Buffer.from(Y.encodeStateAsUpdate(loadDocument(db, projectId))).toString("base64");
}

export function applySharedPromptUpdate(
  db: Database,
  projectId: string,
  deviceId: string,
  updateId: string,
  encodedUpdate: string,
  now = new Date(),
): { update: string; created: boolean } {
  requireProjectMembership(db, projectId, deviceId);
  const update = decodeUpdate(encodedUpdate);
  return db.transaction(() => {
    const existing = db.query(`SELECT project_id AS projectId, sender_device_id AS senderDeviceId,
      update_blob AS updateBlob FROM shared_prompt_updates WHERE update_id = ?`).get(updateId) as {
        projectId: string; senderDeviceId: string; updateBlob: Uint8Array;
      } | null;
    if (existing) {
      if (existing.projectId !== projectId || existing.senderDeviceId !== deviceId
        || !Buffer.from(existing.updateBlob).equals(Buffer.from(update))) {
        throw new Error("Shared prompt update ID was reused with different content");
      }
      return { update: encodedUpdate, created: false };
    }
    const document = loadDocument(db, projectId);
    try { Y.applyUpdate(document, update); }
    catch { throw new Error("Shared prompt update is malformed"); }
    if (document.getText("prompt").length > MAX_PROMPT_TEXT_LENGTH) {
      throw new Error("Shared prompt is too large");
    }
    const state = Y.encodeStateAsUpdate(document);
    if (state.byteLength > MAX_PROMPT_STATE_BYTES) throw new Error("Shared prompt state is too large");
    db.query(`INSERT INTO shared_prompt_updates
      (update_id, project_id, chat_id, sender_device_id, update_blob, accepted_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(updateId, projectId, projectId, deviceId, update, now.toISOString());
    db.query(`INSERT INTO shared_prompt_documents (project_id, chat_id, yjs_state, updated_at)
      VALUES (?, ?, ?, ?) ON CONFLICT(project_id, chat_id) DO UPDATE SET yjs_state = excluded.yjs_state,
      updated_at = excluded.updated_at`).run(projectId, projectId, state, now.toISOString());
    return { update: encodedUpdate, created: true };
  }).immediate();
}

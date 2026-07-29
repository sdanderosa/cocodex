export interface Migration {
  version: number;
  sql: string;
}

export const migrations: readonly Migration[] = [
  {
    version: 1,
    sql: `
CREATE TABLE invitations (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  public_key_pem TEXT NOT NULL UNIQUE,
  fingerprint TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'revoked')),
  invitation_id TEXT NOT NULL REFERENCES invitations(id),
  enrolled_at TEXT NOT NULL,
  approved_at TEXT,
  revoked_at TEXT
);
CREATE TABLE enrollment_challenges (
  id TEXT PRIMARY KEY,
  invitation_id TEXT NOT NULL REFERENCES invitations(id),
  challenge TEXT NOT NULL UNIQUE,
  public_key_pem TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_by_device_id TEXT NOT NULL REFERENCES devices(id),
  created_at TEXT NOT NULL
);
CREATE TABLE project_members (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id),
  role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
  joined_at TEXT NOT NULL,
  PRIMARY KEY (project_id, device_id)
);
CREATE TABLE chat_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL UNIQUE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id),
  content TEXT NOT NULL,
  client_created_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL
);
CREATE INDEX chat_events_project_sequence ON chat_events(project_id, sequence);
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  actor_device_id TEXT,
  subject_id TEXT,
  occurred_at TEXT NOT NULL,
  details_json TEXT NOT NULL
);`,
  },
  {
    version: 2,
    sql: `
CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  host_device_id TEXT NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  FOREIGN KEY (project_id, host_device_id)
    REFERENCES project_members(project_id, device_id)
);
CREATE TABLE agent_tasks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  requester_device_id TEXT NOT NULL REFERENCES devices(id),
  target_device_id TEXT NOT NULL REFERENCES devices(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  prompt TEXT NOT NULL,
  nonce TEXT NOT NULL UNIQUE,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  requester_signature TEXT NOT NULL,
  server_signature TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  accepted_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE TABLE agent_task_events (
  task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
  chat_sequence INTEGER NOT NULL UNIQUE REFERENCES chat_events(sequence) ON DELETE CASCADE,
  final INTEGER NOT NULL CHECK (final IN (0, 1)),
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  PRIMARY KEY (task_id, chat_sequence)
);
CREATE INDEX agent_tasks_target_status ON agent_tasks(target_device_id, status, accepted_at);`,
  },
  {
    version: 3,
    sql: `
ALTER TABLE devices ADD COLUMN messaging_public_key_pem TEXT;
CREATE TABLE private_messages (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL UNIQUE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id),
  recipient_device_id TEXT NOT NULL REFERENCES devices(id),
  ciphertext TEXT NOT NULL,
  client_created_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL
);
CREATE INDEX private_messages_recipient_sequence
  ON private_messages(recipient_device_id, sequence);
CREATE INDEX private_messages_sender_sequence
  ON private_messages(sender_device_id, sequence);`,
  },
  {
    version: 4,
    sql: `
CREATE TABLE shared_prompt_documents (
  project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  yjs_state BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE shared_prompt_updates (
  update_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id),
  update_blob BLOB NOT NULL,
  accepted_at TEXT NOT NULL
);
CREATE INDEX shared_prompt_updates_project_time
  ON shared_prompt_updates(project_id, accepted_at);`,
  },
  {
    version: 5,
    sql: `
CREATE TABLE server_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO server_state (key, value) VALUES ('epoch', '1');`,
  },
  {
    version: 6,
    sql: `
ALTER TABLE agent_tasks ADD COLUMN dependencies_json TEXT NOT NULL DEFAULT '[]';
CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  task_id TEXT REFERENCES agent_tasks(id) ON DELETE SET NULL,
  author_device_id TEXT NOT NULL REFERENCES devices(id),
  type TEXT NOT NULL CHECK (type IN ('finding', 'plan', 'decision', 'api-contract', 'schema', 'code-change', 'commit', 'diff', 'test-result', 'review', 'handoff', 'documentation', 'failure-report', 'browser-result', 'final-result')),
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  content TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft', 'ready', 'accepted', 'rejected', 'superseded', 'integrated')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX artifacts_project_created ON artifacts(project_id, created_at);`,
  },
  {
    version: 7,
    sql: `
CREATE TABLE private_message_replays (
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ciphertext_hash TEXT NOT NULL,
  first_message_id TEXT NOT NULL REFERENCES private_messages(message_id) ON DELETE CASCADE,
  PRIMARY KEY (sender_device_id, recipient_device_id, ciphertext_hash)
);`,
  },
  {
    version: 8,
    sql: `
CREATE TABLE shared_project_context (
  project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  final_goal TEXT NOT NULL DEFAULT '',
  context_json TEXT NOT NULL DEFAULT '{}',
  revision INTEGER NOT NULL DEFAULT 0,
  updated_by_device_id TEXT REFERENCES devices(id),
  updated_at TEXT NOT NULL
  );`,
  },
  {
    version: 9,
    sql: `
CREATE TABLE usage_reports (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  report_json TEXT NOT NULL,
  report_signature TEXT NOT NULL,
  revision INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL
);
CREATE INDEX usage_reports_updated ON usage_reports(updated_at);`,
  },
  {
    version: 10,
    sql: `
ALTER TABLE devices ADD COLUMN project_wrap_public_key_pem TEXT;`,
  },
  {
    version: 11,
    sql: `
CREATE TABLE project_key_envelopes (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
  recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project_id, key_epoch, recipient_device_id)
);
CREATE INDEX project_key_envelopes_recipient
  ON project_key_envelopes(recipient_device_id, project_id, key_epoch);
CREATE TABLE encrypted_project_context (
  project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
  record_id TEXT NOT NULL,
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
  );`,
  },
  {
    version: 12,
    sql: `
CREATE TABLE project_key_epochs (
  project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  current_epoch INTEGER NOT NULL CHECK (current_epoch > 0),
  last_rotation_id TEXT UNIQUE,
  updated_by_device_id TEXT REFERENCES devices(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO project_key_epochs (
  project_id, current_epoch, last_rotation_id, updated_by_device_id,
  created_at, updated_at
)
SELECT project_id, MAX(key_epoch), NULL, NULL, MIN(created_at), MAX(updated_at)
FROM project_key_envelopes
GROUP BY project_id;`,
  },
  {
    version: 13,
    sql: `
CREATE TABLE project_chat_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL UNIQUE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  client_created_at TEXT NOT NULL,
  accepted_at TEXT NOT NULL
);
CREATE INDEX project_chat_events_project_sequence
  ON project_chat_events(project_id, sequence);`,
  },
  {
    version: 14,
    sql: `
CREATE TABLE project_prompt_updates (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  update_id TEXT NOT NULL UNIQUE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  accepted_at TEXT NOT NULL
);
CREATE INDEX project_prompt_updates_project_sequence
  ON project_prompt_updates(project_id, sequence);`,
  },
  {
    version: 15,
    sql: `
CREATE TABLE project_artifacts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  task_id TEXT REFERENCES agent_tasks(id) ON DELETE SET NULL,
  author_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX project_artifacts_project_created
  ON project_artifacts(project_id, created_at, id);`,
  },
  {
    version: 16,
    sql: `
ALTER TABLE agent_tasks ADD COLUMN prompt_envelope_json TEXT;
ALTER TABLE project_chat_events ADD COLUMN task_id TEXT;
ALTER TABLE project_chat_events ADD COLUMN final INTEGER NOT NULL DEFAULT 0 CHECK (final IN (0, 1));
ALTER TABLE project_chat_events ADD COLUMN status TEXT NOT NULL DEFAULT 'chat';
CREATE INDEX project_chat_events_task ON project_chat_events(task_id, sequence);`,
  },
  {
    version: 17,
    sql: `
INSERT OR IGNORE INTO server_state (key, value) VALUES ('authority_status', 'active');
INSERT OR IGNORE INTO server_state (key, value) VALUES ('identity_fingerprint', '');`,
  },
  {
    version: 18,
    sql: `
ALTER TABLE project_key_epochs ADD COLUMN rotation_required INTEGER NOT NULL DEFAULT 0 CHECK (rotation_required IN (0, 1));`,
  },
  {
    version: 19,
    sql: `
ALTER TABLE agent_tasks ADD COLUMN private_share_message_id TEXT;
CREATE INDEX agent_tasks_private_share ON agent_tasks(private_share_message_id);`,
  },
  {
    version: 20,
    sql: `
ALTER TABLE agent_tasks ADD COLUMN input_artifact_ids_json TEXT NOT NULL DEFAULT '[]';`,
  },
  {
    version: 21,
    sql: `
ALTER TABLE agent_tasks ADD COLUMN workspace_mode TEXT
  CHECK (workspace_mode IN ('shared', 'git-worktree'));
ALTER TABLE agent_tasks ADD COLUMN workspace_ref TEXT;
ALTER TABLE agent_tasks ADD COLUMN worktree_branch TEXT;
ALTER TABLE agent_tasks ADD COLUMN base_commit TEXT;
ALTER TABLE agent_tasks ADD COLUMN merge_target TEXT;
ALTER TABLE agent_tasks ADD COLUMN execution_started_at TEXT;
ALTER TABLE agent_tasks ADD COLUMN execution_signature TEXT;`,
  },
  {
    version: 22,
    sql: `
ALTER TABLE agents ADD COLUMN primary_model TEXT NOT NULL DEFAULT 'gpt-5.6-sol';
ALTER TABLE agents ADD COLUMN primary_effort TEXT NOT NULL DEFAULT 'medium'
  CHECK (primary_effort IN ('minimal', 'low', 'medium', 'high', 'xhigh', 'max'));
ALTER TABLE agents ADD COLUMN coagent_model TEXT;
ALTER TABLE agents ADD COLUMN coagent_effort TEXT
  CHECK (coagent_effort IS NULL OR coagent_effort IN ('minimal', 'low', 'medium', 'high', 'xhigh', 'max'));
ALTER TABLE agents ADD COLUMN max_concurrent_coagents INTEGER NOT NULL DEFAULT 0
  CHECK (max_concurrent_coagents BETWEEN 0 AND 8);
CREATE TRIGGER agents_runtime_definition_insert
BEFORE INSERT ON agents
WHEN NOT (
  (NEW.max_concurrent_coagents = 0 AND NEW.coagent_model IS NULL AND NEW.coagent_effort IS NULL)
  OR
  (NEW.max_concurrent_coagents > 0 AND NEW.coagent_model IS NOT NULL AND NEW.coagent_effort IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'inconsistent agent runtime definition');
END;
CREATE TRIGGER agents_runtime_definition_update
BEFORE UPDATE OF coagent_model, coagent_effort, max_concurrent_coagents ON agents
WHEN NOT (
  (NEW.max_concurrent_coagents = 0 AND NEW.coagent_model IS NULL AND NEW.coagent_effort IS NULL)
  OR
  (NEW.max_concurrent_coagents > 0 AND NEW.coagent_model IS NOT NULL AND NEW.coagent_effort IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'inconsistent agent runtime definition');
END;`,
  },
  {
    version: 23,
    sql: `
CREATE TABLE project_file_references (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL REFERENCES project_artifacts(id) ON DELETE CASCADE,
  host_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  author_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX project_file_references_project_created
  ON project_file_references(project_id, created_at, id);
CREATE INDEX project_file_references_artifact_created
  ON project_file_references(artifact_id, created_at, id);`,
  },
  {
    version: 24,
    sql: `
CREATE TABLE agents_v24 (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  host_device_id TEXT NOT NULL REFERENCES devices(id),
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  primary_model TEXT NOT NULL DEFAULT 'gpt-5.6-sol',
  primary_effort TEXT NOT NULL DEFAULT 'medium'
    CHECK (primary_effort IN ('minimal', 'low', 'medium', 'high', 'xhigh', 'max')),
  coagent_model TEXT,
  coagent_effort TEXT
    CHECK (coagent_effort IS NULL OR coagent_effort IN ('minimal', 'low', 'medium', 'high', 'xhigh', 'max')),
  max_concurrent_coagents INTEGER NOT NULL DEFAULT 0
    CHECK (max_concurrent_coagents BETWEEN 0 AND 8)
);
INSERT INTO agents_v24 (
  id, project_id, host_device_id, name, enabled, created_at,
  primary_model, primary_effort, coagent_model, coagent_effort, max_concurrent_coagents
)
SELECT
  id, project_id, host_device_id, name, enabled, created_at,
  primary_model, primary_effort, coagent_model, coagent_effort, max_concurrent_coagents
FROM agents;
DROP TABLE agents;
ALTER TABLE agents_v24 RENAME TO agents;
CREATE TRIGGER agents_runtime_definition_insert
BEFORE INSERT ON agents
WHEN NOT (
  (NEW.max_concurrent_coagents = 0 AND NEW.coagent_model IS NULL AND NEW.coagent_effort IS NULL)
  OR
  (NEW.max_concurrent_coagents > 0 AND NEW.coagent_model IS NOT NULL AND NEW.coagent_effort IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'inconsistent agent runtime definition');
END;
CREATE TRIGGER agents_runtime_definition_update
BEFORE UPDATE OF coagent_model, coagent_effort, max_concurrent_coagents ON agents
WHEN NOT (
  (NEW.max_concurrent_coagents = 0 AND NEW.coagent_model IS NULL AND NEW.coagent_effort IS NULL)
  OR
  (NEW.max_concurrent_coagents > 0 AND NEW.coagent_model IS NOT NULL AND NEW.coagent_effort IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'inconsistent agent runtime definition');
END;`,
  },
  {
    version: 25,
    sql: `
ALTER TABLE devices ADD COLUMN device_key_certificate TEXT;
CREATE TABLE project_member_removal_rotations (
  rotation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  owner_device_id TEXT NOT NULL REFERENCES devices(id),
  removed_device_id TEXT NOT NULL REFERENCES devices(id),
  key_epoch INTEGER NOT NULL CHECK (key_epoch > 1),
  envelopes_json TEXT NOT NULL,
  cancelled_tasks_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(project_id, key_epoch)
);
CREATE INDEX project_member_removal_rotations_project
  ON project_member_removal_rotations(project_id, key_epoch);`,
  },
  {
    version: 26,
    sql: `
CREATE TABLE private_message_receipts (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL REFERENCES private_messages(message_id) ON DELETE CASCADE,
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  receipt TEXT NOT NULL CHECK (receipt IN ('delivered', 'read')),
  accepted_at TEXT NOT NULL,
  UNIQUE(message_id, recipient_device_id, receipt)
);
CREATE INDEX private_message_receipts_sender_sequence
  ON private_message_receipts(sender_device_id, sequence);`,
  },
  {
    version: 27,
    sql: `
CREATE TABLE project_invitations (
  invitation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  server_fingerprint TEXT NOT NULL,
  owner_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
  envelope_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  nonce TEXT NOT NULL,
  owner_signature TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled', 'expired')),
  response_signature TEXT,
  responded_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX project_invitations_pending_recipient
  ON project_invitations(project_id, recipient_device_id)
  WHERE status = 'pending';
CREATE INDEX project_invitations_recipient_status
  ON project_invitations(recipient_device_id, status, expires_at, created_at);
CREATE INDEX project_invitations_owner_status
  ON project_invitations(owner_device_id, status, created_at);
CREATE TABLE encrypted_project_creations (
  creation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  owner_device_id TEXT NOT NULL REFERENCES devices(id),
  envelopes_json TEXT NOT NULL,
  owner_signature TEXT NOT NULL,
  created_at TEXT NOT NULL
);`,
  },
  {
    version: 28,
    sql: `
CREATE TABLE shared_chats (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK (length(trim(title)) BETWEEN 1 AND 120),
  created_by_device_id TEXT NOT NULL REFERENCES devices(id),
  state TEXT NOT NULL CHECK (state IN ('active', 'archived')),
  creation_nonce TEXT UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, id)
);
INSERT INTO shared_chats (
  id, project_id, title, created_by_device_id, state, creation_nonce, created_at, updated_at
)
SELECT id, id, 'General', created_by_device_id, 'active', NULL, created_at, created_at
FROM projects;
CREATE INDEX shared_chats_project_state
  ON shared_chats(project_id, state, created_at, id);

ALTER TABLE chat_events ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE chat_events SET chat_id = project_id;
CREATE INDEX chat_events_chat_sequence
  ON chat_events(project_id, chat_id, sequence);

CREATE TABLE shared_prompt_documents_v28 (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  chat_id TEXT NOT NULL REFERENCES shared_chats(id) ON DELETE CASCADE,
  yjs_state BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project_id, chat_id),
  FOREIGN KEY (project_id, chat_id) REFERENCES shared_chats(project_id, id)
);
INSERT INTO shared_prompt_documents_v28 (project_id, chat_id, yjs_state, updated_at)
SELECT project_id, project_id, yjs_state, updated_at FROM shared_prompt_documents;
DROP TABLE shared_prompt_documents;
ALTER TABLE shared_prompt_documents_v28 RENAME TO shared_prompt_documents;

ALTER TABLE shared_prompt_updates ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE shared_prompt_updates SET chat_id = project_id;
CREATE INDEX shared_prompt_updates_chat_time
  ON shared_prompt_updates(project_id, chat_id, accepted_at);

ALTER TABLE agent_tasks ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE agent_tasks SET chat_id = project_id;
CREATE INDEX agent_tasks_project_chat_status
  ON agent_tasks(project_id, chat_id, status, accepted_at);

ALTER TABLE artifacts ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE artifacts SET chat_id = project_id;
CREATE INDEX artifacts_project_chat_created
  ON artifacts(project_id, chat_id, created_at, id);

CREATE TABLE shared_project_context_v28 (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  chat_id TEXT NOT NULL REFERENCES shared_chats(id) ON DELETE CASCADE,
  final_goal TEXT NOT NULL DEFAULT '',
  context_json TEXT NOT NULL DEFAULT '{}',
  revision INTEGER NOT NULL DEFAULT 0,
  updated_by_device_id TEXT REFERENCES devices(id),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project_id, chat_id),
  FOREIGN KEY (project_id, chat_id) REFERENCES shared_chats(project_id, id)
);
INSERT INTO shared_project_context_v28 (
  project_id, chat_id, final_goal, context_json, revision, updated_by_device_id, updated_at
)
SELECT project_id, project_id, final_goal, context_json, revision, updated_by_device_id, updated_at
FROM shared_project_context;
DROP TABLE shared_project_context;
ALTER TABLE shared_project_context_v28 RENAME TO shared_project_context;

CREATE TABLE encrypted_project_context_v28 (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  chat_id TEXT NOT NULL REFERENCES shared_chats(id) ON DELETE CASCADE,
  key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
  record_id TEXT NOT NULL,
  sender_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  envelope_json TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project_id, chat_id),
  FOREIGN KEY (project_id, chat_id) REFERENCES shared_chats(project_id, id)
);
INSERT INTO encrypted_project_context_v28 (
  project_id, chat_id, key_epoch, record_id, sender_device_id,
  envelope_json, revision, created_at, updated_at
)
SELECT project_id, project_id, key_epoch, record_id, sender_device_id,
  envelope_json, revision, created_at, updated_at
FROM encrypted_project_context;
DROP TABLE encrypted_project_context;
ALTER TABLE encrypted_project_context_v28 RENAME TO encrypted_project_context;

ALTER TABLE project_chat_events ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE project_chat_events SET chat_id = project_id;
CREATE INDEX project_chat_events_chat_sequence
  ON project_chat_events(project_id, chat_id, sequence);

ALTER TABLE project_prompt_updates ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE project_prompt_updates SET chat_id = project_id;
CREATE INDEX project_prompt_updates_chat_sequence
  ON project_prompt_updates(project_id, chat_id, sequence);

ALTER TABLE project_artifacts ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE project_artifacts SET chat_id = project_id;
CREATE INDEX project_artifacts_chat_created
  ON project_artifacts(project_id, chat_id, created_at, id);

ALTER TABLE project_file_references ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''
  REFERENCES shared_chats(id);
UPDATE project_file_references
SET chat_id = (
  SELECT project_artifacts.chat_id
  FROM project_artifacts
  WHERE project_artifacts.id = project_file_references.artifact_id
);
CREATE INDEX project_file_references_chat_created
  ON project_file_references(project_id, chat_id, created_at, id);`,
  },
  {
    version: 29,
    sql: `
CREATE TABLE device_revocation_project_incidents (
  incident_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  revoked_device_id TEXT NOT NULL REFERENCES devices(id),
  recovery_owner_device_id TEXT REFERENCES devices(id),
  current_epoch INTEGER NOT NULL CHECK (current_epoch > 0),
  cancelled_tasks_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('unresolved', 'resolved')),
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  resolution_rotation_id TEXT,
  UNIQUE(project_id, revoked_device_id),
  CHECK (
    (status = 'unresolved' AND resolved_at IS NULL AND resolution_rotation_id IS NULL)
    OR
    (status = 'resolved' AND resolved_at IS NOT NULL AND resolution_rotation_id IS NOT NULL)
  )
);
CREATE INDEX device_revocation_project_incidents_recovery
  ON device_revocation_project_incidents(recovery_owner_device_id, status, created_at);
CREATE INDEX device_revocation_project_incidents_project
  ON device_revocation_project_incidents(project_id, status, created_at);`,
  },
  {
    version: 30,
    sql: `
CREATE TABLE project_lock_state (
  project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('active', 'locked')),
  revision INTEGER NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
  locked_at TEXT,
  locked_by_device_id TEXT REFERENCES devices(id),
  reason TEXT,
  updated_at TEXT NOT NULL,
  CHECK (
    (state = 'active' AND locked_at IS NULL AND locked_by_device_id IS NULL AND reason IS NULL)
    OR
    (state = 'locked' AND locked_at IS NOT NULL AND locked_by_device_id IS NOT NULL
      AND length(trim(reason)) BETWEEN 1 AND 512)
  )
);
INSERT INTO project_lock_state (
  project_id, state, revision, locked_at, locked_by_device_id, reason, updated_at
)
SELECT id, 'active', 0, NULL, NULL, NULL, created_at FROM projects;

CREATE TABLE project_lock_transitions (
  operation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  actor_device_id TEXT NOT NULL REFERENCES devices(id),
  action TEXT NOT NULL CHECK (action IN ('lock', 'unlock')),
  expected_revision INTEGER NOT NULL CHECK (expected_revision BETWEEN 0 AND 2147483646),
  resulting_revision INTEGER NOT NULL CHECK (resulting_revision = expected_revision + 1),
  reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 512),
  server_fingerprint TEXT NOT NULL,
  server_epoch INTEGER NOT NULL CHECK (server_epoch > 0),
  nonce TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  signature TEXT NOT NULL,
  cancelled_tasks_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(actor_device_id, nonce)
);
CREATE INDEX project_lock_transitions_project_revision
  ON project_lock_transitions(project_id, resulting_revision);

CREATE TABLE project_lock_task_cancellations (
  operation_id TEXT NOT NULL REFERENCES project_lock_transitions(operation_id) ON DELETE CASCADE,
  task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target_device_id TEXT NOT NULL REFERENCES devices(id),
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (operation_id, task_id)
);
CREATE INDEX project_lock_task_cancellations_target
  ON project_lock_task_cancellations(target_device_id, created_at);`,
  },
  {
    version: 31,
    sql: `
ALTER TABLE devices ADD COLUMN enrollment_digest TEXT;
ALTER TABLE devices ADD COLUMN enrollment_signature TEXT;
ALTER TABLE devices ADD COLUMN approval_expires_at TEXT;
ALTER TABLE devices ADD COLUMN approval_revision INTEGER NOT NULL DEFAULT 0
  CHECK (approval_revision BETWEEN 0 AND 1);
ALTER TABLE devices ADD COLUMN approved_by_device_id TEXT;
ALTER TABLE devices ADD COLUMN approval_operation_id TEXT;

UPDATE devices
SET approval_expires_at = datetime(enrolled_at, '+15 minutes')
WHERE status = 'pending' AND approval_expires_at IS NULL;

-- A pre-v31 pending row has no immutable enrollment attestation and therefore
-- cannot be safely approved under the signed approval protocol.
UPDATE devices
SET status = 'revoked', revoked_at = datetime('now'), approval_revision = 1
WHERE status = 'pending' AND enrollment_digest IS NULL;

INSERT OR IGNORE INTO server_state (key, value)
VALUES (
  'device_bootstrap_consumed',
  CASE WHEN EXISTS (
    SELECT 1 FROM devices WHERE approved_at IS NOT NULL
  ) THEN '1' ELSE '0' END
);

CREATE TABLE device_approval_operations (
  operation_id TEXT PRIMARY KEY,
  target_device_id TEXT NOT NULL UNIQUE REFERENCES devices(id),
  approver_device_id TEXT NOT NULL REFERENCES devices(id),
  decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
  target_fingerprint TEXT NOT NULL,
  target_enrollment_digest TEXT NOT NULL,
  expected_revision INTEGER NOT NULL CHECK (expected_revision = 0),
  resulting_revision INTEGER NOT NULL CHECK (resulting_revision = 1),
  resulting_status TEXT NOT NULL CHECK (resulting_status IN ('approved', 'rejected')),
  server_identity_fingerprint TEXT NOT NULL,
  server_epoch INTEGER NOT NULL CHECK (server_epoch > 0),
  nonce TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  signature TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  UNIQUE(approver_device_id, nonce)
);
CREATE INDEX device_approval_operations_approver_time
  ON device_approval_operations(approver_device_id, decided_at);
CREATE INDEX devices_pending_approval_expiry
  ON devices(status, approval_expires_at, enrolled_at);`,
  },
  {
    version: 32,
    sql: `
ALTER TABLE projects ADD COLUMN state TEXT NOT NULL DEFAULT 'active'
  CHECK (state IN ('active', 'archived'));
ALTER TABLE projects ADD COLUMN lifecycle_revision INTEGER NOT NULL DEFAULT 0
  CHECK (lifecycle_revision BETWEEN 0 AND 2147483647);
ALTER TABLE projects ADD COLUMN updated_at TEXT;
ALTER TABLE projects ADD COLUMN archived_at TEXT;
UPDATE projects SET updated_at = created_at WHERE updated_at IS NULL;

CREATE TABLE project_lifecycle_operations (
  operation_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  actor_device_id TEXT NOT NULL REFERENCES devices(id),
  action TEXT NOT NULL CHECK (action IN ('rename', 'archive', 'restore', 'delete')),
  expected_revision INTEGER NOT NULL CHECK (expected_revision BETWEEN 0 AND 2147483646),
  resulting_revision INTEGER NOT NULL CHECK (resulting_revision = expected_revision + 1),
  requested_name TEXT,
  confirmation_name TEXT,
  server_fingerprint TEXT NOT NULL,
  server_epoch INTEGER NOT NULL CHECK (server_epoch > 0),
  nonce TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  signature TEXT NOT NULL,
  transition_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(actor_device_id, nonce)
);
CREATE INDEX project_lifecycle_operations_project_revision
  ON project_lifecycle_operations(project_id, resulting_revision);`,
  },
  {
    version: 33,
    sql: `
CREATE TABLE project_member_leave_requests (
  request_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id),
  server_fingerprint TEXT NOT NULL,
  server_epoch INTEGER NOT NULL CHECK (server_epoch > 0),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  nonce TEXT NOT NULL,
  signature TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
  requested_at TEXT NOT NULL,
  completed_at TEXT,
  completed_by_device_id TEXT REFERENCES devices(id),
  completion_rotation_id TEXT,
  CHECK (
    (state = 'pending' AND completed_at IS NULL AND completed_by_device_id IS NULL AND completion_rotation_id IS NULL)
    OR
    (state = 'completed' AND completed_at IS NOT NULL AND completed_by_device_id IS NOT NULL AND completion_rotation_id IS NOT NULL)
  ),
  UNIQUE(device_id, nonce)
);
CREATE UNIQUE INDEX project_member_leave_requests_pending
  ON project_member_leave_requests(project_id, device_id)
  WHERE state = 'pending';
CREATE INDEX project_member_leave_requests_project_time
  ON project_member_leave_requests(project_id, requested_at);`,
  },
  {
    version: 34,
    sql: `
CREATE TABLE project_plaintext_migrations (
  migration_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
  owner_device_id TEXT NOT NULL REFERENCES devices(id),
  snapshot_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('prepared', 'completed', 'invalidated')),
  item_count INTEGER NOT NULL CHECK (item_count BETWEEN 0 AND 10000),
  staged_count INTEGER NOT NULL DEFAULT 0 CHECK (staged_count BETWEEN 0 AND item_count),
  manifest_digest TEXT,
  owner_signature TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK (
    (state = 'prepared' AND manifest_digest IS NULL AND owner_signature IS NULL AND completed_at IS NULL)
    OR
    (state = 'completed' AND manifest_digest IS NOT NULL AND owner_signature IS NOT NULL AND completed_at IS NOT NULL)
    OR
    (state = 'invalidated' AND completed_at IS NULL)
  )
);
CREATE INDEX project_plaintext_migrations_state
  ON project_plaintext_migrations(state, updated_at);
CREATE UNIQUE INDEX project_plaintext_migrations_prepared_project
  ON project_plaintext_migrations(project_id) WHERE state = 'prepared';

CREATE TABLE project_plaintext_migration_items (
  migration_id TEXT NOT NULL REFERENCES project_plaintext_migrations(migration_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 9999),
  source_kind TEXT NOT NULL CHECK (source_kind IN ('shared-context', 'chat', 'agent-response', 'shared-prompt', 'artifact', 'task')),
  source_id TEXT NOT NULL,
  chat_id TEXT NOT NULL REFERENCES shared_chats(id) ON DELETE CASCADE,
  source_digest TEXT NOT NULL,
  inventory_json TEXT NOT NULL,
  envelope_json TEXT,
  envelope_digest TEXT,
  staged_at TEXT,
  PRIMARY KEY (migration_id, source_kind, source_id),
  UNIQUE (migration_id, ordinal),
  CHECK (
    (envelope_json IS NULL AND envelope_digest IS NULL AND staged_at IS NULL)
    OR
    (envelope_json IS NOT NULL AND envelope_digest IS NOT NULL AND staged_at IS NOT NULL)
  )
);
CREATE INDEX project_plaintext_migration_items_page
  ON project_plaintext_migration_items(migration_id, ordinal);

ALTER TABLE encrypted_project_context ADD COLUMN migration_id TEXT;
ALTER TABLE project_chat_events ADD COLUMN migration_id TEXT;
ALTER TABLE project_chat_events ADD COLUMN migrated_attributed_device_id TEXT REFERENCES devices(id);
ALTER TABLE project_prompt_updates ADD COLUMN migration_id TEXT;
ALTER TABLE project_artifacts ADD COLUMN migration_id TEXT;
ALTER TABLE project_artifacts ADD COLUMN migrated_attributed_device_id TEXT REFERENCES devices(id);
ALTER TABLE agent_tasks ADD COLUMN migration_id TEXT;
`,
  },
];

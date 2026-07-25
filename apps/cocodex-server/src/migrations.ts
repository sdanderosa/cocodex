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
];

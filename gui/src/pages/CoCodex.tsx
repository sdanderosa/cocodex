import { useCallback, useEffect, useReducer, useRef, useState, type FormEvent } from "react";
import * as Y from "yjs";
import { cocodexApiJson } from "../cocodex-capability";
import { CollaborativePromptEditor } from "../components/CollaborativePromptEditor";
import {
  independentlyConfirmedFingerprintMatches,
  privateTimelineForContact,
  reconcilePrivateContactSelection,
} from "../cocodex-private-contact-state";
import { referenceArtifactSelectionReducer } from "../cocodex-file-reference-state";
import { projectCreatedFromControl } from "../cocodex-project-creation-state";
import {
  orderedProjects,
  projectLifecycleCommand,
  projectLeaveCommand,
  reconcileDeletedProject,
  type ProjectLifecycleAction,
} from "../cocodex-project-lifecycle-state";
import { buildCoCodexComposerSubmission } from "../cocodex-composer-state";
import { executableLocalAgentIds, stopEveryLocalAgent } from "../cocodex-agent-safety-state";
import { browserCapabilityPresentation, type CodexBrowserCapabilityView } from "../cocodex-browser-state";
import { buildTaskDependencyGraph, type TaskGraphState } from "../cocodex-task-graph";
import {
  PRIVATE_TYPING_EXPIRY_MS,
  PRIVATE_TYPING_IDLE_MS,
  buildPrivateComposerCommand,
  buildPrivateMutationCommand,
  buildPrivateTypingCommand,
  projectPrivateMessageEvents,
  type PrivateMessageEvent,
  type ProjectedPrivateMessage,
} from "../cocodex-private-message-state";
import {
  buildPrivateNotification,
  disablePrivateNotifications,
  enablePrivateNotifications,
  readPrivateNotificationsEnabled,
  shouldNotifyPrivateMessage,
  showPrivateNotification,
} from "../cocodex-private-notifications";
import {
  applyPromptTextEdit,
  encodePromptRelativeCaret,
  resolvePromptRelativeCaret,
  type RelativePromptCaret,
} from "../cocodex-prompt-presence";
import {
  confirmProjectMemberRemoval,
  clearRecoveredProjectSecurity,
  isRevokedProjectMember,
  markProjectMemberRevoked,
  projectMemberRemovalCommand,
  reconcileRevokedProject,
  type Project,
  type ProjectMember,
  type ProjectSecurityIncident,
} from "../cocodex-member-state";
import { useT, type TFn, type TKey } from "../i18n";
import { IconBot, IconKey, IconLock, IconRefresh, IconServer } from "../icons";
import "../styles-cocodex.css";

type ConnectionState = "not-configured" | "stopped" | "connecting" | "connected" | "retrying";
type RightRailTab = "usage" | "agents" | "artifacts" | "messages";

interface Status {
  configured: boolean;
  running: boolean;
  state: ConnectionState;
  deviceId?: string;
  deviceFingerprint?: string;
  displayName?: string;
  verificationPhrase?: string;
  approvalExpiresAt?: string;
  server?: { host: string; port: number };
  agentConfigured: boolean;
  agentAccessProfile?: "project-only" | "full-computer";
  agentWorkspaceMode?: "shared" | "git-worktree";
  agentExecutionEnabled?: boolean;
  agentFullComputerEnabled?: boolean;
  localAgents: Array<{
    agentId: string;
    projectId: string;
    primaryModel: string;
    primaryEffort: string;
    coAgentModel: string | null;
    coAgentEffort: string | null;
    maxConcurrentCoAgents: number;
    accessProfile: "project-only" | "full-computer";
    workspaceMode: "shared" | "git-worktree";
    executionEnabled: boolean;
    fullComputerEnabled: boolean;
  }>;
  latestEventSequence: number;
}

export interface ChatEvent {
  sequence: number;
  projectId: string;
  chatId?: string;
  eventId: string;
  senderDeviceId: string;
  content: string;
  acceptedAt: string;
}

type PrivateMessage = PrivateMessageEvent;

interface SharedChat {
  id: string;
  projectId: string;
  title: string;
  createdByDeviceId: string;
  state: "active" | "archived";
  createdAt: string;
  updatedAt: string;
}

interface PrivateReceipt {
  sequence: number;
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  receipt: "delivered" | "read";
  acceptedAt: string;
}

interface AgentApproval {
  id: string;
  projectId: string;
  chatId?: string;
  agentId: string;
  requesterDeviceId: string;
  prompt: string;
}

interface PrivateContact {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  trusted: boolean;
  projectCapable: boolean;
}

interface PendingDeviceApproval {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  verificationPhrase: string;
  enrolledAt: string;
  approvalExpiresAt: string;
}

interface ProjectInvitation {
  invitationId: string;
  projectId: string;
  projectName: string;
  ownerDeviceId: string;
  ownerDisplayName: string;
  ownerFingerprint: string;
  recipientDeviceId: string;
  recipientDisplayName: string;
  recipientFingerprint: string;
  keyEpoch: number;
  issuedAt: string;
  expiresAt: string;
  status: "pending" | "accepted" | "declined" | "cancelled" | "expired";
  direction: "incoming" | "outgoing";
  trusted: boolean;
  actionable: boolean;
}

type AgentStatus = "offline" | "available" | "queued" | "working" | "completed" | "failed";

interface AgentView {
  id: string;
  projectId: string;
  name: string;
  primaryModel: string;
  primaryEffort: "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
  coAgentModel: string | null;
  coAgentEffort: "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | null;
  maxConcurrentCoAgents: number;
  hostDeviceId: string;
  hostDisplayName: string;
  enabled: boolean;
  status: AgentStatus;
  activeTasks: number;
  queuedTasks: number;
  lastTaskAt: string | null;
}

type AgentTaskStatus = "queued" | "running" | "completed" | "failed";

export interface AgentTaskView {
  id: string;
  projectId: string;
  chatId?: string;
  agentId: string;
  agentName: string;
  requesterDeviceId: string;
  targetDeviceId: string;
  status: AgentTaskStatus;
  dependencies: string[];
  inputArtifactIds: string[];
  workspaceMode: "shared" | "git-worktree" | null;
  workspaceRef: string | null;
  branch: string | null;
  baseCommit: string | null;
  mergeTarget: string | null;
  acceptedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  lastActivityAt: string;
  eventCount: number;
  encrypted: boolean;
}

interface Artifact {
  id: string;
  projectId: string;
  chatId?: string;
  taskId: string | null;
  authorDeviceId: string;
  type: string;
  title: string;
  summary: string;
  content: string;
  status: "draft" | "ready" | "accepted" | "rejected" | "superseded" | "integrated";
  createdAt: string;
  updatedAt: string;
}

interface GitIntegrationPreviewView {
  status: "ready" | "blocked";
  taskId: string;
  projectId: string;
  agentId: string;
  branch: string;
  baseCommit: string;
  mergeTarget: string;
  expectedTargetCommit: string;
  currentTargetCommit: string;
  changedFiles: string[];
  conflicts: string[];
  overlaps: Array<{ taskId: string; branch: string; files: string[] }>;
  blockedReasons: string[];
}

interface GitIntegrationArtifactView {
  status: "integrated" | "revision-required";
  artifactId: string;
  projectId: string;
  taskId: string;
  agentId: string;
  branch: string;
  mergeTarget: string;
  baseCommit: string;
  targetCommit: string;
  integrationCommit: string | null;
  changedFiles: string[];
  conflicts: string[];
  overlaps: Array<{ taskId: string; branch: string; files: string[] }>;
  revision: number;
  createdAt: string;
}

interface GitIntegrationState {
  status: "ready" | "blocked" | "integrated" | "revision-required";
  preview?: GitIntegrationPreviewView;
  artifact?: GitIntegrationArtifactView;
  error?: string;
}
export interface FileReference {
  referenceId: string;
  projectId: string;
  chatId?: string;
  artifactId: string;
  hostDeviceId: string;
  authorDeviceId: string;
  relativePath: string;
  workspaceMode: "shared" | "git-worktree";
  workspaceRef: string;
  branch: string | null;
  commitSha: string | null;
  sha256: string;
  sizeBytes: number;
  mediaType: string | null;
  createdAt: string;
  updatedAt: string;
}

interface SharedProjectContext {
  projectId: string;
  chatId?: string;
  finalGoal: string;
  context: Record<string, unknown>;
  revision: number;
  updatedByDeviceId: string | null;
  updatedAt: string | null;
}

interface UsageReport {
  deviceId: string;
  revision: number;
  updatedAt: string;
  requests: number;
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  reasoningOutputTokens: number;
  activeAgents: number;
  accountLabel?: string;
  fiveHourPercent?: number;
  fiveHourResetAt?: number;
  weeklyPercent?: number;
  weeklyResetAt?: number;
  monthlyPercent?: number;
  monthlyResetAt?: number;
  customWindows?: { label: string; percent: number; resetAt?: number }[];
  agents?: {
    agentId: string;
    requests: number;
    inputTokens: number;
    cachedInputTokens: number;
    outputTokens: number;
    reasoningOutputTokens: number;
  }[];
}

interface UsageReportView {
  deviceId: string;
  displayName: string;
  report: UsageReport | null;
  acceptedAt: string | null;
}

interface PresenceMember {
  deviceId: string;
  displayName: string;
  cursor: { x: number; y: number } | null;
  caret: { anchor: number; head: number } | null;
  relativeCaret?: RelativePromptCaret | null;
  typing: boolean;
}

interface LocalPresence {
  cursor: { x: number; y: number } | null;
  caret: { anchor: number; head: number } | null;
  relativeCaret: RelativePromptCaret | null;
  typing: boolean;
}

interface SessionValue {
  source?: string;
  state?: ConnectionState | "key-available" | "rotation-required" | "revoked" | "device-revoked"
    | "active" | "locked";
  projectId?: string;
  keyEpoch?: number;
  revokedDeviceId?: string;
  promotedOwnerDeviceId?: string | null;
  currentEpoch?: number;
  incidentId?: string;
  localDeviceRevoked?: boolean;
  keyRotationRequired?: boolean;
  revision?: number;
  lockedAt?: string | null;
  lockedByDeviceId?: string | null;
  reason?: string | null;
  approvalState?: "pending" | "resolved";
  executionEnabled?: boolean;
  fullComputerEnabled?: boolean;
  accessProfile?: "project-only" | "full-computer";
  workspaceMode?: "shared" | "git-worktree";
  configured?: boolean;
  ok?: boolean;
  browserCapability?: CodexBrowserCapabilityView;
  officialCodexOpened?: boolean;
  taskId?: string;
  task?: AgentApproval;
  error?: unknown;
  integration?: "preview" | "integrated" | "revision-required";
  blocked?: boolean;
  preview?: GitIntegrationPreviewView;
  artifact?: GitIntegrationArtifactView;
  commit?: string;
  queued?: boolean;
  message?: PrivateMessage;
  receipt?: PrivateReceipt;
  senderDeviceId?: string;
  recipientDeviceId?: string;
  typing?: boolean;
  contacts?: PrivateContact[];
  devices?: PendingDeviceApproval[];
  invitations?: ProjectInvitation[];
  project?: Project;
  frame?: {
    type?: string;
    requestId?: string;
    projectId?: string;
    chatId?: string;
    incidentId?: string;
    revokedDeviceId?: string;
    promotedOwnerDeviceId?: string | null;
    currentEpoch?: number;
    createdAt?: string;
    status?: "approved" | "revoked";
    requestedAt?: string;
    created?: boolean;
    chats?: SharedChat[];
    chat?: SharedChat;
    defaultChat?: SharedChat;
    update?: string;
    deviceId?: string;
    displayName?: string;
    cursor?: { x: number; y: number } | null;
    caret?: { anchor: number; head: number } | null;
    relativeCaret?: RelativePromptCaret | null;
    typing?: boolean;
    members?: PresenceMember[] | ProjectMember[];
    projects?: Project[];
    project?: Project;
    transition?: { projectId?: string; action?: string; resultingRevision?: number };
    events?: ChatEvent[];
    event?: ChatEvent;
    context?: SharedProjectContext;
    reports?: UsageReportView[];
    report?: UsageReportView;
    agents?: AgentView[];
    tasks?: AgentTaskView[];
    artifacts?: Artifact[];
    artifact?: Artifact;
    references?: FileReference[];
    reference?: FileReference;
  };
}

function isConnectionState(value: unknown): value is ConnectionState {
  return value === "not-configured" || value === "stopped" || value === "connecting"
    || value === "connected" || value === "retrying";
}

interface BridgeEvent {
  sequence: number;
  channel: "output" | "error";
  value: SessionValue;
}

const STATE_TKEY: Record<ConnectionState, TKey> = {
  "not-configured": "cocodex.state.enrollment",
  stopped: "cocodex.state.disconnected",
  connecting: "cocodex.state.connecting",
  connected: "cocodex.state.online",
  retrying: "cocodex.state.reconnecting",
};

const AGENT_STATUS_TKEY: Record<AgentStatus, TKey> = {
  offline: "cocodex.agents.offline",
  available: "cocodex.agents.available",
  queued: "cocodex.agents.queued",
  working: "cocodex.agents.working",
  completed: "cocodex.agents.completed",
  failed: "cocodex.agents.failed",
};

const TASK_STATUS_TKEY: Record<AgentTaskStatus, TKey> = {
  queued: "cocodex.tasks.queued",
  running: "cocodex.tasks.working",
  completed: "cocodex.tasks.completed",
  failed: "cocodex.tasks.failed",
};

function stateLabel(t: TFn, state: ConnectionState): string { return t(STATE_TKEY[state]); }
function agentStatusLabel(t: TFn, status: AgentStatus): string { return t(AGENT_STATUS_TKEY[status]); }
function taskStatusLabel(t: TFn, status: AgentTaskStatus): string { return t(TASK_STATUS_TKEY[status]); }

const RIGHT_RAIL_TABS: ReadonlyArray<readonly [RightRailTab, TKey]> = [
  ["usage", "cocodex.usage.title"],
  ["agents", "cocodex.agents.title"],
  ["artifacts", "cocodex.artifacts.title"],
  ["messages", "cocodex.private.title"],
];

export function PrivateTypingIndicator({ active, label }: {
  active: boolean;
  label: string;
}) {
  if (!active) return null;
  return <div className="cocodex-private-typing" role="status" aria-live="polite">
    <span aria-hidden="true"><i /><i /><i /></span>
    {label}
  </div>;
}

export function WorkspaceRailTabs({
  active,
  onChange,
}: {
  active: RightRailTab;
  onChange: (tab: RightRailTab) => void;
}) {
  const t = useT();
  return <nav className="cocodex-rail-tabs" role="tablist" aria-label={t("cocodex.rail.title")}>
    {RIGHT_RAIL_TABS.map(([tab, label]) => (
      <button key={tab} type="button" role="tab" aria-selected={active === tab}
        className={active === tab ? "active" : ""}
        onClick={() => onChange(tab)}>{t(label)}</button>
    ))}
  </nav>;
}

const TASK_GRAPH_STATE_TKEY: Record<TaskGraphState, TKey> = {
  ready: "cocodex.tasks.graph.ready",
  running: "cocodex.tasks.working",
  completed: "cocodex.tasks.completed",
  failed: "cocodex.tasks.failed",
  "blocked-waiting": "cocodex.tasks.graph.blockedWaiting",
  "blocked-failed": "cocodex.tasks.graph.blockedFailed",
  "blocked-missing": "cocodex.tasks.graph.blockedMissing",
  "blocked-cycle": "cocodex.tasks.graph.blockedCycle",
};

function taskGraphStateLabel(t: TFn, state: TaskGraphState): string {
  return t(TASK_GRAPH_STATE_TKEY[state]);
}

function taskGraphVisualStatus(state: TaskGraphState): "available" | "working" | "completed" | "failed" | "queued" {
  if (state === "ready") return "available";
  if (state === "running") return "working";
  if (state === "completed") return "completed";
  if (state === "failed" || state === "blocked-failed" || state === "blocked-missing" || state === "blocked-cycle") return "failed";
  return "queued";
}

export function TaskDependencyGraph({
  tasks,
  artifacts,
}: {
  tasks: AgentTaskView[];
  artifacts: Artifact[];
}) {
  const t = useT();
  const nodes = buildTaskDependencyGraph(tasks, artifacts);
  if (!nodes.length) return <p className="muted">{t("cocodex.tasks.empty")}</p>;
  return <div className="cocodex-task-graph" role="list" aria-label={t("cocodex.tasks.title")}>
    {nodes.map(node => {
      const visualStatus = taskGraphVisualStatus(node.state);
      return <article className={`cocodex-agent-card cocodex-task-card cocodex-task-graph-node state-${node.state}`}
        style={{ marginInlineStart: Math.min(node.layer, 4) * 10 }}
        data-layer={node.layer} data-state={node.state} role="listitem" key={node.task.id}>
        <div className="cocodex-agent-card-head">
          <span className={`cocodex-agent-status status-${visualStatus}`}
            aria-label={taskGraphStateLabel(t, node.state)} />
          <strong>{node.task.agentName}</strong>
          <small>{taskGraphStateLabel(t, node.state)}</small>
        </div>
        <code>{node.task.id.slice(0, 8)}</code>
        {node.dependencies.length > 0 && <div className="cocodex-task-graph-links"
          aria-label={t("cocodex.tasks.graph.dependsOn")}>
          {node.dependencies.map(dependency => <span key={dependency.id}
            className={`state-${dependency.state}`}>
            <b aria-hidden="true">{"<-"}</b>
            {dependency.agentName ?? dependency.id.slice(0, 8)}
            <small>{dependency.state === "missing"
              ? t("cocodex.tasks.graph.blockedMissing")
              : taskGraphStateLabel(t, dependency.state)}</small>
          </span>)}
        </div>}
        {node.artifactInputs.length > 0 && <>
          <small>{t("cocodex.tasks.graph.consumes", { count: node.artifactInputs.length })}</small>
          <div className="cocodex-task-artifact-inputs">
            {node.artifactInputs.map(input => <span key={input.id}>
              <b aria-hidden="true">{"<>"}</b>
              {input.title ?? input.id.slice(0, 8)}
              <small>{input.status ?? t("cocodex.tasks.graph.blockedMissing")}</small>
            </span>)}
          </div>
        </>}
        <small>{t("cocodex.tasks.events", { count: node.task.eventCount })}
          {node.task.encrypted ? ` - ${t("cocodex.tasks.encrypted")}` : ""}</small>
        {node.task.workspaceMode === "shared"
          && <small>{t("cocodex.tasks.workspace.shared")}</small>}
        {node.task.workspaceMode === "git-worktree" && <small>
          {t("cocodex.tasks.workspace.worktree", {
            branch: node.task.branch ?? node.task.workspaceRef ?? "",
            commit: node.task.baseCommit?.slice(0, 8) ?? "",
          })}
        </small>}
      </article>;
    })}
  </div>;
}
export function GitIntegrationReview({
  tasks,
  integrations,
  localDeviceId,
  connected,
  locked,
  onPreview,
  onIntegrate,
}: {
  tasks: AgentTaskView[];
  integrations: Record<string, GitIntegrationState>;
  localDeviceId?: string;
  connected: boolean;
  locked: boolean;
  onPreview: (taskId: string) => void;
  onIntegrate: (taskId: string, expectedTargetCommit: string) => void;
}) {
  const t = useT();
  const candidates = tasks.filter(task =>
    task.status === "completed"
    && task.targetDeviceId === localDeviceId
    && task.workspaceMode === "git-worktree");
  if (!candidates.length) return null;
  return (
    <section className="cocodex-agents cocodex-git-integration">
      <div className="cocodex-section-head">
        <div>
          <strong>{t("cocodex.gitIntegration.title")}</strong>
          <small>{t("cocodex.gitIntegration.subtitle")}</small>
        </div>
        <IconKey />
      </div>
      <div className="cocodex-agent-list">
        {candidates.map(task => {
          const state = integrations[task.id];
          const preview = state?.preview;
          const ready = preview?.status === "ready";
          const integrated = state?.status === "integrated";
          return (
            <article
              className={"cocodex-agent-card cocodex-git-integration-card status-" + (state?.status ?? "unreviewed")}
              key={task.id} data-status={state?.status ?? "unreviewed"}>
              <div className="cocodex-agent-card-head">
                <span className={"cocodex-agent-status status-" + (integrated ? "completed" : ready ? "available" : "queued")}
                  aria-hidden="true" />
                <strong>{task.agentName}</strong>
                <small>{task.branch ?? t("cocodex.gitIntegration.worktree")}</small>
              </div>
              <code>{task.id.slice(0, 12)}</code>
              {!preview && <small>{t("cocodex.gitIntegration.notReviewed")}</small>}
              {preview && <small>
                {preview.status === "ready" ? t("cocodex.gitIntegration.ready") : t("cocodex.gitIntegration.blocked")}
                {" · "}{preview.changedFiles.length} {t(preview.changedFiles.length === 1 ? "cocodex.gitIntegration.changedFile" : "cocodex.gitIntegration.changedFiles")}
              </small>}
              {preview?.blockedReasons.length ? (
                <small className="cocodex-git-integration-blockers">
                  {t("cocodex.gitIntegration.blockers", { reasons: preview.blockedReasons.join(", ") })}
                </small>
              ) : null}
              {state?.artifact && <small>
                {state.artifact.status === "integrated"
                  ? t("cocodex.gitIntegration.integratedAt", { commit: state.artifact.integrationCommit?.slice(0, 12) ?? "unknown" })
                  : t("cocodex.gitIntegration.revisionArtifact")}
              </small>}
              {state?.error && <small className="cocodex-git-integration-blockers">{state.error}</small>}
              <div className="cocodex-git-integration-actions">
                <button className="btn btn-ghost" type="button"
                  disabled={!connected || locked}
                  onClick={() => onPreview(task.id)}>
                  {preview ? t("cocodex.gitIntegration.refresh") : t("cocodex.gitIntegration.review")}
                </button>
                {ready && !integrated && (
                  <button className="btn btn-primary" type="button"
                    disabled={!connected || locked}
                    onClick={() => onIntegrate(task.id, preview.expectedTargetCommit)}>
                    {t("cocodex.gitIntegration.integrate")}
                  </button>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

export function ChatTimeline({
  messages,
  tasks,
  localDeviceId,
  members,
}: {
  messages: ChatEvent[];
  tasks: AgentTaskView[];
  localDeviceId?: string;
  members: ProjectMember[];
}) {
  const t = useT();
  const displayName = (deviceId: string) => deviceId === localDeviceId
    ? t("cocodex.you")
    : members.find(member => member.deviceId === deviceId)?.displayName ?? deviceId.slice(0, 8);
  const entries = [
    ...messages.map(message => ({
      kind: "message" as const,
      acceptedAt: message.acceptedAt,
      stableOrder: `1:${String(message.sequence).padStart(16, "0")}:${message.eventId}`,
      message,
    })),
    ...tasks.map(task => ({
      kind: "task" as const,
      acceptedAt: task.acceptedAt,
      stableOrder: `0:${task.id}`,
      task,
    })),
  ].sort((left, right) => {
    const byTime = Date.parse(left.acceptedAt) - Date.parse(right.acceptedAt);
    return (Number.isFinite(byTime) && byTime !== 0) ? byTime : left.stableOrder.localeCompare(right.stableOrder);
  });

  if (!entries.length) return <div className="cocodex-empty">{t("cocodex.chat.empty")}</div>;

  return <>
    {entries.map(entry => {
      if (entry.kind === "message") {
        const message = entry.message;
        return <article key={`message:${message.eventId}`}
          className={message.senderDeviceId === localDeviceId ? "mine" : ""}>
          <div>
            <strong>{displayName(message.senderDeviceId)}</strong>
            <span>#{message.sequence}</span>
          </div>
          <p>{message.content}</p>
        </article>;
      }

      const task = entry.task;
      const visualStatus = task.status === "running" ? "working" : task.status;
      return <article key={`task:${task.id}`} className={`cocodex-timeline-task status-${visualStatus}`}>
        <div className="cocodex-timeline-task-head">
          <span className={`cocodex-agent-status status-${visualStatus}`} aria-hidden="true" />
          <strong>{task.agentName}</strong>
          <span>{taskStatusLabel(t, task.status)}</span>
        </div>
        <details open={task.status === "running"}>
          <summary>{t("cocodex.tasks.events", { count: task.eventCount })}</summary>
          <div className="cocodex-timeline-task-details">
            <small>{displayName(task.requesterDeviceId)} → {task.targetDeviceId.slice(0, 8)}</small>
            <code>{task.id.slice(0, 12)}</code>
            {task.dependencies.length > 0
              && <small>{t("cocodex.tasks.dependencies", { count: task.dependencies.length })}</small>}
            {task.inputArtifactIds.length > 0
              && <small>{t("cocodex.tasks.artifacts", { count: task.inputArtifactIds.length })}</small>}
            {task.workspaceMode === "shared" && <small>{t("cocodex.tasks.workspace.shared")}</small>}
            {task.workspaceMode === "git-worktree" && <small>{t("cocodex.tasks.workspace.worktree", {
              branch: task.branch ?? task.workspaceRef ?? "",
              commit: task.baseCommit?.slice(0, 8) ?? "",
            })}</small>}
            {task.encrypted && <small><IconLock /> {t("cocodex.tasks.encrypted")}</small>}
          </div>
        </details>
      </article>;
    })}
  </>;
}

function updateToBase64(update: Uint8Array): string {
  let binary = "";
  for (const byte of update) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function updateFromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function usageResetLabel(value: number | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "";
  const milliseconds = value < 10_000_000_000 ? value * 1000 : value;
  return new Date(milliseconds).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

function usageTotalTokens(report: UsageReport): number {
  return report.inputTokens + report.outputTokens;
}

function cacheHitPercent(inputTokens: number, cachedInputTokens: number): number {
  if (inputTokens <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((cachedInputTokens / inputTokens) * 100)));
}

function fileSizeLabel(t: TFn, bytes: number): string {
  if (bytes < 1024) return t("cocodex.fileReferences.bytes", { count: bytes });
  if (bytes < 1024 * 1024) return t("cocodex.fileReferences.kilobytes", { count: (bytes / 1024).toFixed(1) });
  return t("cocodex.fileReferences.megabytes", { count: (bytes / (1024 * 1024)).toFixed(1) });
}

export function FileReferenceMetadata({ reference, local }: { reference: FileReference; local: boolean }) {
  const t = useT();
  return (
    <span className="cocodex-file-reference">
      <code>{reference.relativePath}</code>
      <small>{fileSizeLabel(t, reference.sizeBytes)}
        {reference.mediaType ? ` · ${reference.mediaType}` : ""}
        {local
          ? ` · ${t("cocodex.fileReferences.thisDevice")}`
          : ` · ${t("cocodex.fileReferences.remoteDevice")}`}</small>
    </span>
  );
}

export function ProjectMemberRoster({
  members,
  owner,
  connected,
  busy,
  onRefresh,
  onTrust,
  onRemove,
}: {
  members: ProjectMember[];
  owner: boolean;
  connected: boolean;
  busy: boolean;
  onRefresh: () => void;
  onTrust: (member: ProjectMember) => void;
  onRemove: (member: ProjectMember) => void;
}) {
  const t = useT();
  return (
    <section className="cocodex-members">
      <div className="cocodex-section-head">
        <span>{t("cocodex.members.title")}</span>
        <button type="button" className="btn btn-ghost btn-icon"
          title={t("cocodex.members.refresh")} onClick={onRefresh} disabled={!connected}>
          <IconRefresh />
        </button>
      </div>
      <div className="cocodex-member-list">
        {members.map(member => (
          <article key={member.deviceId}>
            <span>
              <strong>{member.displayName}</strong>
              <small>{member.role} · {member.fingerprint.slice(-12)} · {t(member.trusted
                ? "cocodex.members.trusted"
                : "cocodex.members.unverified")}
                {isRevokedProjectMember(member) && ` · ${t("cocodex.members.revoked")}`}</small>
              {isRevokedProjectMember(member) && <small role="status">{t("cocodex.members.revokedRecovery")}</small>}
              {member.leaveRequestId && <small role="status">{t("cocodex.members.leaveRequestedHelp")}</small>}
            </span>
            {owner && member.role !== "owner" && <span className="cocodex-member-actions">
              {!member.trusted && !isRevokedProjectMember(member) && <button type="button" className="btn btn-ghost"
                disabled={busy || !connected} onClick={() => onTrust(member)}>
                {t("cocodex.members.trust")}
              </button>}
              <button type="button" className="btn btn-danger btn-ghost"
                disabled={busy || !connected} onClick={() => onRemove(member)}>
                {t(member.leaveRequestId
                  ? "cocodex.members.completeLeave"
                  : isRevokedProjectMember(member)
                    ? "cocodex.members.removeAndRotate"
                    : "cocodex.members.remove")}
              </button>
            </span>}
          </article>
        ))}
        {!members.length && <p className="muted">{t("cocodex.members.empty")}</p>}
      </div>
    </section>
  );
}

export default function CoCodex({ apiBase }: { apiBase: string }) {
  const t = useT();
  const [status, setStatus] = useState<Status>();
  const [browserCapability, setBrowserCapability] = useState<CodexBrowserCapabilityView>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [chats, setChats] = useState<SharedChat[]>([]);
  const [chatId, setChatId] = useState("");
  const [chatTitle, setChatTitle] = useState("");
  const [projectName, setProjectName] = useState("");
  const [projectMembers, setProjectMembers] = useState<ProjectMember[]>([]);
  const [projectSecurity, setProjectSecurity] = useState<Record<string, ProjectSecurityIncident>>({});
  const [projectInvitations, setProjectInvitations] = useState<ProjectInvitation[]>([]);
  const [chat, setChat] = useState<ChatEvent[]>([]);
  const [privateMessages, setPrivateMessages] = useState<PrivateMessage[]>([]);
  const [privateReceipts, setPrivateReceipts] = useState<Record<string, "sent" | "delivered" | "read">>({});
  const [privateContacts, setPrivateContacts] = useState<PrivateContact[]>([]);
  const [pendingDeviceApprovals, setPendingDeviceApprovals] = useState<PendingDeviceApproval[]>([]);
  const [deviceApprovalConfirmations, setDeviceApprovalConfirmations] =
    useState<Record<string, string>>({});
  const [privateSearch, setPrivateSearch] = useState("");
  const [presence, setPresence] = useState<PresenceMember[]>([]);
  const [agentApprovals, setAgentApprovals] = useState<AgentApproval[]>([]);
  const [draft, setDraft] = useState("");
  const [sharedPrompt, setSharedPrompt] = useState("");
  const [activePromptDoc, setActivePromptDoc] = useState<Y.Doc>();
  const [sharedContext, setSharedContext] = useState<SharedProjectContext>();
  const [finalGoalDraft, setFinalGoalDraft] = useState("");
  const [usageReports, setUsageReports] = useState<UsageReportView[]>([]);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [tasks, setTasks] = useState<AgentTaskView[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [gitIntegrations, setGitIntegrations] = useState<Record<string, GitIntegrationState>>({});
  const [fileReferences, setFileReferences] = useState<FileReference[]>([]);
  const [selectedArtifactIds, setSelectedArtifactIds] = useState<string[]>([]);
  const [artifactTitle, setArtifactTitle] = useState("");
  const [artifactSummary, setArtifactSummary] = useState("");
  const [artifactContent, setArtifactContent] = useState("");
  const [referenceArtifactId, dispatchReferenceArtifactSelection] = useReducer(referenceArtifactSelectionReducer, "");
  const [referenceWorkspaceRoot, setReferenceWorkspaceRoot] = useState("");
  const [referencePath, setReferencePath] = useState("");
  const [referenceWorkspaceMode, setReferenceWorkspaceMode] = useState<"shared" | "git-worktree">("shared");
  const [referenceWorkspaceRef, setReferenceWorkspaceRef] = useState("main");
  const [referenceMediaType, setReferenceMediaType] = useState("");
  const [agentId, setAgentId] = useState("");
  const [agentName, setAgentName] = useState("");
  const [agentWorkspace, setAgentWorkspace] = useState("");
  const [agentWorkspaceMode, setAgentWorkspaceMode] = useState<"shared" | "git-worktree">("git-worktree");
  const [agentPrimaryModel, setAgentPrimaryModel] = useState("gpt-5.6-sol");
  const [agentPrimaryEffort, setAgentPrimaryEffort] = useState<AgentView["primaryEffort"]>("medium");
  const [agentCoAgentModel, setAgentCoAgentModel] = useState("");
  const [agentCoAgentEffort, setAgentCoAgentEffort] = useState<NonNullable<AgentView["coAgentEffort"]>>("medium");
  const [agentMaxCoAgents, setAgentMaxCoAgents] = useState(0);
  const [trustedRequesterDeviceId, setTrustedRequesterDeviceId] = useState("");
  const [trustedRequesterFingerprint, setTrustedRequesterFingerprint] = useState("");
  const [invite, setInvite] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [recipientDeviceId, setRecipientDeviceId] = useState("");
  const [privateDraft, setPrivateDraft] = useState("");
  const [privateReplyTo, setPrivateReplyTo] = useState<ProjectedPrivateMessage>();
  const [privateEditTarget, setPrivateEditTarget] = useState<ProjectedPrivateMessage>();
  const [privateTypingDeviceIds, setPrivateTypingDeviceIds] = useState<string[]>([]);
  const [privateNotificationsEnabled, setPrivateNotificationsEnabled] =
    useState(readPrivateNotificationsEnabled);
  const [privateVerificationFingerprint, setPrivateVerificationFingerprint] = useState("");
  const [notice, setNotice] = useState("");
  const [runtimeNotice, setRuntimeNotice] = useState("");
  const [rightRailTab, setRightRailTab] = useState<RightRailTab>("agents");
  const [busy, setBusy] = useState(false);
  const cursor = useRef(0);
  const projectListRequested = useRef(false);
  const browserCapabilityRequested = useRef(false);
  const subscribedProject = useRef("");
  const presenceSentAt = useRef(0);
  const presenceProject = useRef("");
  const presenceConnectionState = useRef<ConnectionState | undefined>(undefined);
  const localPresence = useRef<LocalPresence>({
    cursor: null, caret: null, relativeCaret: null, typing: false,
  });
  const presenceSendTimer = useRef<number | undefined>(undefined);
  const typingIdleTimer = useRef<number | undefined>(undefined);
  const privateTypingIdleTimer = useRef<number | undefined>(undefined);
  const privateTypingSentTo = useRef("");
  const privateTypingActive = useRef(false);
  const privateTypingExpiryTimers = useRef(new Map<string, number>());
  const notifiedPrivateMessageIds = useRef(new Set<string>());
  const promptDoc = useRef<Y.Doc | undefined>(undefined);
  const promptProject = useRef("");
  const seenSecurityIncidents = useRef(new Set<string>());

  const command = useCallback((body: Record<string, unknown>) =>
    cocodexApiJson(apiBase, `${apiBase}/api/cocodex/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }), [apiBase]);

  const sendPrivateTypingSignal = useCallback((targetDeviceId: string, typing: boolean) => {
    if (!targetDeviceId || status?.state !== "connected") return;
    void command(buildPrivateTypingCommand(targetDeviceId, typing)).catch(() => {
      // Typing is ephemeral; message sending remains the authoritative error surface.
    });
  }, [command, status?.state]);

  const stopPrivateTyping = useCallback(() => {
    if (privateTypingIdleTimer.current !== undefined) {
      window.clearTimeout(privateTypingIdleTimer.current);
      privateTypingIdleTimer.current = undefined;
    }
    const targetDeviceId = privateTypingSentTo.current;
    if (privateTypingActive.current && targetDeviceId) {
      sendPrivateTypingSignal(targetDeviceId, false);
    }
    privateTypingActive.current = false;
    privateTypingSentTo.current = "";
  }, [sendPrivateTypingSignal]);

  const notePrivateTyping = useCallback((value: string) => {
    const contact = privateContacts.find(item => item.deviceId === recipientDeviceId);
    if (!value.trim() || !contact?.trusted || status?.state !== "connected") {
      stopPrivateTyping();
      return;
    }
    if (privateTypingSentTo.current !== contact.deviceId) stopPrivateTyping();
    if (!privateTypingActive.current) {
      privateTypingActive.current = true;
      privateTypingSentTo.current = contact.deviceId;
      sendPrivateTypingSignal(contact.deviceId, true);
    }
    if (privateTypingIdleTimer.current !== undefined) {
      window.clearTimeout(privateTypingIdleTimer.current);
    }
    privateTypingIdleTimer.current = window.setTimeout(stopPrivateTyping, PRIVATE_TYPING_IDLE_MS);
  }, [privateContacts, recipientDeviceId, sendPrivateTypingSignal, status?.state, stopPrivateTyping]);

  const ensurePromptDocument = useCallback((nextProjectId: string, nextChatId = nextProjectId): Y.Doc => {
    const nextScope = `${nextProjectId}:${nextChatId}`;
    if (promptDoc.current && promptProject.current === nextScope) return promptDoc.current;
    promptDoc.current?.destroy();
    const document = new Y.Doc();
    const text = document.getText("prompt");
    text.observe(() => setSharedPrompt(text.toString()));
    document.on("update", (update, origin) => {
      if (origin === "server" || !promptProject.current) return;
      void command({
        type: "prompt.update",
        projectId: promptProject.current.split(":")[0],
        chatId: promptProject.current.split(":")[1],
        updateId: crypto.randomUUID(),
        update: updateToBase64(update),
      }).catch(error => setNotice(error instanceof Error ? error.message : String(error)));
    });
    promptDoc.current = document;
    promptProject.current = nextScope;
    setActivePromptDoc(document);
    setSharedPrompt("");
    return document;
  }, [command]);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await cocodexApiJson<Status>(apiBase, `${apiBase}/api/cocodex/status`));
      setRuntimeNotice("");
    } catch (error) {
      setRuntimeNotice(error instanceof Error ? error.message : String(error));
    }
  }, [apiBase]);

  const applyEvents = useCallback((events: BridgeEvent[]) => {
    for (const event of events) {
      const value = event.value;
      const frame = value?.frame;
      const nextState = value?.state;
      if (value?.source === "session" && isConnectionState(nextState)) {
        setStatus(previous => previous ? { ...previous, state: nextState, running: nextState !== "stopped" } : previous);
      }
      if (value?.source === "agent-safety") {
        setStatus(previous => previous ? {
          ...previous,
          agentExecutionEnabled: value.executionEnabled === true,
          agentFullComputerEnabled: value.fullComputerEnabled === true,
          ...(value.accessProfile === "project-only" || value.accessProfile === "full-computer"
            ? { agentAccessProfile: value.accessProfile }
            : {}),
        } : previous);
      }
      if (value?.source === "control" && value.browserCapability?.version === 1
        && value.browserCapability.executionSurface === "codex-exec") {
        setBrowserCapability(value.browserCapability as CodexBrowserCapabilityView);
      }
      if (value?.source === "control" && value.officialCodexOpened === true) {
        setNotice(t("cocodex.browser.opened"));
      }
      if (value?.source === "agent-configuration" && value.configured) {
        setNotice(t("cocodex.agent.setup.saved"));
        setAgentName("");
        setAgentWorkspace("");
        void loadStatus();
      }
      if (value?.source === "control"
        && (value.integration === "preview"
          || value.integration === "integrated"
          || value.integration === "revision-required")
        && typeof value.taskId === "string" && value.preview) {
        const preview = value.preview;
        const integrationStatus = value.integration === "preview"
          ? preview.status
          : value.integration;
        setGitIntegrations(previous => ({
          ...previous,
          [value.taskId!]: {
            status: integrationStatus,
            preview,
            ...(value.artifact ? { artifact: value.artifact } : {}),
            ...(typeof value.error === "string" ? { error: value.error } : {}),
          },
        }));
        if (value.integration === "integrated") {
          setNotice(t("cocodex.gitIntegration.completedNotice"));
        } else if (value.integration === "revision-required") {
          setNotice(t("cocodex.gitIntegration.blockedNotice"));
        }
      }
      const safelyCreatedProject = projectCreatedFromControl(value);
      if (safelyCreatedProject) {
        const nextProject = safelyCreatedProject;
        setProjects(previous => [...previous.filter(project => project.id !== nextProject.id), nextProject]);
        setProjectId(nextProject.id);
        setChatId(nextProject.id);
        setProjectName("");
        setNotice(t("cocodex.projects.created", { name: nextProject.name }));
      }
      if (frame?.projectId === projectId && frame.type === "project.chat.list.result"
        && Array.isArray(frame.chats)) {
        const listedChats = frame.chats as SharedChat[];
        setChats(listedChats);
        setChatId(previous => listedChats.some(item => item.id === previous)
          ? previous
          : listedChats[0]?.id ?? projectId);
      } else if (frame?.projectId === projectId
        && (frame.type === "project.chat.created" || frame.type === "project.chat.changed")
        && frame.chat) {
        const nextChat = frame.chat as SharedChat;
        setChats(previous => [...previous.filter(item => item.id !== nextChat.id), nextChat]
          .sort((left, right) => left.createdAt.localeCompare(right.createdAt)));
        if (frame.type === "project.chat.created") {
          setChatId(nextChat.id);
          setChatTitle("");
        }
      }
      if (value?.source === "project-encryption" && value.state === "rotation-required") {
        setNotice(t("cocodex.encryption.rotationRequired"));
        if (value.projectId) {
          setProjectSecurity(previous => {
            const existing = previous[value.projectId!];
            if (existing?.state === "device-revoked") {
              if (typeof existing.currentEpoch === "number" || typeof value.currentEpoch !== "number") {
                return previous;
              }
              return {
                ...previous,
                [value.projectId!]: { ...existing, currentEpoch: value.currentEpoch },
              };
            }
            return {
              ...previous,
              [value.projectId!]: {
                ...existing,
                state: "rotation-required",
                ...(typeof value.currentEpoch === "number" ? { currentEpoch: value.currentEpoch } : {}),
              },
            };
          });
        }
      }
      if (value?.source === "project-encryption" && value.state === "key-available"
        && value.projectId && typeof value.keyEpoch === "number") {
        setProjectSecurity(previous => {
          const incident = previous[value.projectId!];
          const nextIncident = clearRecoveredProjectSecurity(
            incident,
            incident?.revokedDeviceId ?? "",
            value.keyEpoch!,
          );
          if (nextIncident === incident) return previous;
          const next = { ...previous };
          if (nextIncident) next[value.projectId!] = nextIncident;
          else delete next[value.projectId!];
          return next;
        });
      }
      const deviceRevokedFrame = frame?.type === "project.device-revoked" ? frame : undefined;
      const deviceRevokedEvent = value?.source === "project-security" && value.state === "device-revoked"
        ? value
        : undefined;
      const securityProjectId = deviceRevokedEvent?.projectId ?? deviceRevokedFrame?.projectId;
      const revokedDeviceId = deviceRevokedEvent?.revokedDeviceId ?? deviceRevokedFrame?.revokedDeviceId;
      if (securityProjectId && revokedDeviceId) {
        const incidentId = deviceRevokedEvent?.incidentId ?? deviceRevokedFrame?.incidentId;
        const localDeviceRevoked = deviceRevokedEvent?.localDeviceRevoked === true
          || revokedDeviceId === status?.deviceId;
        setProjectSecurity(previous => ({
          ...previous,
          [securityProjectId]: {
            state: "device-revoked",
            revokedDeviceId,
            promotedOwnerDeviceId: deviceRevokedEvent?.promotedOwnerDeviceId
              ?? deviceRevokedFrame?.promotedOwnerDeviceId,
            currentEpoch: deviceRevokedEvent?.currentEpoch ?? deviceRevokedFrame?.currentEpoch,
            incidentId,
            localDeviceRevoked,
          },
        }));
        setProjectMembers(previous => securityProjectId === projectId
          ? markProjectMemberRevoked(previous, revokedDeviceId)
          : previous);
        setNotice(t(localDeviceRevoked
          ? "cocodex.security.deviceRevokedLocal"
          : "cocodex.security.deviceRevoked"));
        if (incidentId && !seenSecurityIncidents.current.has(incidentId)) {
          seenSecurityIncidents.current.add(incidentId);
          if (status?.state === "connected") {
            // Refresh ownership, roster status, and the key-rotation marker;
            // never issue the destructive remove-and-rotate command here.
            void command({ type: "project.list" });
            void command({ type: "project.member.list", projectId: securityProjectId });
            void command({ type: "project.key.get", projectId: securityProjectId });
          }
        }
      }
      if (value?.source === "project-encryption" && value.state === "revoked" && value.projectId) {
        const reconciled = reconcileRevokedProject(projects, projectId, value.projectId);
        setProjects(reconciled.projects);
        setProjectId(reconciled.selectedProjectId);
        if (reconciled.clearedSelection) {
          subscribedProject.current = "";
          setChats([]);
          setChatId("");
          setChatTitle("");
          setChat([]);
          setPresence([]);
          setProjectMembers([]);
          setSharedContext(undefined);
          setFinalGoalDraft("");
          setUsageReports([]);
          setAgents([]);
          setTasks([]);
          setArtifacts([]);
          setGitIntegrations({});
          setFileReferences([]);
          setSelectedArtifactIds([]);
          dispatchReferenceArtifactSelection({ type: "project-changed" });
          promptDoc.current?.destroy();
          promptDoc.current = undefined;
          promptProject.current = "";
          setSharedPrompt("");
        }
        void command({ type: "project.list" });
      }
      if (value?.source === "project-security"
        && (value.state === "active" || value.state === "locked")
        && value.projectId) {
        const lockState = value.state;
        setProjects(previous => previous.map(project => project.id === value.projectId
          ? {
              ...project,
              lock: {
                state: lockState,
                revision: Number(value.revision ?? project.lock?.revision ?? 0),
                lockedAt: value.lockedAt ?? null,
                lockedByDeviceId: value.lockedByDeviceId ?? null,
                reason: value.reason ?? null,
              },
            }
          : project));
        if (value.state === "locked") {
          setAgentApprovals(previous => previous.filter(approval => approval.projectId !== value.projectId));
          setPresence([]);
          setNotice(t("cocodex.lock.lockedNotice"));
        } else {
          setNotice(t("cocodex.lock.unlockedNotice"));
        }
      }
      if (event.channel === "error" && value?.error) setNotice(String(value.error));
      if (value?.source === "agent-approval") {
        if (value.approvalState === "resolved" && value.taskId) {
          setAgentApprovals(previous => previous.filter(item => item.id !== value.taskId));
        } else if (value.approvalState === "pending" && value.task) {
          const task = value.task;
          setAgentApprovals(previous => previous.some(item => item.id === task.id)
            ? previous
            : [...previous, task]);
        }
      }
      if ((frame?.type === "prompt.snapshot" || frame?.type === "prompt.update")
        && frame.projectId && (frame.chatId ?? frame.projectId) === chatId && frame.update) {
        try { Y.applyUpdate(ensurePromptDocument(frame.projectId, frame.chatId ?? frame.projectId), updateFromBase64(frame.update), "server"); }
        catch { setNotice(t("cocodex.prompt.invalid")); }
      }
      if ((frame?.type === "context.result" || frame?.type === "context.updated" || frame?.type === "context.changed")
        && frame.context?.projectId && (frame.chatId ?? frame.context.chatId ?? frame.context.projectId) === chatId) {
        setSharedContext(frame.context);
        setFinalGoalDraft(frame.context.finalGoal);
      }
      if (frame?.projectId === projectId && frame.type === "usage.result" && Array.isArray(frame.reports)) {
        setUsageReports(frame.reports);
      } else if (frame?.projectId === projectId
        && (frame.type === "usage.changed" || frame.type === "usage.accepted") && frame.report) {
        setUsageReports(previous => [...previous.filter(item => item.deviceId !== frame.report!.deviceId), frame.report!]
          .sort((a, b) => a.displayName.localeCompare(b.displayName)));
      }
      if (frame?.projectId === projectId && frame.type === "agent.list.result" && Array.isArray(frame.agents)) {
        setAgents(frame.agents);
      }
      if (frame?.projectId === projectId && (frame.chatId ?? projectId) === chatId
        && frame.type === "agent.task.list.result" && Array.isArray(frame.tasks)) {
        setTasks(frame.tasks);
      }
      if (frame?.projectId === projectId && (frame.chatId ?? projectId) === chatId
        && frame.type === "artifact.list.result" && Array.isArray(frame.artifacts)) {
        setArtifacts(frame.artifacts);
        setSelectedArtifactIds(previous => previous.filter(id => frame.artifacts!.some(artifact => artifact.id === id)));
        dispatchReferenceArtifactSelection({
          type: "artifacts-replaced",
          artifacts: frame.artifacts,
          localDeviceId: status?.deviceId,
        });
      } else if (frame?.projectId === projectId && (frame.chatId ?? frame.artifact?.chatId ?? projectId) === chatId
        && (frame.type === "artifact.accepted" || frame.type === "artifact.published") && frame.artifact) {
        setArtifacts(previous => [...previous.filter(item => item.id !== frame.artifact!.id), frame.artifact!]
          .sort((a, b) => a.createdAt.localeCompare(b.createdAt)));
      }
      if (frame?.projectId === projectId && (frame.chatId ?? projectId) === chatId && frame.type === "file-reference.list.result"
        && Array.isArray(frame.references)) {
        setFileReferences(frame.references);
      } else if (frame?.projectId === projectId && (frame.chatId ?? frame.reference?.chatId ?? projectId) === chatId
        && (frame.type === "file-reference.accepted" || frame.type === "file-reference.published")
        && frame.reference) {
        setFileReferences(previous => [
          ...previous.filter(item => item.referenceId !== frame.reference!.referenceId),
          frame.reference!,
        ].sort((a, b) => a.createdAt.localeCompare(b.createdAt)));
      }
      const listedProjects = frame?.projects;
      if (frame?.type === "project.list.result" && Array.isArray(listedProjects)) {
        setProjects(listedProjects);
        setProjectId(previous => listedProjects.some(project => project.id === previous)
          ? previous
          : listedProjects[0]?.id ?? "");
      } else if ((frame?.type === "project.created" || frame?.type === "project.changed") && frame.project) {
        const nextProject = frame.project as Project;
        setProjects(previous => [...previous.filter(project => project.id !== nextProject.id), nextProject]);
        if (frame.type === "project.created") {
          setProjectId(nextProject.id);
          setProjectName("");
          setNotice(t("cocodex.projects.created", { name: nextProject.name }));
        }
      } else if (frame?.type === "project.deleted" && frame.transition?.projectId) {
        const deletedProjectId = String(frame.transition.projectId);
        setProjects(previous => previous.filter(project => project.id !== deletedProjectId));
        setProjectId(selected =>
          reconcileDeletedProject(projects, selected, deletedProjectId).selectedProjectId);
        setNotice(t("cocodex.projects.deleted"));
      }
      if (frame?.projectId === projectId && (frame.chatId ?? projectId) === chatId
        && frame.type === "presence.snapshot" && Array.isArray(frame.members)) {
        setPresence((frame.members as PresenceMember[]).map(member => ({ ...member, typing: member.typing === true })));
      } else if (frame?.projectId === projectId && frame.type === "project.member.list.result"
        && Array.isArray(frame.members)) {
        const members = frame.members as ProjectMember[];
        setProjectMembers(members);
        const revokedMember = members.find(isRevokedProjectMember);
        if (revokedMember) {
          setProjectSecurity(previous => ({
            ...previous,
            [projectId]: {
              ...previous[projectId],
              state: "device-revoked",
              revokedDeviceId: revokedMember.deviceId,
            },
          }));
        }
      } else if (frame?.projectId === projectId && frame.type === "project.member.leave-requested" && frame.deviceId) {
        setProjectMembers(previous => previous.map(member => member.deviceId === frame.deviceId
          ? {
              ...member,
              leaveRequestId: frame.requestId ?? null,
              leaveRequestedAt: frame.requestedAt ?? null,
            }
          : member));
        if (frame.deviceId !== status?.deviceId) setNotice(t("cocodex.members.leaveRequestedOwner"));
      } else if (frame?.projectId === projectId && frame.type === "project.member.removed" && frame.deviceId) {
        setProjectMembers(previous => previous.filter(member => member.deviceId !== frame.deviceId));
        setProjectSecurity(previous => {
          const incident = previous[projectId];
          if (!incident || incident.revokedDeviceId !== frame.deviceId) return previous;
          return {
            ...previous,
            [projectId]: { ...incident, memberRemoved: true },
          };
        });
      } else if (frame?.projectId === projectId && frame.chatId === chatId
        && frame.type === "presence.update" && frame.deviceId && frame.displayName) {
        setPresence(previous => [...previous.filter(member => member.deviceId !== frame.deviceId), {
          deviceId: frame.deviceId!, displayName: frame.displayName!, cursor: frame.cursor ?? null,
          caret: frame.caret ?? null, relativeCaret: frame.relativeCaret ?? null,
          typing: frame.typing === true,
        }]);
      } else if (frame?.projectId === projectId && (frame.chatId ?? projectId) === chatId
        && frame.type === "presence.leave" && frame.deviceId) {
        setPresence(previous => previous.filter(member => member.deviceId !== frame.deviceId));
      }
      const incoming: ChatEvent[] = frame?.projectId === projectId
        && (frame?.chatId ?? frame?.projectId) === chatId && frame?.type === "chat.snapshot"
        ? frame.events ?? []
        : frame?.projectId === projectId
          && (frame?.chatId ?? frame?.event?.chatId ?? frame?.event?.projectId) === chatId
          && (frame?.type === "chat.event" || frame?.type === "agent.result") && frame.event
          ? [frame.event]
          : [];
      if (incoming.length) {
        setChat(previous => {
          const byId = new Map(previous.map(item => [item.eventId, item]));
          for (const item of incoming) byId.set(item.eventId, item);
          return [...byId.values()].sort((a, b) => a.sequence - b.sequence);
        });
      }
      const privateMessage = value?.message as PrivateMessage | undefined;
      if (value?.source === "private" && privateMessage?.messageId) {
        if ((privateMessage.kind ?? "message") === "message") {
          setPrivateReceipts(previous => previous[privateMessage.messageId]
            ? previous
            : {
              ...previous,
              [privateMessage.messageId]: privateMessage.direction === "sent" ? "sent" : "delivered",
            });
        }
        setPrivateMessages(previous => {
          const byId = new Map(previous.map(item => [item.messageId, item]));
          byId.set(privateMessage.messageId, { ...byId.get(privateMessage.messageId), ...privateMessage });
          return [...byId.values()].sort((left, right) =>
            (left.serverSequence ?? Number.MAX_SAFE_INTEGER) - (right.serverSequence ?? Number.MAX_SAFE_INTEGER)
            || String(left.clientCreatedAt ?? left.acceptedAt ?? "").localeCompare(
              String(right.clientCreatedAt ?? right.acceptedAt ?? ""),
            ) || left.messageId.localeCompare(right.messageId));
        });
      }
      if (value?.source === "private-typing"
        && value.recipientDeviceId === status?.deviceId
        && typeof value.senderDeviceId === "string") {
        const senderDeviceId = value.senderDeviceId;
        const existingTimer = privateTypingExpiryTimers.current.get(senderDeviceId);
        if (existingTimer !== undefined) window.clearTimeout(existingTimer);
        privateTypingExpiryTimers.current.delete(senderDeviceId);
        if (value.typing === true) {
          setPrivateTypingDeviceIds(previous => previous.includes(senderDeviceId)
            ? previous : [...previous, senderDeviceId]);
          const expiryTimer = window.setTimeout(() => {
            privateTypingExpiryTimers.current.delete(senderDeviceId);
            setPrivateTypingDeviceIds(previous => previous.filter(id => id !== senderDeviceId));
          }, PRIVATE_TYPING_EXPIRY_MS);
          privateTypingExpiryTimers.current.set(senderDeviceId, expiryTimer);
        } else {
          setPrivateTypingDeviceIds(previous => previous.filter(id => id !== senderDeviceId));
        }
      }
      if (value?.source === "private-contacts" && Array.isArray(value.contacts)) {
        const contacts = value.contacts as PrivateContact[];
        setPrivateContacts(contacts);
        setRecipientDeviceId(previous => reconcilePrivateContactSelection(previous, contacts));
      }
      if (value?.source === "device-approvals" && Array.isArray(value.devices)) {
        setPendingDeviceApprovals(value.devices as PendingDeviceApproval[]);
        setDeviceApprovalConfirmations(previous => Object.fromEntries(
          Object.entries(previous).filter(([deviceId]) =>
            value.devices!.some(device => device.deviceId === deviceId)),
        ));
      }
      if (value?.source === "project-invitations" && Array.isArray(value.invitations)) {
        setProjectInvitations(value.invitations as ProjectInvitation[]);
      }
      if (value?.source === "private-receipt" && value.receipt?.messageId) {
        setPrivateReceipts(previous => {
          const current = previous[value.receipt!.messageId];
          if (current === "read" || (current === "delivered" && value.receipt!.receipt === "delivered")) return previous;
          return { ...previous, [value.receipt!.messageId]: value.receipt!.receipt };
        });
      }
    }
  }, [chatId, command, ensurePromptDocument, loadStatus, projectId, projects, status?.deviceId, status?.state, t]);

  useEffect(() => {
    const initial = window.setTimeout(() => void loadStatus(), 0);
    const interval = window.setInterval(() => void loadStatus(), 2_000);
    return () => { window.clearTimeout(initial); window.clearInterval(interval); };
  }, [loadStatus]);

  useEffect(() => {
    if (!status?.running || browserCapabilityRequested.current) return;
    browserCapabilityRequested.current = true;
    void command({ type: "codex.browser.capability" }).catch(error => {
      browserCapabilityRequested.current = false;
      setNotice(error instanceof Error ? error.message : String(error));
    });
  }, [command, status?.running]);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const result = await cocodexApiJson<{ events: BridgeEvent[]; latestEventSequence: number }>(
          apiBase, `${apiBase}/api/cocodex/events?after=${cursor.current}`,
        );
        if (cancelled) return;
        applyEvents(result.events);
        cursor.current = result.latestEventSequence;
      } catch {
        // Status polling presents connection errors without flooding the page.
      }
    };
    void poll();
    const interval = window.setInterval(() => void poll(), 750);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [apiBase, applyEvents]);

  useEffect(() => {
    if (status?.state !== "connected") {
      projectListRequested.current = false;
      subscribedProject.current = "";
      return;
    }
    if (!projectListRequested.current) {
      projectListRequested.current = true;
      void command({ type: "project.list" });
    }
  }, [status?.state, command]);

  useEffect(() => {
    if (status?.state !== "connected" || !projectId) return;
    queueMicrotask(() => {
      setChats([]);
      setChatId(projectId);
      setProjectMembers([]);
      setUsageReports([]);
      setAgents([]);
    });
    void command({ type: "project.chat.list", projectId });
    void command({ type: "usage.get", projectId });
    void command({ type: "agent.list", projectId });
    void command({ type: "project.member.list", projectId });
  }, [status?.state, projectId, command]);

  useEffect(() => {
    if (status?.state !== "connected" || !projectId || !chatId) return;
    const scope = `${projectId}:${chatId}`;
    if (subscribedProject.current === scope) return;
    subscribedProject.current = scope;
    setChat([]);
    setPresence([]);
    setSharedContext(undefined);
    setFinalGoalDraft("");
    setTasks([]);
    setArtifacts([]);
    setGitIntegrations({});
    setFileReferences([]);
    setSelectedArtifactIds([]);
    dispatchReferenceArtifactSelection({ type: "project-changed" });
    ensurePromptDocument(projectId, chatId);
    void command({ type: "chat.subscribe", projectId, chatId, afterSequence: 0 });
    void command({ type: "prompt.subscribe", projectId, chatId });
    void command({ type: "context.get", projectId, chatId });
    void command({ type: "agent.task.list", projectId, chatId });
    void command({ type: "artifact.list", projectId, chatId });
    void command({ type: "project.file-reference.list", projectId, chatId });
  }, [status?.state, projectId, chatId, command, ensurePromptDocument]);

  useEffect(() => {
    if (status?.state !== "connected" || !projectId || !chatId) return;
    const refresh = () => {
      void command({ type: "agent.list", projectId });
      void command({ type: "agent.task.list", projectId, chatId });
    };
    refresh();
    const interval = window.setInterval(refresh, 2_000);
    return () => window.clearInterval(interval);
  }, [status?.state, projectId, chatId, command]);

  useEffect(() => {
    presenceConnectionState.current = status?.state;
  }, [status?.state]);

  useEffect(() => {
    if (privateTypingSentTo.current
      && privateTypingSentTo.current !== recipientDeviceId) {
      stopPrivateTyping();
    }
  }, [recipientDeviceId, stopPrivateTyping]);

  useEffect(() => {
    if (status?.state === "connected") return;
    stopPrivateTyping();
    for (const timer of privateTypingExpiryTimers.current.values()) window.clearTimeout(timer);
    privateTypingExpiryTimers.current.clear();
    queueMicrotask(() => setPrivateTypingDeviceIds([]));
  }, [status?.state, stopPrivateTyping]);

  useEffect(() => {
    const expiryTimers = privateTypingExpiryTimers.current;
    return () => {
      if (presenceSendTimer.current !== undefined) window.clearTimeout(presenceSendTimer.current);
      if (typingIdleTimer.current !== undefined) window.clearTimeout(typingIdleTimer.current);
      if (privateTypingIdleTimer.current !== undefined) window.clearTimeout(privateTypingIdleTimer.current);
      for (const timer of expiryTimers.values()) window.clearTimeout(timer);
      expiryTimers.clear();
    };
  }, []);

  useEffect(() => {
    for (const message of privateMessages) {
      if (notifiedPrivateMessageIds.current.has(message.messageId)) continue;
      notifiedPrivateMessageIds.current.add(message.messageId);
      if (!shouldNotifyPrivateMessage(message, {
        enabled: privateNotificationsEnabled,
        localDeviceId: status?.deviceId ?? "",
        selectedContactDeviceId: recipientDeviceId,
        documentVisible: document.visibilityState === "visible",
        windowFocused: document.hasFocus(),
      })) continue;
      const sender = privateContacts.find(contact => contact.deviceId === message.senderDeviceId);
      const descriptor = buildPrivateNotification(sender?.displayName ?? "", {
        title: t("cocodex.private.notificationTitle"),
        body: t("cocodex.private.notificationBody"),
        fallbackSender: t("cocodex.private.notificationFallback"),
      });
      showPrivateNotification(descriptor);
    }
  }, [
    privateContacts,
    privateMessages,
    privateNotificationsEnabled,
    recipientDeviceId,
    status?.deviceId,
    t,
  ]);

  const togglePrivateNotifications = async () => {
    if (privateNotificationsEnabled) {
      disablePrivateNotifications();
      setPrivateNotificationsEnabled(false);
      setNotice(t("cocodex.private.notificationsDisabled"));
      return;
    }
    const granted = await enablePrivateNotifications();
    setPrivateNotificationsEnabled(granted);
    setNotice(t(granted
      ? "cocodex.private.notificationsEnabled"
      : "cocodex.private.notificationsDenied"));
    if (granted) {
      showPrivateNotification({
        title: t("cocodex.title"),
        body: t("cocodex.private.notificationsEnabled"),
      });
    }
  };

  const enroll = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      const next = await cocodexApiJson<Status>(apiBase, `${apiBase}/api/cocodex/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ invite, displayName }),
      });
      setStatus(next);
      setInvite("");
      setNotice(t("cocodex.enroll.success"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const toggleSession = async () => {
    setBusy(true);
    setNotice("");
    try {
      const next = await cocodexApiJson<Status>(apiBase, `${apiBase}/api/cocodex/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: status?.running ? "stop" : "start" }),
      });
      setStatus(next);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const editSharedPrompt = (value: string) => {
    if (!projectId || !chatId) return;
    const text = ensurePromptDocument(projectId, chatId).getText("prompt");
    applyPromptTextEdit(text, value);
  };

  const sendPrompt = async (event: FormEvent) => {
    event.preventDefault();
    const submission = buildCoCodexComposerSubmission({
      projectId,
      chatId,
      agentId,
      chatDraft: draft,
      sharedPrompt,
      finalGoal: sharedContext?.finalGoal,
      inputArtifactIds: selectedArtifactIds,
    });
    if (!submission) return;
    const submittedPromptScope = submission.source === "shared-prompt"
      ? `${projectId}:${chatId}`
      : "";
    const submittedPromptText = submission.source === "shared-prompt"
      ? ensurePromptDocument(projectId, chatId).getText("prompt")
      : undefined;
    try {
      await command(submission.command);
      if (submission.source === "chat-draft") {
        setDraft(current => current === submission.submittedValue ? "" : current);
      } else if (submittedPromptText
        && promptProject.current === submittedPromptScope
        && submittedPromptText.toString() === submission.submittedValue) {
        submittedPromptText.doc?.transact(() =>
          submittedPromptText.delete(0, submittedPromptText.length));
      }
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const sendPrivate = async (event: FormEvent) => {
    event.preventDefault();
    const text = privateDraft.trim();
    const contact = privateContacts.find(item => item.deviceId === recipientDeviceId);
    if (!text || !contact) return;
    if (!contact.trusted) {
      setNotice(t("cocodex.private.verifyBeforeSending"));
      return;
    }
    stopPrivateTyping();
    setPrivateDraft("");
    try {
      await command(buildPrivateComposerCommand(contact.deviceId, text, {
        ...(privateEditTarget ? { editTargetMessageId: privateEditTarget.messageId } : {}),
        ...(privateReplyTo ? { replyToMessageId: privateReplyTo.messageId } : {}),
      }));
      setPrivateReplyTo(undefined);
      setPrivateEditTarget(undefined);
    } catch (error) {
      setPrivateDraft(text);
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const decideAgentTask = async (taskId: string, approved: boolean) => {
    try {
      await command({ type: "agent.approval", taskId, approved });
      setAgentApprovals(previous => previous.filter(item => item.id !== taskId));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const updateDeviceApproval = async (
    device: PendingDeviceApproval,
    decision: "approve" | "reject",
  ) => {
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "device.approval.update",
        targetDeviceId: device.deviceId,
        decision,
        confirmedVerificationPhrase: deviceApprovalConfirmations[device.deviceId] ?? "",
      });
      setNotice(t(decision === "approve"
        ? "cocodex.deviceApproval.approving"
        : "cocodex.deviceApproval.rejecting"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const createProject = async (event: FormEvent) => {
    event.preventDefault();
    const name = projectName.trim();
    if (!name || status?.state !== "connected") return;
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "project.create",
        projectId: crypto.randomUUID(),
        name,
        memberDeviceIds: [],
      });
      setNotice(t("cocodex.projects.creating"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const updateProjectLifecycle = async (action: ProjectLifecycleAction) => {
    if (!selectedProject || selectedProject.role !== "owner" || status?.state !== "connected") return;
    let value: string | undefined;
    if (action === "rename") {
      const entered = window.prompt(t("cocodex.projects.renamePrompt"), selectedProject.name);
      if (entered === null || entered.trim() === selectedProject.name) return;
      value = entered;
    } else if (action === "archive") {
      if (!window.confirm(t("cocodex.projects.archiveConfirm", { name: selectedProject.name }))) return;
    } else if (action === "restore") {
      if (!window.confirm(t("cocodex.projects.restoreConfirm", { name: selectedProject.name }))) return;
    } else {
      const entered = window.prompt(t("cocodex.projects.deleteConfirm", { name: selectedProject.name }));
      if (entered === null) return;
      value = entered;
      if (value !== selectedProject.name) {
        setNotice(t("cocodex.projects.deleteMismatch"));
        return;
      }
    }
    setBusy(true);
    setNotice("");
    try {
      await command(projectLifecycleCommand(selectedProject, action, value));
      setNotice(t("cocodex.projects.lifecyclePending"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const leaveProject = async () => {
    if (!selectedProject || selectedProject.role !== "member" || status?.state !== "connected") return;
    if (!window.confirm(t("cocodex.projects.leaveConfirm", { name: selectedProject.name }))) return;
    setBusy(true);
    setNotice("");
    try {
      await command(projectLeaveCommand(selectedProject));
      setNotice(t("cocodex.projects.leaveQueued"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const createChat = async (event: FormEvent) => {
    event.preventDefault();
    const title = chatTitle.trim();
    if (!projectId || !title || status?.state !== "connected") return;
    try {
      await command({ type: "project.chat.create", projectId, chatId: crypto.randomUUID(), title });
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const inviteProjectMember = async (contact: PrivateContact) => {
    if (!projectId || !contact.trusted || !contact.projectCapable) return;
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "project.invite.create",
        projectId,
        recipientDeviceId: contact.deviceId,
      });
      setNotice(t("cocodex.invites.sent", { name: contact.displayName }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const respondToProjectInvitation = async (
    invitation: ProjectInvitation,
    decision: "accept" | "decline",
  ) => {
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "project.invite.respond",
        invitationId: invitation.invitationId,
        decision,
      });
      setNotice(t(decision === "accept" ? "cocodex.invites.accepted" : "cocodex.invites.declined", {
        name: invitation.projectName,
      }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const cancelProjectInvitation = async (invitation: ProjectInvitation) => {
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "project.invite.cancel",
        invitationId: invitation.invitationId,
      });
      setNotice(t("cocodex.invites.cancelled", { name: invitation.recipientDisplayName }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const verifyPrivateContact = async (contact: PrivateContact) => {
    if (!independentlyConfirmedFingerprintMatches(privateVerificationFingerprint, contact.fingerprint)) {
      setNotice(t("cocodex.private.verificationMismatch"));
      return;
    }
    try {
      await command({
        type: "device.trust",
        deviceId: contact.deviceId,
        fingerprint: contact.fingerprint,
      });
      setPrivateVerificationFingerprint("");
      setPrivateContacts(previous => previous.map(item =>
        item.deviceId === contact.deviceId ? { ...item, trusted: true } : item));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const configureAgent = async (event: FormEvent) => {
    event.preventDefault();
    if (!projectId) return;
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "agent.configure",
        projectId,
        name: agentName.trim(),
        workspaceRoot: agentWorkspace.trim(),
        workspaceMode: agentWorkspaceMode,
        primaryModel: agentPrimaryModel.trim(),
        primaryEffort: agentPrimaryEffort,
        coAgentModel: agentMaxCoAgents > 0 ? agentCoAgentModel.trim() : null,
        coAgentEffort: agentMaxCoAgents > 0 ? agentCoAgentEffort : null,
        maxConcurrentCoAgents: agentMaxCoAgents,
        sandbox: "workspace-write",
        accessProfile: "project-only",
        approvalMode: "trusted-device",
        trustedRequesterDeviceId: trustedRequesterDeviceId.trim(),
        trustedRequesterFingerprint: trustedRequesterFingerprint.trim(),
      });
      setNotice(t("cocodex.agent.setup.pending"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const previewGitIntegration = useCallback((taskId: string) => {
    if (!projectId || !chatId) return;
    void command({
      type: "git.integration.preview",
      projectId,
      chatId,
      taskId,
    }).catch(error => setNotice(error instanceof Error ? error.message : String(error)));
  }, [chatId, command, projectId]);

  const integrateGitIntegration = useCallback((taskId: string, expectedTargetCommit: string) => {
    if (!projectId || !chatId || !expectedTargetCommit) return;
    void command({
      type: "git.integration.integrate",
      projectId,
      chatId,
      taskId,
      expectedTargetCommit,
    }).catch(error => setNotice(error instanceof Error ? error.message : String(error)));
  }, [chatId, command, projectId]);
  const publishArtifact = async (event: FormEvent) => {
    event.preventDefault();
    if (!projectId) return;
    try {
      await command({
        type: "artifact.publish",
        projectId,
        chatId,
        taskId: null,
        artifactType: "handoff",
        title: artifactTitle.trim(),
        summary: artifactSummary.trim(),
        content: artifactContent,
        status: "ready",
      });
      setArtifactTitle("");
      setArtifactSummary("");
      setArtifactContent("");
      setNotice(t("cocodex.artifacts.queued"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const publishFileReference = async (event: FormEvent) => {
    event.preventDefault();
    if (!projectId || !referenceArtifactId) return;
    try {
      await command({
        type: "project.file-reference.publish",
        projectId,
        chatId,
        artifactId: referenceArtifactId,
        workspaceRoot: referenceWorkspaceRoot.trim(),
        path: referencePath.trim(),
        workspaceMode: referenceWorkspaceMode,
        workspaceRef: referenceWorkspaceRef.trim(),
        mediaType: referenceMediaType.trim() || null,
      });
      setReferencePath("");
      setReferenceMediaType("");
      setNotice(t("cocodex.fileReferences.queued"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const sharePrivate = async (message: PrivateMessage) => {
    if (!projectId || !agentId.trim()) {
      setNotice("Select an agent in the shared-chat composer before sharing a private message.");
      return;
    }
    try {
      await command({
        type: "private.share",
        projectId,
        chatId,
        agentId: agentId.trim(),
        messageId: message.messageId,
      });
      setNotice(t("cocodex.private.shared"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const markPrivateRead = async (message: PrivateMessage) => {
    if (privateReceipts[message.messageId] === "read") return;
    try {
      await command({ type: "private.read", messageId: message.messageId });
      setPrivateReceipts(previous => ({ ...previous, [message.messageId]: "read" }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const beginPrivateReply = (message: ProjectedPrivateMessage) => {
    setPrivateEditTarget(undefined);
    setPrivateReplyTo(message);
    setPrivateDraft("");
  };

  const beginPrivateEdit = (message: ProjectedPrivateMessage) => {
    setPrivateReplyTo(undefined);
    setPrivateEditTarget(message);
    setPrivateDraft(message.text);
  };

  const sendPrivateMutation = async (
    message: ProjectedPrivateMessage,
    mutation: { kind: "delete" } | {
      kind: "reaction";
      emoji: string;
      reactionOperation: "add" | "remove";
    },
  ) => {
    const contactId = message.senderDeviceId === status?.deviceId
      ? message.recipientDeviceId
      : message.senderDeviceId;
    const contact = privateContacts.find(item => item.deviceId === contactId);
    if (!contact?.trusted) {
      setNotice(t("cocodex.private.verifyBeforeSending"));
      return;
    }
    try {
      await command(buildPrivateMutationCommand(
        contact.deviceId,
        message.messageId,
        mutation,
      ));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const deletePrivateMessage = async (message: ProjectedPrivateMessage) => {
    if (!window.confirm(t("cocodex.private.deleteConfirm"))) return;
    await sendPrivateMutation(message, { kind: "delete" });
  };

  const togglePrivateReaction = async (message: ProjectedPrivateMessage) => {
    const reacted = message.reactions.some(reaction =>
      reaction.emoji === "thumbs-up" && reaction.senderDeviceIds.includes(status?.deviceId ?? ""));
    await sendPrivateMutation(message, {
      kind: "reaction",
      emoji: "thumbs-up",
      reactionOperation: reacted ? "remove" : "add",
    });
  };

  const localSafetyCommand = async (type: string, agentId: string, confirm = false) => {
    try {
      await command({ type, agentId, ...(confirm ? { confirm: true } : {}) });
      await loadStatus();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const openOfficialCodex = async (agentId: string) => {
    try {
      await command({ type: "codex.official-app.open", agentId });
      setNotice(t("cocodex.browser.opening"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const emergencyStopAllLocalAgents = async () => {
    const agentIds = executableLocalAgentIds(status?.localAgents ?? []);
    if (!agentIds.length || !window.confirm(t("cocodex.agent.safety.stopAllConfirm"))) return;
    setBusy(true);
    setNotice("");
    try {
      await stopEveryLocalAgent(agentIds, agentId => command({ type: "agent.emergency.stop", agentId }));
      setNotice(t("cocodex.agent.safety.stoppedAll"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      await loadStatus();
      setBusy(false);
    }
  };

  const removeProjectMember = async (member: ProjectMember) => {
    if (!projectId || projects.find(project => project.id === projectId)?.role !== "owner") return;
    if (!confirmProjectMemberRemoval(t, member, message => window.confirm(message))) return;
    setBusy(true);
    setNotice("");
    try {
      await command(projectMemberRemovalCommand(projectId, member));
      setNotice(t("cocodex.members.removalQueued", { name: member.displayName }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const trustProjectMember = async (member: ProjectMember) => {
    if (!projectId || member.trusted) return;
    if (!window.confirm(t("cocodex.members.trustConfirm", {
      name: member.displayName,
      fingerprint: member.fingerprint,
    }))) return;
    setBusy(true);
    setNotice("");
    try {
      await command({
        type: "device.trust",
        deviceId: member.deviceId,
        fingerprint: member.fingerprint,
      });
      await command({ type: "project.member.list", projectId });
      setNotice(t("cocodex.members.trustedNotice", { name: member.displayName }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const saveFinalGoal = async (event: FormEvent) => {
    event.preventDefault();
    if (!projectId || !sharedContext || status?.state !== "connected") return;
    try {
      await command({
        type: "context.update",
        projectId,
        chatId,
        expectedRevision: sharedContext.revision,
        finalGoal: finalGoalDraft,
        context: sharedContext.context,
      });
      setNotice(t("cocodex.goal.queued"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const sendPresenceState = useCallback((targetProjectId: string, targetChatId: string | null, state: LocalPresence) => {
    if (presenceConnectionState.current !== "connected" || !targetProjectId) return;
    void command({ type: "presence.update", projectId: targetProjectId, chatId: targetChatId, ...state });
  }, [command]);

  const publishPresence = useCallback((patch: Partial<LocalPresence>, immediate = true) => {
    if (!projectId || !chatId) return;
    const targetProjectId = projectId;
    const targetChatId = chatId;
    const next = { ...localPresence.current, ...patch };
    localPresence.current = next;
    if (next.typing) {
      if (typingIdleTimer.current !== undefined) window.clearTimeout(typingIdleTimer.current);
      typingIdleTimer.current = window.setTimeout(() => {
        if (presenceProject.current !== `${targetProjectId}:${targetChatId}`) return;
        const idle = { ...localPresence.current, typing: false };
        localPresence.current = idle;
        sendPresenceState(targetProjectId, targetChatId, idle);
      }, 1_500);
    }
    if (presenceSendTimer.current !== undefined) window.clearTimeout(presenceSendTimer.current);
    if (immediate) {
      sendPresenceState(targetProjectId, targetChatId, next);
    } else {
      presenceSendTimer.current = window.setTimeout(() => {
        sendPresenceState(targetProjectId, targetChatId, localPresence.current);
      }, 100);
    }
  }, [projectId, chatId, sendPresenceState]);

  useEffect(() => {
    const previousScope = presenceProject.current;
    const nextScope = projectId && chatId ? `${projectId}:${chatId}` : "";
    if (previousScope && previousScope !== nextScope && presenceConnectionState.current === "connected") {
      const [previousProjectId, previousChatId] = previousScope.split(":");
      sendPresenceState(previousProjectId!, previousChatId ?? null, {
        cursor: null, caret: null, relativeCaret: null, typing: false,
      });
    }
    presenceProject.current = nextScope;
    localPresence.current = { cursor: null, caret: null, relativeCaret: null, typing: false };
    if (presenceSendTimer.current !== undefined) window.clearTimeout(presenceSendTimer.current);
    if (typingIdleTimer.current !== undefined) window.clearTimeout(typingIdleTimer.current);
  }, [projectId, chatId, sendPresenceState]);

  useEffect(() => {
    if (status?.state !== "connected" || !projectId || !chatId) return;
    presenceProject.current = `${projectId}:${chatId}`;
    sendPresenceState(projectId, chatId, localPresence.current);
  }, [projectId, chatId, sendPresenceState, status?.state]);

  const visiblePresence = status?.state === "connected" ? presence : [];
  const visibleAgents = status?.state === "connected" ? agents : [];
  const visibleTasks = status?.state === "connected" ? tasks : [];
  const visibleArtifacts = status?.state === "connected" ? artifacts : [];
  const visibleFileReferences = status?.state === "connected" ? fileReferences : [];
  const projectLocalAgents = (status?.localAgents ?? []).filter(agent => agent.projectId === projectId);
  const browserPresentation = browserCapabilityPresentation(browserCapability);
  const selectedProjectSecurity = projectSecurity[projectId];
  const selectedProject = projects.find(project => project.id === projectId);
  const selectedProjectArchived = selectedProject?.state === "archived";
  const selectedProjectLocked = selectedProject?.lock?.state === "locked" || selectedProjectArchived;
  const visibleProjects = orderedProjects(projects);
  const selectedChat = chats.find(item => item.id === chatId);
  const remotePromptPresence = visiblePresence.filter(member => member.deviceId !== status?.deviceId
    && (member.typing || member.caret || member.relativeCaret)).map(member => ({
      ...member,
      caret: activePromptDoc
        ? resolvePromptRelativeCaret(
          activePromptDoc.getText("prompt"),
          member.relativeCaret,
          member.caret,
        )
        : member.caret,
    }));
  const selectedPrivateContact = privateContacts.find(contact => contact.deviceId === recipientDeviceId);
  const projectedPrivateMessages = projectPrivateMessageEvents(privateMessages);
  const selectedPrivateMessages = privateTimelineForContact(
    projectedPrivateMessages,
    selectedPrivateContact?.deviceId ?? "",
    "",
  );
  const visiblePrivateMessages = privateTimelineForContact(
    projectedPrivateMessages,
    selectedPrivateContact?.deviceId ?? "",
    privateSearch,
  );

  return (
    <div className="cocodex-page">
      <header className="cocodex-head">
        <div>
          <div className="cocodex-kicker"><IconLock /> {t("cocodex.kicker")}</div>
          <h2>{t("cocodex.title")}</h2>
          <p>{t("cocodex.subtitle")}</p>
        </div>
        {status?.configured && <div className="cocodex-head-actions">
          {status.localAgents.some(agent => agent.executionEnabled) && (
            <button type="button" className="btn btn-danger cocodex-emergency-stop"
              disabled={busy || !status.running} onClick={() => void emergencyStopAllLocalAgents()}>
              {t("cocodex.agent.safety.stopAll")}
            </button>
          )}
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void toggleSession()}>
            {t(status.running ? "cocodex.disconnect" : "cocodex.connect")}
          </button>
        </div>}
      </header>

      {(runtimeNotice || notice) && <div className="cocodex-notice" role="status">{runtimeNotice || notice}</div>}
      {status?.configured && status.state !== "connected" && status.verificationPhrase
        && status.approvalExpiresAt && (
        <div className="cocodex-notice cocodex-enrollment-verification" role="status">
          <strong>{t("cocodex.deviceApproval.yourPhrase")}</strong>
          <code>{status.verificationPhrase}</code>
          <small>{t("cocodex.deviceApproval.yourPhraseHelp", {
            time: new Date(status.approvalExpiresAt).toLocaleTimeString(),
          })}</small>
        </div>
      )}
      {selectedProjectSecurity && projectId && (
        <div className="cocodex-notice" role="alert">
          <strong>{selectedProjectSecurity.state === "device-revoked"
            ? t("cocodex.security.deviceRevoked")
            : t("cocodex.encryption.rotationRequired")}</strong>
          {selectedProjectSecurity.revokedDeviceId && (
            <small> {selectedProjectSecurity.revokedDeviceId.slice(0, 12)}</small>
          )}
          {selectedProjectSecurity.promotedOwnerDeviceId && (
            <small> · {t("cocodex.security.promotedOwner", {
              device: selectedProjectSecurity.promotedOwnerDeviceId.slice(0, 12),
            })}</small>
          )}
          {selectedProjectSecurity.state === "device-revoked"
            && selectedProject?.role === "owner"
            && projectMembers.some(member => isRevokedProjectMember(member) && member.role !== "owner") && (
            <small> · {t("cocodex.security.ownerRecovery")}</small>
          )}
        </div>
      )}
      {selectedProjectLocked && selectedProject && (
        <div className="cocodex-notice" role="alert">
          <strong>{t("cocodex.lock.title")}</strong>
          <small> {selectedProject.lock?.reason ?? t("cocodex.lock.defaultReason")}</small>
          {selectedProject.role === "owner" && (
            <button type="button" className="btn btn-ghost"
              disabled={busy || status?.state !== "connected"}
              onClick={() => void command({
                type: "project.lock.update",
                projectId: selectedProject.id,
                action: "unlock",
                expectedRevision: selectedProject.lock?.revision,
                reason: t("cocodex.lock.unlockReason"),
              })}>
              {t("cocodex.lock.unlock")}
            </button>
          )}
        </div>
      )}
      {agentApprovals.map(approval => (
        <section className="cocodex-agent-approval" role="alert" key={approval.id}>
          <div>
            <strong>{t("cocodex.approval.title", { agent: approval.agentId })}</strong>
            <small>{t("cocodex.approval.requester", { device: approval.requesterDeviceId })}</small>
            <pre>{approval.prompt}</pre>
          </div>
          <div className="cocodex-agent-approval-actions">
            <button type="button" className="btn btn-danger" onClick={() => void decideAgentTask(approval.id, false)}>
              {t("cocodex.approval.reject")}</button>
            <button type="button" className="btn btn-primary" onClick={() => void decideAgentTask(approval.id, true)}>
              {t("cocodex.approval.approve")}</button>
          </div>
        </section>
      ))}

      {!status?.configured ? (
        <form className="card cocodex-enroll" onSubmit={enroll}>
          <IconKey />
          <div>
            <h3>{t("cocodex.enroll.title")}</h3>
            <p>{t("cocodex.enroll.subtitle")}</p>
          </div>
          <input className="input" value={displayName} onChange={event => setDisplayName(event.target.value)}
            placeholder={t("cocodex.enroll.name")} required maxLength={80} />
          <textarea className="input" value={invite} onChange={event => setInvite(event.target.value)}
            placeholder={t("cocodex.enroll.invite")} required rows={4} />
          <button className="btn btn-primary" disabled={busy}>{t("cocodex.enroll.action")}</button>
        </form>
      ) : (
        <div className="cocodex-shell" onMouseMove={event => {
          if (Date.now() - presenceSentAt.current < 80) return;
          presenceSentAt.current = Date.now();
          const rect = event.currentTarget.getBoundingClientRect();
          publishPresence({ cursor: {
            x: Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)),
            y: Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height)),
          } });
        }} onMouseLeave={() => publishPresence({ cursor: null })}>
          <div className="cocodex-presence-layer" aria-hidden="true">
            {visiblePresence.filter(member => member.deviceId !== status.deviceId && member.cursor).map(member => (
              <span key={member.deviceId} className="cocodex-presence-cursor"
                style={{ left: `${(member.cursor?.x ?? 0) * 100}%`, top: `${(member.cursor?.y ?? 0) * 100}%` }}>
                <i />{member.displayName}
              </span>
            ))}
          </div>
          <aside className="card cocodex-projects">
            <div className="cocodex-section-head">
              <span>{t("cocodex.projects")}</span>
              <button type="button" className="btn btn-ghost btn-icon" title={t("cocodex.projects.refresh")}
                onClick={() => void command({ type: "project.list" })} disabled={status.state !== "connected"}>
                <IconRefresh />
              </button>
            </div>
            <div className={`cocodex-state state-${status.state}`}>
              <span className="cocodex-state-dot" />
              <div>
                <strong>{stateLabel(t, status.state)}</strong>
                <small>{status.server ? `${status.server.host}:${status.server.port}` : t("cocodex.server.none")}</small>
              </div>
            </div>
            {projectInvitations.some(invitation =>
              invitation.direction === "incoming" && invitation.status === "pending") && (
              <section className="cocodex-invitations">
                <div className="cocodex-section-head">
                  <span>{t("cocodex.invites.title")}</span>
                  <button type="button" className="btn btn-ghost btn-icon"
                    title={t("cocodex.invites.refresh")}
                    onClick={() => void command({ type: "project.invite.list" })}
                    disabled={status.state !== "connected"}>
                    <IconRefresh />
                  </button>
                </div>
                {projectInvitations.filter(invitation =>
                  invitation.direction === "incoming" && invitation.status === "pending").map(invitation => (
                  <article key={invitation.invitationId}>
                    <span>
                      <strong>{invitation.projectName}</strong>
                      <small>{t("cocodex.invites.from", { name: invitation.ownerDisplayName })}
                        {" \u00b7 "}{invitation.ownerFingerprint.slice(-12)}</small>
                      {!invitation.trusted && <small>{t("cocodex.invites.verifyOwner")}</small>}
                    </span>
                    <div>
                      <button type="button" className="btn btn-ghost"
                        disabled={busy || status.state !== "connected"}
                        onClick={() => void respondToProjectInvitation(invitation, "decline")}>
                        {t("cocodex.invites.decline")}
                      </button>
                      <button type="button" className="btn btn-primary"
                        disabled={busy || status.state !== "connected" || !invitation.actionable}
                        onClick={() => void respondToProjectInvitation(invitation, "accept")}>
                        {t("cocodex.invites.accept")}
                      </button>
                    </div>
                  </article>
                ))}
              </section>
            )}
            <div className="cocodex-project-list">
              {visibleProjects.map(project => (
                <button key={project.id} type="button" className={`${project.id === projectId ? "active" : ""}${project.state === "archived" ? " archived" : ""}`.trim()}
                  onClick={() => setProjectId(project.id)}>
                  <IconServer />
                  <span>{project.name}<small>{project.role}
                    {project.state === "archived" ? `${t("cocodex.projects.metaSeparator")}${t("cocodex.projects.archived")}` : ""}
                    {project.lock?.state === "locked" ? `${t("cocodex.projects.metaSeparator")}${t("cocodex.lock.short")}` : ""}</small></span>
                </button>
              ))}
              {!projects.length && <p className="muted">{t("cocodex.projects.empty")}</p>}
            </div>
            {projectId && (
              <section className="cocodex-chats">
                <div className="cocodex-section-head">
                  <span>{t("cocodex.chats.title")}</span>
                  <button type="button" className="btn btn-ghost btn-icon"
                    title={t("cocodex.chats.refresh")}
                    onClick={() => void command({ type: "project.chat.list", projectId })}
                    disabled={status.state !== "connected"}>
                    <IconRefresh />
                  </button>
                </div>
                <div className="cocodex-project-list">
                  {chats.map(item => (
                    <button key={item.id} type="button" className={item.id === chatId ? "active" : ""}
                      onClick={() => setChatId(item.id)}>
                      <span>{item.title}</span>
                    </button>
                  ))}
                </div>
                <form className="cocodex-project-create" onSubmit={createChat}>
                  <input className="input" value={chatTitle}
                    onChange={event => setChatTitle(event.target.value)}
                    placeholder={t("cocodex.chats.name")} maxLength={120} required />
                  <button type="submit" className="btn btn-primary"
                    disabled={status.state !== "connected" || selectedProjectLocked || !chatTitle.trim()}>
                    {t("cocodex.chats.create")}
                  </button>
                </form>
              </section>
            )}
            <form className="cocodex-project-create" onSubmit={createProject}>
              <input className="input" value={projectName}
                onChange={event => setProjectName(event.target.value)}
                placeholder={t("cocodex.projects.name")} maxLength={120} required />
              <small>{t("cocodex.projects.ownerOnly")}</small>
              <button type="submit" className="btn btn-primary"
                disabled={busy || status.state !== "connected" || !projectName.trim()}>
                {t("cocodex.projects.create")}
              </button>
            </form>
            {selectedProject?.role === "owner" && (
              <section className="cocodex-project-lifecycle">
                <strong>{t("cocodex.projects.manage")}</strong>
                <small>{selectedProjectArchived
                  ? t("cocodex.projects.archivedHelp")
                  : t("cocodex.projects.manageHelp")}</small>
                <div>
                  {!selectedProjectArchived && <button type="button" className="btn btn-ghost"
                    disabled={busy || status.state !== "connected" || selectedProjectLocked}
                    onClick={() => void updateProjectLifecycle("rename")}>
                    {t("cocodex.projects.rename")}
                  </button>}
                  {!selectedProjectArchived && <button type="button" className="btn btn-ghost"
                    disabled={busy || status.state !== "connected" || selectedProject?.lock?.state !== "locked"}
                    onClick={() => void updateProjectLifecycle("archive")}>
                    {t("cocodex.projects.archive")}
                  </button>}
                  {selectedProjectArchived && <button type="button" className="btn btn-ghost"
                    disabled={busy || status.state !== "connected"}
                    onClick={() => void updateProjectLifecycle("restore")}>
                    {t("cocodex.projects.restore")}
                  </button>}
                  {selectedProjectArchived && <button type="button" className="btn btn-danger btn-ghost"
                    disabled={busy || status.state !== "connected"}
                    onClick={() => void updateProjectLifecycle("delete")}>
                    {t("cocodex.projects.delete")}
                  </button>}
                </div>
              </section>
            )}
            {selectedProject?.role === "member" && (
              <section className="cocodex-project-lifecycle">
                <strong>{t("cocodex.projects.leave")}</strong>
                <small>{t("cocodex.projects.leaveHelp")}</small>
                <div>
                  <button type="button" className="btn btn-danger btn-ghost"
                    disabled={busy || status.state !== "connected"}
                    onClick={() => void leaveProject()}>
                    {t("cocodex.projects.leave")}
                  </button>
                </div>
              </section>
            )}
            {projectId && <ProjectMemberRoster
              members={projectMembers}
              owner={projects.find(project => project.id === projectId)?.role === "owner" && !selectedProjectArchived}
              connected={status.state === "connected"}
              busy={busy}
              onRefresh={() => void command({ type: "project.member.list", projectId })}
              onTrust={member => void trustProjectMember(member)}
              onRemove={member => void removeProjectMember(member)}
            />}
            {selectedProject?.role === "owner" && !selectedProjectLocked && (
              <button type="button" className="btn btn-danger btn-ghost"
                disabled={busy || status.state !== "connected"}
                onClick={() => void command({
                  type: "project.lock.update",
                  projectId: selectedProject.id,
                  action: "lock",
                  expectedRevision: selectedProject.lock?.revision ?? 0,
                  reason: t("cocodex.lock.defaultReason"),
                })}>
                <IconLock /> {t("cocodex.lock.action")}
              </button>
            )}
            {projectId && projects.find(project => project.id === projectId)?.role === "owner" && !selectedProjectArchived && (
              <section className="cocodex-invite-people">
                <strong>{t("cocodex.invites.people")}</strong>
                <small>{t("cocodex.invites.peopleHelp")}</small>
                {privateContacts.filter(contact =>
                  contact.trusted
                  && contact.projectCapable
                  && !projectMembers.some(member => member.deviceId === contact.deviceId)
                  && !projectInvitations.some(invitation =>
                    invitation.projectId === projectId
                    && invitation.recipientDeviceId === contact.deviceId
                    && invitation.status === "pending")).map(contact => (
                  <button type="button" className="btn btn-ghost" key={contact.deviceId}
                    disabled={busy || status.state !== "connected" || selectedProjectLocked}
                    onClick={() => void inviteProjectMember(contact)}>
                    {t("cocodex.invites.invite", { name: contact.displayName })}
                  </button>
                ))}
                {projectInvitations.filter(invitation =>
                  invitation.projectId === projectId
                  && invitation.direction === "outgoing"
                  && invitation.status === "pending").map(invitation => (
                  <span className="cocodex-invite-pending" key={invitation.invitationId}>
                    <small>{t("cocodex.invites.pending", { name: invitation.recipientDisplayName })}</small>
                    <button type="button" className="btn btn-ghost"
                      disabled={busy || status.state !== "connected"}
                      onClick={() => void cancelProjectInvitation(invitation)}>
                      {t("cocodex.invites.cancel")}
                    </button>
                  </span>
                ))}
              </section>
            )}
            <div className="cocodex-device">
              <small>{t("cocodex.device.this")}</small>
              <strong>{status.displayName}</strong>
              <code>{status.deviceId?.slice(0, 12)}</code>
              <span>{projectLocalAgents.length > 0
                ? t("cocodex.agent.configuredCount", { count: projectLocalAgents.length })
                : t("cocodex.agent.none")}</span>
              {projectLocalAgents.map(localAgent => <div className="cocodex-agent-safety" key={localAgent.agentId}>
                <strong>{visibleAgents.find(agent => agent.id === localAgent.agentId)?.name ?? localAgent.agentId.slice(0, 12)}</strong>
                <small>{t("cocodex.agent.access", { profile: localAgent.accessProfile })}</small>
                <small>{t(localAgent.workspaceMode === "git-worktree"
                  ? "cocodex.agent.workspace.worktree"
                  : "cocodex.agent.workspace.shared")}</small>
                <small>{localAgent.primaryModel} · {localAgent.primaryEffort}</small>
                <small>{localAgent.maxConcurrentCoAgents > 0
                  ? t("cocodex.agent.coagents.summary", {
                    count: localAgent.maxConcurrentCoAgents,
                    model: localAgent.coAgentModel ?? "",
                    effort: localAgent.coAgentEffort ?? "",
                  })
                  : t("cocodex.agent.coagents.none")}</small>
                <small>{t(localAgent.executionEnabled ? "cocodex.agent.execution.enabled" : "cocodex.agent.execution.stopped")}
                  {localAgent.accessProfile === "full-computer" && !localAgent.fullComputerEnabled
                    ? ` · ${t("cocodex.agent.fullComputer.disabled")}` : ""}</small>
                <div className="cocodex-browser-capability" role="status">
                  <small><strong>{t("cocodex.browser.label")}</strong>{" / "}{t(browserPresentation.state === "checking"
                    ? "cocodex.browser.checking"
                    : browserPresentation.state === "official-app-only"
                      ? "cocodex.browser.officialAppOnly"
                      : "cocodex.browser.unavailable")}</small>
                  <small>{t("cocodex.browser.cliUnavailable")}</small>
                  {browserPresentation.canOpenOfficialApp && <button type="button" className="btn btn-ghost"
                    disabled={!status.running} onClick={() => void openOfficialCodex(localAgent.agentId)}>
                    {t("cocodex.browser.openOfficial")}
                  </button>}
                </div>
                <div className="cocodex-agent-safety-actions">
                  <button type="button" className="btn btn-danger btn-ghost" disabled={!status.running}
                    onClick={() => void localSafetyCommand("agent.emergency.stop", localAgent.agentId)}>
                    {t("cocodex.agent.safety.stop")}
                  </button>
                  <button type="button" className="btn btn-ghost" disabled={!status.running}
                    onClick={() => void localSafetyCommand("agent.emergency.resume", localAgent.agentId)}>
                    {t("cocodex.agent.safety.resume")}
                  </button>
                  {localAgent.accessProfile === "full-computer" && <button type="button" className="btn btn-ghost" disabled={!status.running}
                    onClick={() => {
                      if (localAgent.fullComputerEnabled) {
                        void localSafetyCommand("agent.full-computer.disable", localAgent.agentId);
                      } else if (window.confirm(t("cocodex.agent.fullComputer.confirm"))) {
                        void localSafetyCommand("agent.full-computer.enable", localAgent.agentId, true);
                      }
                    }}>{t(localAgent.fullComputerEnabled ? "cocodex.agent.fullComputer.disable" : "cocodex.agent.fullComputer.enable")}</button>}
                </div>
              </div>)}
              {projectId && projectLocalAgents.length < 8 && <form className="cocodex-agent-setup" onSubmit={configureAgent}>
                <strong>{t("cocodex.agent.setup.title")}</strong>
                <small>{t("cocodex.agent.setup.subtitle")}</small>
                <input className="input" value={agentName} onChange={event => setAgentName(event.target.value)}
                  placeholder={t("cocodex.agent.setup.name")} required maxLength={120} />
                <input className="input" value={agentWorkspace} onChange={event => setAgentWorkspace(event.target.value)}
                  placeholder={t("cocodex.agent.setup.workspace")} required />
                <select className="input" value={agentWorkspaceMode}
                  onChange={event => setAgentWorkspaceMode(event.target.value as "shared" | "git-worktree")}>
                  <option value="git-worktree">{t("cocodex.agent.setup.worktree")}</option>
                  <option value="shared">{t("cocodex.agent.setup.shared")}</option>
                </select>
                <input className="input" value={agentPrimaryModel}
                  onChange={event => setAgentPrimaryModel(event.target.value)}
                  placeholder={t("cocodex.agent.setup.primaryModel")} required maxLength={160} />
                <select className="input" value={agentPrimaryEffort}
                  onChange={event => setAgentPrimaryEffort(event.target.value as AgentView["primaryEffort"])}>
                  {(["minimal", "low", "medium", "high", "xhigh", "max"] as const)
                    .map(effort => <option key={effort} value={effort}>{effort}</option>)}
                </select>
                <input className="input" type="number" min={0} max={8} value={agentMaxCoAgents}
                  onChange={event => setAgentMaxCoAgents(Math.max(0, Math.min(8, Number(event.target.value))))}
                  aria-label={t("cocodex.agent.setup.maxCoAgents")} />
                {agentMaxCoAgents > 0 && <>
                  <input className="input" value={agentCoAgentModel}
                    onChange={event => setAgentCoAgentModel(event.target.value)}
                    placeholder={t("cocodex.agent.setup.coAgentModel")} required maxLength={160} />
                  <select className="input" value={agentCoAgentEffort}
                    onChange={event => setAgentCoAgentEffort(event.target.value as NonNullable<AgentView["coAgentEffort"]>)}>
                    {(["minimal", "low", "medium", "high", "xhigh", "max"] as const)
                      .map(effort => <option key={effort} value={effort}>{effort}</option>)}
                  </select>
                </>}
                <input className="input cocodex-key-input" value={trustedRequesterDeviceId}
                  onChange={event => setTrustedRequesterDeviceId(event.target.value)}
                  placeholder={t("cocodex.agent.setup.device")} required />
                <input className="input cocodex-key-input" value={trustedRequesterFingerprint}
                  onChange={event => setTrustedRequesterFingerprint(event.target.value)}
                  placeholder={t("cocodex.agent.setup.fingerprint")} required />
                <button className="btn btn-ghost"
                  disabled={busy || status.state !== "connected" || selectedProjectLocked}>
                  {t("cocodex.agent.setup.action")}
                </button>
              </form>}
            </div>
          </aside>

          <section className="card cocodex-chat">
            <div className="cocodex-section-head">
              <div>
                <strong>{selectedChat?.title
                  || projects.find(project => project.id === projectId)?.name
                  || t("cocodex.chat.title")}</strong>
                <small>{t("cocodex.chat.ordered")}</small>
              </div>
              <span className="cocodex-lock"><IconLock /> {t("cocodex.chat.transport")}</span>
            </div>
            <form className="cocodex-final-goal" onSubmit={saveFinalGoal}>
              <div className="cocodex-final-goal-head">
                <span><strong>{t("cocodex.goal.title")}</strong><small>{t("cocodex.goal.subtitle")}</small></span>
                <span className="cocodex-goal-revision">{t("cocodex.goal.revision", { revision: sharedContext?.revision ?? 0 })}</span>
              </div>
              <textarea className="input" value={finalGoalDraft} onChange={event => setFinalGoalDraft(event.target.value)}
                placeholder={t("cocodex.goal.placeholder")} rows={2} maxLength={32_768}
                disabled={!status.running || !projectId || !sharedContext || selectedProjectLocked} />
              <button type="submit" className="btn btn-ghost cocodex-goal-save"
                disabled={!sharedContext || selectedProjectLocked || status.state !== "connected" || finalGoalDraft === sharedContext.finalGoal}>
                {t("cocodex.goal.save")}
              </button>
            </form>
            <label className="cocodex-shared-prompt">
              <span><strong>{t("cocodex.prompt.title")}</strong><small>{t("cocodex.prompt.crdt")}</small></span>
              <CollaborativePromptEditor className="input" value={sharedPrompt}
                remotePresence={remotePromptPresence}
                onChange={event => {
                  editSharedPrompt(event.target.value);
                  const caret = {
                    anchor: event.currentTarget.selectionStart,
                    head: event.currentTarget.selectionEnd,
                  };
                  publishPresence({
                    caret,
                    relativeCaret: encodePromptRelativeCaret(
                      ensurePromptDocument(projectId, chatId).getText("prompt"),
                      caret,
                    ),
                    typing: true,
                  }, false);
                }}
                onFocus={event => {
                  const caret = {
                    anchor: event.currentTarget.selectionStart,
                    head: event.currentTarget.selectionEnd,
                  };
                  publishPresence({
                    caret,
                    relativeCaret: encodePromptRelativeCaret(
                      ensurePromptDocument(projectId, chatId).getText("prompt"),
                      caret,
                    ),
                  });
                }}
                onSelect={event => {
                  const caret = {
                    anchor: event.currentTarget.selectionStart,
                    head: event.currentTarget.selectionEnd,
                  };
                  publishPresence({
                    caret,
                    relativeCaret: encodePromptRelativeCaret(
                      ensurePromptDocument(projectId, chatId).getText("prompt"),
                      caret,
                    ),
                  });
                }}
                onBlur={() => publishPresence({
                  caret: null, relativeCaret: null, typing: false,
                })}
                placeholder={t("cocodex.prompt.placeholder")} rows={3}
                disabled={!status.running || !projectId || selectedProjectLocked} />
              {remotePromptPresence.length > 0 && <div className="cocodex-prompt-presence" aria-live="polite">
                {remotePromptPresence.map(member => {
                  const caret = member.caret;
                  const start = caret ? Math.min(caret.anchor, caret.head) : 0;
                  const end = caret ? Math.max(caret.anchor, caret.head) : start;
                  const statusLabel = member.typing
                    ? t("cocodex.prompt.typing")
                    : start === end
                      ? t("cocodex.prompt.caret", { position: start })
                      : t("cocodex.prompt.selection", { start, end });
                  return <span key={member.deviceId} className="cocodex-prompt-presence-member">
                    <i aria-hidden="true" className={member.typing ? "typing" : "caret"} />
                    <strong>{member.displayName}</strong><small>{statusLabel}</small>
                  </span>;
                })}
              </div>}
            </label>
            <div className="cocodex-message-list" aria-live="polite">
              <ChatTimeline messages={chat} tasks={visibleTasks} localDeviceId={status.deviceId}
                members={projectMembers} />
            </div>
            <form className="cocodex-composer" onSubmit={sendPrompt}>
              <select className="input cocodex-agent-input" value={agentId}
                onChange={event => setAgentId(event.target.value)}>
                <option value="">{t("cocodex.agent.placeholder")}</option>
                {visibleAgents.filter(agent => agent.enabled).map(agent =>
                  <option key={agent.id} value={agent.id}>{agent.name} · {agent.hostDisplayName}</option>)}
              </select>
              <textarea className="input" value={agentId.trim() ? sharedPrompt : draft}
                onChange={event => {
                  if (agentId.trim()) editSharedPrompt(event.target.value);
                  else setDraft(event.target.value);
                }}
                placeholder={agentId
                  ? t("cocodex.composer.agent", { agent: visibleAgents.find(agent => agent.id === agentId)?.name ?? agentId })
                  : t("cocodex.composer.chat")} rows={3}
                disabled={status.state !== "connected" || selectedProjectLocked} />
              <button className="btn btn-primary"
                disabled={!(agentId.trim() ? sharedPrompt : draft).trim()
                  || status.state !== "connected" || selectedProjectLocked}>
                {agentId ? <><IconBot /> {t("cocodex.agent.run")}</> : t("cocodex.send")}
              </button>
            </form>
          </section>

          <aside className="card cocodex-private">
            {pendingDeviceApprovals.length > 0 && (
              <section className="cocodex-device-approvals">
                <div className="cocodex-section-head">
                  <div>
                    <strong>{t("cocodex.deviceApproval.title")}</strong>
                    <small>{t("cocodex.deviceApproval.subtitle")}</small>
                  </div>
                  <button type="button" className="btn btn-ghost btn-icon"
                    title={t("cocodex.deviceApproval.refresh")}
                    onClick={() => void command({ type: "device.approval.list" })}
                    disabled={status.state !== "connected"}>
                    <IconRefresh />
                  </button>
                </div>
                <div className="cocodex-device-approval-list">
                  {pendingDeviceApprovals.map(device => {
                    const confirmation = (deviceApprovalConfirmations[device.deviceId] ?? "")
                      .trim().toLowerCase().replace(/\s+/g, " ");
                    const matches = confirmation === device.verificationPhrase;
                    return (
                      <article key={device.deviceId} className="cocodex-device-approval-card">
                        <strong>{device.displayName}</strong>
                        <code>{device.fingerprint}</code>
                        <small>{t("cocodex.deviceApproval.phrase")}</small>
                        <code>{device.verificationPhrase}</code>
                        <small>{t("cocodex.deviceApproval.expires", {
                          time: new Date(device.approvalExpiresAt).toLocaleTimeString(),
                        })}</small>
                        <input className="input"
                          aria-label={t("cocodex.deviceApproval.confirm")}
                          placeholder={t("cocodex.deviceApproval.confirm")}
                          value={deviceApprovalConfirmations[device.deviceId] ?? ""}
                          onChange={event => setDeviceApprovalConfirmations(previous => ({
                            ...previous,
                            [device.deviceId]: event.target.value,
                          }))} />
                        <div className="cocodex-device-approval-actions">
                          <button type="button" className="btn btn-primary"
                            disabled={busy || status.state !== "connected" || !matches}
                            onClick={() => void updateDeviceApproval(device, "approve")}>
                            {t("cocodex.deviceApproval.approve")}
                          </button>
                          <button type="button" className="btn btn-danger btn-ghost"
                            disabled={busy || status.state !== "connected" || !matches}
                            onClick={() => void updateDeviceApproval(device, "reject")}>
                            {t("cocodex.deviceApproval.reject")}
                          </button>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </section>
            )}
            <WorkspaceRailTabs active={rightRailTab} onChange={setRightRailTab} />
            {rightRailTab === "usage" && <section className="cocodex-usage" role="tabpanel">
              <div className="cocodex-section-head">
                <div><strong>{t("cocodex.usage.title")}</strong><small>{t("cocodex.usage.subtitle")}</small></div>
                <IconRefresh />
              </div>
              <div className="cocodex-usage-list">
                {usageReports.map(view => {
                  const report = view.report;
                  const windows = report ? [
                    [t("cocodex.usage.fiveHour"), report.fiveHourPercent, report.fiveHourResetAt],
                    [t("cocodex.usage.weekly"), report.weeklyPercent, report.weeklyResetAt],
                    [t("cocodex.usage.monthly"), report.monthlyPercent, report.monthlyResetAt],
                    ...(report.customWindows ?? []).map(window => [window.label, window.percent, window.resetAt] as const),
                  ].filter((row): row is [string, number, number | undefined] => typeof row[1] === "number") : [];
                  return (
                    <article key={view.deviceId} className="cocodex-usage-card">
                      <div className="cocodex-usage-card-head">
                        <strong>{view.displayName}</strong>
                        <small>{report ? t("cocodex.usage.updated", { time: new Date(report.updatedAt).toLocaleTimeString() }) : t("cocodex.usage.unreported")}</small>
                      </div>
                      {report ? (
                        <>
                          <small>{report.accountLabel || t("cocodex.usage.localAccount")}</small>
                          <div className="cocodex-usage-metrics">
                            <span>{t("cocodex.usage.requests", { count: report.requests.toLocaleString() })}</span>
                            <span>{t("cocodex.usage.tokens", { count: usageTotalTokens(report).toLocaleString() })}</span>
                            <span>{t("cocodex.usage.active", { count: report.activeAgents })}</span>
                            <span>{t("cocodex.usage.cacheHit", { percent: cacheHitPercent(report.inputTokens, report.cachedInputTokens) })}</span>
                          </div>
                          {(report.agents ?? []).map(agent => (
                            <div className="cocodex-usage-window" key={agent.agentId}>
                              <span>{agent.agentId}</span>
                              <b>{t("cocodex.usage.cacheHit", { percent: cacheHitPercent(agent.inputTokens, agent.cachedInputTokens) })}</b>
                              <small>{t("cocodex.usage.requests", { count: agent.requests.toLocaleString() })}</small>
                            </div>
                          ))}
                          {windows.map(([label, percent, resetAt]) => (
                            <div className="cocodex-usage-window" key={label}>
                              <span>{label}</span><b>{Math.round(percent)}%</b>
                              {resetAt !== undefined && <small>{t("cocodex.usage.reset", { time: usageResetLabel(resetAt) })}</small>}
                            </div>
                          ))}
                        </>
                      ) : <p className="muted">{t("cocodex.usage.noData")}</p>}
                    </article>
                  );
                })}
                {!usageReports.length && <p className="muted">{t("cocodex.usage.noMembers")}</p>}
              </div>
            </section>}
            {rightRailTab === "agents" && <>
            <section className="cocodex-agents" role="tabpanel">
              <div className="cocodex-section-head">
                <div><strong>{t("cocodex.agents.title")}</strong><small>{t("cocodex.agents.subtitle")}</small></div>
                <IconBot />
              </div>
              <div className="cocodex-agent-list">
                {visibleAgents.map(agent => (
                  <article className="cocodex-agent-card" key={agent.id}>
                    <div className="cocodex-agent-card-head">
                      <span className={`cocodex-agent-status status-${agent.status}`} aria-label={agentStatusLabel(t, agent.status)} />
                      <strong>{agent.name}</strong>
                      <small>{agentStatusLabel(t, agent.status)}</small>
                    </div>
                    <small>{t("cocodex.agents.host", { host: agent.hostDisplayName })}</small>
                    <small>{t("cocodex.agents.tasks", { active: agent.activeTasks, queued: agent.queuedTasks })}</small>
                  </article>
                ))}
                {!visibleAgents.length && <p className="muted">{t("cocodex.agents.empty")}</p>}
              </div>
            </section>
            <section className="cocodex-agents cocodex-task-activity">
              <div className="cocodex-section-head">
                <div><strong>{t("cocodex.tasks.title")}</strong><small>{t("cocodex.tasks.subtitle")}</small></div>
                <IconRefresh />
              </div>
              <div className="cocodex-agent-list">
                <TaskDependencyGraph tasks={visibleTasks} artifacts={visibleArtifacts} />
                <GitIntegrationReview tasks={visibleTasks} integrations={gitIntegrations}
                  localDeviceId={status.deviceId} connected={status.state === "connected"}
                  locked={selectedProjectLocked} onPreview={previewGitIntegration}
                  onIntegrate={integrateGitIntegration} />
              </div>
            </section>
            </>}
            {rightRailTab === "artifacts" && <section className="cocodex-agents cocodex-artifacts" role="tabpanel">
              <div className="cocodex-section-head">
                <div><strong>{t("cocodex.artifacts.title")}</strong><small>{t("cocodex.artifacts.subtitle")}</small></div>
                <IconKey />
              </div>
              <div className="cocodex-agent-list">
                {visibleArtifacts.map(artifact => {
                  const consumable = artifact.status === "ready" || artifact.status === "accepted" || artifact.status === "integrated";
                  return (
                    <label className="cocodex-agent-card cocodex-artifact-card" key={artifact.id}>
                      <span className="cocodex-artifact-select">
                        <input type="checkbox" disabled={!consumable || !agentId.trim()}
                          checked={selectedArtifactIds.includes(artifact.id)}
                          onChange={event => setSelectedArtifactIds(previous => event.target.checked
                            ? [...previous, artifact.id]
                            : previous.filter(id => id !== artifact.id))} />
                        <strong>{artifact.title}</strong>
                      </span>
                      <small>{artifact.summary}</small>
                      {visibleFileReferences.filter(reference => reference.artifactId === artifact.id).map(reference => (
                        <FileReferenceMetadata key={reference.referenceId} reference={reference}
                          local={reference.hostDeviceId === status.deviceId} />
                      ))}
                      <small>{artifact.type} · {artifact.status}</small>
                    </label>
                  );
                })}
                {!visibleArtifacts.length && <p className="muted">{t("cocodex.artifacts.empty")}</p>}
              </div>
              <form className="cocodex-artifact-form" onSubmit={publishArtifact}>
                <input className="input" value={artifactTitle} onChange={event => setArtifactTitle(event.target.value)}
                  placeholder={t("cocodex.artifacts.name")} required maxLength={200} />
                <input className="input" value={artifactSummary} onChange={event => setArtifactSummary(event.target.value)}
                  placeholder={t("cocodex.artifacts.summary")} required maxLength={4000} />
                <textarea className="input" value={artifactContent} onChange={event => setArtifactContent(event.target.value)}
                  placeholder={t("cocodex.artifacts.content")} required rows={3} />
                <button className="btn btn-ghost" disabled={status.state !== "connected"}>{t("cocodex.artifacts.publish")}</button>
              </form>
              <form className="cocodex-artifact-form cocodex-file-reference-form" onSubmit={publishFileReference}>
                <strong>{t("cocodex.fileReferences.title")}</strong>
                <small>{t("cocodex.fileReferences.subtitle")}</small>
                <select className="input" value={referenceArtifactId}
                  onChange={event => dispatchReferenceArtifactSelection({
                    type: "select",
                    artifactId: event.target.value,
                  })} required>
                  <option value="">{t("cocodex.fileReferences.artifact")}</option>
                  {visibleArtifacts.filter(artifact => artifact.authorDeviceId === status.deviceId).map(artifact => (
                    <option key={artifact.id} value={artifact.id}>{artifact.title}</option>
                  ))}
                </select>
                <input className="input" value={referenceWorkspaceRoot}
                  onChange={event => setReferenceWorkspaceRoot(event.target.value)}
                  placeholder={t("cocodex.fileReferences.workspaceRoot")} required maxLength={1024} />
                <input className="input" value={referencePath} onChange={event => setReferencePath(event.target.value)}
                  placeholder={t("cocodex.fileReferences.path")} required maxLength={1024} />
                <select className="input" value={referenceWorkspaceMode}
                  onChange={event => setReferenceWorkspaceMode(event.target.value as "shared" | "git-worktree")}>
                  <option value="shared">{t("cocodex.fileReferences.shared")}</option>
                  <option value="git-worktree">{t("cocodex.fileReferences.worktree")}</option>
                </select>
                <input className="input" value={referenceWorkspaceRef}
                  onChange={event => setReferenceWorkspaceRef(event.target.value)}
                  placeholder={t("cocodex.fileReferences.workspaceRef")} required maxLength={500} />
                <input className="input" value={referenceMediaType}
                  onChange={event => setReferenceMediaType(event.target.value)}
                  placeholder={t("cocodex.fileReferences.mediaType")} maxLength={160} />
                <button className="btn btn-ghost"
                  disabled={status.state !== "connected" || !referenceArtifactId}>
                  {t("cocodex.fileReferences.publish")}
                </button>
              </form>
            </section>}
            {rightRailTab === "messages" && <div className="cocodex-messages-panel" role="tabpanel">
            <div className="cocodex-section-head">
              <div>
                <strong>{selectedPrivateContact?.displayName ?? t("cocodex.private.title")}</strong>
                <small>{t("cocodex.private.encrypted")}</small>
              </div>
              <div className="cocodex-section-head-actions">
                <button className="btn btn-ghost" type="button"
                  aria-pressed={privateNotificationsEnabled}
                  onClick={() => void togglePrivateNotifications()}>
                  {t(privateNotificationsEnabled
                    ? "cocodex.private.disableNotifications"
                    : "cocodex.private.enableNotifications")}
                </button>
                <IconLock />
              </div>
            </div>
            <select
              className="input"
              value={recipientDeviceId}
              onChange={event => {
                setRecipientDeviceId(event.target.value);
                setPrivateVerificationFingerprint("");
              }}
              aria-label={t("cocodex.private.contact")}
            >
              <option value="">{t("cocodex.private.selectContact")}</option>
              {privateContacts.map(contact => (
                <option key={contact.deviceId} value={contact.deviceId}>
                  {contact.displayName}{contact.trusted ? "" : ` — ${t("cocodex.private.unverified")}`}
                </option>
              ))}
            </select>
            {selectedPrivateContact && (
              <div className="cocodex-private-contact">
                <small>{selectedPrivateContact.fingerprint}</small>
                {!selectedPrivateContact.trusted && (
                  <>
                    <small>{t("cocodex.private.verifyInstructions")}</small>
                    <input
                      className="input"
                      value={privateVerificationFingerprint}
                      onChange={event => setPrivateVerificationFingerprint(event.target.value)}
                      placeholder={t("cocodex.private.verificationFingerprint")}
                      aria-label={t("cocodex.private.verificationFingerprint")}
                      autoComplete="off"
                    />
                    <button className="btn btn-ghost" type="button"
                      disabled={!independentlyConfirmedFingerprintMatches(
                        privateVerificationFingerprint,
                        selectedPrivateContact.fingerprint,
                      )}
                      onClick={() => void verifyPrivateContact(selectedPrivateContact)}>
                      {t("cocodex.private.verify")}
                    </button>
                  </>
                )}
              </div>
            )}
            <input
              className="input"
              type="search"
              value={privateSearch}
              onChange={event => setPrivateSearch(event.target.value)}
              placeholder={t("cocodex.private.search")}
              aria-label={t("cocodex.private.search")}
            />
            <div className="cocodex-private-list">
              {visiblePrivateMessages.map(message => {
                const replyTarget = message.replyToMessageId
                  ? projectedPrivateMessages.find(item => item.messageId === message.replyToMessageId)
                  : undefined;
                const reacted = message.reactions.some(reaction =>
                  reaction.emoji === "thumbs-up"
                  && reaction.senderDeviceIds.includes(status.deviceId ?? ""));
                return (
                  <article key={message.messageId} className={message.deleted ? "deleted" : undefined}>
                    {replyTarget && <blockquote className="cocodex-private-reply">
                      <strong>{t("cocodex.private.replyingTo")}</strong>
                      <span>{replyTarget.deleted ? t("cocodex.private.deleted") : replyTarget.text}</span>
                    </blockquote>}
                    <strong>{message.senderDeviceId === status.deviceId
                      ? t("cocodex.you")
                      : selectedPrivateContact?.displayName ?? message.senderDeviceId.slice(0, 8)}</strong>
                    <p>{message.deleted ? t("cocodex.private.deleted") : message.text}</p>
                    {message.edited && !message.deleted && <small>{t("cocodex.private.edited")}</small>}
                    {!!message.reactions.length && <div className="cocodex-private-reactions">
                      {message.reactions.map(reaction => <span key={reaction.emoji}>
                        {reaction.emoji === "thumbs-up" ? "\u{1F44D}" : reaction.emoji} {reaction.senderDeviceIds.length}
                      </span>)}
                    </div>}
                    {(message.deliveryState === "rejected" || privateReceipts[message.messageId]) && <small>
                      {message.deliveryState === "rejected"
                        ? `${t("cocodex.private.rejected")}: ${message.rejectionReason ?? t("cocodex.private.rejectedUnknown")}`
                        : privateReceipts[message.messageId] === "read"
                        ? t("cocodex.private.read")
                        : privateReceipts[message.messageId] === "delivered"
                          ? t("cocodex.private.delivered")
                          : t("cocodex.private.sent")}
                    </small>}
                    <div className="cocodex-private-actions">
                      {!message.deleted && <button className="btn btn-ghost" type="button" disabled={!status.running}
                        onClick={() => beginPrivateReply(message)}>{t("cocodex.private.reply")}</button>}
                      {!message.deleted && <button className={reacted ? "btn btn-ghost active" : "btn btn-ghost"}
                        type="button" disabled={!status.running}
                        onClick={() => void togglePrivateReaction(message)}
                        aria-label={t("cocodex.private.react")}>{"\u{1F44D}"}</button>}
                      {!message.deleted && message.senderDeviceId === status.deviceId && <>
                        <button className="btn btn-ghost" type="button" disabled={!status.running}
                          onClick={() => beginPrivateEdit(message)}>{t("cocodex.private.edit")}</button>
                        <button className="btn btn-ghost danger" type="button" disabled={!status.running}
                          onClick={() => void deletePrivateMessage(message)}>{t("cocodex.private.delete")}</button>
                      </>}
                      {message.recipientDeviceId === status.deviceId && privateReceipts[message.messageId] !== "read" &&
                        <button className="btn btn-ghost" type="button" disabled={!status.running}
                          onClick={() => void markPrivateRead(message)}>{t("cocodex.private.markRead")}</button>}
                      {!message.deleted && <button className="btn btn-ghost" type="button"
                        disabled={status.state !== "connected" || !agentId.trim()}
                        onClick={() => void sharePrivate(message)}>{t("cocodex.private.share")}</button>}
                    </div>
                  </article>
                );
              })}
              {!visiblePrivateMessages.length && <p className="muted">
                {selectedPrivateMessages.length ? t("cocodex.private.noSearchResults") : t("cocodex.private.empty")}
              </p>}
            </div>
            <form className="cocodex-private-form" onSubmit={sendPrivate}>
              {(privateReplyTo || privateEditTarget) && <div className="cocodex-private-compose-mode">
                <span>
                  {privateEditTarget ? t("cocodex.private.editing") : t("cocodex.private.replying")}
                  {" "}
                  {(privateEditTarget ?? privateReplyTo)?.text.slice(0, 100)}
                </span>
                <button className="btn btn-ghost" type="button" onClick={() => {
                  if (privateEditTarget) setPrivateDraft("");
                  setPrivateEditTarget(undefined);
                  setPrivateReplyTo(undefined);
                }}>{t("cocodex.private.cancel")}</button>
              </div>}
              <PrivateTypingIndicator
                active={!!selectedPrivateContact
                  && privateTypingDeviceIds.includes(selectedPrivateContact.deviceId)}
                label={selectedPrivateContact
                  ? t("cocodex.private.typing", { name: selectedPrivateContact.displayName })
                  : ""}
              />
              <textarea className="input" value={privateDraft} onChange={event => {
                setPrivateDraft(event.target.value);
                notePrivateTyping(event.target.value);
              }}
                placeholder={privateEditTarget
                  ? t("cocodex.private.editMessage")
                  : privateReplyTo
                    ? t("cocodex.private.replyMessage")
                    : t("cocodex.private.message")} required rows={2}
                disabled={!selectedPrivateContact?.trusted} />
              <button className="btn btn-ghost"
                disabled={!status.running || !selectedPrivateContact?.trusted}>
                {privateEditTarget ? t("cocodex.private.saveEdit") : t("cocodex.private.send")}
              </button>
            </form>
            </div>}
          </aside>
        </div>
      )}
    </div>
  );
}
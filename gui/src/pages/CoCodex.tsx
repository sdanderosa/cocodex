import { useCallback, useEffect, useReducer, useRef, useState, type FormEvent } from "react";
import * as Y from "yjs";
import {
  independentlyConfirmedFingerprintMatches,
  privateTimelineForContact,
  reconcilePrivateContactSelection,
} from "../cocodex-private-contact-state";
import { referenceArtifactSelectionReducer } from "../cocodex-file-reference-state";
import { projectCreatedFromControl } from "../cocodex-project-creation-state";
import {
  confirmProjectMemberRemoval,
  projectMemberRemovalCommand,
  reconcileRevokedProject,
  type Project,
  type ProjectMember,
} from "../cocodex-member-state";
import { useT, type TFn, type TKey } from "../i18n";
import { IconBot, IconKey, IconLock, IconRefresh, IconServer } from "../icons";
import "../styles-cocodex.css";

type ConnectionState = "not-configured" | "stopped" | "connecting" | "connected" | "retrying";

interface Status {
  configured: boolean;
  running: boolean;
  state: ConnectionState;
  deviceId?: string;
  displayName?: string;
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

interface ChatEvent {
  sequence: number;
  projectId: string;
  chatId?: string;
  eventId: string;
  senderDeviceId: string;
  content: string;
  acceptedAt: string;
}

interface PrivateMessage {
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  text: string;
  clientCreatedAt?: string;
  acceptedAt?: string;
  serverSequence?: number;
  direction?: "sent" | "received";
  restored?: boolean;
  deliveryState?: "staged" | "queued" | "accepted" | "rejected";
  rejectionReason?: string;
}

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

interface AgentTaskView {
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
  typing: boolean;
}

interface LocalPresence {
  cursor: { x: number; y: number } | null;
  caret: { anchor: number; head: number } | null;
  typing: boolean;
}

interface SessionValue {
  source?: string;
  state?: ConnectionState | "key-available" | "rotation-required" | "revoked";
  projectId?: string;
  approvalState?: "pending" | "resolved";
  executionEnabled?: boolean;
  fullComputerEnabled?: boolean;
  accessProfile?: "project-only" | "full-computer";
  workspaceMode?: "shared" | "git-worktree";
  configured?: boolean;
  ok?: boolean;
  taskId?: string;
  task?: AgentApproval;
  error?: unknown;
  message?: PrivateMessage;
  receipt?: PrivateReceipt;
  contacts?: PrivateContact[];
  invitations?: ProjectInvitation[];
  project?: Project;
  frame?: {
    type?: string;
    projectId?: string;
    chatId?: string;
    chats?: SharedChat[];
    chat?: SharedChat;
    defaultChat?: SharedChat;
    update?: string;
    deviceId?: string;
    displayName?: string;
    cursor?: { x: number; y: number } | null;
    caret?: { anchor: number; head: number } | null;
    typing?: boolean;
    members?: PresenceMember[] | ProjectMember[];
    projects?: Project[];
    project?: Project;
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

async function apiJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const body = await response.json();
  if (!response.ok) throw new Error(String(body?.error ?? response.status));
  return body as T;
}

const capabilityPromises = new Map<string, Promise<string>>();
function capabilityFor(apiBase: string): Promise<string> {
  let pending = capabilityPromises.get(apiBase);
  if (!pending) {
    pending = apiJson<{ capability: string }>(`${apiBase}/api/cocodex/capability`)
      .then(value => value.capability);
    capabilityPromises.set(apiBase, pending);
  }
  return pending;
}

async function cocodexApiJson<T>(apiBase: string, url: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("X-CoCodex-Capability", await capabilityFor(apiBase));
  return apiJson<T>(url, { ...init, headers });
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
                : "cocodex.members.unverified")}</small>
            </span>
            {owner && member.role !== "owner" && <span className="cocodex-member-actions">
              {!member.trusted && <button type="button" className="btn btn-ghost"
                disabled={busy || !connected} onClick={() => onTrust(member)}>
                {t("cocodex.members.trust")}
              </button>}
              <button type="button" className="btn btn-danger btn-ghost"
                disabled={busy || !connected} onClick={() => onRemove(member)}>
                {t("cocodex.members.remove")}
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
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [chats, setChats] = useState<SharedChat[]>([]);
  const [chatId, setChatId] = useState("");
  const [chatTitle, setChatTitle] = useState("");
  const [projectName, setProjectName] = useState("");
  const [projectMembers, setProjectMembers] = useState<ProjectMember[]>([]);
  const [projectInvitations, setProjectInvitations] = useState<ProjectInvitation[]>([]);
  const [chat, setChat] = useState<ChatEvent[]>([]);
  const [privateMessages, setPrivateMessages] = useState<PrivateMessage[]>([]);
  const [privateReceipts, setPrivateReceipts] = useState<Record<string, "sent" | "delivered" | "read">>({});
  const [privateContacts, setPrivateContacts] = useState<PrivateContact[]>([]);
  const [privateSearch, setPrivateSearch] = useState("");
  const [presence, setPresence] = useState<PresenceMember[]>([]);
  const [agentApprovals, setAgentApprovals] = useState<AgentApproval[]>([]);
  const [draft, setDraft] = useState("");
  const [sharedPrompt, setSharedPrompt] = useState("");
  const [sharedContext, setSharedContext] = useState<SharedProjectContext>();
  const [finalGoalDraft, setFinalGoalDraft] = useState("");
  const [usageReports, setUsageReports] = useState<UsageReportView[]>([]);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [tasks, setTasks] = useState<AgentTaskView[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
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
  const [privateVerificationFingerprint, setPrivateVerificationFingerprint] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const cursor = useRef(0);
  const projectListRequested = useRef(false);
  const subscribedProject = useRef("");
  const presenceSentAt = useRef(0);
  const presenceProject = useRef("");
  const presenceConnectionState = useRef<ConnectionState | undefined>(undefined);
  const localPresence = useRef<LocalPresence>({ cursor: null, caret: null, typing: false });
  const presenceSendTimer = useRef<number | undefined>(undefined);
  const typingIdleTimer = useRef<number | undefined>(undefined);
  const promptDoc = useRef<Y.Doc | undefined>(undefined);
  const promptProject = useRef("");

  const command = useCallback((body: Record<string, unknown>) =>
    cocodexApiJson(apiBase, `${apiBase}/api/cocodex/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }), [apiBase]);

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
    setSharedPrompt("");
    return document;
  }, [command]);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await cocodexApiJson<Status>(apiBase, `${apiBase}/api/cocodex/status`));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
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
      if (value?.source === "agent-configuration" && value.configured) {
        setNotice(t("cocodex.agent.setup.saved"));
        setAgentName("");
        setAgentWorkspace("");
        void loadStatus();
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
      }
      if (frame?.projectId === projectId && (frame.chatId ?? projectId) === chatId
        && frame.type === "presence.snapshot" && Array.isArray(frame.members)) {
        setPresence((frame.members as PresenceMember[]).map(member => ({ ...member, typing: member.typing === true })));
      } else if (frame?.projectId === projectId && frame.type === "project.member.list.result"
        && Array.isArray(frame.members)) {
        setProjectMembers(frame.members as ProjectMember[]);
      } else if (frame?.projectId === projectId && frame.type === "project.member.removed" && frame.deviceId) {
        setProjectMembers(previous => previous.filter(member => member.deviceId !== frame.deviceId));
      } else if (frame?.projectId === projectId && frame.chatId === chatId
        && frame.type === "presence.update" && frame.deviceId && frame.displayName) {
        setPresence(previous => [...previous.filter(member => member.deviceId !== frame.deviceId), {
          deviceId: frame.deviceId!, displayName: frame.displayName!, cursor: frame.cursor ?? null,
          caret: frame.caret ?? null, typing: frame.typing === true,
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
      const privateMessage = value?.message;
      if (value?.source === "private" && privateMessage?.text) {
        setPrivateReceipts(previous => previous[privateMessage.messageId]
          ? previous
          : {
            ...previous,
            [privateMessage.messageId]: privateMessage.direction === "sent" ? "sent" : "delivered",
          });
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
      if (value?.source === "private-contacts" && Array.isArray(value.contacts)) {
        const contacts = value.contacts as PrivateContact[];
        setPrivateContacts(contacts);
        setRecipientDeviceId(previous => reconcilePrivateContactSelection(previous, contacts));
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
  }, [chatId, command, ensurePromptDocument, loadStatus, projectId, projects, status?.deviceId, t]);

  useEffect(() => {
    const initial = window.setTimeout(() => void loadStatus(), 0);
    const interval = window.setInterval(() => void loadStatus(), 2_000);
    return () => { window.clearTimeout(initial); window.clearInterval(interval); };
  }, [loadStatus]);

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
    setProjectMembers([]);
    setSharedContext(undefined);
    setFinalGoalDraft("");
    setUsageReports([]);
    setAgents([]);
    setTasks([]);
    setArtifacts([]);
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
    return () => {
      if (presenceSendTimer.current !== undefined) window.clearTimeout(presenceSendTimer.current);
      if (typingIdleTimer.current !== undefined) window.clearTimeout(typingIdleTimer.current);
    };
  }, []);

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
    text.doc?.transact(() => {
      text.delete(0, text.length);
      text.insert(0, value);
    });
  };

  const sendPrompt = async (event: FormEvent) => {
    event.preventDefault();
    const content = draft.trim();
    if (!content || !projectId || !chatId) return;
    setDraft("");
    try {
      await command(agentId.trim()
        ? { type: "agent.request", projectId, chatId, agentId: agentId.trim(), prompt: content, inputArtifactIds: selectedArtifactIds }
        : { type: "chat.send", projectId, chatId, content });
    } catch (error) {
      setDraft(content);
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
    setPrivateDraft("");
    try {
      await command({
        type: "private.send",
        recipientDeviceId: contact.deviceId,
        text,
      });
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

  const localSafetyCommand = async (type: string, agentId: string, confirm = false) => {
    try {
      await command({ type, agentId, ...(confirm ? { confirm: true } : {}) });
      await loadStatus();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
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
      sendPresenceState(previousProjectId!, previousChatId ?? null, { cursor: null, caret: null, typing: false });
    }
    presenceProject.current = nextScope;
    localPresence.current = { cursor: null, caret: null, typing: false };
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
  const selectedChat = chats.find(item => item.id === chatId);
  const remotePromptPresence = visiblePresence.filter(member => member.deviceId !== status?.deviceId
    && (member.typing || member.caret));
  const selectedPrivateContact = privateContacts.find(contact => contact.deviceId === recipientDeviceId);
  const selectedPrivateMessages = privateTimelineForContact(
    privateMessages,
    selectedPrivateContact?.deviceId ?? "",
    "",
  );
  const visiblePrivateMessages = privateTimelineForContact(
    privateMessages,
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
        {status?.configured && (
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void toggleSession()}>
            {t(status.running ? "cocodex.disconnect" : "cocodex.connect")}
          </button>
        )}
      </header>

      {notice && <div className="cocodex-notice" role="status">{notice}</div>}
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
              {projects.map(project => (
                <button key={project.id} type="button" className={project.id === projectId ? "active" : ""}
                  onClick={() => setProjectId(project.id)}>
                  <IconServer />
                  <span>{project.name}<small>{project.role}</small></span>
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
                    disabled={status.state !== "connected" || !chatTitle.trim()}>
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
            {projectId && <ProjectMemberRoster
              members={projectMembers}
              owner={projects.find(project => project.id === projectId)?.role === "owner"}
              connected={status.state === "connected"}
              busy={busy}
              onRefresh={() => void command({ type: "project.member.list", projectId })}
              onTrust={member => void trustProjectMember(member)}
              onRemove={member => void removeProjectMember(member)}
            />}
            {projectId && projects.find(project => project.id === projectId)?.role === "owner" && (
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
                    disabled={busy || status.state !== "connected"}
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
                <button className="btn btn-ghost" disabled={busy || status.state !== "connected"}>
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
                disabled={!status.running || !projectId || !sharedContext} />
              <button type="submit" className="btn btn-ghost cocodex-goal-save"
                disabled={!sharedContext || status.state !== "connected" || finalGoalDraft === sharedContext.finalGoal}>
                {t("cocodex.goal.save")}
              </button>
            </form>
            <label className="cocodex-shared-prompt">
              <span><strong>{t("cocodex.prompt.title")}</strong><small>{t("cocodex.prompt.crdt")}</small></span>
              <textarea className="input" value={sharedPrompt}
                onChange={event => {
                  editSharedPrompt(event.target.value);
                  publishPresence({ caret: {
                    anchor: event.currentTarget.selectionStart,
                    head: event.currentTarget.selectionEnd,
                  }, typing: true }, false);
                }}
                onFocus={event => publishPresence({ caret: {
                  anchor: event.currentTarget.selectionStart,
                  head: event.currentTarget.selectionEnd,
                } })}
                onSelect={event => publishPresence({ caret: {
                  anchor: event.currentTarget.selectionStart,
                  head: event.currentTarget.selectionEnd,
                } })}
                onBlur={() => publishPresence({ caret: null, typing: false })}
                placeholder={t("cocodex.prompt.placeholder")} rows={3} disabled={!status.running || !projectId} />
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
              {chat.map(message => (
                <article key={message.eventId} className={message.senderDeviceId === status.deviceId ? "mine" : ""}>
                  <div>
                    <strong>{message.senderDeviceId === status.deviceId ? t("cocodex.you") : message.senderDeviceId.slice(0, 8)}</strong>
                    <span>#{message.sequence}</span>
                  </div>
                  <p>{message.content}</p>
                </article>
              ))}
              {!chat.length && <div className="cocodex-empty">{t("cocodex.chat.empty")}</div>}
            </div>
            <form className="cocodex-composer" onSubmit={sendPrompt}>
              <select className="input cocodex-agent-input" value={agentId}
                onChange={event => setAgentId(event.target.value)}>
                <option value="">{t("cocodex.agent.placeholder")}</option>
                {visibleAgents.filter(agent => agent.enabled).map(agent =>
                  <option key={agent.id} value={agent.id}>{agent.name} · {agent.hostDisplayName}</option>)}
              </select>
              <textarea className="input" value={draft} onChange={event => setDraft(event.target.value)}
                placeholder={agentId
                  ? t("cocodex.composer.agent", { agent: visibleAgents.find(agent => agent.id === agentId)?.name ?? agentId })
                  : t("cocodex.composer.chat")} rows={3}
                disabled={status.state !== "connected"} />
              <button className="btn btn-primary" disabled={!draft.trim() || status.state !== "connected"}>
                {agentId ? <><IconBot /> {t("cocodex.agent.run")}</> : t("cocodex.send")}
              </button>
            </form>
          </section>

          <aside className="card cocodex-private">
            <section className="cocodex-usage">
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
                          </div>
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
            </section>
            <section className="cocodex-agents">
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
                {visibleTasks.map(task => {
                  const visualStatus = task.status === "running" ? "working" : task.status;
                  return (
                    <article className="cocodex-agent-card cocodex-task-card" key={task.id}>
                      <div className="cocodex-agent-card-head">
                        <span className={`cocodex-agent-status status-${visualStatus}`} aria-label={taskStatusLabel(t, task.status)} />
                        <strong>{task.agentName}</strong>
                        <small>{taskStatusLabel(t, task.status)}</small>
                      </div>
                      <code>{task.id.slice(0, 8)}</code>
                      <small>{t("cocodex.tasks.events", { count: task.eventCount })}
                        {task.encrypted ? ` · ${t("cocodex.tasks.encrypted")}` : ""}</small>
                      {task.dependencies.length > 0 && <small>{t("cocodex.tasks.dependencies", { count: task.dependencies.length })}</small>}
                      {task.inputArtifactIds.length > 0 && <small>{t("cocodex.tasks.artifacts", { count: task.inputArtifactIds.length })}</small>}
                      {task.workspaceMode === "shared"
                        && <small>{t("cocodex.tasks.workspace.shared")}</small>}
                      {task.workspaceMode === "git-worktree" && <small>
                        {t("cocodex.tasks.workspace.worktree", {
                          branch: task.branch ?? task.workspaceRef ?? "",
                          commit: task.baseCommit?.slice(0, 8) ?? "",
                        })}
                      </small>}
                    </article>
                  );
                })}
                {!visibleTasks.length && <p className="muted">{t("cocodex.tasks.empty")}</p>}
              </div>
            </section>
            <section className="cocodex-agents cocodex-artifacts">
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
            </section>
            <div className="cocodex-section-head">
              <div>
                <strong>{selectedPrivateContact?.displayName ?? t("cocodex.private.title")}</strong>
                <small>{t("cocodex.private.encrypted")}</small>
              </div>
              <IconLock />
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
              {visiblePrivateMessages.map(message => (
                <article key={message.messageId}>
                  <strong>{message.senderDeviceId === status.deviceId
                    ? t("cocodex.you")
                    : selectedPrivateContact?.displayName ?? message.senderDeviceId.slice(0, 8)}</strong>
                  <p>{message.text}</p>
                  {(message.deliveryState === "rejected" || privateReceipts[message.messageId]) && <small>
                    {message.deliveryState === "rejected"
                      ? `${t("cocodex.private.rejected")}: ${message.rejectionReason ?? t("cocodex.private.rejectedUnknown")}`
                      : privateReceipts[message.messageId] === "read"
                      ? t("cocodex.private.read")
                      : privateReceipts[message.messageId] === "delivered"
                        ? t("cocodex.private.delivered")
                        : t("cocodex.private.sent")}
                  </small>}
                  {message.recipientDeviceId === status.deviceId && privateReceipts[message.messageId] !== "read" &&
                    <button className="btn btn-ghost" type="button" disabled={!status.running}
                      onClick={() => void markPrivateRead(message)}>{t("cocodex.private.markRead")}</button>}
                  <button className="btn btn-ghost" type="button" disabled={status.state !== "connected" || !agentId.trim()}
                    onClick={() => void sharePrivate(message)}>{t("cocodex.private.share")}</button>
                </article>
              ))}
              {!visiblePrivateMessages.length && <p className="muted">
                {selectedPrivateMessages.length ? t("cocodex.private.noSearchResults") : t("cocodex.private.empty")}
              </p>}
            </div>
            <form className="cocodex-private-form" onSubmit={sendPrivate}>
              <textarea className="input" value={privateDraft} onChange={event => setPrivateDraft(event.target.value)}
                placeholder={t("cocodex.private.message")} required rows={2}
                disabled={!selectedPrivateContact?.trusted} />
              <button className="btn btn-ghost"
                disabled={!status.running || !selectedPrivateContact?.trusted}>
                {t("cocodex.private.send")}
              </button>
            </form>
          </aside>
        </div>
      )}
    </div>
  );
}

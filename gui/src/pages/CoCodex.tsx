import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import * as Y from "yjs";
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
  latestEventSequence: number;
}

interface Project {
  id: string;
  name: string;
  role: "owner" | "member";
}

interface ChatEvent {
  sequence: number;
  projectId: string;
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
  acceptedAt?: string;
}

interface AgentApproval {
  id: string;
  projectId: string;
  agentId: string;
  requesterDeviceId: string;
  prompt: string;
}

interface PresenceMember {
  deviceId: string;
  displayName: string;
  cursor: { x: number; y: number } | null;
  caret: { anchor: number; head: number } | null;
}

interface SessionValue {
  source?: string;
  state?: ConnectionState;
  approvalState?: "pending" | "resolved";
  taskId?: string;
  task?: AgentApproval;
  error?: unknown;
  message?: PrivateMessage;
  frame?: {
    type?: string;
    projectId?: string;
    update?: string;
    deviceId?: string;
    displayName?: string;
    cursor?: { x: number; y: number } | null;
    caret?: { anchor: number; head: number } | null;
    members?: PresenceMember[];
    projects?: Project[];
    events?: ChatEvent[];
    event?: ChatEvent;
  };
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

function stateLabel(t: TFn, state: ConnectionState): string { return t(STATE_TKEY[state]); }

function updateToBase64(update: Uint8Array): string {
  let binary = "";
  for (const byte of update) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function updateFromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

export default function CoCodex({ apiBase }: { apiBase: string }) {
  const t = useT();
  const [status, setStatus] = useState<Status>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [chat, setChat] = useState<ChatEvent[]>([]);
  const [privateMessages, setPrivateMessages] = useState<PrivateMessage[]>([]);
  const [presence, setPresence] = useState<PresenceMember[]>([]);
  const [agentApprovals, setAgentApprovals] = useState<AgentApproval[]>([]);
  const [draft, setDraft] = useState("");
  const [sharedPrompt, setSharedPrompt] = useState("");
  const [agentId, setAgentId] = useState("");
  const [invite, setInvite] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [recipientDeviceId, setRecipientDeviceId] = useState("");
  const [recipientFingerprint, setRecipientFingerprint] = useState("");
  const [recipientKey, setRecipientKey] = useState("");
  const [privateDraft, setPrivateDraft] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const cursor = useRef(0);
  const projectListRequested = useRef(false);
  const subscribedProject = useRef("");
  const presenceSentAt = useRef(0);
  const promptDoc = useRef<Y.Doc | undefined>(undefined);
  const promptProject = useRef("");

  const command = useCallback((body: Record<string, unknown>) =>
    cocodexApiJson(apiBase, `${apiBase}/api/cocodex/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }), [apiBase]);

  const ensurePromptDocument = useCallback((nextProjectId: string): Y.Doc => {
    if (promptDoc.current && promptProject.current === nextProjectId) return promptDoc.current;
    promptDoc.current?.destroy();
    const document = new Y.Doc();
    const text = document.getText("prompt");
    text.observe(() => setSharedPrompt(text.toString()));
    document.on("update", (update, origin) => {
      if (origin === "server" || !promptProject.current) return;
      void command({
        type: "prompt.update",
        projectId: promptProject.current,
        updateId: crypto.randomUUID(),
        update: updateToBase64(update),
      }).catch(error => setNotice(error instanceof Error ? error.message : String(error)));
    });
    promptDoc.current = document;
    promptProject.current = nextProjectId;
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
      if (value?.source === "session" && nextState) {
        setStatus(previous => previous ? { ...previous, state: nextState, running: nextState !== "stopped" } : previous);
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
        && frame.projectId && frame.update) {
        try { Y.applyUpdate(ensurePromptDocument(frame.projectId), updateFromBase64(frame.update), "server"); }
        catch { setNotice(t("cocodex.prompt.invalid")); }
      }
      const listedProjects = frame?.projects;
      if (frame?.type === "project.list.result" && Array.isArray(listedProjects)) {
        setProjects(listedProjects);
        setProjectId(previous => previous || listedProjects[0]?.id || "");
      }
      if (frame?.type === "presence.snapshot" && Array.isArray(frame.members)) {
        setPresence(frame.members);
      } else if (frame?.type === "presence.update" && frame.deviceId && frame.displayName) {
        setPresence(previous => [...previous.filter(member => member.deviceId !== frame.deviceId), {
          deviceId: frame.deviceId!, displayName: frame.displayName!, cursor: frame.cursor ?? null, caret: frame.caret ?? null,
        }]);
      } else if (frame?.type === "presence.leave" && frame.deviceId) {
        setPresence(previous => previous.filter(member => member.deviceId !== frame.deviceId));
      }
      const incoming: ChatEvent[] = frame?.type === "chat.snapshot"
        ? frame.events ?? []
        : (frame?.type === "chat.event" || frame?.type === "agent.result") && frame.event
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
        setPrivateMessages(previous => previous.some(item => item.messageId === privateMessage.messageId)
          ? previous
          : [...previous, privateMessage]);
      }
    }
  }, [ensurePromptDocument, t]);

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
    if (status?.state !== "connected" || !projectId || subscribedProject.current === projectId) return;
    subscribedProject.current = projectId;
    setChat([]);
    setPresence([]);
    ensurePromptDocument(projectId);
    void command({ type: "chat.subscribe", projectId, afterSequence: 0 });
    void command({ type: "prompt.subscribe", projectId });
  }, [status?.state, projectId, command, ensurePromptDocument]);

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
    if (!projectId) return;
    const text = ensurePromptDocument(projectId).getText("prompt");
    text.doc?.transact(() => {
      text.delete(0, text.length);
      text.insert(0, value);
    });
  };

  const sendPrompt = async (event: FormEvent) => {
    event.preventDefault();
    const content = draft.trim();
    if (!content || !projectId) return;
    setDraft("");
    try {
      await command(agentId.trim()
        ? { type: "agent.request", projectId, agentId: agentId.trim(), prompt: content }
        : { type: "chat.send", projectId, content });
    } catch (error) {
      setDraft(content);
      setNotice(error instanceof Error ? error.message : String(error));
    }
  };

  const sendPrivate = async (event: FormEvent) => {
    event.preventDefault();
    const text = privateDraft.trim();
    if (!text) return;
    setPrivateDraft("");
    try {
      await command({ type: "device.trust", deviceId: recipientDeviceId.trim(), fingerprint: recipientFingerprint.trim() });
      await command({
        type: "private.send",
        recipientDeviceId: recipientDeviceId.trim(),
        recipientKeyCertificate: recipientKey.trim(),
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

  const publishPresence = (cursorValue: { x: number; y: number } | null, caret: { anchor: number; head: number } | null = null) => {
    if (status?.state !== "connected" || !projectId) return;
    void command({ type: "presence.update", projectId, cursor: cursorValue, caret });
  };

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
          publishPresence({
            x: Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width)),
            y: Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height)),
          });
        }} onMouseLeave={() => publishPresence(null)}>
          <div className="cocodex-presence-layer" aria-hidden="true">
            {presence.filter(member => member.deviceId !== status.deviceId && member.cursor).map(member => (
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
            <div className="cocodex-device">
              <small>{t("cocodex.device.this")}</small>
              <strong>{status.displayName}</strong>
              <code>{status.deviceId?.slice(0, 12)}</code>
              <span>{t(status.agentConfigured ? "cocodex.agent.ready" : "cocodex.agent.none")}</span>
            </div>
          </aside>

          <section className="card cocodex-chat">
            <div className="cocodex-section-head">
              <div>
                <strong>{projects.find(project => project.id === projectId)?.name || t("cocodex.chat.title")}</strong>
                <small>{t("cocodex.chat.ordered")}</small>
              </div>
              <span className="cocodex-lock"><IconLock /> {t("cocodex.chat.transport")}</span>
            </div>
            <label className="cocodex-shared-prompt">
              <span><strong>{t("cocodex.prompt.title")}</strong><small>{t("cocodex.prompt.crdt")}</small></span>
              <textarea className="input" value={sharedPrompt} onChange={event => editSharedPrompt(event.target.value)}
                onSelect={event => publishPresence(null, { anchor: event.currentTarget.selectionStart, head: event.currentTarget.selectionEnd })}
                placeholder={t("cocodex.prompt.placeholder")} rows={3} disabled={!status.running || !projectId} />
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
              <input className="input cocodex-agent-input" value={agentId}
                onChange={event => setAgentId(event.target.value)} placeholder={t("cocodex.agent.placeholder")} />
              <textarea className="input" value={draft} onChange={event => setDraft(event.target.value)}
                placeholder={agentId ? t("cocodex.composer.agent", { agent: agentId }) : t("cocodex.composer.chat")} rows={3}
                disabled={status.state !== "connected"} />
              <button className="btn btn-primary" disabled={!draft.trim() || status.state !== "connected"}>
                {agentId ? <><IconBot /> {t("cocodex.agent.run")}</> : t("cocodex.send")}
              </button>
            </form>
          </section>

          <aside className="card cocodex-private">
            <div className="cocodex-section-head">
              <div><strong>{t("cocodex.private.title")}</strong><small>{t("cocodex.private.encrypted")}</small></div>
              <IconLock />
            </div>
            <div className="cocodex-private-list">
              {privateMessages.map(message => (
                <article key={message.messageId}>
                  <strong>{message.senderDeviceId === status.deviceId ? t("cocodex.you") : message.senderDeviceId.slice(0, 8)}</strong>
                  <p>{message.text}</p>
                </article>
              ))}
              {!privateMessages.length && <p className="muted">{t("cocodex.private.empty")}</p>}
            </div>
            <form className="cocodex-private-form" onSubmit={sendPrivate}>
              <input className="input" value={recipientDeviceId} onChange={event => setRecipientDeviceId(event.target.value)}
                placeholder={t("cocodex.private.device")} required />
              <input className="input" value={recipientFingerprint} onChange={event => setRecipientFingerprint(event.target.value)}
                placeholder={t("cocodex.private.fingerprint")} required />
              <textarea className="input cocodex-key-input" value={recipientKey} onChange={event => setRecipientKey(event.target.value)}
                placeholder={t("cocodex.private.key")} required rows={3} />
              <textarea className="input" value={privateDraft} onChange={event => setPrivateDraft(event.target.value)}
                placeholder={t("cocodex.private.message")} required rows={2} />
              <button className="btn btn-ghost" disabled={status.state !== "connected"}>{t("cocodex.private.send")}</button>
            </form>
          </aside>
        </div>
      )}
    </div>
  );
}

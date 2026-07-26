import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentExecutionSigningTranscript, agentRequestSigningTranscript, decodeInvitation, enrollmentSigningTranscript, projectContentSigningTranscript, projectKeyEnvelopeSigningTranscript } from "@cocodex/protocol";
import { createAgentTask, listAgentTasks, listAgents, pendingAgentTasks, registerAgent, appendAgentResult } from "../src/agent-routing";
import { acceptAgentExecutionReport } from "../src/agent-execution";
import { appendEncryptedAgentResult, cancelEncryptedAgentTask, createEncryptedAgentTask, pendingEncryptedAgentTasks } from "../src/encrypted-agent-routing";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { addProjectMember, createProject } from "../src/shared-state";
import { shareProjectKeyEnvelope } from "../src/project-encryption-storage";
import { publishEncryptedArtifact } from "../src/encrypted-artifacts";

function device(db: ReturnType<typeof openDatabase>, name: string, now: Date) {
  const pair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const messaging = generateKeyPairSync("x25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const invitation = decodeInvitation(createInvitation(db, { host: "server.test", port: 1, serverFingerprint: "AAAA-BBBB-CCCC-DDDD", now }));
  const challenge = createEnrollmentChallenge(db, invitation, pair.publicKey, invitation.serverFingerprint, now);
  const signature = sign(null, enrollmentSigningTranscript({ serverFingerprint: invitation.serverFingerprint, invitationId: invitation.invitationId, challengeId: challenge.id, challenge: challenge.challenge, displayName: name, devicePublicKeyPem: pair.publicKey, messagingPublicKeyPem: messaging.publicKey }), pair.privateKey).toString("base64url");
  const enrolled = enrollDevice(db, { invitation, challengeId: challenge.id, challenge: challenge.challenge, displayName: name, devicePublicKeyPem: pair.publicKey, messagingPublicKeyPem: messaging.publicKey, signature }, now);
  approveDevice(db, enrolled.fingerprint, now);
  return { id: enrolled.id, privateKey: pair.privateKey, publicKey: pair.publicKey };
}

function keyEnvelope(projectId: string, sender: ReturnType<typeof device>, recipientDeviceId: string) {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch: 1,
    recipientDeviceId,
    senderDeviceId: sender.id,
    sealedProjectKey: Buffer.alloc(80, 3).toString("base64url"),
    senderPublicKeyPem: sender.publicKey,
  };
  return { ...unsigned, signature: sign(null, projectKeyEnvelopeSigningTranscript(unsigned), sender.privateKey).toString("base64url") };
}

function contentEnvelope(projectId: string, sender: ReturnType<typeof device>, recordType: "task" | "agent-response" | "artifact", recordId: string) {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch: 1,
    recordType,
    recordId,
    nonce: Buffer.alloc(24, recordType === "task" ? 4 : recordType === "artifact" ? 8 : 5).toString("base64url"),
    ciphertext: Buffer.alloc(96, recordType === "task" ? 6 : recordType === "artifact" ? 9 : 7).toString("base64url"),
    senderDeviceId: sender.id,
    senderPublicKeyPem: sender.publicKey,
  };
  return { ...unsigned, signature: sign(null, projectContentSigningTranscript(unsigned), sender.privateKey).toString("base64url") };
}

describe("authoritative agent dependencies", () => {
  test("accepts only the assigned host's signed and immutable workspace report", () => {
    const db = openDatabase(":memory:");
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-execution-"));
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = device(db, "Stephen", now);
      const kai = device(db, "Kai", now);
      const identity = createServerIdentity(serverPaths(root));
      const project = createProject(db, "Execution evidence", stephen.id, now);
      addProjectMember(db, project.id, stephen.id, kai.id, now);
      registerAgent(db, {
        id: "kai-agent",
        projectId: project.id,
        hostDeviceId: kai.id,
        name: "Kai",
      }, now);
      const taskId = "8661361f-ce2f-4bec-88fd-c4fb32f49704";
      const issuedAt = now.toISOString();
      const expiresAt = new Date(now.getTime() + 60_000).toISOString();
      const nonce = "E".repeat(32);
      const prompt = "Prepare the isolated change";
      const requesterSignature = sign(null, agentRequestSigningTranscript({
        taskId,
        projectId: project.id,
        agentId: "kai-agent",
        prompt,
        nonce,
        issuedAt,
        expiresAt,
        dependencies: [],
        inputArtifactIds: [],
      }), stephen.privateKey).toString("base64url");
      createAgentTask(db, identity, {
        id: taskId,
        projectId: project.id,
        requesterDeviceId: stephen.id,
        agentId: "kai-agent",
        prompt,
        nonce,
        issuedAt,
        expiresAt,
        dependencies: [],
        inputArtifactIds: [],
        requesterSignature,
      }, now);
      const unsigned = {
        taskId,
        projectId: project.id,
        agentId: "kai-agent",
        workspaceMode: "git-worktree" as const,
        workspaceRef: `worktrees/${project.id}/kai-agent/${taskId}`,
        branch: `cocodex/${project.id.slice(0, 8)}/kai-agent/${taskId}`,
        baseCommit: "a".repeat(40),
        mergeTarget: "main",
        startedAt: new Date(now.getTime() + 1_000).toISOString(),
      };
      const report = {
        ...unsigned,
        signature: sign(
          null,
          agentExecutionSigningTranscript(unsigned),
          kai.privateKey,
        ).toString("base64url"),
      };
      expect(() => acceptAgentExecutionReport(db, stephen.id, report, now))
        .toThrow("cannot report");
      expect(() => acceptAgentExecutionReport(db, kai.id, {
        ...report,
        signature: sign(
          null,
          agentExecutionSigningTranscript(unsigned),
          stephen.privateKey,
        ).toString("base64url"),
      }, now)).toThrow("signature");
      expect(acceptAgentExecutionReport(db, kai.id, report, now)).toEqual({
        taskId,
        startedAt: unsigned.startedAt,
        created: true,
      });
      expect(acceptAgentExecutionReport(db, kai.id, report, now)).toEqual({
        taskId,
        startedAt: unsigned.startedAt,
        created: false,
      });
      expect(() => acceptAgentExecutionReport(db, kai.id, {
        ...report,
        workspaceRef: `worktrees/${project.id}/other/${taskId}`,
      }, now)).toThrow();
      const spoofedComponent = {
        ...unsigned,
        workspaceRef: `worktrees/${project.id}/other/${taskId}`,
        branch: `cocodex/${project.id.slice(0, 8)}/other/${taskId}`,
      };
      expect(() => acceptAgentExecutionReport(db, kai.id, {
        ...spoofedComponent,
        signature: sign(
          null,
          agentExecutionSigningTranscript(spoofedComponent),
          kai.privateKey,
        ).toString("base64url"),
      }, now)).toThrow("metadata");
      expect(listAgentTasks(db, project.id, stephen.id)).toEqual([
        expect.objectContaining({
          id: taskId,
          status: "running",
          workspaceMode: "git-worktree",
          workspaceRef: unsigned.workspaceRef,
          branch: unsigned.branch,
          baseCommit: unsigned.baseCommit,
          mergeTarget: "main",
          startedAt: unsigned.startedAt,
        }),
      ]);
      const stored = db.query(`
        SELECT execution_signature AS signature FROM agent_tasks WHERE id = ?
      `).get(taskId) as { signature: string };
      expect(stored.signature).toBe(report.signature);
      expect(db.query(`
        SELECT details_json AS detailsJson FROM audit_events
        WHERE event_type = 'agent.execution.started' AND subject_id = ?
      `).get(taskId)).not.toBeNull();
    } finally {
      db.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("lists only project agents with server-derived host and task status", () => {
    const db = openDatabase(":memory:");
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-list-"));
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = device(db, "Stephen", now);
      const kai = device(db, "Kai", now);
      const identity = createServerIdentity(serverPaths(root));
      const project = createProject(db, "Roster", stephen.id, now);
      addProjectMember(db, project.id, stephen.id, kai.id, now);
      registerAgent(db, { id: "kai-agent", projectId: project.id, hostDeviceId: kai.id, name: "Kai" }, now);

      expect(() => listAgents(db, project.id, crypto.randomUUID())).toThrow("approved project member");

      expect(listAgents(db, project.id, stephen.id, () => false)).toEqual([expect.objectContaining({
        id: "kai-agent", hostDisplayName: "Kai", status: "offline", activeTasks: 0, queuedTasks: 0,
      })]);
      expect(listAgents(db, project.id, stephen.id, () => true)).toEqual([expect.objectContaining({
        id: "kai-agent", status: "available", lastTaskAt: null,
      })]);

      const taskId = "8661361f-ce2f-4bec-88fd-c4fb32f49704";
      const issuedAt = now.toISOString();
      const expiresAt = new Date(now.getTime() + 60_000).toISOString();
      const nonce = "N".repeat(32);
      const prompt = "Find the bug";
      const signature = sign(null, agentRequestSigningTranscript({
        taskId, projectId: project.id, agentId: "kai-agent", prompt, nonce, issuedAt, expiresAt, dependencies: [],
      }), stephen.privateKey).toString("base64url");
      createAgentTask(db, identity, {
        id: taskId, projectId: project.id, requesterDeviceId: stephen.id, agentId: "kai-agent", prompt,
        nonce, issuedAt, expiresAt, dependencies: [], requesterSignature: signature,
      }, now);
      expect(listAgents(db, project.id, stephen.id, () => true)).toEqual([expect.objectContaining({
        status: "queued", queuedTasks: 1, lastTaskAt: now.toISOString(),
      })]);
      appendAgentResult(db, kai.id, taskId, "690d9307-4b83-4ff6-9da8-d816219bea53", "Done", true, "completed", now);
      expect(listAgents(db, project.id, stephen.id, () => true)).toEqual([expect.objectContaining({
        status: "completed", activeTasks: 0, queuedTasks: 0,
      })]);
    } finally { db.close(); rmSync(root, { recursive: true, force: true }); }
  });

  test("holds a dependent task until its prerequisite completes", () => {
    const db = openDatabase(":memory:");
    const root = mkdtempSync(join(tmpdir(), "cocodex-agent-routing-"));
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = device(db, "Stephen", now);
      const kai = device(db, "Kai", now);
      const identity = createServerIdentity(serverPaths(root));
      const project = createProject(db, "Dependencies", stephen.id, now);
      addProjectMember(db, project.id, stephen.id, kai.id, now);
      registerAgent(db, { id: "kai-agent", projectId: project.id, hostDeviceId: kai.id, name: "Kai" }, now);
      const make = (id: string, prompt: string, dependencies: string[] = []) => {
        const issuedAt = now.toISOString(); const expiresAt = new Date(now.getTime() + 60_000).toISOString(); const nonce = id.padEnd(32, "0");
        const signature = sign(null, agentRequestSigningTranscript({ taskId: id, projectId: project.id, agentId: "kai-agent", prompt, nonce, issuedAt, expiresAt, dependencies }), stephen.privateKey).toString("base64url");
        return createAgentTask(db, identity, { id, projectId: project.id, requesterDeviceId: stephen.id, agentId: "kai-agent", prompt, nonce, issuedAt, expiresAt, dependencies, requesterSignature: signature }, now).task;
      };
      const first = make("8661361f-ce2f-4bec-88fd-c4fb32f49704", "Find the bug");
      const second = make("4b9abf0f-94c3-4cfa-97a4-1a370b93bb2e", "Write tests", [first.id]);
      const replay = createAgentTask(db, identity, {
        id: second.id,
        projectId: project.id,
        requesterDeviceId: stephen.id,
        agentId: "kai-agent",
        prompt: second.prompt,
        nonce: second.nonce,
        issuedAt: second.issuedAt,
        expiresAt: second.expiresAt,
        dependencies: [first.id, first.id],
        requesterSignature: second.requesterSignature,
      }, now);
      expect(replay.created).toBeFalse();
      expect(pendingAgentTasks(db, kai.id)).toEqual([first]);
      db.query("UPDATE agents SET enabled = 0 WHERE id = ?").run("kai-agent");
      expect(pendingAgentTasks(db, kai.id)).toEqual([]);
      db.query("UPDATE agents SET enabled = 1, host_device_id = ? WHERE id = ?").run(stephen.id, "kai-agent");
      expect(pendingAgentTasks(db, kai.id)).toEqual([]);
      db.query("UPDATE agents SET host_device_id = ? WHERE id = ?").run(kai.id, "kai-agent");
      expect(pendingAgentTasks(db, kai.id)).toEqual([first]);
      appendAgentResult(db, kai.id, first.id, "690d9307-4b83-4ff6-9da8-d816219bea53", "Finding", true, "completed", now);
      expect(pendingAgentTasks(db, kai.id).map(task => task.id)).toEqual([second.id]);

      const cycleId = "e5e0d9f7-0a91-4c1b-a12c-b4ad3e1cf4d4";
      db.query("UPDATE agent_tasks SET dependencies_json = ? WHERE id = ?")
        .run(JSON.stringify([cycleId]), first.id);
      expect(() => make(cycleId, "Cycle must be rejected", [first.id]))
        .toThrow("cycle");
    } finally { db.close(); rmSync(root, { recursive: true, force: true }); }
  });

  test("keeps keyed agent prompts and streamed results opaque while preserving task readiness", () => {
    const db = openDatabase(":memory:");
    const root = mkdtempSync(join(tmpdir(), "cocodex-encrypted-agent-routing-"));
    try {
      const now = new Date("2027-01-01T00:00:00.000Z");
      const stephen = device(db, "Stephen", now);
      const kai = device(db, "Kai", now);
      const identity = createServerIdentity(serverPaths(root));
      const project = createProject(db, "Encrypted agents", stephen.id, now);
      addProjectMember(db, project.id, stephen.id, kai.id, now);
      registerAgent(db, { id: "kai-agent", projectId: project.id, hostDeviceId: kai.id, name: "Kai" }, now);
      expect(shareProjectKeyEnvelope(db, project.id, stephen.id, keyEnvelope(project.id, stephen, stephen.id), now).created).toBeTrue();
      expect(shareProjectKeyEnvelope(db, project.id, stephen.id, keyEnvelope(project.id, stephen, kai.id), now).created).toBeTrue();

      const taskId = "8661361f-ce2f-4bec-88fd-c4fb32f49704";
      const artifactId = "4ed06694-3b43-423f-98b7-3df728f3ad67";
      const artifact = publishEncryptedArtifact(db, {
        artifactId,
        projectId: project.id,
        taskId: null,
        authorDeviceId: stephen.id,
        envelope: contentEnvelope(project.id, stephen, "artifact", artifactId),
      }, now).artifact;
      const issuedAt = now.toISOString();
      const expiresAt = new Date(now.getTime() + 60_000).toISOString();
      const promptEnvelope = contentEnvelope(project.id, stephen, "task", taskId);
      const created = createEncryptedAgentTask(db, identity, {
        id: taskId,
        projectId: project.id,
        requesterDeviceId: stephen.id,
        agentId: "kai-agent",
        nonce: "N".repeat(32),
        issuedAt,
        expiresAt,
        dependencies: [],
        inputArtifactIds: [artifactId, artifactId],
        envelope: promptEnvelope,
      }, now);
      expect(created.created).toBeTrue();
      expect(created.task.prompt).toBe("[encrypted]");
      expect(created.task.inputArtifactIds).toEqual([artifactId]);
      expect(created.task.inputArtifacts).toEqual([artifact]);
      expect(pendingEncryptedAgentTasks(db, kai.id, now)).toEqual([created.task]);
      db.query("UPDATE agents SET enabled = 0 WHERE id = ?").run("kai-agent");
      expect(pendingEncryptedAgentTasks(db, kai.id, now)).toEqual([]);
      db.query("UPDATE agents SET enabled = 1, host_device_id = ? WHERE id = ?").run(stephen.id, "kai-agent");
      expect(pendingEncryptedAgentTasks(db, kai.id, now)).toEqual([]);
      db.query("UPDATE agents SET host_device_id = ? WHERE id = ?").run(kai.id, "kai-agent");
      expect(pendingEncryptedAgentTasks(db, kai.id, now)).toEqual([created.task]);
      expect(cancelEncryptedAgentTask(db, stephen.id, taskId).task.id).toBe(taskId);
      const resultId = "4b9abf0f-94c3-4cfa-97a4-1a370b93bb2e";
      const result = appendEncryptedAgentResult(db, {
        taskId,
        eventId: resultId,
        targetDeviceId: kai.id,
        envelope: contentEnvelope(project.id, kai, "agent-response", resultId),
        final: true,
        status: "completed",
      }, now);
      expect(result.created).toBeTrue();
      expect(result.event.sequence).toBeGreaterThan(0);
      expect(db.query("SELECT status FROM agent_tasks WHERE id = ?").get(taskId)).toEqual({ status: "completed" });
      const storedTask = db.query("SELECT prompt, prompt_envelope_json AS envelopeJson FROM agent_tasks WHERE id = ?").get(taskId) as { prompt: string; envelopeJson: string };
      expect(storedTask.prompt).toBe("[encrypted]");
      expect(storedTask.envelopeJson).not.toContain("agent prompt plaintext");
      const storedResult = db.query("SELECT envelope_json AS envelopeJson FROM project_chat_events WHERE event_id = ?").get(resultId) as { envelopeJson: string };
      expect(storedResult.envelopeJson).not.toContain("agent result plaintext");
      expect(db.query("SELECT COUNT(*) AS count FROM project_chat_events WHERE task_id = ?").get(taskId))
        .toEqual({ count: 1 });
      expect(() => createEncryptedAgentTask(db, identity, {
        id: "82f2266a-16ac-4b83-b70f-f8145e88ae66",
        projectId: project.id,
        requesterDeviceId: stephen.id,
        agentId: "kai-agent",
        nonce: "A".repeat(32),
        issuedAt,
        expiresAt,
        inputArtifactIds: ["be8c6278-c10d-44d6-829f-308030cce0cb"],
        envelope: contentEnvelope(project.id, stephen, "task", "82f2266a-16ac-4b83-b70f-f8145e88ae66"),
      }, now)).toThrow("not found in this project");
      const otherProject = createProject(db, "Other encrypted project", stephen.id, now);
      expect(shareProjectKeyEnvelope(db, otherProject.id, stephen.id,
        keyEnvelope(otherProject.id, stephen, stephen.id), now).created).toBeTrue();
      const otherArtifactId = "f971a036-0989-4eb6-9fba-ddf385b57d13";
      publishEncryptedArtifact(db, {
        artifactId: otherArtifactId,
        projectId: otherProject.id,
        taskId: null,
        authorDeviceId: stephen.id,
        envelope: contentEnvelope(otherProject.id, stephen, "artifact", otherArtifactId),
      }, now);
      expect(() => createEncryptedAgentTask(db, identity, {
        id: "f2c53ee8-ea55-4ba7-9cf8-f9f328bd92a3",
        projectId: project.id,
        requesterDeviceId: stephen.id,
        agentId: "kai-agent",
        nonce: "B".repeat(32),
        issuedAt,
        expiresAt,
        inputArtifactIds: [otherArtifactId],
        envelope: contentEnvelope(project.id, stephen, "task", "f2c53ee8-ea55-4ba7-9cf8-f9f328bd92a3"),
      }, now)).toThrow("not found in this project");
    } finally { db.close(); rmSync(root, { recursive: true, force: true }); }
  });
});

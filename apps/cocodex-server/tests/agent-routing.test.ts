import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentRequestSigningTranscript, decodeInvitation, enrollmentSigningTranscript, projectContentSigningTranscript, projectKeyEnvelopeSigningTranscript } from "@cocodex/protocol";
import { createAgentTask, pendingAgentTasks, registerAgent, appendAgentResult } from "../src/agent-routing";
import { appendEncryptedAgentResult, cancelEncryptedAgentTask, createEncryptedAgentTask, pendingEncryptedAgentTasks } from "../src/encrypted-agent-routing";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { addProjectMember, createProject } from "../src/shared-state";
import { shareProjectKeyEnvelope } from "../src/project-encryption-storage";

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

function contentEnvelope(projectId: string, sender: ReturnType<typeof device>, recordType: "task" | "agent-response", recordId: string) {
  const unsigned = {
    version: 1 as const,
    projectId,
    keyEpoch: 1,
    recordType,
    recordId,
    nonce: Buffer.alloc(24, recordType === "task" ? 4 : 5).toString("base64url"),
    ciphertext: Buffer.alloc(96, recordType === "task" ? 6 : 7).toString("base64url"),
    senderDeviceId: sender.id,
    senderPublicKeyPem: sender.publicKey,
  };
  return { ...unsigned, signature: sign(null, projectContentSigningTranscript(unsigned), sender.privateKey).toString("base64url") };
}

describe("authoritative agent dependencies", () => {
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
      expect(pendingAgentTasks(db, kai.id)).toEqual([first]);
      appendAgentResult(db, kai.id, first.id, "690d9307-4b83-4ff6-9da8-d816219bea53", "Finding", true, "completed", now);
      expect(pendingAgentTasks(db, kai.id).map(task => task.id)).toEqual([second.id]);
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
        envelope: promptEnvelope,
      }, now);
      expect(created.created).toBeTrue();
      expect(created.task.prompt).toBe("[encrypted]");
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
    } finally { db.close(); rmSync(root, { recursive: true, force: true }); }
  });
});

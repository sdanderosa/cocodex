import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentRequestSigningTranscript, decodeInvitation, enrollmentSigningTranscript } from "@cocodex/protocol";
import { createAgentTask, pendingAgentTasks, registerAgent, appendAgentResult } from "../src/agent-routing";
import { openDatabase } from "../src/database";
import { approveDevice, createEnrollmentChallenge, enrollDevice } from "../src/enrollment";
import { createServerIdentity } from "../src/identity";
import { createInvitation } from "../src/invitations";
import { serverPaths } from "../src/paths";
import { addProjectMember, createProject } from "../src/shared-state";

function device(db: ReturnType<typeof openDatabase>, name: string, now: Date) {
  const pair = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const messaging = generateKeyPairSync("x25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const invitation = decodeInvitation(createInvitation(db, { host: "server.test", port: 1, serverFingerprint: "AAAA-BBBB-CCCC-DDDD", now }));
  const challenge = createEnrollmentChallenge(db, invitation, pair.publicKey, invitation.serverFingerprint, now);
  const signature = sign(null, enrollmentSigningTranscript({ serverFingerprint: invitation.serverFingerprint, invitationId: invitation.invitationId, challengeId: challenge.id, challenge: challenge.challenge, displayName: name, devicePublicKeyPem: pair.publicKey, messagingPublicKeyPem: messaging.publicKey }), pair.privateKey).toString("base64url");
  const enrolled = enrollDevice(db, { invitation, challengeId: challenge.id, challenge: challenge.challenge, displayName: name, devicePublicKeyPem: pair.publicKey, messagingPublicKeyPem: messaging.publicKey, signature }, now);
  approveDevice(db, enrolled.fingerprint, now);
  return { id: enrolled.id, privateKey: pair.privateKey };
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
});

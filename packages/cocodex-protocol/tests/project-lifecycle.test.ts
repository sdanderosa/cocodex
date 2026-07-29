import { describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import {
  clientFrameSchema,
  projectDeletedFrameSchema,
  projectLifecycleSigningTranscript,
  projectServerFrameSchema,
} from "../src/index";

function lifecycleFrame(action: "rename" | "archive" | "restore" | "delete") {
  return {
    version: 1 as const,
    type: "project.lifecycle.update" as const,
    requestId: randomUUID(),
    operationId: randomUUID(),
    projectId: randomUUID(),
    action,
    expectedRevision: 2,
    ...(action === "rename" ? { name: "Nocturne Next" } : {}),
    ...(action === "delete" ? { confirmationName: "Nocturne" } : {}),
    serverFingerprint: "AA:BB:CC:DD:EE:FF",
    serverEpoch: 3,
    issuedAt: "2030-01-01T00:00:00.000Z",
    expiresAt: "2030-01-01T00:02:00.000Z",
    nonce: Buffer.alloc(32, 3).toString("base64url"),
    signature: Buffer.alloc(64, 4).toString("base64url"),
  };
}

describe("CoCodex project lifecycle protocol", () => {
  test("binds each signed lifecycle field and rejects ambiguous action payloads", () => {
    const rename = lifecycleFrame("rename");
    expect(clientFrameSchema.parse(rename)).toEqual(rename);
    expect(() => clientFrameSchema.parse({ ...rename, confirmationName: "Nocturne" })).toThrow();
    expect(() => clientFrameSchema.parse({ ...rename, name: undefined })).toThrow();
    const deletion = lifecycleFrame("delete");
    expect(clientFrameSchema.parse(deletion)).toEqual(deletion);
    expect(() => clientFrameSchema.parse({ ...deletion, confirmationName: undefined })).toThrow();
    const transcript = projectLifecycleSigningTranscript(rename);
    expect(transcript.equals(projectLifecycleSigningTranscript(rename))).toBeTrue();
    expect(transcript.equals(projectLifecycleSigningTranscript({ ...rename, expectedRevision: 3 }))).toBeFalse();
    expect(transcript.equals(projectLifecycleSigningTranscript({ ...rename, name: "Other" }))).toBeFalse();
  });

  test("accepts lifecycle acknowledgements and delete tombstones only with coherent transitions", () => {
    const input = lifecycleFrame("delete");
    const transition = {
      operationId: input.operationId,
      projectId: input.projectId,
      action: "delete" as const,
      actorDeviceId: randomUUID(),
      previousName: "Nocturne",
      resultingName: "Nocturne",
      previousState: "archived" as const,
      resultingState: null,
      resultingRevision: 3,
      createdAt: "2030-01-01T00:00:30.000Z",
    };
    expect(projectServerFrameSchema.parse({
      version: 1, type: "project.lifecycle.updated", requestId: input.requestId,
      transition, created: true,
    })).toMatchObject({ type: "project.lifecycle.updated", created: true });
    expect(projectDeletedFrameSchema.parse({ version: 1, type: "project.deleted", transition }))
      .toMatchObject({ type: "project.deleted" });
    expect(() => projectDeletedFrameSchema.parse({
      version: 1,
      type: "project.deleted",
      transition: { ...transition, action: "archive", resultingState: "archived" },
    })).toThrow();
  });
});

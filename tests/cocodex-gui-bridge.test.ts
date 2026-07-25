import { describe, expect, test } from "bun:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { PassThrough } from "node:stream";
import { join } from "node:path";
import { CoCodexGuiBridge } from "../src/cocodex/gui-bridge";
import { clientPaths } from "../src/cocodex/paths";

describe("CoCodex GUI bridge", () => {
  test("runs the resident session without exposing private ciphertext", async () => {
    const root = join(import.meta.dir, ".tmp", crypto.randomUUID());
    mkdirSync(root, { recursive: true });
    const paths = clientPaths(root);
    writeFileSync(paths.connection, JSON.stringify({
      version: 1,
      host: "server.example",
      port: 48120,
      serverFingerprint: "server-fingerprint",
      serverCertificatePem: "certificate",
      serverIdentityPublicKeyPem: "identity",
      deviceId: crypto.randomUUID(),
      displayName: "Stephen",
    }));

    const received: unknown[] = [];
    const runner = async (_paths: typeof paths, options: { input?: NodeJS.ReadableStream; output?: NodeJS.WritableStream }) => {
      const input = options.input as PassThrough;
      const output = options.output as PassThrough;
      output.write(`${JSON.stringify({ source: "session", state: "connected", deviceId: "device" })}\n`);
      output.write(`${JSON.stringify({
        source: "server",
        frame: { type: "private.message", message: { messageId: "message", ciphertext: "secret-box" } },
      })}\n`);
      for await (const chunk of input) {
        for (const line of String(chunk).trim().split("\n")) {
          const command = JSON.parse(line);
          received.push(command);
          if (command.type === "shutdown") return;
        }
      }
    };
    const bridge = new CoCodexGuiBridge(paths, runner);
    const capability = bridge.issueCapability();
    expect(bridge.acceptsCapability(capability)).toBeTrue();
    expect(bridge.acceptsCapability("wrong-capability")).toBeFalse();

    expect(bridge.start().configured).toBe(true);
    await Bun.sleep(5);
    expect(bridge.status().state).toBe("connected");
    expect(bridge.command({ type: "project.list" }).accepted).toBe(true);
    expect(bridge.command({
      type: "context.get",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "context.update",
      projectId: crypto.randomUUID(),
      expectedRevision: 0,
      finalGoal: "Keep the shared goal authoritative",
      context: { source: "gui-test" },
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "usage.get",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "agent.list",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    expect(bridge.command({
      type: "agent.task.list",
      projectId: crypto.randomUUID(),
    }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.approval", taskId: "task-1", approved: true }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.safety.status" }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.emergency.stop", reason: "GUI safety test" }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.emergency.resume" }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.full-computer.enable", confirm: true }).accepted).toBe(true);
    expect(bridge.command({ type: "agent.full-computer.disable" }).accepted).toBe(true);
    bridge.stop();
    await Bun.sleep(5);

    expect(received.some((value: any) => value.type === "project.list")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.list")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.task.list")).toBe(true);
    expect(received.some((value: any) => value.type === "context.get")).toBe(true);
    expect(received.some((value: any) => value.type === "context.update" && value.finalGoal === "Keep the shared goal authoritative")).toBe(true);
    expect(received.some((value: any) => value.type === "usage.get")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.approval" && value.approved === true)).toBe(true);
    expect(received.some((value: any) => value.type === "agent.safety.status")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.emergency.stop")).toBe(true);
    expect(received.some((value: any) => value.type === "agent.emergency.resume")).toBe(true);
    const privateEvent = bridge.eventsAfter(0).events
      .find((event: any) => event.value?.frame?.type === "private.message");
    expect(JSON.stringify(privateEvent)).not.toContain("secret-box");
  });
});

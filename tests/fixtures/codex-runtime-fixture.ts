#!/usr/bin/env bun
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

if (Bun.argv.includes("--version")) {
  console.log("codex-cli 99.0.0");
  process.exit(0);
}

const account = process.env.COCODEX_ACCOUNT_FIXTURE?.trim();
if (!account) throw new Error("COCODEX_ACCOUNT_FIXTURE is required");
const runtimeMarker = (() => {
  try {
    return JSON.parse(process.env.CODEX_RUNTIME_MARKER ?? "{}") as {
      allowFullComputer?: boolean;
      barrierDirectory?: string;
    };
  } catch {
    throw new Error("CODEX_RUNTIME_MARKER must be valid fixture JSON");
  }
})();
if (!Bun.argv.includes("exec") || !Bun.argv.includes("--json")) {
  throw new Error("Expected official Codex exec JSONL arguments");
}
const resumeIndex = Bun.argv.indexOf("resume");
if (resumeIndex >= 0 && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(Bun.argv[resumeIndex + 1] ?? "")) {
  throw new Error("Expected a bounded Codex resume session ID");
}
const dangerFullAccess = Bun.argv.includes("danger-full-access");
if ((dangerFullAccess && runtimeMarker.allowFullComputer !== true)
  || Bun.argv.includes("--yolo")) {
  throw new Error("Unsafe Codex fixture invocation");
}

const prompt = await Bun.stdin.text();
if (!prompt.trim()) throw new Error("Prompt stdin is required");
const marker = join(process.cwd(), `${account}-execution.json`);
writeFileSync(marker, `${JSON.stringify({
  account,
  prompt,
  cwd: process.cwd(),
  args: Bun.argv.slice(2),
  sandbox: dangerFullAccess ? "danger-full-access" : "restricted",
}, null, 2)}\n`, "utf8");
const barrierDirectory = runtimeMarker.barrierDirectory?.trim();
if (barrierDirectory) {
  const release = join(barrierDirectory, "release");
  while (!existsSync(release)) await Bun.sleep(25);
}
console.log(JSON.stringify({
  type: "thread.started",
  thread_id: resumeIndex >= 0
    ? Bun.argv[resumeIndex + 1]
    : "11111111-1111-4111-8111-111111111111",
}));
console.log(JSON.stringify({
  type: "item.completed",
  item: { type: "agent_message", text: `${account}: accepted locally` },
}));
console.log(JSON.stringify({
  type: "item.completed",
  item: { type: "agent_message", text: `${account}: ${prompt}` },
}));
console.log(JSON.stringify({
  type: "turn.completed",
  usage: { input_tokens: account.length + prompt.length, output_tokens: 7 },
}));

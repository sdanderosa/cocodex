#!/usr/bin/env bun
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { createServer } from "node:net";

function option(name: string): string | undefined {
  const index = Bun.argv.indexOf(name);
  return index >= 0 ? Bun.argv[index + 1] : undefined;
}

function requiredOption(name: string): string {
  const value = option(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

const prefix = resolve(requiredOption("--prefix"));
const packageRoot = resolve(prefix, "node_modules", "@sdanderosa", "cocodex");
const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
};
if (manifest.name !== "@sdanderosa/cocodex") throw new Error("Installed package identity is not CoCodex");

const explicitNode = option("--node-command");
const node = explicitNode
  ? resolve(explicitNode)
  : Bun.which(process.platform === "win32" ? "node.exe" : "node") ?? Bun.which("node");
if (!node || !existsSync(node) || !statSync(node).isFile()) {
  throw new Error("Node.js is required to verify the installed launchers; pass --node-command PATH");
}
const ocx = join(packageRoot, "bin", "ocx.mjs");
const client = join(packageRoot, "bin", "ccx.mjs");
const server = join(packageRoot, "bin", "ccx-server.mjs");
for (const path of [ocx, client, server]) {
  if (!existsSync(path) || !statSync(path).isFile()) throw new Error(`Installed launcher is missing: ${path}`);
}

type LockEntry = { version?: string };
const shrinkwrap = JSON.parse(readFileSync(join(packageRoot, "npm-shrinkwrap.json"), "utf8")) as {
  packages?: Record<string, LockEntry>;
};
const locked = new Set<string>();
for (const [path, entry] of Object.entries(shrinkwrap.packages ?? {})) {
  if (!path || typeof entry.version !== "string") continue;
  const marker = "node_modules/";
  const offset = path.lastIndexOf(marker);
  if (offset < 0) continue;
  const name = path.slice(offset + marker.length);
  locked.add(`${name}@${entry.version}`);
}

const installed = new Set<string>();
function visitNodeModules(nodeModules: string): void {
  if (!existsSync(nodeModules)) return;
  for (const entry of readdirSync(nodeModules, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".")) continue;
    if (entry.name.startsWith("@")) {
      for (const scoped of readdirSync(join(nodeModules, entry.name), { withFileTypes: true })) {
        if (scoped.isDirectory()) visitPackage(join(nodeModules, entry.name, scoped.name));
      }
    } else {
      visitPackage(join(nodeModules, entry.name));
    }
  }
}

function visitPackage(directory: string): void {
  const path = join(directory, "package.json");
  if (!existsSync(path)) return;
  const value = JSON.parse(readFileSync(path, "utf8")) as { name?: string; version?: string };
  if (typeof value.name !== "string" || typeof value.version !== "string") {
    throw new Error(`Installed dependency has invalid identity: ${directory}`);
  }
  const id = `${value.name}@${value.version}`;
  installed.add(id);
  if (value.name !== "@sdanderosa/cocodex" && !locked.has(id)) {
    throw new Error(`Installed dependency is outside npm-shrinkwrap.json: ${id}`);
  }
  visitNodeModules(join(directory, "node_modules"));
}

visitNodeModules(join(prefix, "node_modules"));
for (const [name, version] of Object.entries(manifest.dependencies ?? {})) {
  if (!installed.has(`${name}@${version}`)) {
    throw new Error(`Exact direct dependency is not installed: ${name}@${version}`);
  }
}

async function freePort(): Promise<number> {
  const listener = createServer();
  await new Promise<void>((accept, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", accept);
  });
  const address = listener.address();
  if (!address || typeof address === "string") throw new Error("Unable to reserve a local test port");
  await new Promise<void>((accept, reject) => listener.close(error => error ? reject(error) : accept()));
  return address.port;
}

async function run(
  entrypoint: string,
  args: string[],
  env: Record<string, string | undefined>,
  expectedExit = 0,
): Promise<{ stdout: string; stderr: string }> {
  const child = Bun.spawn([node, entrypoint, ...args], {
    env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== expectedExit) {
    throw new Error(`${basename(entrypoint)} ${args.join(" ")} exited ${exitCode}: ${stderr || stdout}`);
  }
  return { stdout, stderr };
}

async function waitForHealth(url: string, tls = false): Promise<Record<string, unknown>> {
  const deadline = Date.now() + 15_000;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, tls ? { tls: { rejectUnauthorized: false } } : undefined);
      last = `${response.status} ${await response.text()}`;
      if (response.ok) return JSON.parse(last.slice(last.indexOf(" ") + 1)) as Record<string, unknown>;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await Bun.sleep(100);
  }
  throw new Error(`Installed process did not become healthy at ${url}: ${last}`);
}

function startDetached(entrypoint: string, args: string[], env: Record<string, string | undefined>): number {
  const child = Bun.spawn([node, entrypoint, ...args], {
    env,
    stdin: "ignore",
    stdout: "ignore",
    stderr: "ignore",
    detached: true,
    windowsHide: true,
  });
  child.unref();
  return child.pid;
}

const root = mkdtempSync(join(tmpdir(), "cocodex-installed-release-"));
const clientHome = join(root, "client");
const serverHome = join(root, "server");
const openCodexHome = join(root, "opencodex");
const codexHome = join(root, "codex");
for (const directory of [clientHome, serverHome, openCodexHome, codexHome]) {
  mkdirSync(directory);
}
const env = {
  ...process.env,
  COCODEX_HOME: clientHome,
  COCODEX_SERVER_HOME: serverHome,
  COCODEX_DISABLE_PORT_MAPPING: "1",
  OPENCODEX_HOME: openCodexHome,
  CODEX_HOME: codexHome,
};

let localPort = 0;
let serverPort = 0;
let serverStarted = false;
try {
  await run(client, ["--help"], env);
  await run(server, ["--help"], env);
  await run(ocx, ["--version"], env);

  localPort = await freePort();
  startDetached(ocx, ["start", "--port", String(localPort)], env);
  const localHealth = await waitForHealth(`http://127.0.0.1:${localPort}/healthz`);
  if (localHealth.service !== "opencodex") throw new Error("Installed local runtime returned the wrong service identity");
  const gui = await fetch(`http://127.0.0.1:${localPort}/`);
  if (!gui.ok || (await gui.text()).length < 100) throw new Error("Installed GUI entrypoint is unavailable");
  await run(ocx, ["stop"], env);

  serverPort = await freePort();
  await run(server, ["init", "--public-host", "127.0.0.1", "--port", String(serverPort), "--state-root", serverHome], env);
  startDetached(server, ["start", "--state-root", serverHome], env);
  serverStarted = true;
  const initialHealth = await waitForHealth(`https://127.0.0.1:${serverPort}/healthz`, true);
  if (initialHealth.service !== "cocodex-server" || initialHealth.protocol !== 1) {
    throw new Error("Installed Server returned the wrong protocol health identity");
  }
  const initialPid = Number(readFileSync(join(serverHome, "server.pid"), "utf8").trim());
  await run(server, ["restart", "--state-root", serverHome], env);
  const restartedHealth = await waitForHealth(`https://127.0.0.1:${serverPort}/healthz`, true);
  if (restartedHealth.service !== "cocodex-server" || restartedHealth.protocol !== 1) {
    throw new Error("Restarted installed Server returned the wrong protocol health identity");
  }
  const restartedPid = Number(readFileSync(join(serverHome, "server.pid"), "utf8").trim());
  if (!Number.isInteger(initialPid) || !Number.isInteger(restartedPid) || initialPid === restartedPid) {
    throw new Error("Installed Server restart did not replace the process");
  }
  await run(server, ["stop", "--state-root", serverHome], env);
  serverStarted = false;
  const stopped = JSON.parse((await run(server, ["status", "--state-root", serverHome], env)).stdout) as { running?: boolean };
  if (stopped.running !== false) throw new Error("Installed Server did not report a stopped state");

  console.log(JSON.stringify({
    verified: true,
    package: `${manifest.name}@${manifest.version}`,
    installedDependencies: installed.size - 1,
    localRuntime: { port: localPort, service: localHealth.service, gui: 200 },
    server: { port: serverPort, initialPid, restartedPid, stopped: true },
  }, null, 2));
} finally {
  try {
    if (localPort) await run(ocx, ["stop"], env);
  } catch {}
  try {
    if (serverStarted) await run(server, ["stop", "--state-root", serverHome], env);
  } catch {}
  rmSync(root, { recursive: true, force: true });
}

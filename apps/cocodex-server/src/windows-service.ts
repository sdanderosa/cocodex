import { createHash, createPrivateKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { hardenSecretDir, hardenSecretPath } from "../../../src/lib/windows-secret-acl";
import { loadConfig } from "./config";
import { loadServerIdentity } from "./identity";
import type { ServerPaths } from "./paths";
import { readTlsPrivateKey } from "./tls";

export const COCODEX_SERVER_SERVICE_ID = "cocodex-server";
export const SERVER_WINSW_VERSION = "2.12.0";
export const SERVER_WINSW_URL =
  `https://github.com/winsw/winsw/releases/download/v${SERVER_WINSW_VERSION}/WinSW.NET461.exe`;
export const SERVER_WINSW_SHA256 =
  "b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f";

export type ServerServiceState = "started" | "stopped" | "nonexistent" | "unknown";

export interface ServerServiceEntry {
  executable: string;
  cliScript?: string;
}

export interface ScmServiceConfig {
  binaryPath: string;
  startType: string;
  startName: string;
}

export interface ServerServiceStatus {
  serviceId: typeof COCODEX_SERVER_SERVICE_ID;
  state: ServerServiceState;
  installed: boolean | null;
  stateRoot: string;
  sameUser: boolean | null;
  automaticStart: boolean | null;
  binaryPathMatches: boolean | null;
  pid: number | null;
  ready: boolean;
}

export interface ServerServiceDeps {
  platform?: NodeJS.Platform;
  ensureBinary?: (paths: ServerPaths) => Promise<string>;
  status?: (paths: ServerPaths) => ServerServiceState;
  run?: (paths: ServerPaths, args: string[]) => string;
  interactive?: (paths: ServerPaths, args: string[]) => void;
  scmConfig?: () => ScmServiceConfig;
  writeXml?: (path: string, content: string) => void;
  waitReady?: (paths: ServerPaths) => Promise<void>;
  waitStopped?: (paths: ServerPaths) => Promise<void>;
  privateStateAccessible?: (paths: ServerPaths) => void;
  healthReady?: (paths: ServerPaths) => Promise<boolean>;
}

function xmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function windowsArgument(value: string): string {
  if (value.includes("\0") || value.includes('"')) throw new Error("Invalid quote or NUL in service path");
  return `"${value}"`;
}

export function buildWindowsServerServiceXml(
  paths: ServerPaths,
  entry: ServerServiceEntry,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const executable = resolve(entry.executable);
  const cliScript = entry.cliScript ? resolve(entry.cliScript) : undefined;
  const args = [...(cliScript ? [windowsArgument(cliScript)] : []), "start", "--state-root", windowsArgument(paths.root)].join(" ");
  const domain = env.USERDOMAIN?.trim() || ".";
  const user = env.USERNAME?.trim();
  if (!user) throw new Error("USERNAME is required to install the CoCodex Server service");
  return `<?xml version="1.0" encoding="UTF-8"?>
<service>
  <id>${COCODEX_SERVER_SERVICE_ID}</id>
  <name>CoCodex Server</name>
  <description>Standalone CoCodex collaboration authority running under its owning Windows user.</description>
  <executable>${xmlEscape(executable)}</executable>
  <arguments>${xmlEscape(args)}</arguments>
  <workingdirectory>${xmlEscape(dirname(cliScript ?? executable))}</workingdirectory>
  <env name="COCODEX_SERVER_HOME" value="${xmlEscape(paths.root)}"/>
  <logpath>${xmlEscape(paths.serviceLogs)}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>4</keepFiles>
  </log>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <onfailure action="restart" delay="5 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>20 sec</stoptimeout>
  <serviceaccount>
    <domain>${xmlEscape(domain)}</domain>
    <user>${xmlEscape(user)}</user>
    <allowservicelogon>true</allowservicelogon>
  </serviceaccount>
</service>
`;
}

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export async function ensureWindowsServerServiceBinary(paths: ServerPaths, fetchImpl: typeof fetch = fetch): Promise<string> {
  if (existsSync(paths.serviceExecutable)) {
    if (sha256Hex(readFileSync(paths.serviceExecutable)) === SERVER_WINSW_SHA256) {
      hardenSecretPath(paths.serviceExecutable, { required: true });
      return paths.serviceExecutable;
    }
    rmSync(paths.serviceExecutable, { force: true });
  }
  mkdirSync(paths.serviceDirectory, { recursive: true });
  hardenSecretDir(paths.serviceDirectory, { required: true });
  let bytes: Buffer;
  try {
    const response = await fetchImpl(SERVER_WINSW_URL);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    bytes = Buffer.from(await response.arrayBuffer());
  } catch (error) {
    throw new Error(`Failed to download WinSW ${SERVER_WINSW_VERSION} (${error instanceof Error ? error.message : String(error)}). Place the official WinSW.NET461.exe at ${paths.serviceExecutable} and retry.`);
  }
  const digest = sha256Hex(bytes);
  if (digest !== SERVER_WINSW_SHA256) {
    throw new Error(`WinSW download failed SHA-256 verification (got ${digest}, expected ${SERVER_WINSW_SHA256}); refusing to install an unverified service binary.`);
  }
  const temporary = `${paths.serviceExecutable}.new`;
  writeFileSync(temporary, bytes, { flag: "wx" });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, paths.serviceExecutable);
  hardenSecretPath(paths.serviceExecutable, { required: true });
  return paths.serviceExecutable;
}

export function parseServerServiceStatus(output: string): ServerServiceState {
  const value = output.trim().toLowerCase();
  if (value.includes("nonexistent")) return "nonexistent";
  if (value.includes("started")) return "started";
  if (value.includes("stopped")) return "stopped";
  return "unknown";
}

function scExePath(): string {
  const candidate = `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\sc.exe`;
  return existsSync(candidate) ? candidate : "sc.exe";
}

function execSc(args: string[]): string {
  return execFileSync(scExePath(), args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], windowsHide: true }).trim();
}

function errorText(error: unknown): string {
  const value = error as { message?: string; stdout?: string | Buffer; stderr?: string | Buffer };
  return [value.message, value.stdout, value.stderr]
    .map(part => typeof part === "string" ? part : Buffer.isBuffer(part) ? part.toString("utf8") : "").join("\n");
}

export function probeServerServiceRegistration(query: () => string = () => execSc(["query", COCODEX_SERVER_SERVICE_ID])): boolean | "error" {
  try {
    query();
    return true;
  } catch (error) {
    const status = (error as { status?: number }).status;
    return status === 1060 || /\b1060\b/.test(errorText(error)) ? false : "error";
  }
}

function runWinsw(paths: ServerPaths, args: string[]): string {
  return execFileSync(paths.serviceExecutable, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], windowsHide: true }).trim();
}

function runWinswInteractive(paths: ServerPaths, args: string[]): void {
  execFileSync(paths.serviceExecutable, args, { stdio: "inherit" });
}
function runServerServiceLifecycle(paths: ServerPaths, args: string[]): string {
  if (existsSync(paths.serviceExecutable)) return runWinsw(paths, args);
  if (args[0] === "stopwait") {
    try { return execSc(["stop", COCODEX_SERVER_SERVICE_ID]); }
    catch (error) {
      if (windowsServerServiceState(paths) === "stopped") return "";
      throw error;
    }
  }
  if (args[0] === "uninstall") return execSc(["delete", COCODEX_SERVER_SERVICE_ID]);
  throw new Error("CoCodex Server service assets are missing; run 'cocodex-server service install' to repair them");
}

export function parseScmQueryState(output: string): ServerServiceState {
  const state = /^\s*STATE\s*:\s*(\d+)/im.exec(output)?.[1];
  if (state === "4") return "started";
  if (state === "1") return "stopped";
  return "unknown";
}

export function windowsServerServiceState(paths: ServerPaths): ServerServiceState {
  if (existsSync(paths.serviceExecutable)) {
    try { return parseServerServiceStatus(runWinsw(paths, ["status"])); }
    catch { return "unknown"; }
  }
  if (process.platform !== "win32") return "nonexistent";
  try {
    return parseScmQueryState(execSc(["query", COCODEX_SERVER_SERVICE_ID]));
  } catch (error) {
    const status = (error as { status?: number }).status;
    return status === 1060 || /\b1060\b/.test(errorText(error)) ? "nonexistent" : "unknown";
  }
}

export function parseScmServiceConfig(output: string): ScmServiceConfig {
  const field = (name: string) => new RegExp(`^\\s*${name}\\s*:\\s*(.+)$`, "im").exec(output)?.[1]?.trim() ?? "";
  return { binaryPath: field("BINARY_PATH_NAME"), startType: field("START_TYPE"), startName: field("SERVICE_START_NAME") };
}

function scmServiceConfig(): ScmServiceConfig {
  return parseScmServiceConfig(execSc(["qc", COCODEX_SERVER_SERVICE_ID]));
}

function normalizedAccount(value: string): string {
  return value.trim().replace(/^\.\\/, "").toLowerCase();
}

export function serviceUsesCurrentUser(config: ScmServiceConfig, env: NodeJS.ProcessEnv = process.env): boolean {
  const actual = normalizedAccount(config.startName);
  const user = normalizedAccount(env.USERNAME ?? "");
  if (!actual || !user || /localsystem|localservice|networkservice/.test(actual)) return false;
  const domain = normalizedAccount(env.USERDOMAIN ?? ".");
  return actual === user || actual === `${domain}\\${user}`;
}

function serviceBinaryMatches(config: ScmServiceConfig, paths: ServerPaths): boolean {
  const configured = config.binaryPath.trim().replace(/^"(.*)"$/, "$1");
  return resolve(configured).toLowerCase() === resolve(paths.serviceExecutable).toLowerCase();
}

function serviceStartsAutomatically(config: ScmServiceConfig): boolean {
  return /auto_start|automatic/i.test(config.startType);
}

function livePid(paths: ServerPaths): number | undefined {
  if (!existsSync(paths.pid)) return undefined;
  const pid = Number(readFileSync(paths.pid, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 0) return undefined;
  try {
    process.kill(pid, 0);
    return pid;
  } catch {
    return undefined;
  }
}

async function healthReady(paths: ServerPaths): Promise<boolean> {
  const config = loadConfig(paths);
  const host = ["0.0.0.0", "::", "[::]"].includes(config.hostname) ? "127.0.0.1" : config.hostname;
  try {
    const response = await fetch(`https://${host}:${config.port}/healthz`, {
      signal: AbortSignal.timeout(1_000),
      tls: { rejectUnauthorized: false },
    });
    const body = await response.json() as Record<string, unknown>;
    return response.ok && body.ok === true && body.service === "cocodex-server" && body.protocol === 1;
  } catch {
    return false;
  }
}

async function waitForReady(paths: ServerPaths, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (livePid(paths) && await healthReady(paths)) return;
    await Bun.sleep(100);
  }
  throw new Error(`CoCodex Server service did not become TLS-ready within ${timeoutMs}ms`);
}

async function waitForStopped(paths: ServerPaths, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!livePid(paths)) {
      if (existsSync(paths.pid)) rmSync(paths.pid, { force: true });
      return;
    }
    await Bun.sleep(100);
  }
  throw new Error(`CoCodex Server PID ${livePid(paths)} did not stop with its service`);
}

function assertWindows(platform: NodeJS.Platform): void {
  if (platform !== "win32") throw new Error("CoCodex Server service mode is available only on Windows");
}

function assertServiceStateRoot(config: ScmServiceConfig, paths: ServerPaths): void {
  if (!serviceBinaryMatches(config, paths)) {
    throw new Error(
      `The ${COCODEX_SERVER_SERVICE_ID} service is registered from another state root; ` +
      "uninstall it from that root before selecting a different Server state root.",
    );
  }
}

function assertPrivateStateAccessible(paths: ServerPaths): void {
  loadConfig(paths);
  loadServerIdentity(paths);
  createPrivateKey(readTlsPrivateKey(paths.tlsPrivateKey));
}

function writeServiceXml(path: string, content: string): void {
  const temporary = `${path}.new`;
  writeFileSync(temporary, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

export async function windowsServerServiceStatus(
  paths: ServerPaths,
  deps: ServerServiceDeps = {},
): Promise<ServerServiceStatus> {
  assertWindows(deps.platform ?? process.platform);
  const state = (deps.status ?? windowsServerServiceState)(paths);
  const base: Pick<ServerServiceStatus, "serviceId" | "state" | "stateRoot" | "pid"> = {
    serviceId: COCODEX_SERVER_SERVICE_ID,
    state,
    stateRoot: paths.root,
    pid: livePid(paths) ?? null,
  };
  if (state === "unknown") {
    return { ...base, installed: null, sameUser: null, automaticStart: null, binaryPathMatches: null, ready: false };
  }
  if (state === "nonexistent") {
    return { ...base, installed: false, sameUser: null, automaticStart: null, binaryPathMatches: null, ready: false };
  }
  const config = (deps.scmConfig ?? scmServiceConfig)();
  const binaryPathMatches = serviceBinaryMatches(config, paths);
  const readyCheck = deps.healthReady ?? healthReady;
  return {
    ...base,
    installed: true,
    sameUser: serviceUsesCurrentUser(config),
    automaticStart: serviceStartsAutomatically(config),
    binaryPathMatches,
    ready: state === "started" && binaryPathMatches && await readyCheck(paths),
  };
}

export async function installWindowsServerService(
  paths: ServerPaths,
  entry: ServerServiceEntry,
  deps: ServerServiceDeps = {},
): Promise<ServerServiceStatus> {
  assertWindows(deps.platform ?? process.platform);
  (deps.privateStateAccessible ?? assertPrivateStateAccessible)(paths);
  const ensureBinary = deps.ensureBinary ?? ensureWindowsServerServiceBinary;
  const state = deps.status ?? windowsServerServiceState;
  const run = deps.run ?? runServerServiceLifecycle;
  const interactive = deps.interactive ?? runWinswInteractive;
  const getScm = deps.scmConfig ?? scmServiceConfig;
  const waitReadyImpl = deps.waitReady ?? waitForReady;
  const waitStoppedImpl = deps.waitStopped ?? waitForStopped;
  const writeXml = deps.writeXml ?? writeServiceXml;

  await ensureBinary(paths);
  const existing = state(paths);
  if (existing === "unknown") throw new Error("Cannot verify the CoCodex Server service state; installation aborted");
  const fresh = existing === "nonexistent";
  const wasStarted = existing === "started";
  const previousXml = !fresh && existsSync(paths.serviceConfig) ? readFileSync(paths.serviceConfig, "utf8") : undefined;
  if (!fresh) {
    const existingConfig = getScm();
    assertServiceStateRoot(existingConfig, paths);
    if (!serviceUsesCurrentUser(existingConfig)) {
      throw new Error("Existing CoCodex Server service is not registered as the current Windows user");
    }
    if (existing === "started") {
      run(paths, ["stopwait"]);
      await waitStoppedImpl(paths);
    }
  } else if (livePid(paths)) {
    throw new Error(`CoCodex Server is already running directly with PID ${livePid(paths)}; stop it before service installation`);
  }

  mkdirSync(paths.serviceLogs, { recursive: true });
  hardenSecretDir(paths.serviceDirectory, { required: true });
  hardenSecretDir(paths.serviceLogs, { required: true });
  writeXml(paths.serviceConfig, buildWindowsServerServiceXml(paths, entry));

  let registered = !fresh;
  try {
    if (fresh) {
      interactive(paths, ["install", "/p"]);
      registered = true;
    }
    const applied = getScm();
    assertServiceStateRoot(applied, paths);
    if (!serviceUsesCurrentUser(applied)) {
      throw new Error(`Service account ${applied.startName || "unknown"} is not the current Windows user`);
    }
    if (!serviceStartsAutomatically(applied)) throw new Error("CoCodex Server service autostart was not applied");
    run(paths, ["start"]);
    await waitReadyImpl(paths);
    return windowsServerServiceStatus(paths, { ...deps, scmConfig: () => applied, status: () => "started" });
  } catch (error) {
    const rollbackFailures: string[] = [];
    try { run(paths, ["stopwait"]); }
    catch (rollbackError) { rollbackFailures.push(`stop: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`); }
    try { await waitStoppedImpl(paths); }
    catch (rollbackError) { rollbackFailures.push(`wait: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`); }
    if (fresh && registered) {
      try { run(paths, ["uninstall"]); }
      catch (rollbackError) { rollbackFailures.push(`uninstall: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`); }
    } else if (!fresh && previousXml !== undefined) {
      try {
        writeXml(paths.serviceConfig, previousXml);
        if (wasStarted) {
          run(paths, ["start"]);
          await waitReadyImpl(paths);
        }
      } catch (rollbackError) {
        rollbackFailures.push(`restore: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`);
      }
    }
    if (rollbackFailures.length > 0) {
      const primary = error instanceof Error ? error.message : String(error);
      throw new Error(`${primary}. Service rollback also failed (${rollbackFailures.join("; ")}); inspect 'cocodex-server service status'.`, { cause: error });
    }
    throw error;
  }
}

export async function startWindowsServerService(
  paths: ServerPaths,
  deps: ServerServiceDeps = {},
): Promise<ServerServiceStatus> {
  assertWindows(deps.platform ?? process.platform);
  (deps.privateStateAccessible ?? assertPrivateStateAccessible)(paths);
  const state = (deps.status ?? windowsServerServiceState)(paths);
  if (state === "unknown") throw new Error("Cannot verify the CoCodex Server service state; start aborted");
  if (state === "nonexistent") throw new Error("CoCodex Server service is not installed");
  const config = (deps.scmConfig ?? scmServiceConfig)();
  assertServiceStateRoot(config, paths);
  if (!serviceUsesCurrentUser(config)) throw new Error("CoCodex Server service is not registered as the current Windows user");
  if (!serviceStartsAutomatically(config)) throw new Error("CoCodex Server service autostart is not configured");
  if (state === "stopped" && livePid(paths)) {
    throw new Error(`A direct CoCodex Server process owns PID ${livePid(paths)}; service start aborted`);
  }
  if (state === "stopped") (deps.run ?? runServerServiceLifecycle)(paths, ["start"]);
  await (deps.waitReady ?? waitForReady)(paths);
  return windowsServerServiceStatus(paths, { ...deps, status: () => "started" });
}

export async function stopWindowsServerService(
  paths: ServerPaths,
  deps: ServerServiceDeps = {},
): Promise<ServerServiceStatus> {
  assertWindows(deps.platform ?? process.platform);
  const state = (deps.status ?? windowsServerServiceState)(paths);
  if (state === "unknown") throw new Error("Cannot verify the CoCodex Server service state; stop aborted");
  if (state === "nonexistent") return windowsServerServiceStatus(paths, deps);
  assertServiceStateRoot((deps.scmConfig ?? scmServiceConfig)(), paths);
  if (state === "started") (deps.run ?? runServerServiceLifecycle)(paths, ["stopwait"]);
  await (deps.waitStopped ?? waitForStopped)(paths);
  return windowsServerServiceStatus(paths, { ...deps, status: () => "stopped" });
}

export async function uninstallWindowsServerService(
  paths: ServerPaths,
  deps: ServerServiceDeps = {},
): Promise<ServerServiceStatus> {
  assertWindows(deps.platform ?? process.platform);
  const stateFn = deps.status ?? windowsServerServiceState;
  const state = stateFn(paths);
  if (state === "unknown") throw new Error("Cannot verify the CoCodex Server service state; uninstall aborted");
  if (state === "nonexistent") return windowsServerServiceStatus(paths, deps);
  assertServiceStateRoot((deps.scmConfig ?? scmServiceConfig)(), paths);
  const run = deps.run ?? runServerServiceLifecycle;
  if (state === "started") {
    run(paths, ["stopwait"]);
    await (deps.waitStopped ?? waitForStopped)(paths);
  }
  run(paths, ["uninstall"]);
  const finalState = stateFn(paths);
  if (finalState !== "nonexistent") throw new Error("CoCodex Server service registration still exists after uninstall");
  return windowsServerServiceStatus(paths, { ...deps, status: () => "nonexistent" });
}

export function serverServiceEntry(argv: string[] = Bun.argv): ServerServiceEntry {
  const script = argv[1];
  return script?.endsWith(".ts")
    ? { executable: process.execPath, cliScript: script }
    : { executable: process.execPath };
}

import { spawnSync, type SpawnSyncOptionsWithBufferEncoding } from "node:child_process";
import { statSync } from "node:fs";
import { codexExecInvocation } from "../codex/exec-invocation";
import { resolveCodexRuntime, type ResolveCodexRuntimeResult } from "../codex/runtime";

const MAX_PROBE_OUTPUT = 512 * 1024;

export interface CodexBrowserCapability {
  version: 1;
  executionSurface: "codex-exec";
  runtimeVersion: string | null;
  agentBrowserAvailable: false;
  officialAppAvailable: boolean;
  browserPluginInstalled: boolean;
  browserFeatureEnabled: boolean;
  externalBrowserFeatureEnabled: boolean;
  fullCdpFeatureEnabled: boolean;
  status: "official-app-only" | "unavailable";
  reason: string;
}

type ProbeResult = { status: number | null; stdout: Buffer; stderr?: Buffer };
type Probe = (
  file: string,
  args: readonly string[],
  options: SpawnSyncOptionsWithBufferEncoding,
) => ProbeResult;

export interface CodexBrowserCapabilityDeps {
  resolveRuntime?: () => ResolveCodexRuntimeResult;
  probe?: Probe;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}

function safeEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const allowed = [
    "APPDATA", "CODEX_CLI_PATH", "CODEX_HOME", "HOME", "HOMEDRIVE", "HOMEPATH",
    "LOCALAPPDATA", "PATH", "PATHEXT", "SystemDrive", "SystemRoot", "TEMP", "TMP",
    "USERPROFILE", "WINDIR",
  ];
  return Object.fromEntries(allowed.flatMap(key => source[key] === undefined ? [] : [[key, source[key]]]));
}

function run(
  command: string,
  args: readonly string[],
  deps: CodexBrowserCapabilityDeps,
): ProbeResult {
  const invocation = codexExecInvocation(command, args, deps.platform ?? process.platform);
  const probe = deps.probe ?? ((file, argv, options) => spawnSync(file, argv, options));
  return probe(invocation.file, invocation.args, {
    cwd: undefined,
    env: safeEnvironment(deps.env ?? process.env),
    shell: false,
    windowsHide: true,
    windowsVerbatimArguments: invocation.options.windowsVerbatimArguments,
    encoding: "buffer",
    timeout: 15_000,
    maxBuffer: MAX_PROBE_OUTPUT,
  });
}

function enabledFeature(output: string, name: string): boolean {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped}\\s+\\S+(?:\\s+)true\\s*$`, "m").test(output);
}

export function detectCodexBrowserCapability(
  deps: CodexBrowserCapabilityDeps = {},
): CodexBrowserCapability {
  let resolved: ResolveCodexRuntimeResult;
  try {
    resolved = (deps.resolveRuntime ?? (() => resolveCodexRuntime({ discoverAlternatives: false })))();
  } catch {
    return {
      version: 1,
      executionSurface: "codex-exec",
      runtimeVersion: null,
      agentBrowserAvailable: false,
      officialAppAvailable: false,
      browserPluginInstalled: false,
      browserFeatureEnabled: false,
      externalBrowserFeatureEnabled: false,
      fullCdpFeatureEnabled: false,
      status: "unavailable",
      reason: "No supported local Codex runtime is available.",
    };
  }
  const runtime = resolved.runtime;
  const features = run(runtime.command, ["features", "list"], deps);
  const plugins = run(runtime.command, ["plugin", "list"], deps);
  const app = run(runtime.command, ["app", "--help"], deps);
  const featureText = features.status === 0 ? features.stdout.toString("utf8") : "";
  const pluginText = plugins.status === 0 ? plugins.stdout.toString("utf8") : "";
  const browserFeatureEnabled = enabledFeature(featureText, "browser_use");
  const externalBrowserFeatureEnabled = enabledFeature(featureText, "browser_use_external");
  const fullCdpFeatureEnabled = enabledFeature(featureText, "browser_use_full_cdp_access");
  const browserPluginInstalled = /^browser@\S+\s+installed, enabled\b/m.test(pluginText);
  const officialAppAvailable = app.status === 0 && browserFeatureEnabled && browserPluginInstalled;
  return {
    version: 1,
    executionSurface: "codex-exec",
    runtimeVersion: runtime.version,
    agentBrowserAvailable: false,
    officialAppAvailable,
    browserPluginInstalled,
    browserFeatureEnabled,
    externalBrowserFeatureEnabled,
    fullCdpFeatureEnabled,
    status: officialAppAvailable ? "official-app-only" : "unavailable",
    reason: officialAppAvailable
      ? "Codex CLI does not expose Browser. Open this workspace in the official Codex app to use its installed Browser capability."
      : "Browser is unavailable to this local Codex execution surface.",
  };
}

export function openOfficialCodexApp(
  workspaceRoot: string,
  deps: CodexBrowserCapabilityDeps = {},
): CodexBrowserCapability {
  if (!statSync(workspaceRoot).isDirectory()) throw new Error("Official Codex workspace is not a directory");
  const capability = detectCodexBrowserCapability(deps);
  if (!capability.officialAppAvailable) throw new Error(capability.reason);
  const runtime = (deps.resolveRuntime ?? (() => resolveCodexRuntime({ discoverAlternatives: false })))().runtime;
  const launched = run(runtime.command, ["app", workspaceRoot], deps);
  if (launched.status !== 0) throw new Error("The official Codex app could not open this agent workspace");
  return capability;
}

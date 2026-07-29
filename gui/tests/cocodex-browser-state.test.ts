import { expect, test } from "bun:test";
import { browserCapabilityPresentation, type CodexBrowserCapabilityView } from "../src/cocodex-browser-state";

const capability: CodexBrowserCapabilityView = {
  version: 1,
  executionSurface: "codex-exec",
  runtimeVersion: "0.146.0-alpha.3.1",
  agentBrowserAvailable: false,
  officialAppAvailable: true,
  browserPluginInstalled: true,
  browserFeatureEnabled: true,
  externalBrowserFeatureEnabled: true,
  fullCdpFeatureEnabled: false,
  status: "official-app-only",
  reason: "Open in official Codex.",
};

test("browser capability UI never equates an installed app plugin with CLI agent control", () => {
  expect(browserCapabilityPresentation()).toEqual({ state: "checking", canOpenOfficialApp: false });
  expect(browserCapabilityPresentation(capability)).toEqual({ state: "official-app-only", canOpenOfficialApp: true });
  expect(browserCapabilityPresentation({ ...capability, officialAppAvailable: false, status: "unavailable" }))
    .toEqual({ state: "unavailable", canOpenOfficialApp: false });
  expect(capability.agentBrowserAvailable).toBeFalse();
});

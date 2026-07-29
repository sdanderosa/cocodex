export interface CodexBrowserCapabilityView {
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

export function browserCapabilityPresentation(capability?: CodexBrowserCapabilityView) {
  if (!capability) return { state: "checking" as const, canOpenOfficialApp: false };
  if (capability.officialAppAvailable) {
    return { state: "official-app-only" as const, canOpenOfficialApp: true };
  }
  return { state: "unavailable" as const, canOpenOfficialApp: false };
}

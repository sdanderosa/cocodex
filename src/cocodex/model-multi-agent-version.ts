import upstreamModelsSnapshot from "../codex/data/upstream-models.json";

export type CodexMultiAgentVersion = "v1" | "v2";

/**
 * Resolve native Codex multi-agent generation from the maintained upstream
 * catalog snapshot. Unknown/provider-routed model IDs may still run as primary
 * agents, but CoCodex will not promise a numeric child-thread limit for them.
 */
export function modelMultiAgentVersion(modelId: string): CodexMultiAgentVersion | null {
  const normalized = modelId.trim().toLowerCase();
  const entry = upstreamModelsSnapshot.models.find(model =>
    typeof model.slug === "string" && model.slug.toLowerCase() === normalized
  );
  return entry?.multi_agent_version === "v1" || entry?.multi_agent_version === "v2"
    ? entry.multi_agent_version
    : null;
}

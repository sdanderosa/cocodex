export function executableLocalAgentIds(
  localAgents: Array<{ agentId: string; executionEnabled: boolean }>,
): string[] {
  return localAgents.filter(agent => agent.executionEnabled).map(agent => agent.agentId);
}

export async function stopEveryLocalAgent(
  agentIds: string[],
  stop: (agentId: string) => Promise<unknown>,
): Promise<void> {
  const failures: string[] = [];
  for (const agentId of agentIds) {
    try {
      await stop(agentId);
    } catch {
      failures.push(agentId);
    }
  }
  if (failures.length) {
    throw new Error(`Emergency stop was rejected for: ${failures.join(", ")}`);
  }
}

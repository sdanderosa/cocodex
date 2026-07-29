import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

test("project-scoped rosters survive chat changes and reset only with the project", () => {
  const source = readFileSync(resolve(import.meta.dir, "../src/pages/CoCodex.tsx"), "utf8").replace(/\r\n/g, "\n");
  const projectEffectStart = source.indexOf(
    'useEffect(() => {\n    if (status?.state !== "connected" || !projectId) return;',
  );
  const chatEffectStart = source.indexOf(
    'useEffect(() => {\n    if (status?.state !== "connected" || !projectId || !chatId) return;',
    projectEffectStart + 1,
  );
  const nextEffectStart = source.indexOf("useEffect(() => {", chatEffectStart + 1);

  expect(projectEffectStart).toBeGreaterThan(-1);
  expect(chatEffectStart).toBeGreaterThan(projectEffectStart);
  const projectEffect = source.slice(projectEffectStart, chatEffectStart);
  const chatEffect = source.slice(chatEffectStart, nextEffectStart);

  for (const setter of ["setProjectMembers([])", "setUsageReports([])", "setAgents([])"]) {
    expect(projectEffect).toContain(setter);
    expect(chatEffect).not.toContain(setter);
  }
  for (const setter of ["setChat([])", "setPresence([])", "setTasks([])", "setArtifacts([])"]) {
    expect(chatEffect).toContain(setter);
  }
});

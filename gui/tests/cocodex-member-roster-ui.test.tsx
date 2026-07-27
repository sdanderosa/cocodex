import { afterEach, beforeEach, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { act } from "react";
import type { Root } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { LanguageProvider } from "../src/i18n/provider";
import type { TFn } from "../src/i18n";
import {
  ProjectMemberRoster,
} from "../src/pages/CoCodex";
import {
  confirmProjectMemberRemoval,
  clearRecoveredProjectSecurity,
  isRevokedProjectMember,
  markProjectMemberRevoked,
  projectMemberRemovalCommand,
  reconcileRevokedProject,
  type ProjectMember,
} from "../src/cocodex-member-state";

const globals = ["document", "window", "navigator", "IS_REACT_ACT_ENVIRONMENT"] as const;
let previousGlobals: Record<(typeof globals)[number], unknown>;
let testWindow: Window;

beforeEach(() => {
  previousGlobals = Object.fromEntries(globals.map(key => [key, Reflect.get(globalThis, key)])) as typeof previousGlobals;
  testWindow = new Window({ url: "http://localhost/" });
  Object.defineProperties(globalThis, {
    document: { configurable: true, value: testWindow.document },
    window: { configurable: true, value: testWindow },
    navigator: { configurable: true, value: testWindow.navigator },
  });
  Object.defineProperty(globalThis.navigator, "language", { configurable: true, value: "en-US" });
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean })
    .IS_REACT_ACT_ENVIRONMENT = true;
});

afterEach(() => {
  testWindow.close();
  for (const key of globals) {
    Object.defineProperty(globalThis, key, { configurable: true, value: previousGlobals[key] });
  }
});

test("owner roster exposes verification before atomic member removal", () => {
  const members: ProjectMember[] = [{
    deviceId: crypto.randomUUID(),
    displayName: "Stephen",
    fingerprint: "owner-fingerprint-1234567890",
    role: "owner",
    trusted: true,
  }, {
    deviceId: crypto.randomUUID(),
    displayName: "Kai",
    fingerprint: "kai-fingerprint-123456789012",
    role: "member",
    trusted: false,
  }];
  const html = renderToStaticMarkup(
    <LanguageProvider>
      <ProjectMemberRoster
        members={members}
        owner
        connected
        busy={false}
        onRefresh={() => {}}
        onTrust={() => {}}
        onRemove={() => {}}
      />
    </LanguageProvider>,
  );

  expect(html).toContain("Stephen");
  expect(html).toContain("verified");
  expect(html).toContain("Kai");
  expect(html).toContain("unverified");
  expect(html).toContain(">Verify<");
  expect(html).toContain(">Remove<");
  expect((html.match(/>Remove</g) ?? []).length).toBe(1);
});

test("non-owner roster never renders trust or removal controls", () => {
  const html = renderToStaticMarkup(
    <LanguageProvider>
      <ProjectMemberRoster
        members={[{
          deviceId: crypto.randomUUID(),
          displayName: "Kai",
          fingerprint: "kai-fingerprint-123456789012",
          role: "member",
          trusted: false,
        }]}
        owner={false}
        connected
        busy={false}
        onRefresh={() => {}}
        onTrust={() => {}}
        onRemove={() => {}}
      />
    </LanguageProvider>,
  );

  expect(html).not.toContain(">Verify<");
  expect(html).not.toContain(">Remove<");
});

test("owner roster marks revoked members and exposes only remove-and-rotate recovery", () => {
  const member: ProjectMember = {
    deviceId: crypto.randomUUID(),
    displayName: "Kai",
    fingerprint: "kai-fingerprint-123456789012",
    role: "member",
    trusted: true,
    status: "revoked",
  };
  const html = renderToStaticMarkup(
    <LanguageProvider>
      <ProjectMemberRoster
        members={[member]}
        owner
        connected
        busy={false}
        onRefresh={() => {}}
        onTrust={() => {}}
        onRemove={() => {}}
      />
    </LanguageProvider>,
  );
  expect(html).toContain("revoked");
  expect(html).toContain("Revoked device");
  expect(html).toContain("Remove &amp; rotate");
  expect(html).not.toContain(">Verify<");
  expect(isRevokedProjectMember(member)).toBeTrue();
  expect(markProjectMemberRevoked([{
    ...member,
    status: "approved",
  }], member.deviceId)[0]?.status).toBe("revoked");
});

test("owner roster invokes enabled controls and disables every action offline", async () => {
  const { createRoot } = await import("react-dom/client");
  const member: ProjectMember = {
    deviceId: crypto.randomUUID(),
    displayName: "Kai",
    fingerprint: "kai-fingerprint-123456789012",
    role: "member",
    trusted: false,
  };
  const calls: string[] = [];
  const container = document.createElement("div");
  document.body.append(container);
  let root: Root;
  await act(async () => {
    root = createRoot(container);
    root.render(
      <LanguageProvider>
        <ProjectMemberRoster
          members={[member]}
          owner
          connected
          busy={false}
          onRefresh={() => calls.push("refresh")}
          onTrust={() => calls.push("trust")}
          onRemove={() => calls.push("remove")}
        />
      </LanguageProvider>,
    );
  });
  const buttons = [...container.querySelectorAll("button")];
  for (const label of ["Refresh project members", "Verify", "Remove"]) {
    const button = buttons.find(candidate =>
      candidate.getAttribute("title") === label || candidate.textContent === label);
    expect(button).toBeDefined();
    button!.click();
  }
  expect(calls).toEqual(["refresh", "trust", "remove"]);

  await act(async () => {
    root.render(
      <LanguageProvider>
        <ProjectMemberRoster
          members={[member]}
          owner
          connected={false}
          busy={false}
          onRefresh={() => calls.push("unexpected")}
          onTrust={() => calls.push("unexpected")}
          onRemove={() => calls.push("unexpected")}
        />
      </LanguageProvider>,
    );
  });
  expect([...container.querySelectorAll("button")].every(button => button.disabled)).toBeTrue();
  await act(async () => root.unmount());
});

test("removal confirmation can cancel and the accepted command is exact", () => {
  const member: ProjectMember = {
    deviceId: crypto.randomUUID(),
    displayName: "Kai",
    fingerprint: "kai-fingerprint-123456789012",
    role: "member",
    trusted: true,
  };
  const messages: string[] = [];
  const t = ((key: string, values?: Record<string, unknown>) =>
    `${key}:${String(values?.name)}:${String(values?.fingerprint)}`) as TFn;
  expect(confirmProjectMemberRemoval(t, member, message => {
    messages.push(message);
    return false;
  })).toBeFalse();
  expect(messages).toEqual([
    `cocodex.members.removeConfirm:Kai:${member.fingerprint.slice(-12)}`,
  ]);
  expect(projectMemberRemovalCommand("project-id", member)).toEqual({
    type: "project.member.remove-and-rotate",
    projectId: "project-id",
    deviceId: member.deviceId,
  });
});

test("revocation removes the project and moves or clears the selected project", () => {
  const projects = [
    { id: "revoked", name: "Revoked", role: "owner" as const },
    { id: "survivor", name: "Survivor", role: "member" as const },
  ];
  expect(reconcileRevokedProject(projects, "revoked", "revoked")).toEqual({
    projects: [projects[1]],
    selectedProjectId: "survivor",
    clearedSelection: true,
  });
  expect(reconcileRevokedProject([projects[0]], "revoked", "revoked")).toEqual({
    projects: [],
    selectedProjectId: "",
    clearedSelection: true,
  });
});

test("security quarantine clears only after the revoked member is removed and a newer key arrives", () => {
  const incident = {
    state: "device-revoked" as const,
    revokedDeviceId: "revoked-device",
    currentEpoch: 2,
    memberRemoved: true,
  };
  expect(clearRecoveredProjectSecurity(incident, "revoked-device", 2)).toEqual(incident);
  expect(clearRecoveredProjectSecurity({ ...incident, memberRemoved: false }, "revoked-device", 3))
    .toEqual({ ...incident, memberRemoved: false });
  expect(clearRecoveredProjectSecurity(incident, "other-device", 3)).toEqual(incident);
  expect(clearRecoveredProjectSecurity(incident, "revoked-device", 3)).toBeUndefined();
});

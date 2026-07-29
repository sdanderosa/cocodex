import { afterEach, beforeEach, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { LanguageProvider } from "../src/i18n/provider";
import {
  FileReferenceMetadata,
  type FileReference,
} from "../src/pages/CoCodex";
import {
  referenceArtifactSelectionReducer,
  retainLocalReferenceArtifactId,
} from "../src/cocodex-file-reference-state";

let languageDescriptor: PropertyDescriptor | undefined;

beforeEach(() => {
  languageDescriptor = Object.getOwnPropertyDescriptor(globalThis.navigator, "language");
  Object.defineProperty(globalThis.navigator, "language", { configurable: true, value: "en-US" });
});

afterEach(() => {
  if (languageDescriptor) Object.defineProperty(globalThis.navigator, "language", languageDescriptor);
  else delete (globalThis.navigator as { language?: string }).language;
});

test("renders privacy-safe decrypted file-reference metadata for local and remote hosts", () => {
  const reference: FileReference = {
    referenceId: crypto.randomUUID(),
    projectId: crypto.randomUUID(),
    artifactId: crypto.randomUUID(),
    hostDeviceId: crypto.randomUUID(),
    authorDeviceId: crypto.randomUUID(),
    relativePath: "reports/result.txt",
    workspaceMode: "shared",
    workspaceRef: "main",
    branch: null,
    commitSha: null,
    sha256: "a".repeat(64),
    sizeBytes: 2048,
    mediaType: "text/plain",
    createdAt: "2030-01-01T00:00:00.000Z",
    updatedAt: "2030-01-01T00:00:00.000Z",
    ...({
      workspaceRoot: "C:\\Users\\Stephen\\ABSOLUTE_PATH_CANARY",
      sealedProjectKey: "PROJECT_KEY_CANARY",
    } as object),
  };
  const local = renderToStaticMarkup(
    <LanguageProvider><FileReferenceMetadata reference={reference} local /></LanguageProvider>,
  );
  const remote = renderToStaticMarkup(
    <LanguageProvider><FileReferenceMetadata reference={reference} local={false} /></LanguageProvider>,
  );

  expect(local).toContain("reports/result.txt");
  expect(local).toContain("2.0 KB");
  expect(local).toContain("available here");
  expect(remote).toContain("remote host");
  expect(local).not.toContain("C:\\Users\\Stephen");
  expect(local).not.toContain("ABSOLUTE_PATH_CANARY");
  expect(local).not.toContain("PROJECT_KEY_CANARY");
  expect(local).not.toContain(reference.sha256);
});

test("clears a file-reference artifact selection when it is missing or remotely authored", () => {
  const selectedId = crypto.randomUUID();
  const localDeviceId = crypto.randomUUID();
  const baseArtifact = {
    id: selectedId,
    projectId: crypto.randomUUID(),
    taskId: null,
    authorDeviceId: localDeviceId,
    type: "finding",
    title: "Local result",
    summary: "Result summary",
    content: "Result body",
    status: "ready" as const,
    createdAt: "2030-01-01T00:00:00.000Z",
    updatedAt: "2030-01-01T00:00:00.000Z",
  };

  expect(retainLocalReferenceArtifactId(selectedId, [baseArtifact], localDeviceId)).toBe(selectedId);
  expect(retainLocalReferenceArtifactId(selectedId, [], localDeviceId)).toBe("");
  expect(retainLocalReferenceArtifactId(selectedId, [{
    ...baseArtifact,
    authorDeviceId: crypto.randomUUID(),
  }], localDeviceId)).toBe("");
  expect(referenceArtifactSelectionReducer(selectedId, { type: "project-changed" })).toBe("");
});

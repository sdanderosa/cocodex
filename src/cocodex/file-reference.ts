import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileReferencePlaintextSchema, type FileReferencePlaintext } from "../../packages/cocodex-protocol/src/index.ts";

function isContained(root: string, target: string): boolean {
  const path = relative(root, target);
  return path !== "" && path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

function assertNoLinkedSegments(root: string, target: string): void {
  const path = relative(root, target);
  let cursor = root;
  for (const segment of path.split(sep)) {
    cursor = resolve(cursor, segment);
    if (lstatSync(cursor).isSymbolicLink()) {
      throw new Error("File references cannot traverse symbolic links or junctions");
    }
  }
}

export const FILE_REFERENCE_MAX_BYTES = 512 * 1024 * 1024;

export interface InspectLocalFileReferenceInput {
  referenceId: string;
  projectId: string;
  chatId?: string;
  artifactId: string;
  hostDeviceId: string;
  workspaceRoot: string;
  path: string;
  workspaceMode: "shared" | "git-worktree";
  workspaceRef: string;
  branch?: string | null;
  commitSha?: string | null;
  mediaType?: string | null;
}

/** Resolve, contain, inspect, and hash a local regular file before sealing its metadata. */
export async function inspectLocalFileReference(
  input: InspectLocalFileReferenceInput,
): Promise<FileReferencePlaintext> {
  const root = realpathSync(input.workspaceRoot);
  if (!lstatSync(root).isDirectory()) throw new Error("File-reference workspace root must be a directory");
  const requested = resolve(root, input.path);
  if (!isContained(root, requested)) throw new Error("File-reference path must stay inside the workspace root");
  assertNoLinkedSegments(root, requested);
  const target = realpathSync(requested);
  if (!isContained(root, target)) throw new Error("File-reference path resolves outside the workspace root");
  const handle = await open(target, "r");
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error("File references must target a regular file");
    if (before.size > FILE_REFERENCE_MAX_BYTES) {
      throw new Error(`File references cannot exceed ${FILE_REFERENCE_MAX_BYTES} bytes`);
    }
    const currentTarget = realpathSync(requested);
    if (!isContained(root, currentTarget)) throw new Error("File-reference path resolves outside the workspace root");
    const currentPathStat = lstatSync(currentTarget);
    if (currentPathStat.isSymbolicLink() || currentPathStat.dev !== before.dev || currentPathStat.ino !== before.ino) {
      throw new Error("File-reference path changed while it was being opened");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < before.size) {
      const length = Math.min(buffer.byteLength, before.size - position);
      const result = await handle.read(buffer, 0, length, position);
      if (result.bytesRead === 0) throw new Error("File changed while its reference was being hashed");
      hash.update(buffer.subarray(0, result.bytesRead));
      position += result.bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || after.dev !== before.dev || after.ino !== before.ino) {
      throw new Error("File changed while its reference was being hashed");
    }
    const relativePath = relative(root, currentTarget).split(sep).join("/");
    return fileReferencePlaintextSchema.parse({
      version: 1,
      referenceId: input.referenceId,
      projectId: input.projectId,
      chatId: input.chatId ?? input.projectId,
      artifactId: input.artifactId,
      hostDeviceId: input.hostDeviceId,
      relativePath,
      workspaceMode: input.workspaceMode,
      workspaceRef: input.workspaceRef,
      branch: input.branch ?? null,
      commitSha: input.commitSha ?? null,
      sha256: hash.digest("hex"),
      sizeBytes: before.size,
      mediaType: input.mediaType ?? null,
    });
  } finally {
    await handle.close();
  }
}

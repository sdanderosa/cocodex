import { randomUUID, sign } from "node:crypto";
import {
  PROJECT_MIGRATION_STAGE_MAX_ITEMS,
  projectMigrationEnvelopeDigest,
  projectMigrationManifestSigningTranscript,
  type ProjectContentEnvelope,
  type ProjectMigrationCompletedFrame,
  type ProjectMigrationInventoryFrame,
  type ProjectMigrationInventoryItem,
  type ProjectMigrationPageResultFrame,
  type ProjectMigrationRequiredFrame,
  type ProjectMigrationStageItem,
  type ProjectMigrationStagedFrame,
} from "../../packages/cocodex-protocol/src/index.ts";
import { sealProjectContent } from "./project-encryption";

export type ProjectMigrationServerFrame =
  | ProjectMigrationRequiredFrame
  | ProjectMigrationInventoryFrame
  | ProjectMigrationPageResultFrame
  | ProjectMigrationStagedFrame
  | ProjectMigrationCompletedFrame;

export interface ProjectMigrationKey {
  keyEpoch: number;
  projectKey: Uint8Array;
}

export interface ProjectMigrationOwner {
  deviceId: string;
  publicKeyPem: string;
  privateKeyPem: string;
  serverFingerprint: string;
}

export interface ProjectMigrationCoordinatorOptions {
  owner: ProjectMigrationOwner;
  loadProjectKey(projectId: string, keyEpoch: number): ProjectMigrationKey | undefined;
  send(frame: Record<string, unknown>): void;
  completed(frame: ProjectMigrationCompletedFrame): void;
  status(event: {
    projectId: string;
    state: "required" | "preparing" | "encrypting" | "staging" | "committing" | "completed" | "failed";
    migrationId?: string;
    itemCount?: number;
    stagedCount?: number;
    error?: string;
  }): void;
}

interface ManifestMapping {
  kind: ProjectMigrationInventoryItem["kind"];
  sourceId: string;
  sourceDigest: string;
  envelopeDigest: string;
}

interface ActiveMigration {
  projectId: string;
  migrationId: string;
  keyEpoch: number;
  snapshotDigest: string;
  itemCount: number;
  mappings: Map<string, ManifestMapping>;
  stageQueue: ProjectMigrationStageItem[][];
  nextCursor: number | null;
  awaiting: "page" | "stage" | "commit" | null;
}

function identity(item: Pick<ProjectMigrationInventoryItem, "kind" | "sourceId">): string {
  return `${item.kind}\u0000${item.sourceId}`;
}

function recordType(item: ProjectMigrationInventoryItem): ProjectContentEnvelope["recordType"] {
  if (item.kind === "shared-context") return "shared-context";
  if (item.kind === "shared-prompt") return "shared-prompt";
  if (item.kind === "agent-response") return "agent-response";
  return item.kind;
}

export function projectMigrationItemPlaintext(projectId: string, item: ProjectMigrationInventoryItem): string {
  if (item.kind === "shared-context") {
    return JSON.stringify({ finalGoal: item.finalGoal, context: item.context });
  }
  if (item.kind === "chat" || item.kind === "agent-response") {
    return JSON.stringify({ content: item.content });
  }
  if (item.kind === "shared-prompt") {
    return JSON.stringify({ update: item.updateBase64 });
  }
  if (item.kind === "artifact") {
    return JSON.stringify({
      id: item.sourceId,
      projectId,
      chatId: item.chatId,
      taskId: item.taskId,
      type: item.artifactType,
      title: item.title,
      summary: item.summary,
      content: item.content,
      status: item.status,
    });
  }
  return JSON.stringify({
    prompt: item.prompt,
    dependencies: item.dependencies,
    inputArtifactIds: item.inputArtifactIds,
    ...(item.privateShareMessageId ? { privateShareMessageId: item.privateShareMessageId } : {}),
  });
}

export async function sealProjectMigrationItem(input: {
  projectId: string;
  item: ProjectMigrationInventoryItem;
  key: ProjectMigrationKey;
  owner: ProjectMigrationOwner;
}): Promise<ProjectMigrationStageItem> {
  if (input.key.keyEpoch < 1) throw new Error("Migration project key epoch is invalid");
  const plaintext = projectMigrationItemPlaintext(input.projectId, input.item);
  const envelope = await sealProjectContent({
    projectId: input.projectId,
    chatId: input.item.chatId,
    keyEpoch: input.key.keyEpoch,
    recordType: recordType(input.item),
    recordId: input.item.sourceId,
    plaintext,
    projectKey: input.key.projectKey,
    senderDeviceId: input.owner.deviceId,
    senderPrivateKeyPem: input.owner.privateKeyPem,
    senderPublicKeyPem: input.owner.publicKeyPem,
  });
  return {
    kind: input.item.kind,
    sourceId: input.item.sourceId,
    sourceDigest: input.item.sourceDigest,
    envelope,
  };
}

export class ProjectPlaintextMigrationCoordinator {
  private readonly active = new Map<string, ActiveMigration>();
  private readonly requestProjects = new Map<string, string>();

  constructor(private readonly options: ProjectMigrationCoordinatorOptions) {}

  private send(projectId: string, frame: Record<string, unknown>): void {
    const requestId = String(frame.requestId ?? "");
    if (requestId) this.requestProjects.set(requestId, projectId);
    this.options.send(frame);
  }

  required(frame: ProjectMigrationRequiredFrame): void {
    if (frame.ownerDeviceId !== this.options.owner.deviceId) {
      this.options.status({
        projectId: frame.projectId,
        state: "required",
        error: "The approved project owner must migrate historical plaintext",
      });
      return;
    }
    if (this.active.has(frame.projectId)) return;
    const key = this.options.loadProjectKey(frame.projectId, frame.keyEpoch);
    if (!key || key.keyEpoch !== frame.keyEpoch) {
      this.options.status({
        projectId: frame.projectId,
        state: "failed",
        error: `No local project key is available for epoch ${frame.keyEpoch}`,
      });
      return;
    }
    const requestId = randomUUID();
    this.options.status({ projectId: frame.projectId, state: "preparing" });
    this.send(frame.projectId, {
      version: 1,
      type: "project.migration.prepare",
      requestId,
      projectId: frame.projectId,
    });
  }

  handleError(requestId: string, error: string): boolean {
    const projectId = this.requestProjects.get(requestId);
    if (!projectId) return false;
    this.requestProjects.delete(requestId);
    this.active.delete(projectId);
    this.options.status({ projectId, state: "failed", error });
    return true;
  }

  fail(projectId: string, error: string): void {
    this.active.delete(projectId);
    for (const [requestId, candidate] of this.requestProjects) {
      if (candidate === projectId) this.requestProjects.delete(requestId);
    }
    this.options.status({ projectId, state: "failed", error });
  }

  async handle(frame: ProjectMigrationServerFrame): Promise<boolean> {
    if (frame.type === "project.migration.required") {
      this.required(frame);
      return true;
    }
    if (frame.type === "project.migration.inventory") {
      this.requestProjects.delete(frame.requestId);
      const key = this.options.loadProjectKey(frame.projectId, frame.keyEpoch);
      if (!key || key.keyEpoch !== frame.keyEpoch) {
        throw new Error(`No local project key is available for ${frame.projectId} epoch ${frame.keyEpoch}`);
      }
      const migration: ActiveMigration = {
        projectId: frame.projectId,
        migrationId: frame.migrationId,
        keyEpoch: frame.keyEpoch,
        snapshotDigest: frame.snapshotDigest,
        itemCount: frame.itemCount,
        mappings: new Map(),
        stageQueue: [],
        nextCursor: frame.itemCount === 0 ? null : 0,
        awaiting: null,
      };
      this.active.set(frame.projectId, migration);
      this.options.status({
        projectId: frame.projectId,
        migrationId: frame.migrationId,
        state: "encrypting",
        itemCount: frame.itemCount,
        stagedCount: frame.stagedCount,
      });
      if (frame.itemCount === 0) this.commit(migration);
      else this.requestPage(migration, 0);
      return true;
    }
    if (frame.type === "project.migration.completed") {
      if (frame.requestId) this.requestProjects.delete(frame.requestId);
      this.active.delete(frame.projectId);
      this.options.status({
        projectId: frame.projectId,
        migrationId: frame.migrationId,
        state: "completed",
        itemCount: frame.migratedCount,
        stagedCount: frame.migratedCount,
      });
      this.options.completed(frame);
      return true;
    }
    const migration = this.active.get(frame.projectId);
    if (!migration || migration.migrationId !== frame.migrationId
      || migration.snapshotDigest !== frame.snapshotDigest) {
      return false;
    }
    if (frame.type === "project.migration.page.result") {
      this.requestProjects.delete(frame.requestId);
      if (migration.awaiting !== "page") throw new Error("Unexpected migration inventory page");
      migration.awaiting = null;
      migration.nextCursor = frame.nextCursor;
      const key = this.options.loadProjectKey(frame.projectId, migration.keyEpoch);
      if (!key || key.keyEpoch !== migration.keyEpoch) {
        throw new Error("Migration project key changed while encrypting inventory");
      }
      const unstaged: ProjectMigrationStageItem[] = [];
      for (const item of frame.items) {
        if (item.staged) {
          if (!item.envelopeDigest) throw new Error("Staged migration item omitted its envelope digest");
          migration.mappings.set(identity(item), {
            kind: item.kind,
            sourceId: item.sourceId,
            sourceDigest: item.sourceDigest,
            envelopeDigest: item.envelopeDigest,
          });
          continue;
        }
        const staged = await sealProjectMigrationItem({
          projectId: frame.projectId,
          item,
          key,
          owner: this.options.owner,
        });
        unstaged.push(staged);
        migration.mappings.set(identity(item), {
          kind: item.kind,
          sourceId: item.sourceId,
          sourceDigest: item.sourceDigest,
          envelopeDigest: projectMigrationEnvelopeDigest(staged.envelope),
        });
      }
      migration.stageQueue = [];
      for (let offset = 0; offset < unstaged.length; offset += PROJECT_MIGRATION_STAGE_MAX_ITEMS) {
        migration.stageQueue.push(unstaged.slice(offset, offset + PROJECT_MIGRATION_STAGE_MAX_ITEMS));
      }
      if (migration.stageQueue.length > 0) this.sendNextStage(migration);
      else this.advance(migration);
      return true;
    }
    if (frame.type === "project.migration.staged") {
      this.requestProjects.delete(frame.requestId);
      if (migration.awaiting !== "stage") throw new Error("Unexpected migration staging acknowledgement");
      migration.awaiting = null;
      this.options.status({
        projectId: frame.projectId,
        migrationId: frame.migrationId,
        state: "staging",
        itemCount: frame.itemCount,
        stagedCount: frame.stagedCount,
      });
      if (migration.stageQueue.length > 0) this.sendNextStage(migration);
      else this.advance(migration);
      return true;
    }
    return false;
  }

  private requestPage(migration: ActiveMigration, cursor: number): void {
    if (migration.awaiting) throw new Error("Migration request is already in flight");
    migration.awaiting = "page";
    this.send(migration.projectId, {
      version: 1,
      type: "project.migration.page",
      requestId: randomUUID(),
      projectId: migration.projectId,
      migrationId: migration.migrationId,
      snapshotDigest: migration.snapshotDigest,
      cursor,
    });
  }

  private sendNextStage(migration: ActiveMigration): void {
    const items = migration.stageQueue.shift();
    if (!items) return this.advance(migration);
    migration.awaiting = "stage";
    this.send(migration.projectId, {
      version: 1,
      type: "project.migration.stage",
      requestId: randomUUID(),
      projectId: migration.projectId,
      migrationId: migration.migrationId,
      snapshotDigest: migration.snapshotDigest,
      items,
    });
  }

  private advance(migration: ActiveMigration): void {
    if (migration.nextCursor !== null) {
      this.requestPage(migration, migration.nextCursor);
      return;
    }
    this.commit(migration);
  }

  private commit(migration: ActiveMigration): void {
    if (migration.mappings.size !== migration.itemCount) {
      throw new Error(`Migration manifest has ${migration.mappings.size} mappings for ${migration.itemCount} items`);
    }
    const mappings = [...migration.mappings.values()];
    const transcript = projectMigrationManifestSigningTranscript({
      serverFingerprint: this.options.owner.serverFingerprint,
      projectId: migration.projectId,
      migrationId: migration.migrationId,
      keyEpoch: migration.keyEpoch,
      snapshotDigest: migration.snapshotDigest,
      ownerDeviceId: this.options.owner.deviceId,
      ownerPublicKeyPem: this.options.owner.publicKeyPem,
      mappings,
    });
    migration.awaiting = "commit";
    this.options.status({
      projectId: migration.projectId,
      migrationId: migration.migrationId,
      state: "committing",
      itemCount: migration.itemCount,
      stagedCount: migration.itemCount,
    });
    this.send(migration.projectId, {
      version: 1,
      type: "project.migration.commit",
      requestId: randomUUID(),
      projectId: migration.projectId,
      migrationId: migration.migrationId,
      keyEpoch: migration.keyEpoch,
      snapshotDigest: migration.snapshotDigest,
      ownerPublicKeyPem: this.options.owner.publicKeyPem,
      ownerSignature: sign(null, transcript, this.options.owner.privateKeyPem).toString("base64url"),
    });
  }
}

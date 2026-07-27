import type { ProjectLockState } from "../../packages/cocodex-protocol/src/index.ts";

export type ProjectLockStateOrder = "advance" | "duplicate" | "stale" | "equivocation";

export function compareProjectLockState(
  current: ProjectLockState | undefined,
  next: ProjectLockState,
): ProjectLockStateOrder {
  if (!current || next.revision > current.revision) return "advance";
  if (next.revision < current.revision) return "stale";
  return current.state === next.state
    && current.lockedAt === next.lockedAt
    && current.lockedByDeviceId === next.lockedByDeviceId
    && current.reason === next.reason
    ? "duplicate"
    : "equivocation";
}

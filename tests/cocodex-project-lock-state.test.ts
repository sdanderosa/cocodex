import { describe, expect, test } from "bun:test";
import type { ProjectLockState } from "../packages/cocodex-protocol/src";
import { compareProjectLockState } from "../src/cocodex/project-lock-state";

const locked: ProjectLockState = {
  state: "locked",
  revision: 4,
  lockedAt: "2030-01-01T00:00:00.000Z",
  lockedByDeviceId: crypto.randomUUID(),
  reason: "Owner review",
};

describe("resident project lock authority state", () => {
  test("accepts monotonic advances and exact duplicates", () => {
    expect(compareProjectLockState(undefined, locked)).toBe("advance");
    expect(compareProjectLockState(locked, { ...locked })).toBe("duplicate");
    expect(compareProjectLockState(locked, {
      state: "active",
      revision: 5,
      lockedAt: null,
      lockedByDeviceId: null,
      reason: null,
    })).toBe("advance");
  });

  test("rejects stale revisions and same-revision equivocation", () => {
    expect(compareProjectLockState(locked, {
      ...locked,
      revision: 3,
    })).toBe("stale");
    expect(compareProjectLockState(locked, {
      state: "active",
      revision: locked.revision,
      lockedAt: null,
      lockedByDeviceId: null,
      reason: null,
    })).toBe("equivocation");
    expect(compareProjectLockState(locked, {
      ...locked,
      reason: "Changed without a revision",
    })).toBe("equivocation");
  });
});

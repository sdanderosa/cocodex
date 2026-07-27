import { expect, test } from "bun:test";
import { eligibleProjectMembersForRotation } from "../src/cocodex/session";

test("recovery rotation excludes every revoked roster device", () => {
  const members = [
    { deviceId: "owner", status: "approved" as const },
    { deviceId: "revoked-target", status: "revoked" as const },
    { deviceId: "revoked-other", status: "revoked" as const },
    { deviceId: "approved-member", status: "approved" as const },
  ];

  expect(eligibleProjectMembersForRotation(members, "revoked-target")).toEqual([
    members[0],
    members[3],
  ]);
  // Legacy roster entries without a status remain eligible until the
  // authoritative server marks them revoked.
  expect(eligibleProjectMembersForRotation([
    { deviceId: "owner" },
    { deviceId: "removed" },
  ], "removed")).toEqual([{ deviceId: "owner" }]);
});

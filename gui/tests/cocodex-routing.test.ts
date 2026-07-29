import { describe, expect, test } from "bun:test";
import { hashBelongsToPage, readPageFromHash, resolveAppHashChange } from "../src/app-routing";

describe("CoCodex GUI routing", () => {
  test("recognizes and preserves the collaboration page hash", () => {
    expect(readPageFromHash("#cocodex")).toBe("cocodex");
    expect(hashBelongsToPage("cocodex", "cocodex")).toBeTrue();
    expect(resolveAppHashChange("cocodex", "classic")).toEqual({
      page: "cocodex",
      viewMode: null,
      persistViewMode: null,
      replaceTo: null,
    });
  });
});

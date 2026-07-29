import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { CollaborativePromptEditor } from "../src/components/CollaborativePromptEditor";
import {
  buildPromptOverlayParts,
  promptPresenceColor,
} from "../src/cocodex-prompt-overlay-state";

describe("CoCodex collaborative prompt overlay", () => {
  test("segments bounded overlapping selections and places each remote head caret", () => {
    const parts = buildPromptOverlayParts("shared prompt", [
      { deviceId: "kai-device", displayName: "Kai", typing: true, caret: { anchor: 2, head: 8 } },
      { deviceId: "stephen-device", displayName: "Stephen", typing: false, caret: { anchor: 999, head: 6 } },
      { deviceId: "offline", displayName: "Offline", typing: false, caret: null },
    ]);

    expect(parts.map(part => [part.start, part.end])).toEqual([
      [0, 2], [2, 6], [6, 8], [8, 13], [13, 13],
    ]);
    expect(parts.find(part => part.start === 2)?.selectedBy.map(member => member.displayName)).toEqual(["Kai"]);
    expect(parts.find(part => part.start === 6)?.selectedBy.map(member => member.displayName)).toEqual(["Kai", "Stephen"]);
    expect(parts.find(part => part.start === 6)?.carets.map(member => member.displayName)).toEqual(["Stephen"]);
    expect(parts.find(part => part.start === 8)?.carets.map(member => member.displayName)).toEqual(["Kai"]);
    expect(parts.at(-1)?.text).toBe("\u200b");
  });

  test("renders privacy-safe inline labels without serializing device identifiers", () => {
    const markup = renderToStaticMarkup(<CollaborativePromptEditor
      value="review this change"
      remotePresence={[{
        deviceId: "private-device-id-should-not-render",
        displayName: "Kai",
        typing: true,
        caret: { anchor: 0, head: 6 },
      }]}
      readOnly
      aria-label="Shared prompt"
    />);

    expect(markup).toContain("cocodex-prompt-overlay");
    expect(markup).toContain("Kai · typing");
    expect(markup).toContain('data-selected="true"');
    expect(markup).not.toContain("private-device-id-should-not-render");
    expect(markup).toContain("review this change");
  });

  test("assigns a stable bounded palette color per device", () => {
    expect(promptPresenceColor("kai-device")).toBe(promptPresenceColor("kai-device"));
    expect(promptPresenceColor("kai-device")).toMatch(/^#[0-9a-f]{6}$/);
  });
});

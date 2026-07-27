import { describe, expect, test } from "bun:test";
import * as Y from "yjs";
import {
  applyPromptTextEdit,
  encodePromptRelativeCaret,
  resolvePromptRelativeCaret,
} from "../src/cocodex-prompt-presence";

describe("CoCodex shared-prompt presence", () => {
  test("tracks a remote selection across concurrent CRDT inserts", () => {
    const stephen = new Y.Doc();
    const kai = new Y.Doc();
    const stephenText = stephen.getText("prompt");
    const kaiText = kai.getText("prompt");
    stephenText.insert(0, "review this");
    Y.applyUpdate(kai, Y.encodeStateAsUpdate(stephen));

    const relative = encodePromptRelativeCaret(stephenText, { anchor: 7, head: 11 });
    applyPromptTextEdit(kaiText, "Please review this");
    Y.applyUpdate(stephen, Y.encodeStateAsUpdate(kai));

    expect(resolvePromptRelativeCaret(stephenText, relative, null)).toEqual({
      anchor: 14,
      head: 18,
    });
  });

  test("bounds legacy offsets and safely rejects malformed relative positions", () => {
    const document = new Y.Doc();
    const text = document.getText("prompt");
    text.insert(0, "hello");

    expect(resolvePromptRelativeCaret(
      text,
      { anchor: "not-base64", head: "also-not-base64" },
      { anchor: 999, head: -4 },
    )).toEqual({ anchor: 5, head: 0 });
  });
});

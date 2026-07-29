import * as Y from "yjs";

export interface PromptCaret {
  anchor: number;
  head: number;
}

export interface RelativePromptCaret {
  anchor: string;
  head: string;
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function boundedIndex(text: Y.Text, value: number): number {
  return Math.max(0, Math.min(text.length, Math.trunc(value)));
}

export function applyPromptTextEdit(text: Y.Text, value: string): void {
  const current = text.toString();
  if (current === value) return;
  let prefix = 0;
  const prefixLimit = Math.min(current.length, value.length);
  while (prefix < prefixLimit && current[prefix] === value[prefix]) prefix += 1;

  let suffix = 0;
  const suffixLimit = Math.min(current.length - prefix, value.length - prefix);
  while (suffix < suffixLimit
    && current[current.length - suffix - 1] === value[value.length - suffix - 1]) {
    suffix += 1;
  }

  text.doc?.transact(() => {
    const deleteLength = current.length - prefix - suffix;
    if (deleteLength > 0) text.delete(prefix, deleteLength);
    const insert = value.slice(prefix, value.length - suffix);
    if (insert) text.insert(prefix, insert);
  });
}

export function encodePromptRelativeCaret(
  text: Y.Text,
  caret: PromptCaret,
): RelativePromptCaret {
  return {
    anchor: bytesToBase64(Y.encodeRelativePosition(
      Y.createRelativePositionFromTypeIndex(text, boundedIndex(text, caret.anchor)),
    )),
    head: bytesToBase64(Y.encodeRelativePosition(
      Y.createRelativePositionFromTypeIndex(text, boundedIndex(text, caret.head)),
    )),
  };
}

export function resolvePromptRelativeCaret(
  text: Y.Text,
  relativeCaret: RelativePromptCaret | null | undefined,
  fallback: PromptCaret | null,
): PromptCaret | null {
  if (relativeCaret) {
    try {
      const anchor = Y.createAbsolutePositionFromRelativePosition(
        Y.decodeRelativePosition(base64ToBytes(relativeCaret.anchor)),
        text.doc!,
      );
      const head = Y.createAbsolutePositionFromRelativePosition(
        Y.decodeRelativePosition(base64ToBytes(relativeCaret.head)),
        text.doc!,
      );
      if (anchor?.type === text && head?.type === text) {
        return { anchor: anchor.index, head: head.index };
      }
    } catch {
      // A malformed or stale awareness value is ephemeral; fall back to its bounded offset.
    }
  }
  if (!fallback) return null;
  return {
    anchor: boundedIndex(text, fallback.anchor),
    head: boundedIndex(text, fallback.head),
  };
}

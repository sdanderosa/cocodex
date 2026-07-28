export interface PromptOverlayCaret {
  anchor: number;
  head: number;
}

export interface RemotePromptEditorPresence {
  deviceId: string;
  displayName: string;
  typing: boolean;
  caret: PromptOverlayCaret | null;
}

export interface PromptOverlayPart {
  start: number;
  end: number;
  text: string;
  selectedBy: RemotePromptEditorPresence[];
  carets: RemotePromptEditorPresence[];
}

function boundedOffset(value: number, length: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(length, Math.trunc(value)));
}

function normalizedPresence(
  text: string,
  presence: RemotePromptEditorPresence[],
): RemotePromptEditorPresence[] {
  return presence.flatMap(member => {
    if (!member.caret) return [];
    return [{
      ...member,
      caret: {
        anchor: boundedOffset(member.caret.anchor, text.length),
        head: boundedOffset(member.caret.head, text.length),
      },
    }];
  });
}

export function buildPromptOverlayParts(
  text: string,
  presence: RemotePromptEditorPresence[],
): PromptOverlayPart[] {
  const members = normalizedPresence(text, presence);
  const points = new Set<number>([0, text.length]);
  for (const member of members) {
    points.add(member.caret!.anchor);
    points.add(member.caret!.head);
  }
  const ordered = [...points].sort((left, right) => left - right);
  return ordered.map((start, index) => {
    const end = ordered[index + 1] ?? start;
    return {
      start,
      end,
      text: end > start ? text.slice(start, end) : "\u200b",
      selectedBy: members.filter(member => {
        const selectionStart = Math.min(member.caret!.anchor, member.caret!.head);
        const selectionEnd = Math.max(member.caret!.anchor, member.caret!.head);
        return selectionStart < selectionEnd && start >= selectionStart && start < selectionEnd;
      }),
      carets: members.filter(member => member.caret!.head === start),
    };
  });
}

const PRESENCE_COLORS = ["#8b5cf6", "#06b6d4", "#f97316", "#22c55e", "#ec4899", "#eab308"] as const;

export function promptPresenceColor(deviceId: string): string {
  let hash = 0;
  for (let index = 0; index < deviceId.length; index += 1) {
    hash = ((hash << 5) - hash + deviceId.charCodeAt(index)) | 0;
  }
  return PRESENCE_COLORS[Math.abs(hash) % PRESENCE_COLORS.length];
}

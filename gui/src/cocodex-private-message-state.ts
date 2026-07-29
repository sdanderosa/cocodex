export type PrivateMessageEventKind = "message" | "reaction" | "edit" | "delete";

export interface PrivateMessageEvent {
  messageId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  text: string;
  kind?: PrivateMessageEventKind;
  targetMessageId?: string;
  replyToMessageId?: string;
  emoji?: string;
  reactionOperation?: "add" | "remove";
  clientCreatedAt?: string;
  acceptedAt?: string;
  serverSequence?: number;
  direction?: "sent" | "received";
  restored?: boolean;
  deliveryState?: "staged" | "queued" | "accepted" | "rejected";
  rejectionReason?: string;
}

export interface PrivateMessageReaction {
  emoji: string;
  senderDeviceIds: string[];
}

export interface ProjectedPrivateMessage extends PrivateMessageEvent {
  kind: "message";
  edited: boolean;
  deleted: boolean;
  reactions: PrivateMessageReaction[];
}

function compareEvents(left: PrivateMessageEvent, right: PrivateMessageEvent): number {
  return (left.serverSequence ?? Number.MAX_SAFE_INTEGER) - (right.serverSequence ?? Number.MAX_SAFE_INTEGER)
    || String(left.clientCreatedAt ?? left.acceptedAt ?? "").localeCompare(
      String(right.clientCreatedAt ?? right.acceptedAt ?? ""),
    )
    || left.messageId.localeCompare(right.messageId);
}

function sameConversation(left: PrivateMessageEvent, right: PrivateMessageEvent): boolean {
  return (left.senderDeviceId === right.senderDeviceId
      && left.recipientDeviceId === right.recipientDeviceId)
    || (left.senderDeviceId === right.recipientDeviceId
      && left.recipientDeviceId === right.senderDeviceId);
}

export function projectPrivateMessageEvents(
  events: readonly PrivateMessageEvent[],
): ProjectedPrivateMessage[] {
  const messages = new Map<string, ProjectedPrivateMessage>();
  const reactionSets = new Map<string, Map<string, Set<string>>>();

  for (const event of [...events].sort(compareEvents)) {
    const kind = event.kind ?? "message";
    if (kind === "message") {
      const existing = messages.get(event.messageId);
      const replyTarget = event.replyToMessageId
        ? messages.get(event.replyToMessageId)
        : undefined;
      const replyToMessageId = replyTarget && sameConversation(event, replyTarget)
        ? event.replyToMessageId
        : undefined;
      messages.set(event.messageId, {
        ...(existing ?? event),
        ...event,
        text: existing?.deleted ? "" : event.text,
        kind: "message",
        ...(replyToMessageId ? { replyToMessageId } : { replyToMessageId: undefined }),
        edited: existing?.edited ?? false,
        deleted: existing?.deleted ?? false,
        reactions: existing?.reactions ?? [],
      });
      continue;
    }

    const target = event.targetMessageId ? messages.get(event.targetMessageId) : undefined;
    if (!target || !sameConversation(event, target)) continue;
    if (target.deleted) continue;
    if (kind === "edit") {
      if (event.senderDeviceId !== target.senderDeviceId || !event.text) continue;
      messages.set(target.messageId, { ...target, text: event.text, edited: true });
      continue;
    }
    if (kind === "delete") {
      if (event.senderDeviceId !== target.senderDeviceId) continue;
      messages.set(target.messageId, { ...target, text: "", deleted: true });
      continue;
    }
    if (!event.emoji || (event.reactionOperation !== "add" && event.reactionOperation !== "remove")) continue;
    const byEmoji = reactionSets.get(target.messageId) ?? new Map<string, Set<string>>();
    const senders = byEmoji.get(event.emoji) ?? new Set<string>();
    if (event.reactionOperation === "add") senders.add(event.senderDeviceId);
    else senders.delete(event.senderDeviceId);
    if (senders.size) byEmoji.set(event.emoji, senders);
    else byEmoji.delete(event.emoji);
    reactionSets.set(target.messageId, byEmoji);
    messages.set(target.messageId, {
      ...target,
      reactions: [...byEmoji.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([emoji, senderDeviceIds]) => ({ emoji, senderDeviceIds: [...senderDeviceIds].sort() })),
    });
  }

  return [...messages.values()].sort(compareEvents);
}
export const PRIVATE_TYPING_IDLE_MS = 1_800;
export const PRIVATE_TYPING_EXPIRY_MS = 5_000;

export function buildPrivateTypingCommand(
  recipientDeviceId: string,
  typing: boolean,
): Record<string, unknown> {
  return { type: "private.typing", recipientDeviceId, typing };
}

export function buildPrivateComposerCommand(
  recipientDeviceId: string,
  text: string,
  options: { replyToMessageId?: string; editTargetMessageId?: string } = {},
): Record<string, unknown> {
  if (options.replyToMessageId && options.editTargetMessageId) {
    throw new Error("A private composer cannot reply and edit at the same time");
  }
  return {
    type: "private.send",
    recipientDeviceId,
    text,
    kind: options.editTargetMessageId ? "edit" : "message",
    ...(options.editTargetMessageId
      ? { targetMessageId: options.editTargetMessageId }
      : options.replyToMessageId
        ? { replyToMessageId: options.replyToMessageId }
        : {}),
  };
}

export function buildPrivateMutationCommand(
  recipientDeviceId: string,
  targetMessageId: string,
  mutation: { kind: "delete" } | {
    kind: "reaction";
    emoji: string;
    reactionOperation: "add" | "remove";
  },
): Record<string, unknown> {
  return {
    type: "private.send",
    recipientDeviceId,
    targetMessageId,
    ...mutation,
  };
}

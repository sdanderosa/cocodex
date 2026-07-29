import { describe, expect, test } from "bun:test";
import {
  PRIVATE_TYPING_EXPIRY_MS,
  PRIVATE_TYPING_IDLE_MS,
  buildPrivateComposerCommand,
  buildPrivateMutationCommand,
  buildPrivateTypingCommand,
  projectPrivateMessageEvents,
  type PrivateMessageEvent,
} from "../src/cocodex-private-message-state";

const a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const c = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

function event(overrides: Partial<PrivateMessageEvent> = {}): PrivateMessageEvent {
  return {
    messageId: crypto.randomUUID(),
    senderDeviceId: a,
    recipientDeviceId: b,
    text: "original",
    kind: "message",
    clientCreatedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("private message event projection", () => {
  test("projects replies, authorized edits, reactions, and deletes from immutable events", () => {
    const original = event({ messageId: crypto.randomUUID(), serverSequence: 1 });
    const reply = event({
      messageId: crypto.randomUUID(),
      senderDeviceId: b,
      recipientDeviceId: a,
      text: "reply",
      replyToMessageId: original.messageId,
      serverSequence: 2,
    });
    const edit = event({
      kind: "edit",
      messageId: crypto.randomUUID(),
      targetMessageId: original.messageId,
      text: "edited",
      serverSequence: 3,
    });
    const reaction = event({
      kind: "reaction",
      messageId: crypto.randomUUID(),
      senderDeviceId: b,
      recipientDeviceId: a,
      targetMessageId: original.messageId,
      text: "",
      emoji: "thumbs-up",
      reactionOperation: "add",
      serverSequence: 4,
    });
    const deletion = event({
      kind: "delete",
      messageId: crypto.randomUUID(),
      senderDeviceId: b,
      recipientDeviceId: a,
      targetMessageId: reply.messageId,
      text: "",
      serverSequence: 5,
    });
    const lateEdit = event({
      kind: "edit",
      messageId: crypto.randomUUID(),
      senderDeviceId: b,
      recipientDeviceId: a,
      targetMessageId: reply.messageId,
      text: "must not return",
      serverSequence: 6,
    });
    const replayedReply = { ...reply, text: "must not return", serverSequence: 7 };
    const projected = projectPrivateMessageEvents([
      replayedReply,
      lateEdit,
      deletion,
      reaction,
      edit,
      reply,
      original,
    ]);
    expect(projected).toHaveLength(2);
    expect(projected[0]).toMatchObject({
      messageId: original.messageId,
      text: "edited",
      edited: true,
      deleted: false,
      reactions: [{ emoji: "thumbs-up", senderDeviceIds: [b] }],
    });
    expect(projected[1]).toMatchObject({
      messageId: reply.messageId,
      replyToMessageId: original.messageId,
      text: "",
      deleted: true,
    });
  });

  test("ignores cross-conversation actions and unauthorized edits or deletes", () => {
    const original = event({ messageId: crypto.randomUUID(), serverSequence: 1 });
    const unauthorizedEdit = event({
      kind: "edit",
      senderDeviceId: b,
      recipientDeviceId: a,
      targetMessageId: original.messageId,
      text: "tampered",
      serverSequence: 2,
    });
    const crossConversationDelete = event({
      kind: "delete",
      senderDeviceId: a,
      recipientDeviceId: c,
      targetMessageId: original.messageId,
      text: "",
      serverSequence: 3,
    });
    expect(projectPrivateMessageEvents([original, unauthorizedEdit, crossConversationDelete])[0])
      .toMatchObject({ text: "original", edited: false, deleted: false });
  });

  test("removes a sender reaction without mutating the encrypted event log", () => {
    const original = event({ messageId: crypto.randomUUID(), serverSequence: 1 });
    const add = event({
      kind: "reaction",
      senderDeviceId: b,
      recipientDeviceId: a,
      targetMessageId: original.messageId,
      text: "",
      emoji: "thumbs-up",
      reactionOperation: "add",
      serverSequence: 2,
    });
    const remove = event({
      ...add,
      messageId: crypto.randomUUID(),
      reactionOperation: "remove",
      serverSequence: 3,
    });
    expect(projectPrivateMessageEvents([original, add, remove])[0]?.reactions).toEqual([]);
  });
  test("builds exact resident-client commands for reply, edit, reaction, and delete", () => {
    const targetMessageId = crypto.randomUUID();
    expect(buildPrivateComposerCommand(b, "reply", { replyToMessageId: targetMessageId })).toEqual({
      type: "private.send",
      recipientDeviceId: b,
      text: "reply",
      kind: "message",
      replyToMessageId: targetMessageId,
    });
    expect(buildPrivateComposerCommand(b, "edited", { editTargetMessageId: targetMessageId })).toEqual({
      type: "private.send",
      recipientDeviceId: b,
      text: "edited",
      kind: "edit",
      targetMessageId,
    });
    expect(buildPrivateMutationCommand(b, targetMessageId, {
      kind: "reaction",
      emoji: "thumbs-up",
      reactionOperation: "remove",
    })).toEqual({
      type: "private.send",
      recipientDeviceId: b,
      targetMessageId,
      kind: "reaction",
      emoji: "thumbs-up",
      reactionOperation: "remove",
    });
    expect(buildPrivateTypingCommand(b, true)).toEqual({
      type: "private.typing",
      recipientDeviceId: b,
      typing: true,
    });
    expect(PRIVATE_TYPING_EXPIRY_MS).toBeGreaterThan(PRIVATE_TYPING_IDLE_MS);
    expect(buildPrivateMutationCommand(b, targetMessageId, { kind: "delete" })).toEqual({
      type: "private.send",
      recipientDeviceId: b,
      targetMessageId,
      kind: "delete",
    });
    expect(() => buildPrivateComposerCommand(b, "invalid", {
      replyToMessageId: targetMessageId,
      editTargetMessageId: targetMessageId,
    })).toThrow("cannot reply and edit");
  });
});

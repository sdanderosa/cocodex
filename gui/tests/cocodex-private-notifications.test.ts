import { describe, expect, test } from "bun:test";
import {
  PRIVATE_NOTIFICATIONS_KEY,
  buildPrivateNotification,
  disablePrivateNotifications,
  enablePrivateNotifications,
  readPrivateNotificationsEnabled,
  shouldNotifyPrivateMessage,
  showPrivateNotification,
  type NotificationStorage,
  type PrivateNotificationApi,
} from "../src/cocodex-private-notifications";

function storage(initial: string | null = null): NotificationStorage & { value: string | null } {
  return {
    value: initial,
    getItem() { return this.value; },
    setItem(_key, value) { this.value = value; },
  };
}

describe("private desktop notifications", () => {
  test("requests native permission only through explicit enable and persists the result", async () => {
    const store = storage();
    let requests = 0;
    const api: PrivateNotificationApi = {
      isPermissionGranted: async () => false,
      requestPermission: async () => { requests += 1; return "granted"; },
      sendNotification() {},
    };
    expect(await enablePrivateNotifications(store, api)).toBe(true);
    expect(requests).toBe(1);
    expect(store.value).toBe("enabled");
    expect(readPrivateNotificationsEnabled(store)).toBe(true);
    disablePrivateNotifications(store);
    expect(store.value).toBe("disabled");
    expect(PRIVATE_NOTIFICATIONS_KEY).toContain("privateNotifications");
  });

  test("fails closed on denied permission or inaccessible storage", async () => {
    const denied = storage();
    const api: PrivateNotificationApi = {
      isPermissionGranted: async () => false,
      requestPermission: async () => "denied",
      sendNotification() {},
    };
    expect(await enablePrivateNotifications(denied, api)).toBe(false);
    expect(denied.value).toBe("disabled");
    expect(readPrivateNotificationsEnabled({
      getItem() { throw new Error("blocked"); },
      setItem() { throw new Error("blocked"); },
    })).toBe(false);
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      get() { throw new Error("getter blocked"); },
    });
    try {
      expect(readPrivateNotificationsEnabled()).toBe(false);
      disablePrivateNotifications();
    } finally {
      if (descriptor) Object.defineProperty(globalThis, "localStorage", descriptor);
      else Reflect.deleteProperty(globalThis, "localStorage");
    }
  });

  test("notifies only a new inbound message outside the focused active conversation", () => {
    const message = {
      messageId: crypto.randomUUID(),
      senderDeviceId: "kai",
      direction: "received" as const,
      kind: "message" as const,
    };
    const context = {
      enabled: true,
      localDeviceId: "stephen",
      selectedContactDeviceId: "kai",
      documentVisible: true,
      windowFocused: true,
    };
    expect(shouldNotifyPrivateMessage(message, context)).toBe(false);
    expect(shouldNotifyPrivateMessage(message, { ...context, windowFocused: false })).toBe(true);
    expect(shouldNotifyPrivateMessage({ ...message, restored: true }, { ...context, windowFocused: false })).toBe(false);
    expect(shouldNotifyPrivateMessage({ ...message, kind: "reaction" }, { ...context, windowFocused: false })).toBe(false);
    expect(shouldNotifyPrivateMessage({ ...message, direction: "sent" }, { ...context, windowFocused: false })).toBe(false);
  });

  test("builds bounded plaintext-free labels and catches native delivery failure", () => {
    const descriptor = buildPrivateNotification("Kai\nInjected", {
      title: "New private message",
      body: "{name} sent an encrypted private message.",
      fallbackSender: "Trusted contact",
    });
    expect(descriptor).toEqual({
      title: "New private message",
      body: "Kai Injected sent an encrypted private message.",
    });
    expect(JSON.stringify(descriptor)).not.toContain("SECRET-MESSAGE-BODY");
    expect(showPrivateNotification(descriptor, {
      isPermissionGranted: async () => true,
      requestPermission: async () => "granted",
      sendNotification() { throw new Error("native unavailable"); },
    })).toBe(false);
  });
});

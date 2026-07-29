import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

export const PRIVATE_NOTIFICATIONS_KEY = "cocodex.privateNotifications.v1";

export interface NotificationStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function browserStorage(): NotificationStorage | undefined {
  try { return globalThis.localStorage; } catch { return undefined; }
}

export interface PrivateNotificationApi {
  isPermissionGranted(): Promise<boolean>;
  requestPermission(): Promise<NotificationPermission>;
  sendNotification(options: { title: string; body: string }): void;
}

const nativeNotificationApi: PrivateNotificationApi = {
  isPermissionGranted,
  requestPermission,
  sendNotification,
};

export interface PrivateNotificationCandidate {
  messageId: string;
  senderDeviceId: string;
  direction?: "sent" | "received";
  restored?: boolean;
  kind?: "message" | "reaction" | "edit" | "delete";
}

export function readPrivateNotificationsEnabled(
  storage?: NotificationStorage,
): boolean {
  try {
    return (storage ?? browserStorage())?.getItem(PRIVATE_NOTIFICATIONS_KEY) === "enabled";
  } catch {
    return false;
  }
}

export async function enablePrivateNotifications(
  storage?: NotificationStorage,
  api: PrivateNotificationApi = nativeNotificationApi,
): Promise<boolean> {
  const targetStorage = storage ?? browserStorage();
  try {
    const granted = await api.isPermissionGranted()
      || await api.requestPermission() === "granted";
    targetStorage?.setItem(PRIVATE_NOTIFICATIONS_KEY, granted ? "enabled" : "disabled");
    return granted;
  } catch {
    try { targetStorage?.setItem(PRIVATE_NOTIFICATIONS_KEY, "disabled"); } catch {
      // Inaccessible storage already implies the fail-closed disabled state.
    }
    return false;
  }
}

export function disablePrivateNotifications(
  storage?: NotificationStorage,
): void {
  try { (storage ?? browserStorage())?.setItem(PRIVATE_NOTIFICATIONS_KEY, "disabled"); } catch {
    // Inaccessible storage already implies the fail-closed disabled state.
  }
}

export function shouldNotifyPrivateMessage(
  candidate: PrivateNotificationCandidate,
  context: {
    enabled: boolean;
    localDeviceId: string;
    selectedContactDeviceId: string;
    documentVisible: boolean;
    windowFocused: boolean;
  },
): boolean {
  if (!context.enabled || candidate.restored || (candidate.kind ?? "message") !== "message") return false;
  if (candidate.direction !== "received" || candidate.senderDeviceId === context.localDeviceId) return false;
  return !(context.documentVisible
    && context.windowFocused
    && context.selectedContactDeviceId === candidate.senderDeviceId);
}

function safeLabel(value: string, fallback: string): string {
  const withoutControls = [...value].map(character => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127 ? " " : character;
  }).join("");
  const normalized = withoutControls.replace(/\s+/g, " ").trim();
  return (normalized || fallback).slice(0, 120);
}

export function buildPrivateNotification(
  senderDisplayName: string,
  labels: { title: string; body: string; fallbackSender: string },
): { title: string; body: string } {
  const sender = safeLabel(senderDisplayName, labels.fallbackSender);
  return {
    title: safeLabel(labels.title, "CoCodex"),
    body: safeLabel(labels.body.replace("{name}", sender), "New encrypted private message"),
  };
}

export function showPrivateNotification(
  descriptor: { title: string; body: string },
  api: PrivateNotificationApi = nativeNotificationApi,
): boolean {
  try {
    api.sendNotification({
      title: safeLabel(descriptor.title, "CoCodex"),
      body: safeLabel(descriptor.body, "New encrypted private message"),
    });
    return true;
  } catch {
    return false;
  }
}

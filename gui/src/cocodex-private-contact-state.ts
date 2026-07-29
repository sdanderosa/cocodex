export interface PrivateContactSummary {
  deviceId: string;
  trusted: boolean;
}

export interface PrivateTimelineEntry {
  senderDeviceId: string;
  recipientDeviceId: string;
  text: string;
}

export function reconcilePrivateContactSelection(
  currentDeviceId: string,
  contacts: readonly PrivateContactSummary[],
): string {
  if (contacts.some(contact => contact.deviceId === currentDeviceId)) return currentDeviceId;
  return contacts.find(contact => contact.trusted)?.deviceId ?? contacts[0]?.deviceId ?? "";
}

export function independentlyConfirmedFingerprintMatches(
  enteredFingerprint: string,
  directoryFingerprint: string,
): boolean {
  return enteredFingerprint.trim() === directoryFingerprint;
}

export function privateTimelineForContact<T extends PrivateTimelineEntry>(
  messages: readonly T[],
  contactDeviceId: string,
  search: string,
): T[] {
  if (!contactDeviceId) return [];
  const normalized = search.trim().toLocaleLowerCase();
  return messages.filter(message =>
    (message.senderDeviceId === contactDeviceId || message.recipientDeviceId === contactDeviceId)
    && (!normalized || message.text.toLocaleLowerCase().includes(normalized)));
}

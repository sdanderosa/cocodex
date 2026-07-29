import { describe, expect, test } from "bun:test";
import {
  independentlyConfirmedFingerprintMatches,
  privateTimelineForContact,
  reconcilePrivateContactSelection,
} from "../src/cocodex-private-contact-state";

describe("CoCodex private-contact UI state", () => {
  test("preserves a valid selection and otherwise prefers a verified contact", () => {
    const contacts = [
      { deviceId: "unverified", trusted: false },
      { deviceId: "trusted", trusted: true },
    ];
    expect(reconcilePrivateContactSelection("unverified", contacts)).toBe("unverified");
    expect(reconcilePrivateContactSelection("missing", contacts)).toBe("trusted");
    expect(reconcilePrivateContactSelection("missing", [])).toBe("");
  });

  test("shows only the selected contact conversation and searches locally", () => {
    const messages = [
      { messageId: "one", senderDeviceId: "kai", recipientDeviceId: "local", text: "Secret finding" },
      { messageId: "two", senderDeviceId: "local", recipientDeviceId: "kai", text: "Thanks" },
      { messageId: "three", senderDeviceId: "other", recipientDeviceId: "local", text: "Unrelated" },
    ];
    expect(privateTimelineForContact(messages, "kai", "")).toHaveLength(2);
    expect(privateTimelineForContact(messages, "kai", "FINDING").map(message => message.messageId))
      .toEqual(["one"]);
    expect(privateTimelineForContact(messages, "", "")).toEqual([]);
  });

  test("requires an exact independently confirmed fingerprint before verification", () => {
    const fingerprint = "SHA256:AAAA-BBBB-CCCC-DDDD";
    expect(independentlyConfirmedFingerprintMatches(fingerprint, fingerprint)).toBeTrue();
    expect(independentlyConfirmedFingerprintMatches(` ${fingerprint} `, fingerprint)).toBeTrue();
    expect(independentlyConfirmedFingerprintMatches("SHA256:AAAA-BBBB-CCCC-EEEE", fingerprint)).toBeFalse();
    expect(independentlyConfirmedFingerprintMatches("", fingerprint)).toBeFalse();
  });
});

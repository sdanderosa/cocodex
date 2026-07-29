import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { z } from "zod";
import {
  privateContactViewSchema,
  type PrivateContactView,
} from "../../packages/cocodex-protocol/src/index.ts";
import { hardenSecretDir, hardenSecretPath } from "../lib/windows-secret-acl";
import { verifyDeviceKeyCertificate } from "./identity";

const MAX_PRIVATE_CONTACT_CACHE_BYTES = 2 * 1024 * 1024;
const privateContactCacheSchema = z.object({
  version: z.literal(2),
  deviceId: z.uuid(),
  authority: z.object({
    serverIdentityFingerprint: z.string().min(16).max(256),
    serverEpoch: z.number().int().positive(),
  }).strict(),
  contacts: z.array(privateContactViewSchema).max(128),
}).strict();

export interface PrivateContactAuthority {
  serverIdentityFingerprint: string;
  serverEpoch: number;
}

export interface CachedPrivateContact extends PrivateContactView {
  messagingPublicKeyPem: string;
  projectWrapPublicKeyPem: string | null;
}

export interface SafePrivateContact {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  trusted: boolean;
  projectCapable: boolean;
}

export function verifyPrivateContactSnapshot(
  contacts: readonly PrivateContactView[],
  localDeviceId: string,
): Map<string, CachedPrivateContact> {
  const verifiedContacts = new Map<string, CachedPrivateContact>();
  const fingerprints = new Set<string>();
  for (const contact of contacts) {
    if (contact.deviceId === localDeviceId) {
      throw new Error("Private-contact snapshot included the local device");
    }
    if (verifiedContacts.has(contact.deviceId) || fingerprints.has(contact.fingerprint)) {
      throw new Error("Private-contact snapshot contains a duplicate identity");
    }
    const certificate = verifyDeviceKeyCertificate(contact.deviceKeyCertificate, contact.deviceId);
    if (certificate.fingerprint !== contact.fingerprint) {
      throw new Error("Private-contact certificate fingerprint does not match the directory");
    }
    fingerprints.add(contact.fingerprint);
    verifiedContacts.set(contact.deviceId, {
      ...contact,
      messagingPublicKeyPem: certificate.messagingPublicKeyPem,
      projectWrapPublicKeyPem: certificate.projectWrapPublicKeyPem ?? null,
    });
  }
  return verifiedContacts;
}

export function safePrivateContacts(
  contacts: ReadonlyMap<string, CachedPrivateContact>,
  trustedFingerprints: Readonly<Record<string, string>>,
): SafePrivateContact[] {
  return [...contacts.values()].map(contact => ({
    deviceId: contact.deviceId,
    displayName: contact.displayName,
    fingerprint: contact.fingerprint,
    trusted: trustedFingerprints[contact.deviceId] === contact.fingerprint,
    projectCapable: contact.projectWrapPublicKeyPem !== null,
  }));
}

export function loadPrivateContactSnapshot(
  path: string,
  localDeviceId: string,
  authority: PrivateContactAuthority,
): PrivateContactView[] {
  if (!existsSync(path)) return [];
  hardenSecretPath(path, { required: true });
  if (statSync(path).size > MAX_PRIVATE_CONTACT_CACHE_BYTES) {
    throw new Error("Private-contact cache is too large");
  }
  const parsed = privateContactCacheSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  if (parsed.deviceId !== localDeviceId) {
    throw new Error("Private-contact cache belongs to a different device");
  }
  if (parsed.authority.serverIdentityFingerprint !== authority.serverIdentityFingerprint
    || parsed.authority.serverEpoch !== authority.serverEpoch) {
    throw new Error("Private-contact cache belongs to a different server authority");
  }
  verifyPrivateContactSnapshot(parsed.contacts, localDeviceId);
  return parsed.contacts;
}

export function savePrivateContactSnapshot(
  path: string,
  localDeviceId: string,
  authority: PrivateContactAuthority,
  contacts: readonly PrivateContactView[],
): void {
  verifyPrivateContactSnapshot(contacts, localDeviceId);
  const parsed = privateContactCacheSchema.parse({
    version: 2,
    deviceId: localDeviceId,
    authority,
    contacts,
  });
  const serialized = `${JSON.stringify(parsed, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_PRIVATE_CONTACT_CACHE_BYTES) {
    throw new Error("Private-contact cache is too large");
  }
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true });
  hardenSecretDir(directory, { required: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
  hardenSecretPath(temporary, { required: true });
  renameSync(temporary, path);
  hardenSecretPath(path, { required: true });
}

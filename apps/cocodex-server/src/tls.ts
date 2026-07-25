import { X509Certificate, createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import selfsigned from "selfsigned";
import type { ServerPaths } from "./paths";

export async function createTlsIdentity(paths: ServerPaths): Promise<void> {
  if (existsSync(paths.tlsCertificate) || existsSync(paths.tlsPrivateKey)) {
    throw new Error("TLS identity already exists");
  }
  const generated = await selfsigned.generate(
    [{ name: "commonName", value: "CoCodex Server" }],
    {
      algorithm: "sha256",
      keySize: 2048,
      notAfterDate: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
      extensions: [
        { name: "basicConstraints", cA: false },
        { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
        { name: "extKeyUsage", serverAuth: true },
        { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }, { type: 7, ip: "127.0.0.1" }] },
      ],
    },
  );
  mkdirSync(dirname(paths.tlsPrivateKey), { recursive: true });
  writeFileSync(paths.tlsPrivateKey, generated.private, { encoding: "utf8", mode: 0o600, flag: "wx" });
  writeFileSync(paths.tlsCertificate, generated.cert, { encoding: "utf8", mode: 0o644, flag: "wx" });
}

export function tlsCertificateFingerprint(certificatePath: string): string {
  const certificate = new X509Certificate(readFileSync(certificatePath, "utf8"));
  const hex = createHash("sha256").update(certificate.raw).digest("hex").toUpperCase();
  return hex.match(/.{1,4}/g)?.join("-") ?? hex;
}

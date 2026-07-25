import { X509Certificate, createHash } from "node:crypto";
import { isIP } from "node:net";
import { connect } from "node:tls";

function formattedFingerprint(raw: Buffer): string {
  const hex = createHash("sha256").update(raw).digest("hex").toUpperCase();
  return hex.match(/.{1,4}/g)?.join("-") ?? hex;
}

function certificatePem(raw: Buffer): string {
  const base64 = raw.toString("base64").match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

export interface PinnedCertificate {
  fingerprint: string;
  pem: string;
}

export async function readAndVerifyServerCertificate(
  host: string,
  port: number,
  expectedFingerprint: string,
): Promise<PinnedCertificate> {
  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: unknown, result?: PinnedCertificate) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.destroy();
      if (error) reject(error);
      else resolve(result!);
    };
    const socket = connect({
      host,
      port,
      rejectUnauthorized: false,
      servername: isIP(host) ? undefined : host,
    }, () => {
      try {
        const peer = socket.getPeerCertificate();
        if (!peer.raw) throw new Error("Server did not provide a TLS certificate");
        const fingerprint = formattedFingerprint(peer.raw);
        if (fingerprint !== expectedFingerprint) {
          throw new Error("CoCodex Server certificate fingerprint does not match the invitation");
        }
        const pem = certificatePem(peer.raw);
        const certificate = new X509Certificate(pem);
        const matchedAddress = isIP(host) ? certificate.checkIP(host) : certificate.checkHost(host);
        if (!matchedAddress) throw new Error("CoCodex Server certificate does not match its address");
        finish(undefined, { fingerprint, pem });
      } catch (error) {
        finish(error);
      }
    });
    const timeout = setTimeout(
      () => finish(new Error("Timed out while verifying the CoCodex Server certificate")),
      10_000,
    );
    socket.once("error", error => finish(error));
  });
}

import dgram from "node:dgram";
import { networkInterfaces } from "node:os";

export interface PortMappingResult {
  status: "mapped" | "unavailable" | "failed";
  method: "upnp" | "nat-pmp" | "none";
  message: string;
  gateway?: string;
  internalHost?: string;
}

export interface DirectHostingDiagnostic {
  status: "ready" | "manual-forwarding-required" | "likely-cgnat" | "blocked";
  localAddress?: string;
  message: string;
  mapping: PortMappingResult;
}

const SSDP_ADDRESS = "239.255.255.250";
const SSDP_PORT = 1900;
const DISCOVERY_TIMEOUT_MS = 650;
const REQUEST = [
  "M-SEARCH * HTTP/1.1",
  `HOST: ${SSDP_ADDRESS}:${SSDP_PORT}`,
  'MAN: "ssdp:discover"',
  "MX: 1",
  "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
  "",
  "",
].join("\r\n");
const NAT_PMP_PORT = 5351;
const NAT_PMP_TIMEOUT_MS = 800;

export function localIpv4(): string | undefined {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) return entry.address;
    }
  }
  return undefined;
}

function isCgnatOrPrivate(address: string | undefined): boolean {
  if (!address) return false;
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return false;
  const [a, b] = octets;
  return a === 10 || a === 100 && b >= 64 && b <= 127 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168;
}

export function classifyDirectHosting(mapping: PortMappingResult, address = localIpv4()): DirectHostingDiagnostic {
  if (mapping.status === "mapped") {
    return { status: "ready", localAddress: address, mapping, message: "Direct hosting is ready: the CoCodex port mapping succeeded." };
  }
  if (!address) {
    return { status: "blocked", mapping, message: "No usable local IPv4 address was found. Direct hosting is unavailable until this PC has a LAN connection." };
  }
  if (isCgnatOrPrivate(address)) {
    return { status: "likely-cgnat", localAddress: address, mapping, message: "The PC has a private or carrier-grade address and automatic mapping did not succeed. Your ISP or upstream router may be using CGNAT; ask for a public IPv4 address or forward the port on every upstream router." };
  }
  if (mapping.status === "unavailable") {
    return { status: "manual-forwarding-required", localAddress: address, mapping, message: "No automatic router mapping is available. Forward one TCP port manually and allow it through the firewall." };
  }
  return { status: "blocked", localAddress: address, mapping, message: "Automatic mapping failed. Verify the router, firewall, and ISP inbound-port policy, then retry or use manual forwarding." };
}

function header(value: string, name: string): string | undefined {
  const match = value.match(new RegExp(`^${name}:\\s*(.+)$`, "im"));
  return match?.[1]?.trim();
}

async function discoverGateway(): Promise<string | undefined> {
  const socket = dgram.createSocket("udp4");
  return await new Promise(resolve => {
    let settled = false;
    const finish = (value?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      resolve(value);
    };
    const timer = setTimeout(() => finish(), DISCOVERY_TIMEOUT_MS);
    socket.on("error", () => finish());
    socket.on("message", message => {
      const location = header(message.toString("utf8"), "LOCATION");
      if (location) finish(location);
    });
    socket.bind(0, () => {
      socket.send(Buffer.from(REQUEST, "ascii"), SSDP_PORT, SSDP_ADDRESS, error => {
        if (error) finish();
      });
    });
  });
}

function controlUrl(descriptionUrl: string, description: string): string | undefined {
  const service = description.match(/<service>[\s\S]*?<serviceType>urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:1<\/serviceType>[\s\S]*?<controlURL>([^<]+)<\/controlURL>[\s\S]*?<\/service>/i);
  if (!service?.[1]) return undefined;
  return new URL(service[1].trim(), descriptionUrl).toString();
}

function soapBody(port: number, internalHost: string): string {
  return `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>${port}</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>${port}</NewInternalPort><NewInternalClient>${internalHost}</NewInternalClient>
<NewEnabled>1</NewEnabled><NewPortMappingDescription>CoCodex Server</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping></s:Body></s:Envelope>`;
}

export function natPmpMappingRequest(port: number, lifetimeSeconds = 7 * 24 * 60 * 60): Buffer {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("Invalid NAT-PMP port");
  const request = Buffer.alloc(12);
  request.writeUInt8(0, 0);
  request.writeUInt8(2, 1); // TCP mapping opcode
  request.writeUInt16BE(0, 2); // any private port
  request.writeUInt16BE(port, 4);
  request.writeUInt32BE(Math.max(0, Math.min(0xffffffff, Math.trunc(lifetimeSeconds))), 8);
  return request;
}

export function parseNatPmpMappingResponse(response: Uint8Array): { publicPort: number; lifetimeSeconds: number } {
  if (response.byteLength < 16 || response[0] !== 0 || response[1] !== 130) throw new Error("Invalid NAT-PMP response");
  const view = new DataView(response.buffer, response.byteOffset, response.byteLength);
  const resultCode = view.getUint16(2);
  if (resultCode !== 0) throw new Error(`NAT-PMP gateway rejected mapping (code ${resultCode})`);
  return { publicPort: view.getUint16(10), lifetimeSeconds: view.getUint32(12) };
}

function natPmpGateways(internalHost: string): string[] {
  const configured = process.env.COCODEX_NATPMP_GATEWAY?.trim();
  if (configured) return [configured];
  const parts = internalHost.split(".");
  if (parts.length !== 4) return [];
  return [`${parts[0]}.${parts[1]}.${parts[2]}.1`, `${parts[0]}.${parts[1]}.${parts[2]}.254`];
}

async function tryNatPmpMapping(port: number, internalHost: string): Promise<PortMappingResult | undefined> {
  for (const gateway of natPmpGateways(internalHost)) {
    const socket = dgram.createSocket("udp4");
    const result = await new Promise<PortMappingResult | undefined>(resolve => {
      let settled = false;
      const finish = (value?: PortMappingResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.close();
        resolve(value);
      };
      const timer = setTimeout(() => finish(), NAT_PMP_TIMEOUT_MS);
      socket.on("error", () => finish());
      socket.on("message", message => {
        try {
          const mapping = parseNatPmpMappingResponse(message);
          finish({ status: "mapped", method: "nat-pmp", gateway, internalHost, message: `NAT-PMP mapped TCP ${mapping.publicPort} to ${internalHost}:${port}.` });
        } catch (error) {
          finish({ status: "failed", method: "nat-pmp", gateway, internalHost, message: error instanceof Error ? error.message : String(error) });
        }
      });
      socket.bind(0, () => socket.send(natPmpMappingRequest(port), NAT_PMP_PORT, gateway, error => { if (error) finish(); }));
    });
    if (result) return result;
  }
  return undefined;
}

export async function tryAutomaticPortMapping(port: number): Promise<PortMappingResult> {
  if (process.env.COCODEX_DISABLE_PORT_MAPPING === "1") {
    return { status: "unavailable", method: "none", message: "Automatic port mapping disabled by configuration." };
  }
  const internalHost = localIpv4();
  if (!internalHost) {
    return { status: "unavailable", method: "none", message: "No non-loopback IPv4 interface was found; manual forwarding is required." };
  }
  try {
    const descriptionUrl = await discoverGateway();
    if (!descriptionUrl) {
      const natPmp = await tryNatPmpMapping(port, internalHost);
      if (natPmp) return natPmp;
      return {
        status: "unavailable", method: "none", internalHost,
        message: "No UPnP gateway responded. Check CGNAT/router settings or forward the TCP port manually.",
      };
    }
    const descriptionResponse = await fetch(descriptionUrl, { signal: AbortSignal.timeout(1_500) });
    if (!descriptionResponse.ok) throw new Error(`gateway description returned HTTP ${descriptionResponse.status}`);
    const description = await descriptionResponse.text();
    const control = controlUrl(descriptionUrl, description);
    if (!control) throw new Error("gateway has no WAN IP/PPP control service");
    const response = await fetch(control, {
      method: "POST",
      signal: AbortSignal.timeout(1_500),
      headers: {
        "content-type": "text/xml; charset=\"utf-8\"",
        SOAPAction: '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
      },
      body: soapBody(port, internalHost),
    });
    if (!response.ok) throw new Error(`AddPortMapping returned HTTP ${response.status}`);
    return {
      status: "mapped", method: "upnp", gateway: new URL(descriptionUrl).hostname, internalHost,
      message: `UPnP mapped TCP ${port} to ${internalHost}:${port}.`,
    };
  } catch (error) {
    const natPmp = await tryNatPmpMapping(port, internalHost);
    if (natPmp) return natPmp;
    return {
      status: "failed", method: "upnp", internalHost,
      message: `Automatic UPnP mapping failed (${error instanceof Error ? error.message : String(error)}). Manual forwarding or CGNAT troubleshooting is required.`,
    };
  }
}

export { controlUrl, soapBody };

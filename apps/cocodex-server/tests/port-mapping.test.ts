import { afterEach, describe, expect, test } from "bun:test";
import { classifyDirectHosting, controlUrl, natPmpMappingRequest, parseNatPmpMappingResponse, parsePcpMappingResponse, pcpMappingRequest, soapBody, tryAutomaticPortMapping } from "../src/port-mapping";

const previous = process.env.COCODEX_DISABLE_PORT_MAPPING;
afterEach(() => {
  if (previous === undefined) delete process.env.COCODEX_DISABLE_PORT_MAPPING;
  else process.env.COCODEX_DISABLE_PORT_MAPPING = previous;
});

describe("CoCodex automatic port mapping", () => {
  test("resolves a gateway WAN control URL and binds the requested port", () => {
    const location = "http://192.168.1.1:49000/root.xml";
    const description = `<root><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/upnp/control</controlURL></service></serviceList></root>`;
    expect(controlUrl(location, description)).toBe("http://192.168.1.1:49000/upnp/control");
    expect(soapBody(19463, "192.168.1.42")).toContain("<NewExternalPort>19463</NewExternalPort>");
    expect(soapBody(19463, "192.168.1.42")).toContain("<NewInternalClient>192.168.1.42</NewInternalClient>");
  });

  test("reports an explicit opt-out instead of touching the network", async () => {
    process.env.COCODEX_DISABLE_PORT_MAPPING = "1";
    await expect(tryAutomaticPortMapping(19463)).resolves.toEqual({
      status: "unavailable", method: "none", message: "Automatic port mapping disabled by configuration.",
    });
  });

  test("distinguishes ready, manual-forwarding, and likely-CGNAT outcomes", () => {
    const mapped = { status: "mapped" as const, method: "upnp" as const, message: "mapped" };
    expect(classifyDirectHosting(mapped, "192.168.1.42").status).toBe("ready");
    const unavailable = { status: "unavailable" as const, method: "none" as const, message: "none" };
    expect(classifyDirectHosting(unavailable, "192.168.1.42").status).toBe("likely-cgnat");
    expect(classifyDirectHosting(unavailable, "8.8.8.8").status).toBe("manual-forwarding-required");
  });

  test("encodes and validates NAT-PMP TCP mapping packets", () => {
    const request = natPmpMappingRequest(19463, 3600);
    expect(request.length).toBe(12);
    expect(request[1]).toBe(2);
    expect(request.readUInt16BE(4)).toBe(19463);
    const response = Buffer.alloc(16);
    response.writeUInt8(0, 0); response.writeUInt8(130, 1); response.writeUInt16BE(0, 2);
    response.writeUInt32BE(123, 4); response.writeUInt16BE(19463, 10); response.writeUInt32BE(3600, 12);
    expect(parseNatPmpMappingResponse(response)).toEqual({ publicPort: 19463, lifetimeSeconds: 3600 });
    response.writeUInt16BE(2, 2);
    expect(() => parseNatPmpMappingResponse(response)).toThrow("rejected mapping");
  });

  test("encodes and validates PCP TCP MAP packets", () => {
    const nonce = Buffer.alloc(12, 7);
    const request = pcpMappingRequest(19463, "192.168.1.42", 3600, nonce);
    expect(request.length).toBe(60);
    expect(request[0]).toBe(2);
    expect(request[1]).toBe(1);
    expect(request.readUInt32BE(4)).toBe(3600);
    expect(request.slice(8, 24)).toEqual(Buffer.from("00000000000000000000ffffc0a8012a", "hex"));
    expect(request.slice(24, 36)).toEqual(nonce);
    expect(request[36]).toBe(6);
    expect(request.readUInt16BE(40)).toBe(19463);
    const response = Buffer.from(request);
    response[1] = 0x81;
    response.writeUInt16BE(0, 2);
    response.writeUInt32BE(19463, 42);
    response.writeUInt32BE(3600, 4);
    response.writeUInt16BE(19463, 42);
    response.writeUInt16BE(0, 40);
    response.write("00000000000000000000ffffcb007105", 44, "hex");
    expect(parsePcpMappingResponse(response, nonce)).toEqual({
      publicPort: 19463,
      lifetimeSeconds: 3600,
      externalAddress: "203.0.113.5",
    });
    expect(() => parsePcpMappingResponse(response, Buffer.alloc(12, 8))).toThrow("nonce");
  });
});

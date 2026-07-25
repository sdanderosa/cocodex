import { afterEach, describe, expect, test } from "bun:test";
import { controlUrl, soapBody, tryAutomaticPortMapping } from "../src/port-mapping";

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
});

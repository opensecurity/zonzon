import { describe, it, mock, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import * as net from "node:net";
import { SniProxyService } from "./sni-proxy.js";
import { ServerConfig } from "./types.js";
import { firewallEngine } from "./firewall.js";
import { audit } from "./audit.js";

function buildClientHello(sni: string): Buffer {
  const sniBuffer = Buffer.from(sni, "utf8");
  const extLength = sniBuffer.length + 9;
  const buf = Buffer.alloc(100 + extLength);

  buf[0] = 0x16; 
  buf[5] = 0x01; 

  buf[43] = 0x00;

  buf.writeUInt16BE(0x0002, 44);
  buf[46] = 0x00;
  buf[47] = 0x00;

  buf[48] = 0x01;
  buf[49] = 0x00;

  buf.writeUInt16BE(extLength, 50);

  buf.writeUInt16BE(0x0000, 52); 
  buf.writeUInt16BE(sniBuffer.length + 5, 54); 
  buf.writeUInt16BE(sniBuffer.length + 3, 56); 
  buf[58] = 0x00; 
  buf.writeUInt16BE(sniBuffer.length, 59); 
  sniBuffer.copy(buf, 61);

  return buf;
}

describe("SniProxyService - Protocol Extraction", () => {
  const dummyConfig: ServerConfig = {
    port: 53,
    hosts: {}
  };

  it("extracts SNI from valid TLS ClientHello structure", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = buildClientHello("secure.internal.loop");
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, "secure.internal.loop");
  });

  it("returns null for non-TLS packets", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, null);
  });

  it("returns null for TLS packets without ServerName extension", () => {
    const service = new SniProxyService(dummyConfig);
    const buf = Buffer.alloc(100);
    buf[0] = 0x16;
    buf[5] = 0x01;
    buf[43] = 0x00; 
    buf.writeUInt16BE(0x0002, 44); 
    buf[48] = 0x01; 
    buf.writeUInt16BE(0x0004, 50); 
    buf.writeUInt16BE(0x000A, 52); 
    buf.writeUInt16BE(0x0000, 54); 
    
    const extracted = (service as any).extractSNI(buf);
    assert.strictEqual(extracted, null);
  });

  it("gracefully handles truncated packets without throwing", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = buildClientHello("secure.internal.loop").subarray(0, 50);
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, null);
  });

  it("gracefully handles corrupt length markers without throwing", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = buildClientHello("secure.internal.loop");
    packet.writeUInt16BE(0xFFFF, 44); 
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, null);
  });
});

describe("SniProxyService - Upstream Port Resolution", { timeout: 5000 }, () => {
  let domainPolicy: "ALLOW" | "DENY" = "ALLOW";
  
  before(() => {
    mock.method(firewallEngine, "evaluateDomain", () => domainPolicy);
    mock.method(firewallEngine, "evaluateIp", () => "ALLOW");
    mock.method(firewallEngine, "isRestrictedOutbound", () => false);
  });

  after(() => {
    mock.restoreAll();
  });

  beforeEach(() => {
    domainPolicy = "ALLOW";
  });

  afterEach(() => {
    if ((audit.http as any).mock) (audit.http as any).mock.restore();
    if ((audit.error as any).mock) (audit.error as any).mock.restore();
  });

  it("defaults to routing traffic to port 443 when tls_proxy is undefined", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "standard.loop": {
          records: [{ type: "A", address: "127.0.0.1" }]
        }
      }
    };
    
    const service = new SniProxyService(config);
    const packet = buildClientHello("standard.loop");

    const httpMock = mock.method(audit, "http", () => {});
    mock.method(audit, "error", () => {}); // silence ECONNREFUSED

    const clientSocket = {
      remoteAddress: "127.0.0.1",
      setTimeout: () => {},
      on: (event: string, cb: any) => {
        if (event === "data") cb(packet);
      },
      destroy: () => {},
      pipe: () => {}
    } as unknown as net.Socket;

    await (service as any).handleConnection(clientSocket);
    
    // Wait for the real net.connect to fire, log to audit, and immediately fail/clean itself up
    await new Promise(resolve => setTimeout(resolve, 50));
    
    assert.ok(httpMock.mock.calls.some(call => 
      call.arguments[5] === "Tunneled to 127.0.0.1:443"
    ), "Did not route to default port 443");
  });

  it("routes traffic to the configured targetPort within tls_proxy", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "custom.loop": {
          records: [{ type: "A", address: "127.0.0.1" }],
          tls_proxy: {
            targetPort: 8443
          }
        }
      }
    };
    
    const service = new SniProxyService(config);
    const packet = buildClientHello("custom.loop");

    const httpMock = mock.method(audit, "http", () => {});
    mock.method(audit, "error", () => {}); // silence ECONNREFUSED

    const clientSocket = {
      remoteAddress: "127.0.0.1",
      setTimeout: () => {},
      on: (event: string, cb: any) => {
        if (event === "data") cb(packet);
      },
      destroy: () => {},
      pipe: () => {}
    } as unknown as net.Socket;

    await (service as any).handleConnection(clientSocket);
    
    await new Promise(resolve => setTimeout(resolve, 50));
    
    assert.ok(httpMock.mock.calls.some(call => 
      call.arguments[5] === "Tunneled to 127.0.0.1:8443"
    ), "Did not route to custom port 8443");
  });

  it("routes traffic to custom ports via wildcard matches", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "*.wild.loop": {
          records: [{ type: "A", address: "10.0.0.3" }],
          tls_proxy: {
            targetPort: 9443
          }
        }
      }
    };
    
    const service = new SniProxyService(config);
    const packet = buildClientHello("sub.wild.loop");

    const httpMock = mock.method(audit, "http", () => {});
    mock.method(audit, "error", () => {}); // silence ECONNREFUSED

    const clientSocket = {
      remoteAddress: "127.0.0.1",
      setTimeout: () => {},
      on: (event: string, cb: any) => {
        if (event === "data") cb(packet);
      },
      destroy: () => {},
      pipe: () => {}
    } as unknown as net.Socket;

    await (service as any).handleConnection(clientSocket);
    
    await new Promise(resolve => setTimeout(resolve, 50));
    
    assert.ok(httpMock.mock.calls.some(call => 
      call.arguments[5] === "Tunneled to 10.0.0.3:9443"
    ), "Did not route wildcard to custom port 9443");
  });

  it("aborts connection immediately if domain blocks occur prior to port resolution", async () => {
    const config: ServerConfig = {
      port: 53,
      firewall: {
        defaultPolicy: "deny",
        blocklist_domains: ["blocked.loop"]
      },
      hosts: {
        "blocked.loop": {
          records: [{ type: "A", address: "10.0.0.4" }],
          tls_proxy: {
            targetPort: 1234
          }
        }
      }
    };
    
    domainPolicy = "DENY";
    
    const service = new SniProxyService(config);
    const packet = buildClientHello("blocked.loop");

    const httpMock = mock.method(audit, "http", () => {});
    mock.method(audit, "error", () => {});

    let destroyed = false;
    const clientSocket = {
      remoteAddress: "127.0.0.1",
      setTimeout: () => {},
      on: (event: string, cb: any) => {
        if (event === "data") cb(packet);
      },
      destroy: () => { destroyed = true; },
      pipe: () => {}
    } as unknown as net.Socket;

    await (service as any).handleConnection(clientSocket);
    
    await new Promise(resolve => setTimeout(resolve, 50));
    
    assert.strictEqual(httpMock.mock.calls.some(call => 
      call.arguments[5] && String(call.arguments[5]).startsWith("Tunneled to")
    ), false, "Proxy attempted to tunnel a blocked domain");
    assert.strictEqual(destroyed, true, "Socket was not destroyed after block");
  });
});
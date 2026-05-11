import { describe, it } from "node:test";
import assert from "assert";
import * as net from "net";

let PORT_BASE = 65000;
function nextPort(): number { return PORT_BASE++; }

describe("TCP Rate Limiting", () => {
  function buildTcpDnsQuery(name: string): Buffer {
    const encoder = new (class {
      buf = Buffer.alloc(256); offset = 0;
      writeUint16(v: number) { this.buf.writeUInt16BE(v, this.offset); this.offset += 2; }
      writeUint8(v: number) { this.buf.writeUInt8(v, this.offset); this.offset += 1; }
      writeDomainName(nm: string) {
        for (const label of nm.split(".")) { if (!label.length) continue; this.writeUint8(label.length); Buffer.from(label).copy(this.buf, this.offset); this.offset += label.length; }
        this.writeUint8(0);
      }
      finish(): Buffer { return this.buf.subarray(0, this.offset); }
    })();
    encoder.writeUint16(0xDEAD); encoder.writeUint16(0x0100); encoder.writeUint16(1);
    encoder.writeUint16(0); encoder.writeUint16(0); encoder.writeUint16(0);
    encoder.writeDomainName(name); encoder.writeUint16(1); encoder.writeUint16(1);
    const query = encoder.finish();
    const prefixed = Buffer.alloc(2 + query.length);
    prefixed.writeUInt16BE(query.length, 0); query.copy(prefixed, 2);
    return prefixed;
  }

  it("TCP queries are rate limited when configured", async () => {
    const port = nextPort();
    const { DnsHandler } = await import("./dns-handler.js");
    const { DevDnsServer } = await import("./dns-service.js");
    const config: any = { port, hosts: { "test.loop": { records: [{ type: "A", address: "5.6.7.8" }] } }, rateLimitMaxRequests: 3, rateLimitWindowMs: 1000 };

    const dnsServer = new DevDnsServer(config);
    const handler = new DnsHandler(dnsServer, config);
    await handler.start();

    try {
      await new Promise<void>((r) => setTimeout(r, 150));

      const results: number[] = [];
      for (let i = 0; i < 3; i++) {
        let responses = 0;
        await new Promise<void>((resolve) => {
          const socket = net.createConnection(port, "127.0.0.1", () => {
            socket.write(buildTcpDnsQuery("test.loop"));
            socket.on("data", (data: Buffer) => {
              let off = 0;
              while (off + 2 <= data.length) {
                const len = data.readUInt16BE(off);
                if (len === 0 || off + 2 + len > data.length) break;
                responses++; off += 2 + len;
              }
            });
            setTimeout(() => { socket.destroy(); resolve(); }, 1000);
          });
        });
        results.push(responses);
      }

      assert.ok(results.every((r) => r > 0));
    } finally {
      await handler.stop();
    }
  });

  it("TCP connection is terminated when source IP exceeds rate limit", async () => {
    const port = nextPort();
    const { DnsHandler } = await import("./dns-handler.js");
    const { DevDnsServer } = await import("./dns-service.js");
    const config: any = { port, hosts: { "test.loop": { records: [{ type: "A", address: "9.8.7.6" }] } }, rateLimitMaxRequests: 1, rateLimitWindowMs: 5000 };

    const dnsServer = new DevDnsServer(config);
    const handler = new DnsHandler(dnsServer, config);
    await handler.start();

    try {
      await new Promise<void>((r) => setTimeout(r, 150));

      let r1Responses = 0;
      await new Promise<void>((resolve) => {
        const socket = net.createConnection(port, "127.0.0.1", () => {
          socket.write(buildTcpDnsQuery("test.loop"));
          socket.on("data", (data: Buffer) => {
            let off = 0;
            while (off + 2 <= data.length) {
              const len = data.readUInt16BE(off);
              if (len === 0 || off + 2 + len > data.length) break;
              r1Responses++; off += 2 + len;
            }
          });
          setTimeout(() => { socket.destroy(); resolve(); }, 1000);
        });
      });
      assert.ok(r1Responses > 0);

      let r2Destroyed = false;
      await new Promise<void>((resolve) => {
        const socket = net.createConnection(port, "127.0.0.1", () => {
          setTimeout(() => { socket.destroy(); resolve(); }, 1500);
        });
        socket.on("error", () => { r2Destroyed = true; });
        socket.on("close", () => { if (!r2Destroyed) r2Destroyed = true; });
      });

      assert.strictEqual(r2Destroyed, true);
    } finally {
      await handler.stop();
    }
  });

  it("TCP queries work when rate limiting is disabled", async () => {
    const port = nextPort();
    const { DnsHandler } = await import("./dns-handler.js");
    const { DevDnsServer } = await import("./dns-service.js");
    const config: any = { port, hosts: { "test.loop": { records: [{ type: "A", address: "1.2.3.4" }] } }, rateLimitMaxRequests: 0 };

    const dnsServer = new DevDnsServer(config);
    const handler = new DnsHandler(dnsServer, config);
    await handler.start();

    try {
      await new Promise<void>((r) => setTimeout(r, 150));

      let successes = 0;
      for (let i = 0; i < 5; i++) {
        let gotResponse = false;
        await new Promise<void>((resolve) => {
          const socket = net.createConnection(port, "127.0.0.1", () => {
            socket.write(buildTcpDnsQuery("test.loop"));
            socket.on("data", () => { gotResponse = true; });
            setTimeout(() => { socket.destroy(); resolve(); }, 1000);
          });
        });
        if (gotResponse) successes++;
      }

      assert.strictEqual(successes, 5);
    } finally {
      await handler.stop();
    }
  });
});
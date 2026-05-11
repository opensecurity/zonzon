import { describe, it } from "node:test";
import assert from "node:assert";
import * as net from "node:net";

let PORT_BASE = 61500;

function nextPort(): number {
  return PORT_BASE++;
}

describe("DnsHandler - TCP Connection Limiting", () => {
  it("rejects new connections after max is reached", async () => {
    const port = nextPort();
    const { DnsHandler } = await import("./dns-handler.js");
    const { DevDnsServer } = await import("./dns-service.js");
    const config: any = { port, hosts: {}, maxTcpConnections: 2, tcpIdleTimeoutMs: 30000, rateLimitMaxRequests: 0 };

    const dnsServer = new DevDnsServer(config);
    const handler = new DnsHandler(dnsServer, config);
    await handler.start();

    try {
      await new Promise<void>((r) => setTimeout(r, 150));

      const sockets: net.Socket[] = [];
      for (let i = 0; i < 2; i++) {
        const s = net.createConnection(port, "127.0.0.1", () => {});
        sockets.push(s);
      }

      await new Promise<void>((r) => setTimeout(r, 150));

      const thirdPromise = new Promise<boolean>((resolve) => {
        const socket = net.createConnection(port, "127.0.0.1");
        socket.on("connect", () => {
          setTimeout(() => resolve(socket.destroyed), 500);
        });
        socket.on("error", () => resolve(true));
      });

      const destroyed = await thirdPromise;
      assert.strictEqual(destroyed, true);

      for (const s of sockets) s.destroy();
    } finally {
      await handler.stop();
    }
  });

  it("admits connections when one closes (below max)", async () => {
    const port = nextPort();
    const { DnsHandler } = await import("./dns-handler.js");
    const { DevDnsServer } = await import("./dns-service.js");
    const config: any = { port, hosts: {}, maxTcpConnections: 2, tcpIdleTimeoutMs: 1000, rateLimitMaxRequests: 0 };

    const dnsServer = new DevDnsServer(config);
    const handler = new DnsHandler(dnsServer, config);
    await handler.start();

    try {
      await new Promise<void>((r) => setTimeout(r, 150));

      const socket1 = net.createConnection(port, "127.0.0.1");
      const socket2 = net.createConnection(port, "127.0.0.1");

      await new Promise<void>((r) => setTimeout(r, 150));

      socket1.end();
      await new Promise<void>((r) => { socket1.on("close", r); });

      await new Promise<void>((r) => setTimeout(r, 200));

      const thirdPromise = new Promise<boolean>((resolve) => {
        const socket3 = net.createConnection(port, "127.0.0.1", () => resolve(true));
        socket3.on("error", () => resolve(false));
        socket3.setTimeout(500);
        socket3.on("timeout", () => { socket3.destroy(); resolve(false); });
      });

      const admitted = await thirdPromise;
      assert.strictEqual(admitted, true);
    } finally {
      await handler.stop();
    }
  });

  it("closes idle connections after timeout", async () => {
    const port = nextPort();
    const { DnsHandler } = await import("./dns-handler.js");
    const { DevDnsServer } = await import("./dns-service.js");
    const config: any = { port, hosts: {}, maxTcpConnections: 5, tcpIdleTimeoutMs: 300, rateLimitMaxRequests: 0 };

    const dnsServer = new DevDnsServer(config);
    const handler = new DnsHandler(dnsServer, config);
    await handler.start();

    try {
      await new Promise<void>((r) => setTimeout(r, 150));

      const socket = net.createConnection(port, "127.0.0.1");
      await new Promise<void>((r) => socket.on("connect", () => r()));

      await new Promise<void>((r) => setTimeout(r, 800));

      assert.strictEqual(socket.destroyed, true);
    } finally {
      await handler.stop();
    }
  });
});
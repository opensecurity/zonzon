import { describe, it } from "node:test";
import assert from "node:assert";
import * as http from "node:http";
import { HttpHandler } from "./http-handler.js";
import { DevDnsServer } from "./dns-service.js";

describe("HttpHandler - Internal Mapped Routing Verification", () => {
  it("routes HTTP traffic securely to an offline host mapped entirely via config.hosts", async () => {
    let reachedUpstream = false;
    let receivedHostHeader = "";

    const upstreamServer = http.createServer((req, res) => {
      reachedUpstream = true;
      receivedHostHeader = req.headers.host || "";
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("internal-success-payload");
    });

    await new Promise<void>((resolve) => upstreamServer.listen(0, "127.0.0.1", resolve));
    const upstreamPort = (upstreamServer.address() as any).port;

    const config: any = {
      port: 53,
      httpPort: 0,
      firewall: {
        defaultPolicy: "allow",
        allowlist_ips: ["127.0.0.1"]
      },
      hosts: {
        "airgapped.local": {
          records: [{ type: "A", address: "127.0.0.1" }]
        }
      }
    };

    const dnsServer = new DevDnsServer(config);
    const handler = new HttpHandler(dnsServer, config, 0);
    await handler.start();
    const handlerPort = handler.getPort();

    try {
      const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = http.request({
          hostname: "127.0.0.1",
          port: handlerPort,
          path: "/secure-data",
          method: "GET",
          headers: {
            "Host": `airgapped.local:${upstreamPort}`,
            "Connection": "close"
          }
        }, (res) => {
          let body = "";
          res.on("data", chunk => body += chunk);
          res.on("end", () => resolve({ status: res.statusCode || 500, body }));
        });
        req.on("error", reject);
        req.end();
      });

      assert.strictEqual(result.status, 200, "Handler failed to route to internal host via 200 OK");
      assert.strictEqual(result.body, "internal-success-payload", "Upstream payload mutation or loss");
      assert.strictEqual(reachedUpstream, true, "Traffic escaped isolation boundary or failed to reach target");
      assert.strictEqual(receivedHostHeader, `airgapped.local:${upstreamPort}`, "Host header was corrupted or lost during internal forward");
    } finally {
      await handler.stop();
      if ('closeAllConnections' in upstreamServer) {
        (upstreamServer as any).closeAllConnections();
      }
      await new Promise<void>((resolve) => upstreamServer.close(() => resolve()));
    }
  });

  it("enforces L7 firewall boundaries against internal mapped hosts", async () => {
    const upstreamServer = http.createServer((req, res) => {
      res.writeHead(200);
      res.end("should-not-be-reached");
    });

    await new Promise<void>((resolve) => upstreamServer.listen(0, "127.0.0.1", resolve));
    const upstreamPort = (upstreamServer.address() as any).port;

    const config: any = {
      port: 53,
      httpPort: 0,
      firewall: {
        defaultPolicy: "allow",
        blocklist_domains: ["forbidden.local"]
      },
      hosts: {
        "forbidden.local": {
          records: [{ type: "A", address: "127.0.0.1" }]
        }
      }
    };

    const dnsServer = new DevDnsServer(config);
    const handler = new HttpHandler(dnsServer, config, 0);
    await handler.start();
    const handlerPort = handler.getPort();

    try {
      const result = await new Promise<{ status: number }>((resolve, reject) => {
        const req = http.request({
          hostname: "127.0.0.1",
          port: handlerPort,
          path: "/",
          method: "GET",
          headers: {
            "Host": `forbidden.local:${upstreamPort}`,
            "Connection": "close"
          }
        }, (res) => {
          res.resume(); 
          res.on("end", () => resolve({ status: res.statusCode || 500 }));
        });
        req.on("error", reject);
        req.end();
      });

      assert.strictEqual(result.status, 403, "Firewall bypassed: Target was reachable despite domain blocklist");
    } finally {
      await handler.stop();
      if ('closeAllConnections' in upstreamServer) {
        (upstreamServer as any).closeAllConnections();
      }
      await new Promise<void>((resolve) => upstreamServer.close(() => resolve()));
    }
  });

  it("detects and terminates L7 SSRF routing loops deterministically returning 508", async () => {
    const config: any = {
      port: 53,
      httpPort: 0,
      firewall: {
        defaultPolicy: "allow",
        allowlist_ips: ["127.0.0.1"]
      },
      hosts: {
        "loop.local": {
          records: [{ type: "A", address: "127.0.0.1" }],
          http_proxy: {
            enabled: true,
            upstream: "http://127.0.0.1",
            headers: {}
          }
        }
      }
    };

    const dnsServer = new DevDnsServer(config);
    const handler = new HttpHandler(dnsServer, config, 0);
    await handler.start();
    const handlerPort = handler.getPort();

    config.hosts["loop.local"].http_proxy.upstream = `http://127.0.0.1:${handlerPort}`;

    try {
      const result = await new Promise<{ status: number }>((resolve, reject) => {
        const req = http.request({
          hostname: "127.0.0.1",
          port: handlerPort,
          path: "/",
          method: "GET",
          headers: {
            "Host": `loop.local`,
            "Connection": "close"
          }
        }, (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode || 500 }));
        });
        req.on("error", reject);
        req.end();
      });

      assert.strictEqual(result.status, 508, "Firewall bypassed: Routing loop was not terminated with 508");
    } finally {
      await handler.stop();
    }
  });
});
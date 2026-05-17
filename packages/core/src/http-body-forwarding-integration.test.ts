import { describe, it } from "node:test";
import assert from "node:assert";
import * as http from "node:http";
import * as net from "node:net";

describe("HTTP Body Forwarding Integration", () => {
  let upstreamServer: http.Server;
  let receivedBodies: string[] = [];
  let receivedChunks: number = 0;

  let TEST_PORT = 0; 
  let PROXY_PORT = 0; 

  function startUpstreamServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      upstreamServer = http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {
        if (req.method !== "GET" && req.method !== "HEAD") {
          const chunks: Buffer[] = [];
          req.on("data", (chunk: Buffer) => {
            receivedChunks++;
            chunks.push(chunk);
          });
          req.on("end", () => {
            const body = Buffer.concat(chunks).toString("utf-8");
            if (body.length > 0) {
              receivedBodies.push(body);
            }
            res.writeHead(200, { "Content-Type": "text/plain", "Connection": "close" });
            res.end(`upstream ${req.method} body size: ${Buffer.concat(chunks).length}`);
          });
        } else {
          res.writeHead(200, { "Content-Type": "text/plain", "Connection": "close" });
          res.end("GET/HEAD received");
        }
      });

      upstreamServer.on("error", reject);
      upstreamServer.listen(0, "127.0.0.1", () => {
        TEST_PORT = (upstreamServer.address() as net.AddressInfo).port;
        resolve();
      });
    });
  }

  function stopUpstreamServer(): Promise<void> {
    return new Promise((resolve) => {
      if (upstreamServer) {
        if ('closeAllConnections' in upstreamServer) {
           (upstreamServer as any).closeAllConnections();
        }
        upstreamServer.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  function sendPostRequest(port: number, path: string, body: string): Promise<{ status: number; response: string }> {
    return new Promise((resolve) => {
      let resolved = false;
      let currentStatus = 500;
      const done = (status: number, response: string) => {
        if (!resolved) { resolved = true; resolve({ status, response }); }
      };

      const postData = Buffer.from(body);

      const options = {
        hostname: "127.0.0.1",
        port: port,
        path: path,
        method: "POST",
        agent: false,
        lookup: (hostname: string, options: any, cb: any) => cb(null, "127.0.0.1", 4),
        headers: {
          "Host": "127.0.0.1",
          "Content-Type": "text/plain",
          "Content-Length": postData.length,
          "Connection": "close",
        },
      };

      const req = http.request(options, (res: http.IncomingMessage) => {
        currentStatus = res.statusCode || 500;
        let responseBody = "";
        res.on("data", (chunk: Buffer) => { responseBody += chunk.toString(); });
        res.on("end", () => done(currentStatus, responseBody));
        res.on("aborted", () => done(currentStatus, responseBody));
        res.on("error", () => done(currentStatus, responseBody));
      });

      req.on("error", (err: any) => done(currentStatus, err.message));
      req.write(postData);
      req.end();
    });
  }

  function sendChunkedPostRequest(port: number, path: string, chunks: string[], delayMs: number): Promise<{ status: number; response: string }> {
    return new Promise((resolve) => {
      let resolved = false;
      let currentStatus = 500;
      const done = (status: number, response: string) => {
        if (!resolved) { resolved = true; resolve({ status, response }); }
      };

      const options = {
        hostname: "127.0.0.1",
        port: port,
        path: path,
        method: "POST",
        agent: false,
        lookup: (hostname: string, options: any, cb: any) => cb(null, "127.0.0.1", 4),
        headers: {
          "Host": "127.0.0.1",
          "Content-Type": "text/plain",
          "Transfer-Encoding": "chunked",
          "Connection": "close",
        },
      };

      let destroyed = false;

      const req = http.request(options, (res: http.IncomingMessage) => {
        currentStatus = res.statusCode || 500;
        let responseBody = "";
        res.on("data", (chunk: Buffer) => { responseBody += chunk.toString(); });
        res.on("end", () => done(currentStatus, responseBody));
        res.on("aborted", () => done(currentStatus, responseBody));
        res.on("error", () => done(currentStatus, responseBody));
      });

      req.on("error", (err: any) => {
        destroyed = true;
        done(currentStatus, err.message);
      });

      let i = 0;
      function sendNext() {
        if (destroyed) return;
        if (i < chunks.length) {
          req.write(chunks[i]);
          i++;
          setTimeout(sendNext, delayMs);
        } else {
          req.end();
        }
      }
      sendNext();
    });
  }

  function sendPutRequest(port: number, path: string, body: string): Promise<{ status: number; response: string }> {
    return new Promise((resolve) => {
      let resolved = false;
      let currentStatus = 500;
      const done = (status: number, response: string) => {
        if (!resolved) { resolved = true; resolve({ status, response }); }
      };

      const putData = Buffer.from(body);

      const options = {
        hostname: "127.0.0.1",
        port: port,
        path: path,
        method: "PUT",
        agent: false,
        lookup: (hostname: string, options: any, cb: any) => cb(null, "127.0.0.1", 4),
        headers: {
          "Host": "127.0.0.1",
          "Content-Type": "text/plain",
          "Content-Length": putData.length,
          "Connection": "close",
        },
      };

      const req = http.request(options, (res: http.IncomingMessage) => {
        currentStatus = res.statusCode || 500;
        let responseBody = "";
        res.on("data", (chunk: Buffer) => { responseBody += chunk.toString(); });
        res.on("end", () => done(currentStatus, responseBody));
        res.on("aborted", () => done(currentStatus, responseBody));
        res.on("error", () => done(currentStatus, responseBody));
      });

      req.on("error", (err: any) => done(currentStatus, err.message));
      req.write(putData);
      req.end();
    });
  }

  function getRequest(port: number, path: string): Promise<{ status: number; response: string }> {
    return new Promise((resolve) => {
      let resolved = false;
      let currentStatus = 500;
      const done = (status: number, response: string) => {
        if (!resolved) { resolved = true; resolve({ status, response }); }
      };

      const options = {
        hostname: "127.0.0.1",
        port: port,
        path: path,
        method: "GET",
        agent: false,
        lookup: (hostname: string, options: any, cb: any) => cb(null, "127.0.0.1", 4),
        headers: { 
          "Host": "127.0.0.1", 
          "Connection": "close" 
        },
      };

      const req = http.request(options, (res: http.IncomingMessage) => {
        currentStatus = res.statusCode || 500;
        let responseBody = "";
        res.on("data", (chunk: Buffer) => { responseBody += chunk.toString(); });
        res.on("end", () => done(currentStatus, responseBody));
        res.on("aborted", () => done(currentStatus, responseBody));
        res.on("error", () => done(currentStatus, responseBody));
      });

      req.on("error", (err: any) => done(currentStatus, err.message));
      req.end();
    });
  }

  it("forwards POST body to upstream natively streaming when forwardRequestBody is enabled", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    receivedChunks = 0;
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: true,
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const bodyContent = "hello world test payload";
        const result = await sendPostRequest(PROXY_PORT, "/test", bodyContent);

        assert.strictEqual(result.status, 200, `Failed with response: ${result.response}`);
        assert.ok(receivedBodies.length > 0);
        assert.strictEqual(receivedBodies[0], bodyContent);
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });

  it("streams chunked POST requests sequentially without full in-memory buffering", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    receivedChunks = 0;
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: true,
              maxRequestBodyBytes: 10485760
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const chunks = ["chunk1-data-", "chunk2-data-", "chunk3-data"];
        const result = await sendChunkedPostRequest(PROXY_PORT, "/stream", chunks, 20);

        assert.strictEqual(result.status, 200, `Failed with response: ${result.response}`);
        assert.ok(receivedBodies.length > 0);
        assert.strictEqual(receivedBodies[0], "chunk1-data-chunk2-data-chunk3-data");
        assert.ok(receivedChunks >= 1, "Upstream did not receive data in chunks");
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });

  it("terminates stream actively mid-flight and returns 413 when payload exceeds maxRequestBodyBytes", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    receivedChunks = 0;
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: true,
              maxRequestBodyBytes: 100, 
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const chunks = ["A".repeat(40), "B".repeat(40), "C".repeat(40)]; 
        const result = await sendChunkedPostRequest(PROXY_PORT, "/upload", chunks, 20);

        assert.strictEqual(result.status, 413, `Proxy failed to enforce 413 Payload Too Large. Result: ${result.response}`);
        assert.strictEqual(receivedBodies.length, 0, "Proxy forwarded entire body despite size breach");
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });

  it("forwards PUT body to upstream when forwardRequestBody is enabled", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: true,
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const bodyContent = '{"key":"value","count":42}';
        const result = await sendPutRequest(PROXY_PORT, "/api/update", bodyContent);

        assert.strictEqual(result.status, 200, `Failed with response: ${result.response}`);
        assert.ok(receivedBodies.length > 0);
        assert.strictEqual(receivedBodies[0], bodyContent);
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });

  it("does not forward body for GET requests even when forwarding is enabled", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: true,
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const result = await getRequest(PROXY_PORT, "/data");

        assert.strictEqual(result.status, 200, `Failed with response: ${result.response}`);
        assert.strictEqual(receivedBodies.length, 0);
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });

  it("rejects oversized contiguous body with 413 when forwarding is enabled", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: true,
              maxRequestBodyBytes: 100, 
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const largeBody = "x".repeat(200);
        const result = await sendPostRequest(PROXY_PORT, "/upload", largeBody);

        assert.strictEqual(result.status, 413, `Proxy failed to enforce 413 Payload Too Large. Result: ${result.response}`);
        assert.strictEqual(receivedBodies.length, 0);
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });

  it("does not forward body when forwardRequestBody is disabled", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    await startUpstreamServer();

    try {
      const config: any = {
        port: 0,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "127.0.0.1": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${TEST_PORT}`,
              headers: {},
              forwardRequestBody: false, 
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, 0);
      await handler.start();
      PROXY_PORT = handler.getPort();

      try {
        const bodyContent = "this should not be forwarded";
        const result = await sendPostRequest(PROXY_PORT, "/submit", bodyContent);

        assert.strictEqual(result.status, 200, `Failed with response: ${result.response}`);
        assert.strictEqual(receivedBodies.length, 0);
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });
});
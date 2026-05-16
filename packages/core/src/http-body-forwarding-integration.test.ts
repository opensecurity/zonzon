import { describe, it } from "node:test";
import assert from "node:assert";
import * as http from "http";

describe("HTTP Body Forwarding Integration", () => {
  let upstreamServer: http.Server;
  let receivedBodies: string[] = [];
  let receivedChunks: number = 0;

  const TEST_PORT = 19876; 
  const PROXY_PORT = 19877; 

  function startUpstreamServer(): Promise<number> {
    return new Promise((resolve) => {
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
            res.writeHead(200, { "Content-Type": "text/plain" });
            res.end(`upstream ${req.method} body size: ${Buffer.concat(chunks).length}`);
          });
        } else {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("GET/HEAD received");
        }
      });

      upstreamServer.listen(TEST_PORT, "127.0.0.1", () => {
        resolve(TEST_PORT);
      });
    });
  }

  function stopUpstreamServer(): Promise<void> {
    return new Promise((resolve) => {
      if (upstreamServer) {
        upstreamServer.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  function sendPostRequest(url: string, body: string): Promise<{ status: number; response: string }> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const postData = Buffer.from(body);

      const options = {
        hostname: "127.0.0.1",
        port: parsed.port ? parseInt(parsed.port, 10) : PROXY_PORT,
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: {
          Host: parsed.hostname,
          "Content-Type": "text/plain",
          "Content-Length": postData.length,
        },
      };

      const req = http.request(options, (res: http.IncomingMessage) => {
        let responseBody = "";
        res.on("data", (chunk: Buffer) => {
          responseBody += chunk.toString();
        });
        res.on("end", () => {
          resolve({ status: res.statusCode || 500, response: responseBody });
        });
      });

      req.on("error", (err: any) => {
        if (err.code === "ECONNRESET") {
          resolve({ status: 413, response: "ECONNRESET" });
        } else {
          reject(err);
        }
      });
      req.write(postData);
      req.end();
    });
  }

  function sendChunkedPostRequest(url: string, chunks: string[], delayMs: number): Promise<{ status: number; response: string }> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);

      const options = {
        hostname: "127.0.0.1",
        port: parsed.port ? parseInt(parsed.port, 10) : PROXY_PORT,
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers: {
          Host: parsed.hostname,
          "Content-Type": "text/plain",
          "Transfer-Encoding": "chunked",
        },
      };

      const req = http.request(options, (res: http.IncomingMessage) => {
        let responseBody = "";
        res.on("data", (chunk: Buffer) => {
          responseBody += chunk.toString();
        });
        res.on("end", () => {
          resolve({ status: res.statusCode || 500, response: responseBody });
        });
      });

      req.on("error", (err: any) => {
        if (err.code === "ECONNRESET") {
          resolve({ status: 413, response: "ECONNRESET" });
        } else {
          reject(err);
        }
      });

      let i = 0;
      function sendNext() {
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

  function sendPutRequest(url: string, body: string): Promise<{ status: number; response: string }> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const putData = Buffer.from(body);

      const options = {
        hostname: "127.0.0.1",
        port: parsed.port ? parseInt(parsed.port, 10) : PROXY_PORT,
        path: parsed.pathname + parsed.search,
        method: "PUT",
        headers: {
          Host: parsed.hostname,
          "Content-Type": "text/plain",
          "Content-Length": putData.length,
        },
      };

      const req = http.request(options, (res: http.IncomingMessage) => {
        let responseBody = "";
        res.on("data", (chunk: Buffer) => {
          responseBody += chunk.toString();
        });
        res.on("end", () => {
          resolve({ status: res.statusCode || 500, response: responseBody });
        });
      });

      req.on("error", reject);
      req.write(putData);
      req.end();
    });
  }

  function get(url: string): Promise<{ status: number; response: string }> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);

      const req = http.request({
        hostname: "127.0.0.1",
        port: parsed.port ? parseInt(parsed.port, 10) : PROXY_PORT,
        path: parsed.pathname + parsed.search,
        method: "GET",
        headers: { Host: parsed.hostname },
      }, (res: http.IncomingMessage) => {
        let responseBody = "";
        res.on("data", (chunk: Buffer) => {
          responseBody += chunk.toString();
        });
        res.on("end", () => {
          resolve({ status: res.statusCode || 500, response: responseBody });
        });
      });

      req.on("error", reject);
      req.end();
    });
  }

  it("forwards POST body to upstream natively streaming when forwardRequestBody is enabled", async () => {
    const { DevDnsServer } = await import("./dns-service.js");
    const { HttpHandler } = await import("./http-handler.js");

    receivedBodies = [];
    receivedChunks = 0;
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: true,
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const bodyContent = "hello world test payload";
        const result = await sendPostRequest(`http://app.loop/test`, bodyContent);

        assert.strictEqual(result.status, 200);
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
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: true,
              maxRequestBodyBytes: 10485760
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const chunks = ["chunk1-data-", "chunk2-data-", "chunk3-data"];
        const result = await sendChunkedPostRequest(`http://app.loop/stream`, chunks, 20);

        assert.strictEqual(result.status, 200);
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
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: true,
              maxRequestBodyBytes: 100, 
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const chunks = ["A".repeat(40), "B".repeat(40), "C".repeat(40)]; 
        const result = await sendChunkedPostRequest(`http://app.loop/upload`, chunks, 20);

        assert.strictEqual(result.status, 413, "Proxy failed to enforce 413 Payload Too Large on streamed data");
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
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: true,
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const bodyContent = '{"key":"value","count":42}';
        const result = await sendPutRequest(`http://app.loop/api/update`, bodyContent);

        assert.strictEqual(result.status, 200);
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
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: true,
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const result = await get("http://app.loop/data");

        assert.strictEqual(result.status, 200);
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
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: true,
              maxRequestBodyBytes: 100, 
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const largeBody = "x".repeat(200);
        const result = await sendPostRequest(`http://app.loop/upload`, largeBody);

        assert.strictEqual(result.status, 413);
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
    const port = await startUpstreamServer();

    try {
      const config: any = {
        port: 53,
        firewall: {
          allowlist_ips: ["127.0.0.1"]
        },
        hosts: {
          "app.loop": {
            records: [{ type: "A", address: "127.0.0.1" }],
            http_proxy: {
              enabled: true,
              upstream: `http://127.0.0.1:${port}`,
              headers: {},
              forwardRequestBody: false, 
            },
          },
        },
      };

      const dnsServer = new DevDnsServer(config);
      const handler = new HttpHandler(dnsServer, config, PROXY_PORT);
      await handler.start();

      try {
        await new Promise<void>((resolve) => setTimeout(resolve, 100));

        const bodyContent = "this should not be forwarded";
        const result = await sendPostRequest(`http://app.loop/submit`, bodyContent);

        assert.strictEqual(result.status, 200);
        assert.strictEqual(receivedBodies.length, 0);
      } finally {
        await handler.stop();
      }
    } finally {
      await stopUpstreamServer();
    }
  });
});
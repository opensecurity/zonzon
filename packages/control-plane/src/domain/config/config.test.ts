import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import * as http from "http";
import * as net from "net";
import { createHash } from "crypto";
import { ConfigService } from "./config.service.js";
import { ConfigHandler } from "./config.handler.js";
import { ServerConfig } from "@opensecurity/zonzon-core";

const MOCK_SALT = "test-salt-1234567890";
const MOCK_API_KEY = "test-api-key-very-long-and-secure-32-chars";
const MOCK_DEVICE_ID = "test-device-id-1234";

function generateValidPoW(salt: string): string {
  let nonce = 0;
  const timeWindow = Math.floor(Date.now() / 300000);
  const challenge = `${salt}:${timeWindow}`;
  while (true) {
    const hash = createHash("sha256").update(challenge + nonce.toString()).digest("hex");
    if (hash.startsWith("0000")) {
      return nonce.toString();
    }
    nonce++;
  }
}

describe("Control Plane API Tests", () => {
  let server: http.Server;
  let port: number;
  let validNonce: string;

  const initialConfig: ServerConfig = {
    port: 53,
    hosts: {
      "initial.loop": { records: [{ type: "A", address: "1.1.1.1" }] }
    }
  };

  before(async () => {
    validNonce = generateValidPoW(MOCK_SALT);
    const service = new ConfigService(initialConfig);
    const handler = new ConfigHandler(service, MOCK_API_KEY, MOCK_SALT);

    server = http.createServer((req, res) => handler.handleRequest(req, res));
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        port = (server.address() as net.AddressInfo).port;
        resolve();
      });
    });
  });

  after(() => {
    server.close();
  });

  function makeRequest(method: string, path: string, headers: Record<string, string>, body?: string): Promise<{ status: number, data: any }> {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: "127.0.0.1",
        port: port,
        path: path,
        method: method,
        headers: headers
      };

      const req = http.request(options, (res) => {
        let responseBody = "";
        res.on("data", chunk => responseBody += chunk);
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode || 500, data: JSON.parse(responseBody) });
          } catch {
            resolve({ status: res.statusCode || 500, data: responseBody });
          }
        });
      });

      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
  }

  it("rejects GET requests without authentication", async () => {
    const res = await makeRequest("GET", "/api/v1/config", {});
    assert.strictEqual(res.status, 401);
  });

  it("accepts GET requests with valid API key and device ID", async () => {
    const res = await makeRequest("GET", "/api/v1/config", {
      "x-api-key": MOCK_API_KEY,
      "x-device-id": MOCK_DEVICE_ID
    });
    assert.strictEqual(res.status, 200);
    assert.ok("hosts" in res.data);
    assert.ok("initial.loop" in res.data.hosts);
  });

  it("rejects PUT requests without Proof of Work challenge", async () => {
    const newConfig = { ...initialConfig, port: 5353 };
    const res = await makeRequest("PUT", "/api/v1/config", {
      "x-api-key": MOCK_API_KEY,
      "x-device-id": MOCK_DEVICE_ID,
      "Content-Type": "application/json"
    }, JSON.stringify(newConfig));
    assert.strictEqual(res.status, 401);
    assert.ok(res.data.error.includes("x-pow-nonce"));
  });

  it("rejects PUT requests with invalid Proof of Work challenge", async () => {
    const newConfig = { ...initialConfig, port: 5353 };
    const res = await makeRequest("PUT", "/api/v1/config", {
      "x-api-key": MOCK_API_KEY,
      "x-device-id": MOCK_DEVICE_ID,
      "x-pow-nonce": "invalid-nonce-value",
      "Content-Type": "application/json"
    }, JSON.stringify(newConfig));
    assert.strictEqual(res.status, 403);
    assert.ok(res.data.error.includes("Invalid Proof of Work"));
  });

  it("accepts PUT requests with valid configuration and PoW", async () => {
    const newConfig: ServerConfig = {
      port: 5353,
      hosts: {
        "updated.loop": { records: [{ type: "A", address: "8.8.8.8" }] }
      }
    };
    const res = await makeRequest("PUT", "/api/v1/config", {
      "x-api-key": MOCK_API_KEY,
      "x-device-id": MOCK_DEVICE_ID,
      "x-pow-nonce": validNonce,
      "Content-Type": "application/json"
    }, JSON.stringify(newConfig));
    
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);

    const checkRes = await makeRequest("GET", "/api/v1/config", {
      "x-api-key": MOCK_API_KEY,
      "x-device-id": MOCK_DEVICE_ID
    });
    assert.strictEqual(checkRes.status, 200);
    assert.strictEqual(checkRes.data.port, 5353);
    assert.ok("updated.loop" in checkRes.data.hosts);
  });

  it("rejects payloads exceeding the memory boundary", async () => {
    const hugePayload = JSON.stringify({ port: 53, hosts: {} }) + " ".repeat(1.5 * 1024 * 1024);
    const res = await makeRequest("PUT", "/api/v1/config", {
      "x-api-key": MOCK_API_KEY,
      "x-device-id": MOCK_DEVICE_ID,
      "x-pow-nonce": validNonce,
      "Content-Type": "application/json"
    }, hugePayload);
    
    assert.strictEqual(res.status, 413);
  });
});
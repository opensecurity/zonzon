import { describe, it } from "node:test";
import assert from "node:assert";
import { DnsHandler } from "./dns-handler.js";
import { DevDnsServer } from "./dns-service.js";
import { ServerConfig } from "./types.js";

function createMockReqRes(method: string, url: string, headers: Record<string, string> = {}) {
  const req: any = {
    method,
    url,
    headers,
    socket: { remoteAddress: "127.0.0.1" },
    destroy: () => {}
  };

  let statusCode = 0;
  let endData: any = null;
  const resHeaders: Record<string, string | number | readonly string[]> = {};

  const res: any = {
    writeHead: (code: number, headers?: any) => {
      statusCode = code;
      if (headers) Object.assign(resHeaders, headers);
    },
    end: (data?: any) => {
      endData = data;
    }
  };

  return { req, res, getStatus: () => statusCode, getEndData: () => endData, getHeaders: () => resHeaders };
}

describe("Modern DNS Protocols (DoH)", () => {
  const config: ServerConfig = {
    port: 53,
    hosts: {}
  };

  const server = new DevDnsServer(config);
  const handler = new DnsHandler(server, config);

  it("rejects DoH request on invalid path", async () => {
    const { req, res, getStatus } = createMockReqRes("GET", "/invalid-path");
    
    // @ts-ignore - Accessing private method for strict L7 unit testing
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 404);
  });

  it("rejects DoH GET request missing dns query parameter", async () => {
    const { req, res, getStatus } = createMockReqRes("GET", "/dns-query");
    
    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 400);
  });

  it("rejects DoH GET request with invalid base64url payload", async () => {
    const { req, res, getStatus } = createMockReqRes("GET", "/dns-query?dns=!!!invalid_base64!!!");
    
    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 400);
  });

  it("rejects DoH POST request with invalid content-type", async () => {
    const { req, res, getStatus } = createMockReqRes("POST", "/dns-query", {
      "content-type": "application/json"
    });
    
    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 415);
  });

  it("rejects unsupported HTTP methods", async () => {
    const { req, res, getStatus } = createMockReqRes("PUT", "/dns-query");
    
    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 405);
  });

  it("rejects payloads that are too short to be valid DNS packets", async () => {
    const { req, res, getStatus } = createMockReqRes("GET", "/dns-query?dns=abcd"); 
    
    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 400);
  });

  it("enforces memory bounds on DoH POST payloads to prevent exhaustion", async () => {
    const { req, res, getStatus } = createMockReqRes("POST", "/dns-query", {
      "content-type": "application/dns-message"
    });

    const oversizedBuffer = Buffer.alloc(65 * 1024); // Exceeds MAX_TCP_BUFFER_SIZE (64KB)

    req[Symbol.asyncIterator] = async function* () {
      yield oversizedBuffer;
    };

    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 413);
  });

  it("processes a structurally valid DoH POST request", async () => {
    const { req, res, getStatus, getHeaders } = createMockReqRes("POST", "/dns-query", {
      "content-type": "application/dns-message"
    });

    // Create a minimal 12-byte valid DNS header
    const validDnsHeader = Buffer.alloc(12);
    validDnsHeader.writeUInt16BE(0x1234, 0); // ID
    validDnsHeader.writeUInt16BE(0x0100, 2); // Flags (Standard Query)
    validDnsHeader.writeUInt16BE(0x0000, 4); // QDCOUNT

    req[Symbol.asyncIterator] = async function* () {
      yield validDnsHeader;
    };

    // @ts-ignore
    await handler.handleDohRequest(req, res);
    
    assert.strictEqual(getStatus(), 200);
    const headers = getHeaders();
    assert.strictEqual(headers["Content-Type"], "application/dns-message");
    assert.strictEqual(headers["Cache-Control"], "max-age=0");
  });
});
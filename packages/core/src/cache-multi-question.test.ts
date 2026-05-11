import { describe, it } from "node:test";
import assert from "node:assert";
import { DevDnsServer } from "./dns-service.js";
import { ServerConfig, DNS_TYPES, DNS_CLASSES } from "./types.js";

describe("Multi-Question TTL Cache Rewriting", () => {
  function buildMultiQuestionQuery(names: string[], types: number[]): Buffer {
    const encoder = new (class {
      buf = Buffer.alloc(1024);
      offset = 0;

      writeUint16(v: number) {
        this.buf.writeUInt16BE(v, this.offset);
        this.offset += 2;
      }

      writeUint8(v: number) {
        this.buf.writeUInt8(v, this.offset);
        this.offset += 1;
      }

      writeDomainName(nm: string) {
        for (const label of nm.split(".")) {
          if (label.length === 0) continue;
          this.writeUint8(label.length);
          Buffer.from(label).copy(this.buf, this.offset);
          this.offset += label.length;
        }
        this.writeUint8(0);
      }

      finish(): Buffer {
        return this.buf.subarray(0, this.offset);
      }
    })();

    encoder.writeUint16(0xCAFE); 
    encoder.writeUint16(0x0100); 
    encoder.writeUint16(names.length); 
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);

    for (let i = 0; i < names.length; i++) {
      encoder.writeDomainName(names[i]);
      encoder.writeUint16(types[i] || DNS_TYPES.A);
      encoder.writeUint16(DNS_CLASSES.IN);
    }

    return encoder.finish();
  }

  function extractAnswerTtls(response: Buffer): number[] {
    const ttls: number[] = [];

    const qdcount = response.readUInt16BE(4);
    let offset = 12;

    for (let i = 0; i < qdcount && offset < response.length; i++) {
      while (offset < response.length) {
        const len = response[offset];
        if (len === 0) { offset++; break; }
        if ((len & 0xc0) === 0xc0) {
          offset += 2;
          break;
        }
        offset += 1 + len;
      }
      offset += 4;
    }

    const ancount = response.readUInt16BE(6);
    for (let i = 0; i < ancount && offset + 8 <= response.length; i++) {
      offset += 2; 
      offset += 2; 
      offset += 2; 
      ttls.push(response.readUInt32BE(offset)); 
      offset += 4;

      const rdlength = response.readUInt16BE(offset);
      offset += 2 + rdlength;
    }

    return ttls;
  }

  it("rewrites TTL for all answer entries in a cached multi-question response", async () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 10000, 
      hosts: {
        "alpha.loop": { records: [{ type: "A", address: "1.1.1.1" }] },
        "beta.loop": { records: [{ type: "A", address: "2.2.2.2" }] },
      },
    };

    const server = new DevDnsServer(config);

    const query = buildMultiQuestionQuery(
      ["alpha.loop", "beta.loop"],
      [DNS_TYPES.A, DNS_TYPES.A]
    );

    const response1 = server.resolve(query)!;
    assert.ok(response1.length > 0);

    const ttlsAfterFirst = extractAnswerTtls(response1);
    assert.strictEqual(ttlsAfterFirst.length, 2);
    assert.ok(
      ttlsAfterFirst.every((t) => t > 0)
    );

    await new Promise<void>((resolve) => setTimeout(resolve, 200));

    const response2 = server.resolve(query)!;
    assert.ok(response2.length > 0);

    const ttlsAfterCacheHit = extractAnswerTtls(response2);
    assert.strictEqual(ttlsAfterCacheHit.length, 2);

    const originalTotalTtl = ttlsAfterFirst.reduce((a, b) => a + b, 0);
    const cachedTotalTtl = ttlsAfterCacheHit.reduce((a, b) => a + b, 0);

    assert.ok(
      cachedTotalTtl < originalTotalTtl
    );

    assert.ok(
      ttlsAfterCacheHit.every((t) => t >= 0)
    );
  });

  it("handles three-question multi-query without TTL corruption", async () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 10000,
      hosts: {
        "one.loop": { records: [{ type: "A", address: "1.0.0.1" }] },
        "two.loop": { records: [{ type: "A", address: "1.0.0.2" }] },
        "three.loop": { records: [{ type: "A", address: "1.0.0.3" }] },
      },
    };

    const server = new DevDnsServer(config);

    const query = buildMultiQuestionQuery(
      ["one.loop", "two.loop", "three.loop"],
      [DNS_TYPES.A, DNS_TYPES.A, DNS_TYPES.A]
    );

    const response1 = server.resolve(query)!;
    assert.ok(response1.length > 0);

    const ttlsAfterFirst = extractAnswerTtls(response1);
    assert.strictEqual(ttlsAfterFirst.length, 3);

    await new Promise<void>((resolve) => setTimeout(resolve, 300));
    const response2 = server.resolve(query)!;
    assert.ok(response2.length > 0);

    const ttlsAfterCache = extractAnswerTtls(response2);
    assert.strictEqual(ttlsAfterCache.length, 3);

    const maxTtl = config.dnsCacheTtlMs! / 1000;
    for (const ttl of ttlsAfterCache) {
      assert.ok(
        ttl >= 0 && ttl <= maxTtl
      );
    }
  });

  it("does not corrupt question data when rewriting TTL in multi-question response", async () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 10000,
      hosts: {
        "a.loop": { records: [{ type: "A", address: "1.2.3.4" }] },
        "b.loop": { records: [{ type: "A", address: "5.6.7.8" }] },
      },
    };

    const server = new DevDnsServer(config);

    const query = buildMultiQuestionQuery(
      ["a.loop", "b.loop"],
      [DNS_TYPES.A, DNS_TYPES.A]
    );

    const originalResponse = server.resolve(query)!;
    assert.ok(originalResponse.length > 0);

    const originalBytes = Buffer.from(originalResponse);

    await new Promise<void>((resolve) => setTimeout(resolve, 150));
    const cachedResponse = server.resolve(query)!;
    assert.ok(cachedResponse.length > 0);

    assert.strictEqual(
      cachedResponse.readUInt16BE(6),
      originalResponse.readUInt16BE(6)
    );

    assert.strictEqual(
      cachedResponse.length,
      originalBytes.length
    );

    const origQdcount = originalResponse.readUInt16BE(4);
    const cacheQdcount = cachedResponse.readUInt16BE(4);
    assert.strictEqual(origQdcount, cacheQdcount);

    const origAncount = originalResponse.readUInt16BE(6);
    const cacheAncount = cachedResponse.readUInt16BE(6);
    assert.strictEqual(origAncount, cacheAncount);

    const origTtls = extractAnswerTtls(originalResponse);
    const cacheTtls = extractAnswerTtls(cachedResponse);
    for (let i = 0; i < origTtls.length; i++) {
      assert.ok(
        cacheTtls[i] <= origTtls[i]
      );
    }
  });

  it("handles multi-question with mismatched record types", async () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 10000,
      hosts: {
        "a.loop": { records: [{ type: "A", address: "1.2.3.4" }] },
        "b.loop": { records: [{ type: "AAAA", address: "::1" }] },
      },
    };

    const server = new DevDnsServer(config);

    const query = buildMultiQuestionQuery(
      ["a.loop", "b.loop"],
      [DNS_TYPES.A, DNS_TYPES.AAAA]
    );

    const response1 = server.resolve(query)!;
    assert.ok(response1.length > 0);

    const ttlsFirst = extractAnswerTtls(response1);
    assert.strictEqual(ttlsFirst.length, 2);

    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    const response2 = server.resolve(query)!;
    assert.ok(response2.length > 0);

    const ttlsCache = extractAnswerTtls(response2);
    assert.strictEqual(ttlsCache.length, 2);

    for (const ttl of ttlsCache) {
      assert.ok(ttl >= 0);
    }
  });
});
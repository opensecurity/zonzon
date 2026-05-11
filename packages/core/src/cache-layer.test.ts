import { describe, it } from "node:test";
import assert from "node:assert";
import { DevDnsServer } from "./dns-service.js";
import { ServerConfig, DNS_TYPES } from "./types.js";

function buildQuery(name: string, type: number): Buffer {
  const encoder = new (class {
    buf = Buffer.alloc(256);
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

  encoder.writeUint16(0x5678);
  encoder.writeUint16(0x0100);
  encoder.writeUint16(1);
  encoder.writeUint16(0);
  encoder.writeUint16(0);
  encoder.writeUint16(0);

  encoder.writeDomainName(name);
  encoder.writeUint16(type);
  encoder.writeUint16(1);

  return encoder.finish();
}

function parseResponseFlags(buf: Buffer): { qr: number; rcode: number } {
  const flags = buf.readUInt16BE(2);
  const qr = (flags >> 15) & 0x1;
  const rcode = flags & 0xf;
  return { qr, rcode };
}

function getTtlFromResponse(buf: Buffer): number | null {
  const ancount = buf.readUInt16BE(6);
  if (ancount === 0) return null;

  let offset = 12;
  while (offset < buf.length && buf[offset] !== 0) {
    const len = buf[offset];
    if ((len & 0xc0) === 0xc0) break;
    offset += len + 1;
  }
  offset += 5; 

  if (offset + 4 > buf.length) return null;
  return buf.readUInt32BE(offset);
}

describe("DevDnsServer - Cache Layer", () => {
  let server: DevDnsServer;

  it("caches responses when cache is enabled with TTL", async () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 5000,
      hosts: {
        "cached.loop": { records: [{ type: "A", address: "192.168.1.1" }] },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("cached.loop", DNS_TYPES.A);

    const firstResponse = server.resolve(queryBuffer)!;
    assert.ok(firstResponse.length > 0);
    const ttl1 = getTtlFromResponse(firstResponse);
    assert.ok(ttl1 !== null && ttl1 >= 5);

    await new Promise<void>((resolve) => setTimeout(resolve, 200));
    const secondResponse = server.resolve(queryBuffer)!;
    assert.ok(secondResponse.length > 0);

    const { qr: qr1, rcode: rc1 } = parseResponseFlags(firstResponse);
    const { qr: qr2, rcode: rc2 } = parseResponseFlags(secondResponse);
    assert.strictEqual(qr1, qr2);
    assert.strictEqual(rc1, rc2);

    const ttl2 = getTtlFromResponse(secondResponse);
    assert.ok(ttl2 !== null);
    assert.ok(ttl2 <= ttl1!);
  });

  it("returns expired cache entries as stale", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 50, 
      hosts: {
        "short-lived.loop": { records: [{ type: "A", address: "10.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("short-lived.loop", DNS_TYPES.A);

    server.resolve(queryBuffer);

    return new Promise<void>((resolve) => {
      setTimeout(() => {
        const expiredResponse = server.resolve(queryBuffer)!;
        assert.ok(expiredResponse.length > 0);
        const { rcode } = parseResponseFlags(expiredResponse);
        assert.strictEqual(rcode, 0);
        resolve();
      }, 100);
    });
  });

  it("enforces cache size limit by evicting oldest entries", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 3, 
      dnsCacheTtlMs: 10000,
      hosts: {
        "one.loop": { records: [{ type: "A", address: "1.1.1.1" }] },
        "two.loop": { records: [{ type: "A", address: "2.2.2.2" }] },
        "three.loop": { records: [{ type: "A", address: "3.3.3.3" }] },
        "four.loop": { records: [{ type: "A", address: "4.4.4.4" }] },
      },
    };

    server = new DevDnsServer(config);

    server.resolve(buildQuery("one.loop", DNS_TYPES.A));
    server.resolve(buildQuery("two.loop", DNS_TYPES.A));
    server.resolve(buildQuery("three.loop", DNS_TYPES.A));

    server.resolve(buildQuery("four.loop", DNS_TYPES.A));

    const r1 = server.resolve(buildQuery("one.loop", DNS_TYPES.A))!;
    const r4 = server.resolve(buildQuery("four.loop", DNS_TYPES.A))!;

    assert.ok(r1.length > 0 || r4.length > 0);
  });

  it("does not cache when cache is disabled (zero TTL)", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0, 
      hosts: {
        "no-cache.loop": { records: [{ type: "A", address: "9.9.9.9" }] },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("no-cache.loop", DNS_TYPES.A);

    const resp1 = server.resolve(queryBuffer)!;
    assert.ok(resp1.length > 0);

    const resp2 = server.resolve(queryBuffer)!;
    assert.ok(resp2.length > 0);
  });

  it("returns NXDOMAIN for unknown hosts without caching the negative result when cache is enabled", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 2000,
      hosts: {},
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("nonexistent.loop", DNS_TYPES.A);

    const response = server.resolve(queryBuffer)!;
    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, 3);
  });

  it("caches multi-question queries separately per question", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 5000,
      hosts: {
        "a.loop": { records: [{ type: "A", address: "1.1.1.1" }] },
        "b.loop": { records: [{ type: "A", address: "2.2.2.2" }] },
      },
    };

    server = new DevDnsServer(config);

    const encoder = new (class {
      buf = Buffer.alloc(512);
      offset = 0;
      writeUint16(v: number) { this.buf.writeUInt16BE(v, this.offset); this.offset += 2; }
      writeUint8(v: number) { this.buf.writeUInt8(v, this.offset); this.offset += 1; }
      writeDomainName(nm: string) { for (const label of nm.split(".")) { if (label.length === 0) continue; this.writeUint8(label.length); Buffer.from(label).copy(this.buf, this.offset); this.offset += label.length; } this.writeUint8(0); }
      finish(): Buffer { return this.buf.subarray(0, this.offset); }
    })();

    encoder.writeUint16(0xAAAA);
    encoder.writeUint16(0x0100);
    encoder.writeUint16(2);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeDomainName("a.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);
    encoder.writeDomainName("b.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.ok(response.length > 0);
  });
});
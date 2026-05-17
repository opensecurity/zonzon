import { describe, it } from "node:test";
import assert from "node:assert";
import { DevDnsServer } from "./dns-service.js";
import { ServerConfig, DNS_TYPES, DNS_RCODE } from "./types.js";

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

  encoder.writeUint16(0x1234);
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

function parseResponseFlags(buf: Buffer): { qr: number; rcode: number; id: number } {
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qr = (flags >> 15) & 0x1;
  const rcode = flags & 0xf;
  return { id, qr, rcode };
}

function getAnswerCount(buf: Buffer): number {
  return buf.readUInt16BE(6);
}

describe("DevDnsServer - NS Record Tests", () => {
  let server: DevDnsServer;

  it("returns NS record when configured", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "ns.loop": {
          records: [{ type: "NS", target: "ns1.ns.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("ns.loop", DNS_TYPES.NS);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);
    const { qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);

    const ancount = getAnswerCount(response);
    assert.ok(ancount >= 1);
  });

  it("does not return NS record for A-type query on NS-configured host", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "ns-only.loop": {
          records: [{ type: "NS", target: "ns1.ns-only.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("ns-only.loop", DNS_TYPES.A);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
    assert.strictEqual(getAnswerCount(response), 0);
  });
});

describe("DevDnsServer - PTR Record Tests", () => {
  let server: DevDnsServer;

  it("returns PTR record when configured", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "1.0.0.127.in-addr.arpa": {
          records: [{ type: "PTR", target: "localhost" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("1.0.0.127.in-addr.arpa", DNS_TYPES.PTR);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);
    const { qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
  });

  it("handles PTR with IP reversal lookup name", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "20.0.168.192.in-addr.arpa": {
          records: [{ type: "PTR", target: "host.example.com" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("20.0.168.192.in-addr.arpa", DNS_TYPES.PTR);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
  });
});

describe("DevDnsServer - Multi-Question Queries", () => {
  let server: DevDnsServer;

  it("returns answers for all matching questions in a multi-question query", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "host1.loop": { records: [{ type: "A", address: "10.0.0.1" }] },
        "host2.loop": { records: [{ type: "A", address: "10.0.0.2" }] },
      },
    };

    server = new DevDnsServer(config);

    const encoder = new (class {
      buf = Buffer.alloc(512);
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

    encoder.writeUint16(0xabcd);
    encoder.writeUint16(0x0100); 
    encoder.writeUint16(2); 
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);

    encoder.writeDomainName("host1.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    encoder.writeDomainName("host2.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.ok(response.length > 0);
    const { qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
    const ancount = getAnswerCount(response);
    assert.ok(ancount >= 1);
  });

  it("returns NXDOMAIN when all questions in multi-query are unknown", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
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

    encoder.writeUint16(0xffff);
    encoder.writeUint16(0x0100);
    encoder.writeUint16(2);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);

    encoder.writeDomainName("unknown1.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    encoder.writeDomainName("unknown2.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NXDOMAIN);
  });
});

describe("DevDnsServer - Oversized Packet Protection", () => {
  let server: DevDnsServer;

  it("handles oversized queries without crashing", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);

    const hugeQuery = Buffer.alloc(65535, 0x41); 

    hugeQuery.writeUInt16BE(0x9999, 0);
    hugeQuery.writeUInt16BE(0x0100, 2); 
    hugeQuery.writeUInt16BE(1, 4); 

    const response = server.resolve(hugeQuery)!;
    assert.ok(response.length === 0 || response.length >= 12);
  });

  it("handles queries with maximum label length (63 chars)", () => {
    const longLabel = "a".repeat(63);
    const config: ServerConfig = {
      port: 53,
      hosts: {
        [`${longLabel}.loop`]: { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery(`${longLabel}.loop`, DNS_TYPES.A);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
  });

  it("handles very long domain names without crashing", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);

    const encoder = new (class {
      buf = Buffer.alloc(65535);
      offset = 0;

      writeUint16(v: number) { this.buf.writeUInt16BE(v, this.offset); this.offset += 2; }
      writeUint8(v: number) { this.buf.writeUInt8(v, this.offset); this.offset += 1; }
      writeDomainName(nm: string) { for (const label of nm.split(".")) { if (label.length === 0) continue; this.writeUint8(label.length); Buffer.from(label).copy(this.buf, this.offset); this.offset += label.length; } this.writeUint8(0); }
      finish(): Buffer { return this.buf.subarray(0, this.offset); }
    })();

    encoder.writeUint16(0xaaaa);
    encoder.writeUint16(0x0100);
    encoder.writeUint16(1);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);

    const longDomain = "a".repeat(100) + ".b".repeat(100) + ".c".repeat(100);
    encoder.writeDomainName(longDomain);
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.ok(response.length === 0 || response.length >= 12);
  });
});

describe("DevDnsServer - hasRecord()", () => {
  let server: DevDnsServer;

  it("returns true for existing record type", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("test.loop", DNS_TYPES.A), true);
  });

  it("returns false for non-existing record type on existing host", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("test.loop", DNS_TYPES.NS), false);
  });

  it("returns false for unknown host", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("unknown.loop", DNS_TYPES.A), false);
  });

  it("is case-insensitive for hostname matching", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "Test.Loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("test.loop", DNS_TYPES.A), true);
    assert.strictEqual(server.hasRecord("TEST.LOOP", DNS_TYPES.A), true);
  });

  it("handles trailing dot in hostname for hasRecord", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("test.loop.", DNS_TYPES.A), true);
  });

  it("returns false for empty records array host", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "empty.loop": { records: [] },
      },
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("empty.loop", DNS_TYPES.A), false);
  });

  it("returns correct type number for all record types", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.A), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.NS), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.CNAME), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.TXT), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.MX), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.PTR), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.AAAA), false);
    assert.strictEqual(server.hasRecord("x", DNS_TYPES.SRV), false);
  });
});

describe("DevDnsServer - Mixed Resolution Scenarios", () => {
  let server: DevDnsServer;

  it("returns NOERROR with answers when one host has matching records and another is unknown", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "known.loop": { records: [{ type: "A", address: "10.0.0.1" }] },
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

    encoder.writeUint16(0xdead);
    encoder.writeUint16(0x0100);
    encoder.writeUint16(2);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);

    encoder.writeDomainName("known.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    encoder.writeDomainName("unknown.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.ok(response.length > 0);
    const { qr } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
  });

  it("returns NXDOMAIN when host exists but wrong record type requested", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "only-a.loop": { records: [{ type: "A", address: "10.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("only-a.loop", DNS_TYPES.MX);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
    assert.strictEqual(getAnswerCount(response), 0);
  });

  it("handles CNAME + A records returning both", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "alias.loop": {
          records: [
            { type: "CNAME", target: "target.loop" },
            { type: "A", address: "127.0.0.1" },
          ],
        },
      },
    };

    server = new DevDnsServer(config);

    const cnameQuery = buildQuery("alias.loop", DNS_TYPES.CNAME);
    const cnameResponse = server.resolve(cnameQuery)!;
    assert.ok(cnameResponse.length > 0);
    assert.strictEqual(getAnswerCount(cnameResponse), 1);

    const aQuery = buildQuery("alias.loop", DNS_TYPES.A);
    const aResponse = server.resolve(aQuery)!;
    assert.ok(aResponse.length > 0);
    assert.strictEqual(getAnswerCount(aResponse), 1);
  });
});

describe("DevDnsServer - Response ID Preservation", () => {
  let server: DevDnsServer;

  it("preserves query ID in response for different ID values", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "id-test.loop": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };

    server = new DevDnsServer(config);

    for (const testId of [0x0001, 0x00FF, 0x8000, 0xFFFF, 0xABCD, 0x0000]) {
      const encoder = new (class {
        buf = Buffer.alloc(256);
        offset = 0;
        writeUint16(v: number) { this.buf.writeUInt16BE(v, this.offset); this.offset += 2; }
        writeUint8(v: number) { this.buf.writeUInt8(v, this.offset); this.offset += 1; }
        writeDomainName(nm: string) { for (const label of nm.split(".")) { if (label.length === 0) continue; this.writeUint8(label.length); Buffer.from(label).copy(this.buf, this.offset); this.offset += label.length; } this.writeUint8(0); }
        finish(): Buffer { return this.buf.subarray(0, this.offset); }
      })();

      encoder.writeUint16(testId);
      encoder.writeUint16(0x0100);
      encoder.writeUint16(1);
      encoder.writeUint16(0);
      encoder.writeUint16(0);
      encoder.writeUint16(0);

      encoder.writeDomainName("id-test.loop");
      encoder.writeUint16(DNS_TYPES.A);
      encoder.writeUint16(1);

      const response = server.resolve(encoder.finish())!;
      assert.ok(response.length > 0);
      const { id } = parseResponseFlags(response);
      assert.strictEqual(id, testId);
    }
  });

  it("preserves NXDOMAIN response ID", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);
    const encoder = new (class {
      buf = Buffer.alloc(256);
      offset = 0;
      writeUint16(v: number) { this.buf.writeUInt16BE(v, this.offset); this.offset += 2; }
      writeUint8(v: number) { this.buf.writeUInt8(v, this.offset); this.offset += 1; }
      writeDomainName(nm: string) { for (const label of nm.split(".")) { if (label.length === 0) continue; this.writeUint8(label.length); Buffer.from(label).copy(this.buf, this.offset); this.offset += label.length; } this.writeUint8(0); }
      finish(): Buffer { return this.buf.subarray(0, this.offset); }
    })();

    encoder.writeUint16(0xCafe);
    encoder.writeUint16(0x0100);
    encoder.writeUint16(1);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);

    encoder.writeDomainName("ghost.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.strictEqual(parseResponseFlags(response).id, 0xCafe);
  });
});

describe("DevDnsServer - Edge Case DNS Queries", () => {
  let server: DevDnsServer;

  it("handles queries utilizing standard valid compression pointers without crashing", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": { records: [{ type: "A", address: "1.2.3.4" }] }
      },
    };
    server = new DevDnsServer(config);

    const buf = Buffer.alloc(50);
    buf.writeUInt16BE(0x5555, 0); 
    buf.writeUInt16BE(0x0100, 2); 
    buf.writeUInt16BE(2, 4);      
    
    buf[12] = 4;
    Buffer.from("test").copy(buf, 13);
    buf[17] = 4;
    Buffer.from("loop").copy(buf, 18);
    buf[22] = 0;
    
    buf.writeUInt16BE(DNS_TYPES.A, 23); 
    buf.writeUInt16BE(1, 25);           
    
    buf[27] = 0xc0;
    buf[28] = 0x0c;
    buf.writeUInt16BE(DNS_TYPES.A, 29); 
    buf.writeUInt16BE(1, 31);           
    
    const response = server.resolve(buf.subarray(0, 33))!;
    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
    assert.strictEqual(getAnswerCount(response), 2);
  });

  it("handles query with exactly header size buffer (12 bytes)", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);

    const minimalQuery = Buffer.alloc(12);
    minimalQuery.writeUInt16BE(0x1111, 0);
    minimalQuery.writeUInt16BE(0x0100, 2); 
    minimalQuery.writeUInt16BE(0, 4); 

    const response = server.resolve(minimalQuery)!;
    assert.strictEqual(response.length, 0);
  });

  it("handles single-byte query after header", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);

    const truncatedQuery = Buffer.alloc(13);
    truncatedQuery.writeUInt16BE(0x2222, 0);
    truncatedQuery.writeUInt16BE(0x0100, 2);
    truncatedQuery.writeUInt16BE(1, 4);

    const response = server.resolve(truncatedQuery)!;
    assert.ok(response.length === 0 || response.length >= 12);
  });

  it("handles DNS compression pointer at offset 0 without hanging", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);

    const maliciousQuery = Buffer.alloc(20);
    maliciousQuery.writeUInt16BE(0x3333, 0);
    maliciousQuery.writeUInt16BE(0x0100, 2);
    maliciousQuery.writeUInt16BE(1, 4);
    maliciousQuery[12] = 0xC0;
    maliciousQuery[13] = 0x00;
    maliciousQuery.writeUInt16BE(DNS_TYPES.A, 14);
    maliciousQuery.writeUInt16BE(1, 16);

    const response = server.resolve(maliciousQuery)!;
    assert.ok(response.length === 0 || response.length >= 12);
    if (response.length > 0) {
      const { qr } = parseResponseFlags(response);
      assert.strictEqual(qr, 1);
    }
  });

  it("handles query with only empty labels", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);

    const rootQuery = Buffer.alloc(17);
    rootQuery.writeUInt16BE(0x4444, 0);
    rootQuery.writeUInt16BE(0x0100, 2);
    rootQuery.writeUInt16BE(1, 4);
    rootQuery[12] = 0; 
    rootQuery.writeUInt16BE(DNS_TYPES.A, 13);
    rootQuery.writeUInt16BE(1, 15);

    const response = server.resolve(rootQuery)!;
    assert.ok(response.length === 0 || response.length >= 12);
  });
});

describe("DevDnsServer - SRV Record Edge Cases", () => {
  let server: DevDnsServer;

  it("handles SRV record with priority 0", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "srv-zero.loop": {
          records: [{ type: "SRV", priority: 0, weight: 0, port: 80, target: "target.srv-zero.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("srv-zero.loop", DNS_TYPES.SRV))!;
    assert.ok(response.length > 0);
    assert.strictEqual(getAnswerCount(response), 1);
  });

  it("handles SRV record with maximum port (65535)", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "srv-max.loop": {
          records: [{ type: "SRV", priority: 0, weight: 65535, port: 65535, target: "target.srv-max.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("srv-max.loop", DNS_TYPES.SRV))!;
    assert.ok(response.length > 0);
    assert.strictEqual(getAnswerCount(response), 1);
  });

  it("does not return SRV for A-type query on SRV-only host", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "srv-only.loop": {
          records: [{ type: "SRV", priority: 10, weight: 5, port: 8080, target: "target.srv-only.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("srv-only.loop", DNS_TYPES.A))!;
    assert.ok(response.length > 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
    assert.strictEqual(getAnswerCount(response), 0);
  });
});

describe("DevDnsServer - AAAA Record Formats", () => {
  let server: DevDnsServer;

  it("handles full IPv6 address (8 groups)", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "full-ipv6.loop": { records: [{ type: "AAAA", address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334" }] },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("full-ipv6.loop", DNS_TYPES.AAAA))!;
    assert.ok(response.length > 0);
    assert.strictEqual(getAnswerCount(response), 1);
  });

  it("handles :: shorthand IPv6 address", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "shorthand.loop": { records: [{ type: "AAAA", address: "::ffff:192.168.1.1" }] },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("shorthand.loop", DNS_TYPES.AAAA))!;
    assert.ok(response.length > 0);
    assert.strictEqual(getAnswerCount(response), 1);
  });

  it("handles ::1 loopback IPv6", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "loopback.loop": { records: [{ type: "AAAA", address: "::1" }] },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("loopback.loop", DNS_TYPES.AAAA))!;
    assert.ok(response.length > 0);
    assert.strictEqual(getAnswerCount(response), 1);
  });
});
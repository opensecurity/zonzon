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

    writeDomainName(name: string) {
      for (const label of name.split(".")) {
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

function buildMalformedQuery(): Buffer {
  return Buffer.from([0x12, 0x34]); 
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

describe("DevDnsServer - Baseline Tests", () => {
  let server: DevDnsServer;

  it("returns A record with matching ID and NOERROR for configured host", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [{ type: "A", address: "127.0.0.1" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("test.loop", DNS_TYPES.A);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { id, qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(id, 0x1234);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);

    const ancount = getAnswerCount(response);
    assert.ok(ancount >= 1);
  });

  it("returns NXDOMAIN for unconfigured host", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {},
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("notexist.loop", DNS_TYPES.A);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { id, qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(id, 0x1234);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NXDOMAIN);
  });

  it("returns CNAME record when configured", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "alias.loop": {
          records: [{ type: "CNAME", target: "target.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("alias.loop", DNS_TYPES.CNAME);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);

    const ancount = getAnswerCount(response);
    assert.ok(ancount >= 1);
  });

  it("returns TXT record when configured", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "txt.loop": {
          records: [{ type: "TXT", data: ["v=spf1 include:_example.com ~all"] }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("txt.loop", DNS_TYPES.TXT);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { qr } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);

    const ancount = getAnswerCount(response);
    assert.ok(ancount >= 1);
  });

  it("rejects malformed (too short) query packets", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [{ type: "A", address: "127.0.0.1" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const malformed = buildMalformedQuery();
    const response = server.resolve(malformed)!;

    assert.strictEqual(response.length, 0);
  });

  it("rejects packets that are DNS responses (QR=1)", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [{ type: "A", address: "127.0.0.1" }],
        },
      },
    };

    server = new DevDnsServer(config);

    const encoder = new (class {
      buf = Buffer.alloc(256);
      offset = 0;

      writeUint16(v: number) {
        this.buf.writeUInt16BE(v, this.offset);
        this.offset += 2;
      }

      writeDomainName(name: string) {
        for (const label of name.split(".")) {
          if (label.length === 0) continue;
          this.writeUint8(label.length);
          Buffer.from(label).copy(this.buf, this.offset);
          this.offset += label.length;
        }
        this.writeUint8(0);
      }

      writeUint8(v: number) {
        this.buf.writeUInt8(v, this.offset);
        this.offset += 1;
      }

      finish(): Buffer {
        return this.buf.subarray(0, this.offset);
      }
    })();

    encoder.writeUint16(0xdead);
    encoder.writeUint16(0x8100); 
    encoder.writeUint16(1);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeDomainName("test.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.strictEqual(response.length, 0);
  });

  it("does not process queries with RD=0 (recursion not desired)", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [{ type: "A", address: "127.0.0.1" }],
        },
      },
    };

    server = new DevDnsServer(config);

    const encoder = new (class {
      buf = Buffer.alloc(256);
      offset = 0;

      writeUint16(v: number) {
        this.buf.writeUInt16BE(v, this.offset);
        this.offset += 2;
      }

      writeDomainName(name: string) {
        for (const label of name.split(".")) {
          if (label.length === 0) continue;
          this.writeUint8(label.length);
          Buffer.from(label).copy(this.buf, this.offset);
          this.offset += label.length;
        }
        this.writeUint8(0);
      }

      writeUint8(v: number) {
        this.buf.writeUInt8(v, this.offset);
        this.offset += 1;
      }

      finish(): Buffer {
        return this.buf.subarray(0, this.offset);
      }
    })();

    encoder.writeUint16(0xbeef);
    encoder.writeUint16(0x0000); 
    encoder.writeUint16(1);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeUint16(0);
    encoder.writeDomainName("test.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(1);

    const response = server.resolve(encoder.finish())!;
    assert.strictEqual(response.length, 0);
  });

  it("handles multiple host lookups correctly (isolated hosts)", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "alpha.loop": {
          records: [{ type: "A", address: "10.0.0.1" }],
        },
        "beta.loop": {
          records: [{ type: "A", address: "10.0.0.2" }],
        },
      },
    };

    server = new DevDnsServer(config);

    const alphaResponse = server.resolve(buildQuery("alpha.loop", DNS_TYPES.A))!;
    assert.ok(alphaResponse.length > 0);
    const { qr: qrAlpha } = parseResponseFlags(alphaResponse);
    assert.strictEqual(qrAlpha, 1);

    const betaResponse = server.resolve(buildQuery("beta.loop", DNS_TYPES.A))!;
    assert.ok(betaResponse.length > 0);
    const { qr: qrBeta } = parseResponseFlags(betaResponse);
    assert.strictEqual(qrBeta, 1);
  });

  it("supports AAAA records", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "ipv6.loop": {
          records: [{ type: "AAAA", address: "::1" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("ipv6.loop", DNS_TYPES.AAAA);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { qr } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
  });

  it("supports MX records", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "mx.loop": {
          records: [{ type: "MX", priority: 10, exchange: "mail.mx.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("mx.loop", DNS_TYPES.MX);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { qr } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
  });

  it("supports SRV records", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "srv.loop": {
          records: [{ type: "SRV", priority: 10, weight: 5, port: 8080, target: "app.srv.loop" }],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("srv.loop", DNS_TYPES.SRV);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { qr } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
  });
});
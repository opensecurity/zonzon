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

  encoder.writeUint16(0xabcd);
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

function getAnswerCount(buf: Buffer): number {
  return buf.readUInt16BE(6);
}

describe("DevDnsServer - SRV Wire Format Encoding", () => {
  let server: DevDnsServer;

  it("returns correctly encoded SRV record with priority=10 weight=5 port=8080", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "my.service.loop": {
          records: [
            { type: "SRV", priority: 10, weight: 5, port: 8080, target: "backend.my.service.loop" },
          ],
        },
      },
    };

    server = new DevDnsServer(config);
    const queryBuffer = buildQuery("my.service.loop", DNS_TYPES.SRV);
    const response = server.resolve(queryBuffer)!;

    assert.ok(response.length > 0);

    const { qr, rcode } = parseResponseFlags(response);
    assert.strictEqual(qr, 1);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);

    const ancount = getAnswerCount(response);
    assert.strictEqual(ancount, 1);
    assert.ok(response.length > 40);
    const rdlen = response.readUInt16BE(20);
    assert.ok(rdlen >= 6);
  });

  it("returns correctly encoded SRV record with zero priority and weight", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "zero.srv.loop": {
          records: [
            { type: "SRV", priority: 0, weight: 0, port: 443, target: "primary.zero.srv.loop" },
          ],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("zero.srv.loop", DNS_TYPES.SRV))!;

    assert.ok(response.length > 0);
    const ancount = getAnswerCount(response);
    assert.strictEqual(ancount, 1);
  });

  it("returns multiple SRV records for same host (weighted load balancing)", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "lb.srv.loop": {
          records: [
            { type: "SRV", priority: 10, weight: 7, port: 8080, target: "server1.lb.srv.loop" },
            { type: "SRV", priority: 20, weight: 3, port: 8080, target: "server2.lb.srv.loop" },
          ],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("lb.srv.loop", DNS_TYPES.SRV))!;

    assert.ok(response.length > 0);
    const ancount = getAnswerCount(response);
    assert.strictEqual(ancount, 2);
  });

  it("does not respond with A record type when host only has SRV records", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "only-srv.loop": {
          records: [
            { type: "SRV", priority: 10, weight: 5, port: 8080, target: "target.only-srv.loop" },
          ],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("only-srv.loop", DNS_TYPES.A))!;

    assert.ok(response.length > 0);
    assert.strictEqual(getAnswerCount(response), 0);
    const { rcode } = parseResponseFlags(response);
    assert.strictEqual(rcode, DNS_RCODE.NOERROR);
  });

  it("handles SRV with maximum port value 65535", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "maxport.srv.loop": {
          records: [
            { type: "SRV", priority: 100, weight: 200, port: 65535, target: "max.maxport.srv.loop" },
          ],
        },
      },
    };

    server = new DevDnsServer(config);
    const response = server.resolve(buildQuery("maxport.srv.loop", DNS_TYPES.SRV))!;

    assert.ok(response.length > 0);
    const ancount = getAnswerCount(response);
    assert.strictEqual(ancount, 1);
  });

  it("preserves query ID in SRV response", () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "id.srv.loop": {
          records: [
            { type: "SRV", priority: 10, weight: 5, port: 8080, target: "target.id.srv.loop" },
          ],
        },
      },
    };

    const testEncoder = new (class {
      buf = Buffer.alloc(256);
      offset = 0;
      writeUint16(v: number) { this.buf.writeUInt16BE(v, this.offset); this.offset += 2; }
      writeUint8(v: number) { this.buf.writeUInt8(v, this.offset); this.offset += 1; }
      writeDomainName(nm: string) { for (const label of nm.split(".")) { if (label.length === 0) continue; this.writeUint8(label.length); Buffer.from(label).copy(this.buf, this.offset); this.offset += label.length; } this.writeUint8(0); }
      finish(): Buffer { return this.buf.subarray(0, this.offset); }
    })();

    const testId = 0xDEAD;
    testEncoder.writeUint16(testId);
    testEncoder.writeUint16(0x0100);
    testEncoder.writeUint16(1);
    testEncoder.writeUint16(0);
    testEncoder.writeUint16(0);
    testEncoder.writeUint16(0);
    testEncoder.writeDomainName("id.srv.loop");
    testEncoder.writeUint16(DNS_TYPES.SRV);
    testEncoder.writeUint16(1);

    server = new DevDnsServer(config);
    const response = server.resolve(testEncoder.finish())!;
    assert.strictEqual(response.readUInt16BE(0), testId);
  });
});
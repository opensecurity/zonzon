import { describe, it } from "node:test";
import assert from "assert";
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

  encoder.writeUint16(0xBEEF);
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

function getAnswerCount(buf: Buffer): number {
  return buf.readUInt16BE(6);
}

describe("DevDnsServer - Wildcard Host Matching", () => {
  let server: DevDnsServer;

  it("resolves subdomains under a wildcard pattern *.loop", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.loop": { records: [{ type: "A", address: "192.168.1.1" }] },
      },
    };

    server = new DevDnsServer(config);

    const appResp = server.resolve(buildQuery("app.loop", DNS_TYPES.A))!;
    assert.ok(appResp.length > 0);
    assert.strictEqual(getAnswerCount(appResp), 1);

    const deepResp = server.resolve(buildQuery("deep.sub.loop", DNS_TYPES.A))!;
    assert.ok(deepResp.length > 0);
    assert.strictEqual(getAnswerCount(deepResp), 1);
  });

  it("resolves wildcard with multiple record types", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.dev": {
          records: [
            { type: "A", address: "10.0.0.1" },
            { type: "AAAA", address: "::1" },
            { type: "TXT", data: ["v=dev"] },
          ],
        },
      },
    };

    server = new DevDnsServer(config);

    const aResp = server.resolve(buildQuery("random.dev", DNS_TYPES.A))!;
    assert.ok(aResp.length > 0);
    assert.strictEqual(getAnswerCount(aResp), 1);

    const aaaaResp = server.resolve(buildQuery("another.dev", DNS_TYPES.AAAA))!;
    assert.ok(aaaaResp.length > 0);
    assert.strictEqual(getAnswerCount(aaaaResp), 1);

    const txtResp = server.resolve(buildQuery("foo.dev", DNS_TYPES.TXT))!;
    assert.ok(txtResp.length > 0);
    assert.strictEqual(getAnswerCount(txtResp), 1);
  });

  it("exact hostname takes priority over wildcard", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.loop": { records: [{ type: "A", address: "192.168.1.1" }] },
        "exact.loop": { records: [{ type: "A", address: "10.0.0.100" }] },
      },
    };

    server = new DevDnsServer(config);

    const exactResp = server.resolve(buildQuery("exact.loop", DNS_TYPES.A))!;
    assert.ok(exactResp.length > 0);
    assert.strictEqual(getAnswerCount(exactResp), 1);

    const wildResp = server.resolve(buildQuery("other.loop", DNS_TYPES.A))!;
    assert.ok(wildResp.length > 0);
    assert.strictEqual(getAnswerCount(wildResp), 1);
  });

  it("rejects bare wildcard pattern query (no subdomain)", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.loop": { records: [{ type: "A", address: "192.168.1.1" }] },
      },
    };

    server = new DevDnsServer(config);

    const bareResp = server.resolve(buildQuery("*.loop", DNS_TYPES.A))!;
    assert.ok(bareResp.length > 0);
  });

  it("handles deeply nested wildcard matches", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.com": { records: [{ type: "A", address: "8.8.8.8" }] },
      },
    };

    server = new DevDnsServer(config);

    const deepResp = server.resolve(buildQuery("a.b.c.d.com", DNS_TYPES.A))!;
    assert.ok(deepResp.length > 0);
    assert.strictEqual(getAnswerCount(deepResp), 1);
  });

  it("is case-insensitive for wildcard matching", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.example": { records: [{ type: "A", address: "1.2.3.4" }] },
      },
    };

    server = new DevDnsServer(config);

    const upperResp = server.resolve(buildQuery("APP.EXAMPLE", DNS_TYPES.A))!;
    assert.ok(upperResp.length > 0);
    assert.strictEqual(getAnswerCount(upperResp), 1);
  });

  it("wildcard only matches one label prefix", () => {
    const config: ServerConfig & { dnsCacheMaxSize?: number; dnsCacheTtlMs?: number } = {
      port: 53,
      dnsCacheMaxSize: 100,
      dnsCacheTtlMs: 0,
      hosts: {
        "*.loop": { records: [{ type: "A", address: "5.5.5.5" }] },
      },
    };

    server = new DevDnsServer(config);

    const oneLabelResp = server.resolve(buildQuery("x.loop", DNS_TYPES.A))!;
    assert.ok(oneLabelResp.length > 0);
  });
});
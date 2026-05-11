import { describe, it } from "node:test";
import assert from "node:assert";
import { validateServerConfig, validateHostConfig } from "./schema.js";

describe("Schema Validation - Server Config", () => {
  it("accepts valid server config with minimal hosts", async () => {
    const config = {
      port: 53,
      hosts: {
        "localhost": {
          records: [{ type: "A", address: "127.0.0.1" }],
        },
      },
    };

    const result = validateServerConfig(config);
    assert.strictEqual(result.port, 53);
    assert.ok("localhost" in result.hosts);
    assert.strictEqual(result.hosts["localhost"].records.length, 1);
  });

  it("accepts server config with HTTP proxy headers", async () => {
    const config = {
      port: 53,
      hosts: {
        "app.loop": {
          records: [{ type: "A", address: "10.0.0.1" }],
          http_proxy: {
            enabled: true,
            upstream: "http://localhost:8080",
            headers: {
              "X-Debug": "true",
              "X-Environment": "dev",
            },
          },
        },
      },
    };

    const result = validateServerConfig(config);
    assert.ok(result.hosts["app.loop"].http_proxy?.enabled);
    assert.strictEqual(result.hosts["app.loop"].http_proxy!.headers["X-Debug"], "true");
  });

  it("accepts server config with redirect", async () => {
    const config = {
      port: 53,
      hosts: {
        "redirect.loop": {
          records: [{ type: "A", address: "10.0.0.2" }],
          redirect: {
            code: 302,
            target: "https://production.example.com",
          },
        },
      },
    };

    const result = validateServerConfig(config);
    assert.strictEqual(result.hosts["redirect.loop"].redirect?.code, 302);
    assert.strictEqual(result.hosts["redirect.loop"].redirect?.target, "https://production.example.com");
  });

  it("rejects invalid port", async () => {
    const config = {
      port: 99999,
      hosts: {},
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects non-numeric port", async () => {
    const config = {
      port: "abc" as unknown as number,
      hosts: {},
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects host with invalid hostname format", async () => {
    const config = {
      port: 53,
      hosts: {
        "invalid hostname": {
          records: [{ type: "A", address: "127.0.0.1" }],
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("accepts host with empty records array (no DNS responses)", async () => {
    const config = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [],
        },
      },
    };

    const result = validateServerConfig(config);
    assert.strictEqual(result.hosts["test.loop"].records.length, 0);
  });

  it("rejects TXT with CRLF injection", async () => {
    const config = {
      port: 53,
      hosts: {
        "evil.loop": {
          records: [{ type: "TXT", data: ["value\r\nInjected"] }],
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects header values with CRLF injection", async () => {
    const config = {
      port: 53,
      hosts: {
        "app.loop": {
          records: [{ type: "A", address: "10.0.0.1" }],
          http_proxy: {
            enabled: true,
            upstream: "http://localhost:8080",
            headers: {
              "X-Evil": "value\r\nInjected-Header: yes",
            },
          },
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects header names with special characters", async () => {
    const config = {
      port: 53,
      hosts: {
        "app.loop": {
          records: [{ type: "A", address: "10.0.0.1" }],
          http_proxy: {
            enabled: true,
            upstream: "http://localhost:8080",
            headers: {
              "X- Evil Header": "value",
            },
          },
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects invalid IPv4 address", async () => {
    const config = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [{ type: "A", address: "256.0.0.1" }],
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects invalid IPv6 address", async () => {
    const config = {
      port: 53,
      hosts: {
        "test.loop": {
          records: [{ type: "AAAA", address: "zzzz::1" }],
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects TXT exceeding 255 characters per segment", async () => {
    const longValue = "x".repeat(256);
    const config = {
      port: 53,
      hosts: {
        "txt.loop": {
          records: [{ type: "TXT", data: [longValue] }],
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects redirect with invalid code", async () => {
    const config = {
      port: 53,
      hosts: {
        "redir.loop": {
          records: [{ type: "A", address: "1.2.3.4" }],
          redirect: {
            code: 999,
            target: "https://example.com",
          },
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("accepts multiple record types for same host", async () => {
    const config = {
      port: 53,
      hosts: {
        "multi.loop": {
          records: [
            { type: "A", address: "10.0.0.1" },
            { type: "AAAA", address: "::1" },
            { type: "TXT", data: ["v=spf1 ~all"] },
          ],
        },
      },
    };

    const result = validateServerConfig(config);
    assert.strictEqual(result.hosts["multi.loop"].records.length, 3);
  });

  it("rejects CNAME pointing to invalid hostname", async () => {
    const config = {
      port: 53,
      hosts: {
        "bad.loop": {
          records: [{ type: "CNAME", target: "not a valid host!" }],
        },
      },
    };

    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("accepts _dmarc hostnames (valid DKIM/DKSP record pattern)", async () => {
    const config = {
      port: 53,
      hosts: {
        "_dmarc.example.loop": {
          records: [{ type: "TXT", data: ["v=DMARC1"] }],
        },
      },
    };

    const result = validateServerConfig(config);
    assert.ok("_dmarc.example.loop" in result.hosts);
  });

  it("accepts properly formatted underscore hostnames (valid per RFC)", async () => {
    const config = {
      port: 53,
      hosts: {
        "_service.loop": {
          records: [{ type: "SRV", priority: 10, weight: 5, port: 8080, target: "app.loop" }],
        },
      },
    };

    const result = validateServerConfig(config);
    assert.ok("_service.loop" in result.hosts);
  });
});

describe("Schema Validation - Host Config", () => {
  it("accepts minimal host config with single A record", async () => {
    const config = {
      records: [{ type: "A", address: "127.0.0.1" }],
    };

    const result = validateHostConfig(config);
    assert.strictEqual(result.records.length, 1);
    assert.strictEqual(result.records[0].type, "A");
  });

  it("accepts host config with CNAME and A records", async () => {
    const config = {
      records: [
        { type: "CNAME", target: "target.loop" },
        { type: "A", address: "10.0.0.1" },
      ],
    };

    const result = validateHostConfig(config);
    assert.strictEqual(result.records.length, 2);
  });

  it("defaults records to empty array if omitted", async () => {
    const config = {};
    const result = validateHostConfig(config);
    assert.strictEqual(Array.isArray(result.records), true);
    assert.strictEqual(result.records.length, 0);
  });

  it("rejects proxy enabled without upstream", async () => {
    const config = {
      records: [{ type: "A", address: "127.0.0.1" }],
      http_proxy: {
        enabled: true,
        headers: {},
      },
    };

    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects proxy with invalid header value containing newline", async () => {
    const config = {
      records: [{ type: "A", address: "127.0.0.1" }],
      http_proxy: {
        enabled: true,
        upstream: "http://localhost:8080",
        headers: {
          "X-Bad": "value\nwith\nnewlines",
        },
      },
    };

    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("accepts host config with redirect to valid URL", async () => {
    const config = {
      records: [{ type: "A", address: "127.0.0.1" }],
      redirect: {
        code: 301,
        target: "https://target.com/path?query=value",
      },
    };

    const result = validateHostConfig(config);
    assert.strictEqual(result.redirect?.code, 301);
  });

  it("rejects redirect with missing target", async () => {
    const config = {
      records: [{ type: "A", address: "127.0.0.1" }],
      redirect: {
        code: 302,
      },
    };

    assert.throws(() => validateHostConfig(config), /error/i);
  });
});

describe("Schema Validation - NS Record", () => {
  it("accepts valid NS record", () => {
    const config = validateHostConfig({
      records: [{ type: "NS", target: "ns1.example.loop" }],
    });
    assert.strictEqual(config.records[0].type, "NS");
    assert.strictEqual((config.records[0] as { type: "NS"; target: string }).target, "ns1.example.loop");
  });

  it("rejects NS record without target", () => {
    const config = { records: [{ type: "NS" }] as unknown };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects NS record with invalid hostname target", () => {
    const config = { records: [{ type: "NS", target: "invalid hostname!" }] as unknown };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects non-object NS record", () => {
    assert.throws(() => validateHostConfig({ records: ["not an object"] }), /error/i);
  });
});

describe("Schema Validation - MX Record Edge Cases", () => {
  it("accepts MX with priority 0", () => {
    const config = validateHostConfig({
      records: [{ type: "MX", priority: 0, exchange: "mail.example.loop" }],
    });
    assert.strictEqual((config.records[0] as { type: "MX"; priority: number }).priority, 0);
  });

  it("accepts MX with maximum priority (65535)", () => {
    const config = validateHostConfig({
      records: [{ type: "MX", priority: 65535, exchange: "mail.example.loop" }],
    });
    assert.strictEqual((config.records[0] as { type: "MX"; priority: number }).priority, 65535);
  });

  it("rejects MX with negative priority", () => {
    const config = { records: [{ type: "MX", priority: -1, exchange: "mail.loop" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects MX with priority exceeding 65535", () => {
    const config = { records: [{ type: "MX", priority: 65536, exchange: "mail.loop" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects MX without exchange field", () => {
    const config = { records: [{ type: "MX", priority: 10 }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });
});

describe("Schema Validation - SRV Record Edge Cases", () => {
  it("accepts valid SRV record with minimum values", () => {
    const config = validateHostConfig({
      records: [{ type: "SRV", priority: 0, weight: 0, port: 1, target: "target.loop" }],
    });
    assert.strictEqual((config.records[0] as { type: "SRV"; priority: number }).priority, 0);
    assert.strictEqual((config.records[0] as { type: "SRV"; weight: number }).weight, 0);
    assert.strictEqual((config.records[0] as { type: "SRV"; port: number }).port, 1);
  });

  it("accepts SRV with maximum values", () => {
    const config = validateHostConfig({
      records: [{ type: "SRV", priority: 65535, weight: 65535, port: 65535, target: "target.loop" }],
    });
    assert.strictEqual((config.records[0] as { type: "SRV"; priority: number }).priority, 65535);
    assert.strictEqual((config.records[0] as { type: "SRV"; port: number }).port, 65535);
  });

  it("rejects SRV with port 0", () => {
    const config = { records: [{ type: "SRV", priority: 10, weight: 5, port: 0, target: "target.loop" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects SRV with missing port", () => {
    const config = { records: [{ type: "SRV", priority: 10, weight: 5, target: "target.loop" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects SRV with negative priority", () => {
    const config = { records: [{ type: "SRV", priority: -1, weight: 5, port: 80, target: "target.loop" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects SRV with missing target", () => {
    const config = { records: [{ type: "SRV", priority: 10, weight: 5, port: 80 }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });
});

describe("Schema Validation - PTR Record", () => {
  it("accepts valid PTR record", () => {
    const config = validateHostConfig({
      records: [{ type: "PTR", target: "localhost" }],
    });
    assert.strictEqual(config.records[0].type, "PTR");
  });

  it("rejects PTR without target", () => {
    const config = { records: [{ type: "PTR" }] as unknown };
    assert.throws(() => validateHostConfig(config), /error/i);
  });
});

describe("Schema Validation - IPv4 Edge Cases", () => {
  it("rejects IPv4 with leading zeros (strict validator)", () => {
    const config = { records: [{ type: "A", address: "010.0.0.1" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects IPv4 with too many octets", () => {
    const config = { records: [{ type: "A", address: "1.2.3.4.5" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects IPv4 with too few octets", () => {
    const config = { records: [{ type: "A", address: "1.2.3" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects IPv4 with non-numeric octets", () => {
    const config = { records: [{ type: "A", address: "1.2.x.4" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("accepts IPv4 minimum boundary (0.0.0.0)", () => {
    const config = validateHostConfig({
      records: [{ type: "A", address: "0.0.0.0" }],
    });
    assert.strictEqual((config.records[0] as { type: "A"; address: string }).address, "0.0.0.0");
  });

  it("accepts IPv4 maximum boundary (255.255.255.255)", () => {
    const config = validateHostConfig({
      records: [{ type: "A", address: "255.255.255.255" }],
    });
    assert.strictEqual((config.records[0] as { type: "A"; address: string }).address, "255.255.255.255");
  });
});

describe("Schema Validation - IPv6 Edge Cases", () => {
  it("rejects :: with too many explicit groups (9 total)", () => {
    const config = { records: [{ type: "AAAA", address: "::1:2:3:4:5:6:7:8" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("accepts :: as all-zeros shorthand", () => {
    const config = validateHostConfig({
      records: [{ type: "AAAA", address: "::" }],
    });
    assert.strictEqual((config.records[0] as { type: "AAAA"; address: string }).address, "::");
  });

  it("rejects partial expansion with :: but too many groups (11 total)", () => {
    const config = { records: [{ type: "AAAA", address: "2001:db8::1:2:3:4:5:6" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects full form with wrong number of groups (9 instead of 8)", () => {
    const config = { records: [{ type: "AAAA", address: "2001:db8:85a3:0:0:8a2e:370:7334:1" }] };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("accepts ::1 shorthand for loopback", () => {
    const config = validateHostConfig({
      records: [{ type: "AAAA", address: "::1" }],
    });
    assert.strictEqual((config.records[0] as { type: "AAAA"; address: string }).address, "::1");
  });
});

describe("Schema Validation - CRLF Injection Vectors", () => {
  it("rejects hostname with CR/LF in host key", () => {
    const config = {
      port: 53,
      hosts: {
        "evil.loop\r\nInjected: header": { records: [{ type: "A", address: "127.0.0.1" }] },
      },
    };
    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects redirect target with CRLF injection", () => {
    const config = {
      port: 53,
      hosts: {
        "redir.loop": {
          records: [{ type: "A", address: "1.2.3.4" }],
          redirect: { code: 302, target: "https://evil.com\r\nSet-Cookie: hacked=true" },
        },
      },
    };
    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects proxy upstream with CRLF", () => {
    const config = {
      port: 53,
      hosts: {
        "proxy.loop": {
          records: [{ type: "A", address: "10.0.0.1" }],
          http_proxy: {
            enabled: true,
            upstream: "http://evil.com\r\nInjected-Header: yes",
            headers: {},
          },
        },
      },
    };
    assert.throws(() => validateServerConfig(config), /error/i);
  });
});

describe("Schema Validation - Port Boundaries", () => {
  it("rejects port 0", () => {
    const config = { port: 0, hosts: {} };
    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("accepts minimum valid port (1)", () => {
    const config = validateServerConfig({ port: 1, hosts: {} });
    assert.strictEqual(config.port, 1);
  });

  it("accepts maximum valid port (65535)", () => {
    const config = validateServerConfig({ port: 65535, hosts: {} });
    assert.strictEqual(config.port, 65535);
  });

  it("rejects port above 65535", () => {
    const config = { port: 65536, hosts: {} };
    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("rejects port below 1", () => {
    const config = { port: -1, hosts: {} };
    assert.throws(() => validateServerConfig(config), /error/i);
  });
});

describe("Schema Validation - Hostname Length Limits", () => {
  it("accepts hostname at exactly 253 characters total (with dots)", () => {
    const adjustedLong = `${"a".repeat(62)}.${"b".repeat(62)}.${"c".repeat(62)}.${"d".repeat(62)}.x`; 
    assert.strictEqual(adjustedLong.length, 253);
    const config = validateServerConfig({
      port: 53,
      hosts: { [adjustedLong]: { records: [{ type: "A", address: "127.0.0.1" }] } },
    });
    assert.ok(adjustedLong in config.hosts);
  });

  it("rejects hostname at 254 characters (exceeds limit)", () => {
    const tooLong = "a".repeat(254);
    const config = { port: 53, hosts: { [tooLong]: { records: [{ type: "A", address: "127.0.0.1" }] } } };
    assert.throws(() => validateServerConfig(config), /error/i);
  });

  it("accepts single-character labels (minimum)", () => {
    const config = validateServerConfig({
      port: 53,
      hosts: { "a.b.c": { records: [{ type: "A", address: "127.0.0.1" }] } },
    });
    assert.ok("a.b.c" in config.hosts);
  });

  it("rejects label exceeding 63 characters", () => {
    const tooLongLabel = "a".repeat(64);
    const config = { port: 53, hosts: { [tooLongLabel]: { records: [{ type: "A", address: "127.0.0.1" }] } } };
    assert.throws(() => validateServerConfig(config), /error/i);
  });
});

describe("Schema Validation - Unsupported Record Types", () => {
  it("rejects SOA record type", () => {
    const config = { records: [{ type: "SOA", mname: "ns1.loop", rname: "admin.loop" }] as unknown };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects UNKNOWN record type", () => {
    const config = { records: [{ type: "UNKNOWN" }] as unknown };
    assert.throws(() => validateHostConfig(config), /error/i);
  });

  it("rejects empty string record type", () => {
    const config = { records: [{ type: "" }] as unknown };
    assert.throws(() => validateHostConfig(config), /error/i);
  });
});

describe("Schema Validation - Config Type Safety", () => {
  it("rejects null config", () => {
    assert.throws(() => validateServerConfig(null as unknown), /error/i);
  });

  it("rejects undefined config", () => {
    assert.throws(() => validateServerConfig(undefined as unknown), /error/i);
  });

  it("rejects string config", () => {
    assert.throws(() => validateServerConfig("not a config" as unknown), /error/i);
  });

  it("rejects number config", () => {
    assert.throws(() => validateServerConfig(42 as unknown), /error/i);
  });

  it("rejects array config (missing hosts)", () => {
    assert.throws(() => validateServerConfig([1, 2, 3] as unknown), /error/i);
  });

  it("accepts default port when not specified", () => {
    const config = { hosts: {} };
    const validated = validateServerConfig(config);
    assert.strictEqual(validated.port, 53);
  });

  it("rejects hosts that are not an object", () => {
    const config = { port: 53, hosts: "not an object" };
    assert.throws(() => validateServerConfig(config), /error/i);
  });
});
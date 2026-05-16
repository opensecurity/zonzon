import { describe, it } from "node:test";
import assert from "node:assert";
import { HttpProxyService } from "./http-proxy.js";
import { ServerConfig } from "./types.js";

describe("HttpProxyService - Zero-Trust Internal Resolution", { timeout: 15000 }, () => {
  const proxy = new HttpProxyService();

  it("resolves exact mapped internal hostnames bypassing external DNS", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "secure.brain.mlops": {
          records: [{ type: "A", address: "172.53.0.53" }]
        }
      }
    };
    
    const ips = await proxy.resolveHost("secure.brain.mlops", config);
    assert.deepStrictEqual(ips, ["172.53.0.53"]);
  });

  it("resolves wildcard mapped internal hostnames", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "*.brain.mlops": {
          records: [{ type: "A", address: "10.0.0.99" }]
        }
      }
    };
    
    const ips = await proxy.resolveHost("sandbox.brain.mlops", config);
    assert.deepStrictEqual(ips, ["10.0.0.99"]);
  });

  it("intentionally ignores catch-all '*' records to prevent infinite routing loops", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "*": {
          records: [{ type: "A", address: "192.168.1.1" }]
        }
      }
    };
    
    // Should bypass the "*" rule and attempt external DNS resolution, which fails with NXDOMAIN
    await assert.rejects(
      proxy.resolveHost("this-domain-does-not-exist.invalid", config),
      /ENOTFOUND|NXDOMAIN/
    );
  });

  it("prioritizes exact matches over wildcard matches in config.hosts", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "*.brain.mlops": {
          records: [{ type: "A", address: "10.0.0.1" }]
        },
        "exact.brain.mlops": {
          records: [{ type: "A", address: "10.0.0.2" }]
        }
      }
    };
    
    const exactIps = await proxy.resolveHost("exact.brain.mlops", config);
    assert.deepStrictEqual(exactIps, ["10.0.0.2"]);

    const wildIps = await proxy.resolveHost("other.brain.mlops", config);
    assert.deepStrictEqual(wildIps, ["10.0.0.1"]);
  });

  it("prioritizes AAAA records if present alongside A records in local resolution", async () => {
    const config: ServerConfig = {
      port: 53,
      hosts: {
        "ipv6.local": {
          records: [
            { type: "A", address: "10.0.0.1" },
            { type: "AAAA", address: "::1" }
          ]
        }
      }
    };

    const ips = await proxy.resolveHost("ipv6.local", config);
    assert.ok(ips.includes("10.0.0.1"));
    assert.ok(ips.includes("::1"));
    assert.strictEqual(ips.length, 2);
  });
});

describe("HttpProxyService - Target Firewall Validation Integration", { timeout: 15000 }, () => {
  const proxy = new HttpProxyService();

  it("resolves literal IPv4 addresses directly without DNS", async () => {
    const config: ServerConfig = { port: 53, hosts: {} };
    const ips = await proxy.validateTargetFirewall("http://8.8.8.8", config);
    assert.deepStrictEqual(ips, ["8.8.8.8"]);
  });

  it("validates target firewall allows internal routing when policy permits", async () => {
    const config: ServerConfig = {
      port: 53,
      firewall: {
        defaultPolicy: "allow",
        allowlist_ips: ["10.0.0.5"]
      },
      hosts: {
        "internal.app": {
          records: [{ type: "A", address: "10.0.0.5" }]
        }
      }
    };
    const ips = await proxy.validateTargetFirewall("https://internal.app:443", config);
    assert.deepStrictEqual(ips, ["10.0.0.5"]);
  });

  it("validates target firewall blocks internal routing when IP is blocklisted", async () => {
    const config: ServerConfig = {
      port: 53,
      firewall: {
        defaultPolicy: "allow",
        blocklist_ips: ["9.9.9.9"]
      },
      hosts: {
        "metadata.aws.internal": {
          records: [{ type: "A", address: "9.9.9.9" }]
        }
      }
    };
    
    await assert.rejects(
      proxy.validateTargetFirewall("http://metadata.aws.internal", config),
      /IP Blocked: 9\.9\.9\.9/
    );
  });

  it("blocks routing to domains completely unknown to internal mapping and external DNS", async () => {
    const config: ServerConfig = { port: 53, hosts: {} };
    
    await assert.rejects(
      proxy.validateTargetFirewall("http://this-domain-does-not-exist.invalid", config),
      /Resolution Fault: 'this-domain-does-not-exist\.invalid'/
    );
  });
});
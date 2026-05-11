import { describe, it } from "node:test";
import assert from "node:assert";
import { FirewallEngine } from "./firewall.js";
import { FirewallConfig } from "./types.js";

describe("FirewallEngine - Domain Evaluation", () => {
  const engine = new FirewallEngine();

  it("returns ALLOW when firewall config is undefined", () => {
    assert.strictEqual(engine.evaluateDomain("example.com"), "ALLOW");
  });

  it("respects default deny policy", () => {
    const config: FirewallConfig = { defaultPolicy: "deny" };
    assert.strictEqual(engine.evaluateDomain("example.com", config), "DENY");
  });

  it("respects default allow policy", () => {
    const config: FirewallConfig = { defaultPolicy: "allow" };
    assert.strictEqual(engine.evaluateDomain("example.com", config), "ALLOW");
  });

  it("blocks explicitly blocklisted domains", () => {
    const config: FirewallConfig = {
      defaultPolicy: "allow",
      blocklist_domains: ["evil.com"],
    };
    assert.strictEqual(engine.evaluateDomain("evil.com", config), "DENY");
  });

  it("allows explicitly allowlisted domains overriding default deny", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_domains: ["good.com"],
    };
    assert.strictEqual(engine.evaluateDomain("good.com", config), "ALLOW");
  });

  it("prioritizes blocklist over allowlist", () => {
    const config: FirewallConfig = {
      defaultPolicy: "allow",
      allowlist_domains: ["conflict.com"],
      blocklist_domains: ["conflict.com"],
    };
    assert.strictEqual(engine.evaluateDomain("conflict.com", config), "DENY");
  });

  it("supports exact domain matching case-insensitively", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_domains: ["secure.loop"],
    };
    assert.strictEqual(engine.evaluateDomain("SECURE.LOOP", config), "ALLOW");
  });

  it("supports wildcard domain matching", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_domains: ["*.internal.net"],
    };
    assert.strictEqual(engine.evaluateDomain("api.internal.net", config), "ALLOW");
    assert.strictEqual(engine.evaluateDomain("db.internal.net", config), "ALLOW");
    assert.strictEqual(engine.evaluateDomain("internal.net", config), "DENY"); 
  });

  it("handles trailing dots seamlessly", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_domains: ["trailing.loop"],
    };
    assert.strictEqual(engine.evaluateDomain("trailing.loop.", config), "ALLOW");
  });
});

describe("FirewallEngine - IP Evaluation", () => {
  const engine = new FirewallEngine();

  it("blocks malformed IPs universally", () => {
    const config: FirewallConfig = { defaultPolicy: "allow" };
    assert.strictEqual(engine.evaluateIp("not.an.ip", config), "DENY");
    assert.strictEqual(engine.evaluateIp("999.999.999.999", config), "DENY");
  });

  it("blocks explicitly blocklisted IPs", () => {
    const config: FirewallConfig = {
      defaultPolicy: "allow",
      blocklist_ips: ["192.168.1.100"],
    };
    assert.strictEqual(engine.evaluateIp("192.168.1.100", config), "DENY");
  });

  it("blocks IPs matching blocklist CIDR ranges", () => {
    const config: FirewallConfig = {
      defaultPolicy: "allow",
      blocklist_ranges: ["10.0.0.0/8"],
    };
    assert.strictEqual(engine.evaluateIp("10.5.5.5", config), "DENY");
    assert.strictEqual(engine.evaluateIp("11.0.0.1", config), "ALLOW");
  });

  it("allows IPs matching allowlist CIDR ranges overriding default deny", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_ranges: ["172.16.0.0/12"],
    };
    assert.strictEqual(engine.evaluateIp("172.20.5.1", config), "ALLOW");
    assert.strictEqual(engine.evaluateIp("192.168.1.1", config), "DENY");
  });

  it("prioritizes IP blocklist over IP allowlist", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_ips: ["1.1.1.1"],
      blocklist_ips: ["1.1.1.1"],
    };
    assert.strictEqual(engine.evaluateIp("1.1.1.1", config), "DENY");
  });

  it("safely ignores malformed CIDR ranges without crashing", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_ranges: ["invalid/cidr/string"],
      allowlist_ips: ["8.8.8.8"]
    };
    assert.strictEqual(engine.evaluateIp("8.8.8.8", config), "ALLOW");
    assert.strictEqual(engine.evaluateIp("1.1.1.1", config), "DENY");
  });
});

describe("FirewallEngine - Outbound SSRF Protection", () => {
  const engine = new FirewallEngine();

  it("blocks IPv4 loopback addresses natively", () => {
    assert.strictEqual(engine.isRestrictedOutbound("127.0.0.1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("127.255.255.254"), true);
  });

  it("blocks IPv4 RFC1918 private network addresses natively", () => {
    assert.strictEqual(engine.isRestrictedOutbound("10.0.0.1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("172.16.0.1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("172.31.255.255"), true);
    assert.strictEqual(engine.isRestrictedOutbound("192.168.1.1"), true);
  });

  it("blocks IPv4 link-local and broadcast addresses natively", () => {
    assert.strictEqual(engine.isRestrictedOutbound("169.254.169.254"), true);
    assert.strictEqual(engine.isRestrictedOutbound("0.0.0.0"), true);
    assert.strictEqual(engine.isRestrictedOutbound("224.0.0.1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("255.255.255.255"), true);
  });

  it("blocks IPv4 Carrier-Grade NAT addresses natively", () => {
    assert.strictEqual(engine.isRestrictedOutbound("100.64.0.1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("100.127.255.254"), true);
  });

  it("allows standard public IPv4 addresses", () => {
    assert.strictEqual(engine.isRestrictedOutbound("8.8.8.8"), false);
    assert.strictEqual(engine.isRestrictedOutbound("1.1.1.1"), false);
    assert.strictEqual(engine.isRestrictedOutbound("104.21.5.1"), false);
  });

  it("blocks IPv6 loopback and unspecified addresses natively", () => {
    assert.strictEqual(engine.isRestrictedOutbound("::1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("::"), true);
  });

  it("blocks IPv6 link-local and unique local addresses natively", () => {
    assert.strictEqual(engine.isRestrictedOutbound("fe80::1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("fc00::1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("fd00::1"), true);
  });

  it("blocks IPv4-mapped IPv6 addresses for restricted ranges", () => {
    assert.strictEqual(engine.isRestrictedOutbound("::ffff:127.0.0.1"), true);
    assert.strictEqual(engine.isRestrictedOutbound("::ffff:169.254.169.254"), true);
  });

  it("allows configured overrides for restricted IPs via allowlist", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_ips: ["127.0.0.1"],
    };
    assert.strictEqual(engine.evaluateOutbound("127.0.0.1", config), "ALLOW");
  });

  it("allows configured overrides for restricted IPs via CIDR", () => {
    const config: FirewallConfig = {
      defaultPolicy: "deny",
      allowlist_ranges: ["10.0.0.0/8"],
    };
    assert.strictEqual(engine.evaluateOutbound("10.5.0.1", config), "ALLOW");
  });
});
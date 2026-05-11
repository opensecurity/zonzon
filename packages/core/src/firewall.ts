import * as net from "net";
import { FirewallConfig } from "./types.js";

export class FirewallEngine {
  private ipToInt(ip: string): number {
    return ip.split('.').reduce((int, octet) => (int << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  private matchCidr(ip: string, cidr: string): boolean {
    try {
      const [range, bits] = cidr.split('/');
      const mask = bits ? ~(Math.pow(2, 32 - parseInt(bits, 10)) - 1) : 0xFFFFFFFF;
      return (this.ipToInt(ip) & mask) === (this.ipToInt(range) & mask);
    } catch {
      return false;
    }
  }

  private matchDomain(domain: string, pattern: string): boolean {
    if (pattern === "*") return true; 
    const normDomain = domain.toLowerCase().replace(/\.$/, "");
    const normPattern = pattern.toLowerCase().replace(/\.$/, "");
    
    if (normPattern === normDomain) return true;
    if (normPattern.startsWith("*.")) {
      const suffix = normPattern.slice(2);
      return normDomain === suffix || normDomain.endsWith("." + suffix);
    }
    return false;
  }

  public evaluateIp(ip: string, fw?: FirewallConfig): "ALLOW" | "DENY" {
    if (!fw) return "ALLOW"; 
    if (!net.isIPv4(ip)) return "DENY"; 

    if (fw.blocklist_ips && fw.blocklist_ips.includes(ip)) return "DENY";

    for (const range of fw.blocklist_ranges || []) {
      if (this.matchCidr(ip, range)) return "DENY";
    }

    if (fw.allowlist_ips && fw.allowlist_ips.includes(ip)) return "ALLOW";

    for (const range of fw.allowlist_ranges || []) {
      if (this.matchCidr(ip, range)) return "ALLOW";
    }

    return fw.defaultPolicy === "allow" ? "ALLOW" : "DENY";
  }

  public evaluateDomain(domain: string, fw?: FirewallConfig): "ALLOW" | "DENY" {
    if (!fw) return "ALLOW";

    for (const pattern of fw.blocklist_domains || []) {
      if (this.matchDomain(domain, pattern)) return "DENY";
    }

    for (const pattern of fw.allowlist_domains || []) {
      if (this.matchDomain(domain, pattern)) return "ALLOW";
    }

    return fw.defaultPolicy === "allow" ? "ALLOW" : "DENY";
  }
}

export const firewallEngine = new FirewallEngine();
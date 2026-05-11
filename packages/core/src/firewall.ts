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
      return normDomain.endsWith("." + suffix);
    }
    return false;
  }

  public isRestrictedOutbound(ip: string): boolean {
    if (net.isIPv6(ip)) {
      const normalized = ip.toLowerCase();
      if (normalized === "::1") return true;
      if (normalized === "::") return true;
      if (normalized.startsWith("fe80:")) return true;
      if (normalized.startsWith("fc00:") || normalized.startsWith("fd")) return true;
      if (normalized.includes("::ffff:127.")) return true;
      if (normalized.includes("::ffff:169.254.")) return true;
      return false;
    }

    if (!net.isIPv4(ip)) return true;

    const parts = ip.split('.').map(Number);
    
    if (parts[0] === 0) return true; 
    if (parts[0] === 10) return true; 
    if (parts[0] === 127) return true; 
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; 
    if (parts[0] === 169 && parts[1] === 254) return true; 
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; 
    if (parts[0] === 192 && parts[1] === 168) return true; 
    if (parts[0] >= 224 && parts[0] <= 239) return true; 
    if (parts[0] >= 240 && parts[0] <= 255) return true; 
    
    return false;
  }

  public evaluateOutbound(ip: string, fw?: FirewallConfig): "ALLOW" | "DENY" {
    if (fw) {
      if (fw.allowlist_ips && fw.allowlist_ips.includes(ip)) return "ALLOW";
      if (net.isIPv4(ip)) {
        for (const range of fw.allowlist_ranges || []) {
          if (this.matchCidr(ip, range)) return "ALLOW";
        }
      }
    }
    
    if (this.isRestrictedOutbound(ip)) return "DENY";
    
    return "ALLOW";
  }

  public evaluateIp(ip: string, fw?: FirewallConfig): "ALLOW" | "DENY" {
    if (!fw) return "ALLOW"; 
    if (!net.isIPv4(ip) && !net.isIPv6(ip)) return "DENY"; 

    if (fw.blocklist_ips && fw.blocklist_ips.includes(ip)) return "DENY";

    if (net.isIPv4(ip)) {
      for (const range of fw.blocklist_ranges || []) {
        if (this.matchCidr(ip, range)) return "DENY";
      }
    }

    if (fw.allowlist_ips && fw.allowlist_ips.includes(ip)) return "ALLOW";

    if (net.isIPv4(ip)) {
      for (const range of fw.allowlist_ranges || []) {
        if (this.matchCidr(ip, range)) return "ALLOW";
      }
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
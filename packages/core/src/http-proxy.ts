import * as net from "node:net";
import * as dns from "node:dns/promises";
import { HostConfig, ProxiedRequest, ModifiedHeaders, FirewallConfig, ServerConfig } from "./types.js";
import { firewallEngine } from "./firewall.js";
import { decryptSecret } from "./crypto.js";

export class HttpProxyService {
  async resolveHost(hostname: string, config: ServerConfig): Promise<string[]> {
    const normalizedName = hostname.toLowerCase().replace(/\.$/, "");
    
    let hostConfig = config.hosts[normalizedName];
    if (!hostConfig) {
      const labels = normalizedName.split(".");
      for (let i = 0; i < labels.length - 1; i++) {
        const wildcardKey = "*." + labels.slice(i).join(".");
        if (config.hosts[wildcardKey]) {
          hostConfig = config.hosts[wildcardKey];
          break;
        }
      }
    }

    if (hostConfig && hostConfig.records) {
      const ips = hostConfig.records
        .filter(r => r.type === "A" || r.type === "AAAA")
        .map(r => (r as any).address);
      if (ips.length > 0) return ips;
    }

    const records = await dns.resolve(hostname);
    return records.filter(ip => typeof ip === "string") as string[];
  }

  async validateTargetFirewall(targetUrl: string, config: ServerConfig): Promise<string[]> {
    const parsed = new URL(targetUrl);
    const host = parsed.hostname;
    const isLiteralIp = net.isIP(host) !== 0;

    if (config.firewall && !isLiteralIp) {
      if (firewallEngine.evaluateDomain(host, config.firewall) === "DENY") {
        throw new Error(`Domain Blocked: '${host}'`);
      }
    }

    let targetIps: string[] = [];

    if (isLiteralIp) {
      targetIps = [host];
    } else {
      try {
        targetIps = await this.resolveHost(host, config);
      } catch {
        throw new Error(`Resolution Fault: '${host}'`);
      }
    }

    if (targetIps.length === 0) {
      throw new Error(`NXDOMAIN: '${host}'`);
    }

    for (const ip of targetIps) {
      if (firewallEngine.evaluateOutbound(ip, config.firewall) === "DENY") {
        throw new Error(`Restricted IP: (${ip})`);
      }
      
      if (config.firewall) {
        if (firewallEngine.evaluateIp(ip, config.firewall) === "DENY") {
          throw new Error(`IP Blocked: ${ip}`);
        }
      }
    }

    return targetIps;
  }

  getUpstreamHeaders(config: HostConfig, originalRequest: ProxiedRequest): ModifiedHeaders {
    const result: ModifiedHeaders = {
      upstreamHeaders: {},
      clientResponseHeaders: {},
    };

    if (!config.http_proxy || !config.http_proxy.enabled) {
      return result;
    }

    for (const [key, value] of Object.entries(originalRequest.headers)) {
      const lowerKey = key.toLowerCase();
      if (!["connection", "keep-alive", "te", "transfer-encoding", "upgrade", "proxy-authorization"].includes(lowerKey)) {
        result.clientResponseHeaders[key] = value;
      }
    }

    for (const [key, value] of Object.entries(config.http_proxy.headers)) {
      const decryptedValue = decryptSecret(value);
      const sanitized = this.sanitizeHeader(decryptedValue);
      if (sanitized) {
        result.upstreamHeaders[key] = sanitized;
        result.clientResponseHeaders[key] = sanitized;
      }
    }

    result.clientResponseHeaders["X-Proxy"] = "zonzon";

    if (config.http_proxy.forwardRequestBody) {
      if (originalRequest.body) {
        const maxBodyBytes = config.http_proxy.maxRequestBodyBytes ?? 5 * 1024 * 1024;
        if (originalRequest.body.length <= maxBodyBytes) {
          result.upstreamHeaders["X-Body-Forwarded"] = "true";
          result.upstreamHeaders["X-Body-Size"] = String(originalRequest.body.length);
        } else {
          throw new Error(`Payload Limit Exceeded`);
        }
      } else {
        result.upstreamHeaders["X-Body-Forwarded"] = "true";
        if (originalRequest.headers["content-length"]) {
          result.upstreamHeaders["X-Body-Size"] = originalRequest.headers["content-length"];
        }
      }
    }

    return result;
  }

  checkRedirect(config: HostConfig): { code: number; target: string } | null {
    if (!config.redirect || !config.redirect.enabled) {
      return null;
    }

    const { code, target } = config.redirect;

    if (![301, 302, 303, 307, 308].includes(code)) {
      return null;
    }

    try {
      const parsed = new URL(target);
      if (!parsed.protocol || !parsed.hostname) {
        return null;
      }
    } catch {
      return null;
    }

    return { code, target };
  }

  sanitizeHeader(value: string): string | null {
    if (typeof value !== "string") return null;
    if (/[\r\n\t]/.test(value)) return null;
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)) return null;
    if (/%0[dD]/i.test(value) || /%0[aA]/.test(value)) return null;
    if (value.length > 8192) return null;
    return value;
  }

  isValidHeaderName(name: string): boolean {
    if (typeof name !== "string" || name.length === 0) return false;
    if (name.length > 256) return false;
    return /^[a-zA-Z0-9!#$%&'*+\-.^_`|~]+$/.test(name);
  }

  getHopByHopHeaders(): string[] {
    return [
      "connection",
      "keep-alive",
      "proxy-authenticate",
      "proxy-authorization",
      "te",
      "trailer",
      "transfer-encoding",
      "upgrade",
    ];
  }

  calculateTimeout(config: HostConfig): number {
    if (config.http_proxy?.enabled) {
      return Math.max(1000, Math.min(30000, 5000));
    }
    return 0;
  }
}
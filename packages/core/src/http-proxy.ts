import * as net from "net";
import * as dns from "dns/promises";
import { HostConfig, ProxiedRequest, ModifiedHeaders, FirewallConfig } from "./types.js";
import { firewallEngine } from "./firewall.js";

export class HttpProxyService {
  async validateTargetFirewall(targetUrl: string, fw?: FirewallConfig): Promise<string[]> {
    const parsed = new URL(targetUrl);
    const host = parsed.hostname;
    const isLiteralIp = net.isIP(host) !== 0;

    if (fw && !isLiteralIp) {
      if (firewallEngine.evaluateDomain(host, fw) === "DENY") {
        throw new Error(`Domain Blocked: '${host}'`);
      }
    }

    let targetIps: string[] = [];

    if (isLiteralIp) {
      targetIps = [host];
    } else {
      try {
        const records = await dns.resolve(host);
        targetIps = records.filter(ip => typeof ip === 'string') as string[];
      } catch {
        throw new Error(`Resolution Fault: '${host}'`);
      }
    }

    if (targetIps.length === 0) {
      throw new Error(`NXDOMAIN: '${host}'`);
    }

    for (const ip of targetIps) {
      if (firewallEngine.evaluateOutbound(ip, fw) === "DENY") {
        throw new Error(`Restricted IP: (${ip})`);
      }
      
      if (fw) {
        if (firewallEngine.evaluateIp(ip, fw) === "DENY") {
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
      const sanitized = this.sanitizeHeader(value);
      if (sanitized) {
        result.upstreamHeaders[key] = sanitized;
        result.clientResponseHeaders[key] = sanitized;
      }
    }

    result.clientResponseHeaders["X-Proxy"] = "zonzon";

    if (config.http_proxy.forwardRequestBody && originalRequest.body) {
      const maxBodyBytes = config.http_proxy.maxRequestBodyBytes ?? 5 * 1024 * 1024;
      if (originalRequest.body.length <= maxBodyBytes) {
        result.upstreamHeaders["X-Body-Forwarded"] = "true";
        result.upstreamHeaders["X-Body-Size"] = String(originalRequest.body.length);
      } else {
        throw new Error(`Payload Limit Exceeded`);
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
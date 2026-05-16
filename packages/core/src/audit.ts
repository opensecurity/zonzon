import { DNS_TYPES } from "./types.js";

const REVERSE_DNS_TYPES = Object.fromEntries(Object.entries(DNS_TYPES).map(([k, v]) => [v, k]));

export class AuditLogger {
  private isTestEnv = process.argv.includes("--test") || process.env.NODE_ENV === "test";
  private useJson = false;

  private metrics = {
    dns_queries: 0,
    dns_blocked: 0,
    http_requests: 0,
    http_blocked: 0,
    firewall_drops: 0,
    system_events: 0,
    errors: 0
  };

  private sanitize(input: any): string {
    return String(input || "").replace(/[\r\n\t]/g, " ").replace(/[^\x20-\x7E]/g, "?");
  }

  public setJsonMode(enable: boolean): void {
    this.useJson = enable;
  }

  public getMetricsPrometheus(): string {
    return [
      `# HELP zonzon_dns_queries_total Total DNS queries processed`,
      `# TYPE zonzon_dns_queries_total counter`,
      `zonzon_dns_queries_total ${this.metrics.dns_queries}`,
      `# HELP zonzon_dns_blocked_total Total DNS queries blocked by policy`,
      `# TYPE zonzon_dns_blocked_total counter`,
      `zonzon_dns_blocked_total ${this.metrics.dns_blocked}`,
      `# HELP zonzon_http_requests_total Total HTTP requests routed`,
      `# TYPE zonzon_http_requests_total counter`,
      `zonzon_http_requests_total ${this.metrics.http_requests}`,
      `# HELP zonzon_http_blocked_total Total HTTP requests blocked`,
      `# TYPE zonzon_http_blocked_total counter`,
      `zonzon_http_blocked_total ${this.metrics.http_blocked}`,
      `# HELP zonzon_firewall_drops_total Total connection drops across L3/L4/L7`,
      `# TYPE zonzon_firewall_drops_total counter`,
      `zonzon_firewall_drops_total ${this.metrics.firewall_drops}`,
      `# HELP zonzon_errors_total Total system errors encountered`,
      `# TYPE zonzon_errors_total counter`,
      `zonzon_errors_total ${this.metrics.errors}`
    ].join("\n") + "\n";
  }

  public dns(ip: string, questions: any[], rcode: number, cached: boolean = false): void {
    this.metrics.dns_queries += questions.length;
    if (rcode === 5 || rcode === 3) this.metrics.dns_blocked += questions.length;
    
    if (this.isTestEnv) return;
    
    const ts = new Date().toISOString();
    if (this.useJson) {
      console.log(JSON.stringify({
        timestamp: ts,
        level: "INFO",
        component: "DNS",
        ip,
        questions: questions.map(q => ({ name: q.name, type: REVERSE_DNS_TYPES[q.type] || q.type })),
        rcode,
        cached
      }));
    } else {
      const codeMap: any = { 0: "Found (NOERROR)", 3: "Not Found (NXDOMAIN)", 5: "Blocked by Firewall (REFUSED)" };
      const prefix = cached ? "[Cached] " : "";
      questions.forEach(q => {
        console.log(`[${ts}] [DNS] ${this.sanitize(ip)} | ${prefix}${REVERSE_DNS_TYPES[q.type] || q.type} ${this.sanitize(q.name)} -> ${codeMap[rcode] || rcode}`);
      });
    }
  }

  public firewall(ip: string, target: string, action: "ALLOW" | "DENY", detail: string = "") {
    if (action === "DENY") this.metrics.firewall_drops++;
    
    if (this.isTestEnv) return;
    
    const ts = new Date().toISOString();
    if (this.useJson) {
      console.log(JSON.stringify({
        timestamp: ts,
        level: action === "DENY" ? "WARN" : "INFO",
        component: "FIREWALL",
        action,
        ip,
        target,
        detail
      }));
    } else {
      const color = action === "ALLOW" ? "\x1b[32mALLOW\x1b[0m" : "\x1b[31mDENY\x1b[0m";
      console.log(`[${ts}] [FIREWALL] ${this.sanitize(ip)} | ${color} | ${this.sanitize(target)} ${detail ? `(${this.sanitize(detail)})` : ""}`);
    }
  }

  public http(ip: string, method: string, host: string, path: string, status: number, target: string = "") {
    this.metrics.http_requests++;
    if (status === 403 || status === 413 || status === 429) this.metrics.http_blocked++;

    if (this.isTestEnv) return;
    
    const ts = new Date().toISOString();
    if (this.useJson) {
      console.log(JSON.stringify({
        timestamp: ts,
        level: status >= 400 ? "WARN" : "INFO",
        component: "HTTP",
        ip,
        method,
        host,
        path,
        status,
        target
      }));
    } else {
      console.log(`[${ts}] [HTTP] ${this.sanitize(ip)} | Returned Status ${status} | ${this.sanitize(method)} ${this.sanitize(host)}${this.sanitize(path)} ${target ? `-> ${this.sanitize(target)}` : ""}`);
    }
  }

  public system(msg: string) { 
    this.metrics.system_events++;
    if (this.isTestEnv) return;
    
    const ts = new Date().toISOString();
    if (this.useJson) {
      console.log(JSON.stringify({
        timestamp: ts,
        level: "INFO",
        component: "SYSTEM",
        message: msg
      }));
    } else {
      console.log(`[${ts}] [SYSTEM] ${this.sanitize(msg)}`);
    }
  }
  
  public error(msg: string) { 
    this.metrics.errors++;
    if (this.isTestEnv) return;
    
    const ts = new Date().toISOString();
    if (this.useJson) {
      console.error(JSON.stringify({
        timestamp: ts,
        level: "ERROR",
        component: "SYSTEM",
        message: msg
      }));
    } else {
      console.error(`[${ts}] [ERROR] \x1b[31m${this.sanitize(msg)}\x1b[0m`);
    }
  }
}

export const audit = new AuditLogger();
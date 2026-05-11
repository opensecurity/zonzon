import { DNS_TYPES } from "./types.js";

const REVERSE_DNS_TYPES = Object.fromEntries(Object.entries(DNS_TYPES).map(([k, v]) => [v, k]));

export class AuditLogger {
  private isTestEnv = process.argv.includes("--test") || process.env.NODE_ENV === "test";

  private sanitize(input: any): string {
    return String(input || "").replace(/[\r\n\t]/g, " ").replace(/[^\x20-\x7E]/g, "?");
  }

  public dns(ip: string, questions: any[], rcode: number, cached: boolean = false): void {
    if (this.isTestEnv) return;
    const codeMap: any = { 0: "Found (NOERROR)", 3: "Not Found (NXDOMAIN)", 5: "Blocked by Firewall (REFUSED)" };
    const prefix = cached ? "[Cached] " : "";
    questions.forEach(q => {
      console.log(`[DNS] ${this.sanitize(ip)} | ${prefix}${REVERSE_DNS_TYPES[q.type] || q.type} ${this.sanitize(q.name)} -> ${codeMap[rcode] || rcode}`);
    });
  }

  public firewall(ip: string, target: string, action: "ALLOW" | "DENY", detail: string = "") {
    if (this.isTestEnv) return;
    const color = action === "ALLOW" ? "\x1b[32mALLOW\x1b[0m" : "\x1b[31mDENY\x1b[0m";
    console.log(`[FIREWALL] ${this.sanitize(ip)} | ${color} | ${this.sanitize(target)} ${detail ? `(${this.sanitize(detail)})` : ""}`);
  }

  public http(ip: string, method: string, host: string, path: string, status: number, target: string = "") {
    if (this.isTestEnv) return;
    console.log(`[HTTP] ${this.sanitize(ip)} | Returned Status ${status} | ${this.sanitize(method)} ${this.sanitize(host)}${this.sanitize(path)} ${target ? `-> ${this.sanitize(target)}` : ""}`);
  }

  public system(msg: string) { 
    if (this.isTestEnv) return;
    console.log(`[SYSTEM] ${this.sanitize(msg)}`); 
  }
  
  public error(msg: string) { 
    if (this.isTestEnv) return;
    console.error(`[ERROR] \x1b[31m${this.sanitize(msg)}\x1b[0m`); 
  }
}

export const audit = new AuditLogger();
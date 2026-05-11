export interface ARecord {
  type: "A";
  address: string;
}

export interface AAAARecord {
  type: "AAAA";
  address: string;
}

export interface CNAME {
  type: "CNAME";
  target: string;
}

export interface TXT {
  type: "TXT";
  data: string[];
}

export interface MX {
  type: "MX";
  priority: number;
  exchange: string;
}

export interface NS {
  type: "NS";
  target: string;
}

export interface SRV {
  type: "SRV";
  priority: number;
  weight: number;
  port: number;
  target: string;
}

export interface PTR {
  type: "PTR";
  target: string;
}

export type DnsRecord = ARecord | AAAARecord | CNAME | TXT | MX | NS | SRV | PTR;

export interface HttpProxyConfig {
  enabled: boolean;
  upstream?: string;
  headers: Record<string, string>;
  forwardRequestBody?: boolean;
  maxRequestBodyBytes?: number;
}

export interface RedirectConfig {
  enabled: boolean;
  code: number;
  target: string;
}

export interface HostConfig {
  records: DnsRecord[];
  http_proxy?: HttpProxyConfig;
  redirect?: RedirectConfig;
}

export interface FirewallConfig {
  defaultPolicy: "allow" | "deny";
  allowlist_domains?: string[];
  blocklist_domains?: string[];
  allowlist_ranges?: string[];
  blocklist_ranges?: string[];
  allowlist_ips?: string[];
  blocklist_ips?: string[];
}

export interface ControlPlaneConfig {
  enabled?: boolean;
  port?: number;
  apiKey?: string;
}

export interface ServerConfig {
  port: number;
  httpPort?: number;
  httpsPort?: number;
  fallbackDns?: string;
  firewall?: FirewallConfig;
  controlPlane?: ControlPlaneConfig;
  dnsCacheMaxSize?: number;
  dnsCacheTtlMs?: number;
  maxTcpConnections?: number;
  tcpIdleTimeoutMs?: number;
  rateLimitMaxRequests?: number;
  rateLimitWindowMs?: number;
  hosts: Record<string, HostConfig>;
}

export interface DnsQuestion {
  name: string;
  type: number;
  class: number;
}

export interface DnsResponseHeader {
  id: number;
  flags: number;
  qdcount: number;
  ancount: number;
  nscount: number;
  arcount: number;
}

export interface DnsQuestionSection {
  questions: DnsQuestion[];
  additional?: string; 
}

export interface ProxiedRequest {
  hostname: string;
  originalUrl: string;
  headers: Record<string, string>;
  method: string;
  body?: Buffer;
}

export interface ModifiedHeaders {
  upstreamHeaders: Record<string, string>;
  clientResponseHeaders: Record<string, string>;
}

export const DNS_CLASSES = { IN: 1 };

export const DNS_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  PTR: 12,
  AAAA: 28,
  SRV: 33,
} as const;

export const DNS_OPCODE = {
  QUERY: 0,
  IQUERY: 1,
  STATUS: 2,
};

export const DNS_RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
};

export const RESPONSE_FLAGS = {
  QR: (1 << 15) as number,
  AA: (1 << 10) as number,
  TC: (1 << 9) as number,
  RD: (1 << 8) as number,
  RA: (1 << 7) as number,
};

export const MAX_DNS_PACKET_SIZE = 512;
export const MAX_TXT_RECORD_LENGTH = 255;
import { z } from "zod";
import * as net from "node:net";
import { HostConfig, DnsRecord, ServerConfig } from "./types.js";

const CrlfFreeString = z.string().max(8192).refine((val) => !/[\r\n]/.test(val), "Contains CR/LF");

const Ipv4Schema = z.string().max(45).refine((ip) => net.isIPv4(ip), "Invalid IPv4");
const Ipv6Schema = z.string().max(45).refine((ip) => net.isIPv6(ip), "Invalid IPv6");

const HostnameSchema = z.string().max(253).refine((hostname) => {
  const parts = hostname.split(".");
  const hostPattern = /^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$/;
  return parts.every((part) => part.length > 0 && part.length <= 63 && hostPattern.test(part));
}, "Invalid hostname");

const PortSchema = z.number().int().min(1).max(65535);

const ARecordSchema = z.object({ type: z.literal("A"), address: Ipv4Schema });
const AAAARecordSchema = z.object({ type: z.literal("AAAA"), address: Ipv6Schema });
const CNAMERecordSchema = z.object({ type: z.literal("CNAME"), target: HostnameSchema });
const TXTRecordSchema = z.object({ type: z.literal("TXT"), data: z.array(z.string().max(255).refine((val) => !/[\r\n]/.test(val), "Contains CR/LF")) });
const MXRecordSchema = z.object({ type: z.literal("MX"), priority: z.number().int().min(0).max(65535), exchange: HostnameSchema });
const NSRecordSchema = z.object({ type: z.literal("NS"), target: HostnameSchema });
const SRVRecordSchema = z.object({ type: z.literal("SRV"), priority: z.number().int().min(0).max(65535), weight: z.number().int().min(0).max(65535), port: PortSchema, target: HostnameSchema });
const PTRRecordSchema = z.object({ type: z.literal("PTR"), target: HostnameSchema });

const DnsRecordSchema = z.discriminatedUnion("type", [
  ARecordSchema,
  AAAARecordSchema,
  CNAMERecordSchema,
  TXTRecordSchema,
  MXRecordSchema,
  NSRecordSchema,
  SRVRecordSchema,
  PTRRecordSchema,
]);

const TlsSchema = z.object({
  cert: z.string().min(1),
  key: z.string().min(1),
  ca: z.string().min(1).optional(),
  serverName: HostnameSchema.optional()
});

const HttpProxySchema = z.object({
  enabled: z.boolean(),
  upstream: CrlfFreeString.optional(),
  headers: z.record(z.string().max(256).regex(/^[a-zA-Z0-9\-]+$/), CrlfFreeString).default({}),
  forwardRequestBody: z.boolean().default(false),
  maxRequestBodyBytes: z.number().int().min(0).max(10485760).default(5242880),
  clientTls: TlsSchema.optional()
}).refine(data => !data.enabled || !!data.upstream, {
  message: "HTTP proxy requires 'upstream' URL when enabled",
  path: ["upstream"]
});

const TlsProxySchema = z.object({
  targetPort: z.number().int().min(1).max(65535).optional(),
  targetIp: Ipv4Schema.or(Ipv6Schema).optional()
});

const RedirectSchema = z.object({
  enabled: z.boolean().default(true),
  code: z.union([z.literal(301), z.literal(302), z.literal(303), z.literal(307), z.literal(308)]),
  target: CrlfFreeString,
});

const HostConfigSchema = z.object({
  records: z.array(DnsRecordSchema).default([]),
  http_proxy: HttpProxySchema.optional(),
  tls_proxy: TlsProxySchema.optional(),
  redirect: RedirectSchema.optional(),
});

const FirewallSchema = z.object({
  defaultPolicy: z.enum(["allow", "deny"]).default("deny"),
  allowlist_domains: z.array(z.string().max(253)).default([]),
  blocklist_domains: z.array(z.string().max(253)).default([]),
  allowlist_ranges: z.array(z.string().max(40)).default([]),
  blocklist_ranges: z.array(z.string().max(40)).default([]),
  allowlist_ips: z.array(z.string().max(40)).default([]),
  blocklist_ips: z.array(z.string().max(40)).default([]),
});

const ControlPlaneSchema = z.object({
  enabled: z.boolean().default(true).optional(),
  port: z.coerce.number().int().min(1).max(65535).default(8080).optional(),
  socketPath: z.string().max(256).optional(),
  apiKey: z.string().max(256).optional()
});

const ServerConfigSchema = z.object({
  port: z.coerce.number().int().min(1).max(65535).default(53),
  httpPort: z.coerce.number().int().min(1).max(65535).optional(),
  httpsPort: z.coerce.number().int().min(1).max(65535).optional(),
  tls: TlsSchema.optional(),
  dotPort: z.coerce.number().int().min(1).max(65535).default(853).optional(),
  dohPort: z.coerce.number().int().min(1).max(65535).default(8443).optional(),
  fallbackDns: Ipv4Schema.optional(),
  firewall: FirewallSchema.optional(),
  controlPlane: ControlPlaneSchema.optional(),
  dnsCacheMaxSize: z.coerce.number().int().min(1).max(100000).default(1024),
  dnsCacheTtlMs: z.coerce.number().int().min(0).max(3600000).default(0),
  maxTcpConnections: z.coerce.number().int().min(1).max(10000).default(100),
  tcpIdleTimeoutMs: z.coerce.number().int().min(1000).max(600000).default(30000),
  rateLimitMaxRequests: z.coerce.number().int().min(0).max(100000).default(0),
  rateLimitWindowMs: z.coerce.number().int().min(100).max(60000).default(1000),
  hosts: z.record(z.string().max(253), HostConfigSchema).default({}),
}).refine(data => {
  for (const key of Object.keys(data.hosts)) {
    const normalized = key.toLowerCase();
    if (normalized === "*") continue;
    if (normalized.startsWith("*.")) {
      HostnameSchema.parse(normalized.slice(2));
    } else {
      HostnameSchema.parse(normalized);
    }
  }
  return true;
}, "Contains invalid hostnames in configuration keys");

export function validateARecord(record: unknown): DnsRecord { return ARecordSchema.parse(record) as DnsRecord; }
export function validateAAAARecord(record: unknown): DnsRecord { return AAAARecordSchema.parse(record) as DnsRecord; }
export function validateCNAME(record: unknown): DnsRecord { return CNAMERecordSchema.parse(record) as DnsRecord; }
export function validateTXT(record: unknown): DnsRecord { return TXTRecordSchema.parse(record) as DnsRecord; }
export function validateMX(record: unknown): DnsRecord { return MXRecordSchema.parse(record) as DnsRecord; }
export function validateNS(record: unknown): DnsRecord { return NSRecordSchema.parse(record) as DnsRecord; }
export function validateSRV(record: unknown): DnsRecord { return SRVRecordSchema.parse(record) as DnsRecord; }
export function validatePTR(record: unknown): DnsRecord { return PTRRecordSchema.parse(record) as DnsRecord; }

export function validateRecord(record: unknown): DnsRecord {
  if (!record || typeof record !== "object" || !("type" in record)) {
    throw new Error("DNS record must be an object with a 'type' field");
  }
  return DnsRecordSchema.parse(record) as DnsRecord;
}

export function validateHostConfig(config: unknown): HostConfig {
  try {
    return HostConfigSchema.parse(config) as HostConfig;
  } catch (error) {
    throw new Error(`Host validation error: ${error}`);
  }
}

export function validateServerConfig(config: unknown): ServerConfig {
  try {
    const parsed = ServerConfigSchema.parse(config);
    const lowercaseHosts: Record<string, HostConfig> = {};
    for (const [key, value] of Object.entries(parsed.hosts)) {
      lowercaseHosts[key.toLowerCase()] = value as HostConfig;
    }
    return { ...parsed, hosts: lowercaseHosts } as ServerConfig;
  } catch (error) {
    throw new Error(`Configuration validation error: ${error}`);
  }
}
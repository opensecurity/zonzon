import dgram, { RemoteInfo } from "dgram";
import * as net from "net";
import * as tls from "node:tls";
import * as https from "node:https";
import * as http from "node:http";
import { randomBytes } from "node:crypto";
import { DevDnsServer, DnsWireFormat, extractQuestions } from "./dns-service.js";
import { ServerConfig, DNS_RCODE } from "./types.js";
import { RateLimiter } from "./rate-limiter.js";
import { audit } from "./audit.js";
import { firewallEngine } from "./firewall.js";

const MAX_TCP_BUFFER_SIZE = 64 * 1024; 

interface PendingUdpQuery {
  rinfo: RemoteInfo;
  originalId: number;
  timeoutId: NodeJS.Timeout;
}

export class DnsHandler {
  private server: DevDnsServer;
  private udpServer: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private dotServer: tls.Server | null = null;
  private dohServer: https.Server | null = null;

  private port: number;
  private fallbackDns: string | undefined;
  private config: ServerConfig;

  private activeTcpConnections = new Map<net.Socket | tls.TLSSocket, { timeoutId?: ReturnType<typeof setTimeout> }>();
  private maxTcpConnections: number;
  private tcpIdleTimeoutMs: number;

  private pendingUpstreamQueries = new Map<number, PendingUdpQuery>();
  private readonly maxConcurrentUdpForwards = 2000;

  private rateLimiter: RateLimiter | null;

  constructor(server: DevDnsServer, config: ServerConfig) {
    this.server = server;
    this.config = config;
    this.port = config.port;
    this.fallbackDns = config.fallbackDns;
    this.maxTcpConnections = config.maxTcpConnections ?? 100;
    this.tcpIdleTimeoutMs = config.tcpIdleTimeoutMs ?? 30000;

    if (config.rateLimitMaxRequests && config.rateLimitMaxRequests > 0) {
      this.rateLimiter = new RateLimiter({
        maxRequests: config.rateLimitMaxRequests,
        windowMs: config.rateLimitWindowMs ?? 1000,
      });
    } else {
      this.rateLimiter = null;
    }
  }

  async start(): Promise<void> {
    await this.startUdp();
    await this.startTcp();
    
    if (this.config.tls) {
      await this.startDoT();
      await this.startDoH();
    }
  }

  async stop(): Promise<void> {
    if (this.udpServer) {
      await new Promise<void>((resolve) => {
        this.udpServer?.close(() => resolve());
      });
      this.udpServer = null;
    }
    
    for (const pending of this.pendingUpstreamQueries.values()) {
      clearTimeout(pending.timeoutId);
    }
    this.pendingUpstreamQueries.clear();

    if (this.tcpServer) {
      await new Promise<void>((resolve) => {
        this.tcpServer?.close(() => resolve());
      });
      this.tcpServer = null;
    }

    if (this.dotServer) {
      await new Promise<void>((resolve) => {
        this.dotServer?.close(() => resolve());
      });
      this.dotServer = null;
    }

    if (this.dohServer) {
      if ('closeIdleConnections' in this.dohServer) {
         (this.dohServer as any).closeIdleConnections();
      }
      await new Promise<void>((resolve) => {
        this.dohServer?.close(() => resolve());
      });
      this.dohServer = null;
    }

    this.activeTcpConnections.clear();
  }

  private startUdp(): Promise<void> {
    return new Promise((resolve, reject) => {
      const udp = dgram.createSocket("udp4");

      udp.on("message", (data: Buffer, rinfo: RemoteInfo) => {
        this.handleUdpMessage(data, rinfo);
      });

      udp.on("error", (err: NodeJS.ErrnoException) => {
        if (err.code === "EACCES" || err.code === "EADDRINUSE") {
          reject(err);
        }
      });

      udp.on("listening", () => {
        try { udp.setRecvBufferSize(1024 * 1024); } catch {}
        this.udpServer = udp;
        resolve();
      });

      udp.bind(this.port, "0.0.0.0");
    });
  }

  private startTcp(): Promise<void> {
    return new Promise((resolve) => {
      const tcpServer = net.createServer((socket: net.Socket) => {
        if (this.activeTcpConnections.size >= this.maxTcpConnections) {
          socket.destroy();
          return;
        }

        this.activeTcpConnections.set(socket, { timeoutId: undefined });

        socket.setTimeout(this.tcpIdleTimeoutMs);
        socket.on("timeout", () => {
          this.removeTcpConnection(socket);
          socket.destroy();
        });

        this.handleTcpConnection(socket);
      });

      tcpServer.on("listening", () => {
        this.tcpServer = tcpServer;
        resolve();
      });

      tcpServer.listen(this.port, "0.0.0.0");
    });
  }

  private startDoT(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.config.tls) {
        resolve();
        return;
      }

      const dotServer = tls.createServer({
        cert: this.config.tls.cert,
        key: this.config.tls.key,
        minVersion: "TLSv1.2"
      }, (socket: tls.TLSSocket) => {
        if (this.activeTcpConnections.size >= this.maxTcpConnections) {
          socket.destroy();
          return;
        }

        this.activeTcpConnections.set(socket, { timeoutId: undefined });

        socket.setTimeout(this.tcpIdleTimeoutMs);
        socket.on("timeout", () => {
          this.removeTcpConnection(socket);
          socket.destroy();
        });

        this.handleTcpConnection(socket);
      });

      dotServer.on("listening", () => {
        this.dotServer = dotServer;
        audit.system(`DoT (DNS over TLS) isolated boundary listening on port ${this.config.dotPort || 853}`);
        resolve();
      });

      dotServer.listen(this.config.dotPort || 853, "0.0.0.0");
    });
  }

  private startDoH(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.config.tls) {
        resolve();
        return;
      }

      const dohServer = https.createServer({
        cert: this.config.tls.cert,
        key: this.config.tls.key,
        minVersion: "TLSv1.2"
      }, (req, res) => {
        this.handleDohRequest(req, res).catch(() => {
          if (!res.headersSent) {
            res.writeHead(500);
            res.end();
          }
        });
      });

      dohServer.on("listening", () => {
        this.dohServer = dohServer;
        audit.system(`DoH (DNS over HTTPS) isolated boundary listening on port ${this.config.dohPort || 8443}`);
        resolve();
      });

      dohServer.listen(this.config.dohPort || 8443, "0.0.0.0");
    });
  }

  private isRateLimited(ip: string): boolean {
    if (!this.rateLimiter) return false;
    return !this.rateLimiter.allow(ip);
  }

  private parseResolvedIpv4s(resp: Buffer): string[] {
    const ips: string[] = []; 
    try {
      const f = new DnsWireFormat(resp); 
      f.offset = 4;
      const qd = f.readUint16();
      const an = f.readUint16(); 
      f.offset += 4;
      
      for (let i = 0; i < qd; i++) { 
        f.readDomainName(); 
        f.offset += 4; 
      }
      
      for (let i = 0; i < an; i++) {
        f.readDomainName(); 
        const type = f.readUint16(); 
        f.offset += 6;
        const len = f.readUint16();
        if (type === 1 && len === 4) {
          ips.push(`${resp[f.offset]}.${resp[f.offset+1]}.${resp[f.offset+2]}.${resp[f.offset+3]}`);
        }
        f.offset += len;
      }
    } catch {} 
    return ips;
  }

  private isPrivateIp(ip: string): boolean {
    if (!net.isIPv4(ip) && !net.isIPv6(ip)) return false;
    if (net.isIPv6(ip)) {
      const normalized = ip.toLowerCase();
      return normalized === "::1" || normalized.startsWith("fe80:") || normalized.startsWith("fc00:") || normalized.startsWith("fd");
    }
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
  }

  private resolveQueryAsync(query: Buffer, clientIp: string): Promise<Buffer> {
    return new Promise((resolve) => {
      const response = this.server.resolve(query, clientIp);
      if (response) {
        if (response.length > 0) resolve(response);
        else resolve(this.server.generateErrorResponse(query, DNS_RCODE.SERVFAIL));
        return;
      }

      if (!this.fallbackDns) {
        resolve(this.server.generateErrorResponse(query, DNS_RCODE.NXDOMAIN));
        return;
      }

      const fwdSocket = dgram.createSocket("udp4");
      const timeoutId = setTimeout(() => {
        try { fwdSocket.close(); } catch {}
        resolve(this.server.generateErrorResponse(query, DNS_RCODE.SERVFAIL));
      }, 3000);

      fwdSocket.on("message", (msg) => {
        clearTimeout(timeoutId);
        try { fwdSocket.close(); } catch {}
        
        const ips = this.parseResolvedIpv4s(msg);
        let blockedIp = null;
        for (const ip of ips) {
          if (firewallEngine.evaluateIp(ip, this.config.firewall) === "DENY") {
            blockedIp = ip;
            break;
          }
        }

        const questions = extractQuestions(query);

        if (blockedIp) {
          audit.firewall(clientIp, blockedIp, "DENY", "Upstream target IP blocked");
          audit.dns(clientIp, questions, DNS_RCODE.REFUSED, false);
          resolve(this.server.generateErrorResponse(query, DNS_RCODE.REFUSED));
        } else {
          const rcode = msg.length >= 4 ? msg.readUInt16BE(2) & 0xf : 0;
          audit.dns(clientIp, questions, rcode, false);
          resolve(msg);
        }
      });

      fwdSocket.on("error", () => {
        clearTimeout(timeoutId);
        try { fwdSocket.close(); } catch {}
        resolve(this.server.generateErrorResponse(query, DNS_RCODE.SERVFAIL));
      });

      fwdSocket.send(query, 0, query.length, 53, this.fallbackDns);
    });
  }

  private async handleDohRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const clientIp = req.socket.remoteAddress || "unknown";
    if (this.isRateLimited(clientIp)) {
      res.writeHead(429);
      res.end();
      return;
    }

    const method = req.method || "GET";
    const url = new URL(req.url || "/", `https://${req.headers.host || "localhost"}`);

    if (url.pathname !== "/dns-query") {
      res.writeHead(404);
      res.end();
      return;
    }

    let query: Buffer | null = null;

    if (method === "GET") {
      const dnsParam = url.searchParams.get("dns");
      if (!dnsParam) {
        res.writeHead(400);
        res.end();
        return;
      }
      try {
        query = Buffer.from(dnsParam, "base64url");
      } catch {
        res.writeHead(400);
        res.end();
        return;
      }
    } else if (method === "POST") {
      if (req.headers["content-type"] !== "application/dns-message") {
        res.writeHead(415);
        res.end();
        return;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      for await (const chunk of req) {
        total += chunk.length;
        if (total > MAX_TCP_BUFFER_SIZE) {
          res.writeHead(413);
          res.end();
          return;
        }
        chunks.push(chunk);
      }
      query = Buffer.concat(chunks);
    } else {
      res.writeHead(405);
      res.end();
      return;
    }

    if (!query || query.length < 12) {
      res.writeHead(400);
      res.end();
      return;
    }

    try {
      const response = await this.resolveQueryAsync(query, clientIp);
      res.writeHead(200, {
        "Content-Type": "application/dns-message",
        "Content-Length": response.length,
        "Cache-Control": "max-age=0"
      });
      res.end(response);
    } catch {
      res.writeHead(502);
      res.end();
    }
  }

  private forwardUdpQuery(data: Buffer, clientInfo: RemoteInfo): void {
    if (!this.fallbackDns) return;

    if (!this.isPrivateIp(clientInfo.address)) {
      if (this.config.firewall && (!this.config.firewall.allowlist_ips || !this.config.firewall.allowlist_ips.includes(clientInfo.address))) {
        audit.system(`Dropped UDP forward request from untrusted WAN IP: ${clientInfo.address} (Anti-Amplification)`);
        return;
      }
    }

    if (this.pendingUpstreamQueries.size >= this.maxConcurrentUdpForwards) {
      audit.system("Dropped UDP forward request: Concurrent connection limit reached");
      return;
    }

    if (data.length < 2) return;

    const originalId = data.readUInt16BE(0);
    const ephemeralId = randomBytes(2).readUInt16BE(0);
    const trackingId = randomBytes(4).readUInt32BE(0);

    const fwdSocket = dgram.createSocket("udp4");
    
    const timeoutId = setTimeout(() => {
      this.pendingUpstreamQueries.delete(trackingId);
      try { fwdSocket.close(); } catch {}
      const ref = this.server.generateErrorResponse(data, DNS_RCODE.SERVFAIL);
      this.udpServer?.send(ref, 0, ref.length, clientInfo.port, clientInfo.address);
    }, 3000);

    this.pendingUpstreamQueries.set(trackingId, { rinfo: clientInfo, originalId, timeoutId });

    fwdSocket.on("message", (msg) => {
      this.pendingUpstreamQueries.delete(trackingId);
      clearTimeout(timeoutId);
      try { fwdSocket.close(); } catch {}

      if (msg.length < 2) return;
      const responseId = msg.readUInt16BE(0);
      if (responseId !== ephemeralId) return;

      const restoredMsg = Buffer.from(msg);
      restoredMsg.writeUInt16BE(originalId, 0);

      const ips = this.parseResolvedIpv4s(restoredMsg);
      let blockedIp = null;
      
      for (const ip of ips) {
        if (firewallEngine.evaluateIp(ip, this.config.firewall) === "DENY") {
          blockedIp = ip;
          break;
        }
      }

      const questions = extractQuestions(restoredMsg);

      if (blockedIp) {
        audit.firewall(clientInfo.address, blockedIp, "DENY", "Upstream target IP blocked");
        audit.dns(clientInfo.address, questions, DNS_RCODE.REFUSED, false);
        const ref = this.server.generateErrorResponse(restoredMsg, DNS_RCODE.REFUSED);
        this.udpServer?.send(ref, 0, ref.length, clientInfo.port, clientInfo.address);
      } else {
        const rcode = restoredMsg.length >= 4 ? restoredMsg.readUInt16BE(2) & 0xf : 0;
        audit.dns(clientInfo.address, questions, rcode, false);
        this.udpServer?.send(restoredMsg, 0, restoredMsg.length, clientInfo.port, clientInfo.address);
      }
    });

    fwdSocket.on("error", () => {
      this.pendingUpstreamQueries.delete(trackingId);
      clearTimeout(timeoutId);
      try { fwdSocket.close(); } catch {}
    });

    const queryToForward = Buffer.from(data);
    queryToForward.writeUInt16BE(ephemeralId, 0);

    fwdSocket.send(queryToForward, 0, queryToForward.length, 53, this.fallbackDns);
  }

  private handleUdpMessage(data: Buffer, rinfo: RemoteInfo): void {
    if (this.isRateLimited(rinfo.address)) {
      return;
    }

    try {
      const response = this.server.resolve(data, rinfo.address);
      if (response) {
        if (response.length > 0) {
          this.udpServer?.send(response, 0, response.length, rinfo.port, rinfo.address);
        }
      } else {
        if (this.fallbackDns) {
          this.forwardUdpQuery(data, rinfo);
        } else {
          const nx = this.server.generateErrorResponse(data, DNS_RCODE.NXDOMAIN);
          this.udpServer?.send(nx, 0, nx.length, rinfo.port, rinfo.address);
        }
      }
    } catch (err) {
    }
  }

  private removeTcpConnection(socket: net.Socket | tls.TLSSocket): void {
    const entry = this.activeTcpConnections.get(socket);
    if (entry?.timeoutId) clearTimeout(entry.timeoutId);
    this.activeTcpConnections.delete(socket);
  }

  private forwardTcpQuery(query: Buffer, clientSocket: net.Socket | tls.TLSSocket, peerAddr: string): void {
    if (!this.fallbackDns) return;

    const fwd = net.createConnection(53, this.fallbackDns, () => {
      const prefixed = Buffer.alloc(2 + query.length);
      prefixed.writeUInt16BE(query.length, 0);
      query.copy(prefixed, 2);
      fwd.write(prefixed);
    });

    fwd.setTimeout(this.tcpIdleTimeoutMs);
    fwd.on("timeout", () => {
      fwd.destroy();
    });

    fwd.on("data", (data) => {
      if (data.length < 2) return;
      const resp = data.subarray(2);
      
      const ips = this.parseResolvedIpv4s(resp);
      let blockedIp = null;
      
      for (const ip of ips) {
        if (firewallEngine.evaluateIp(ip, this.config.firewall) === "DENY") {
          blockedIp = ip;
          break;
        }
      }

      const questions = extractQuestions(query);

      if (blockedIp) {
        audit.firewall(peerAddr, blockedIp, "DENY", "Upstream target IP blocked");
        audit.dns(peerAddr, questions, DNS_RCODE.REFUSED, false);
        if (!clientSocket.destroyed) {
          const ref = this.server.generateErrorResponse(query, DNS_RCODE.REFUSED);
          const p = Buffer.alloc(2 + ref.length);
          p.writeUInt16BE(ref.length, 0);
          ref.copy(p, 2);
          clientSocket.write(p);
          clientSocket.end();
        }
      } else {
        const rcode = resp.length >= 4 ? resp.readUInt16BE(2) & 0xf : 0;
        audit.dns(peerAddr, questions, rcode, false);
        if (!clientSocket.destroyed) clientSocket.write(data);
      }
    });

    fwd.on("end", () => {
      if (!clientSocket.destroyed) clientSocket.end();
    });

    fwd.on("error", (err) => {
      if (!clientSocket.destroyed) {
        const sf = this.server.generateErrorResponse(query, DNS_RCODE.SERVFAIL);
        const p = Buffer.alloc(2 + sf.length);
        p.writeUInt16BE(sf.length, 0);
        sf.copy(p, 2);
        clientSocket.write(p);
        clientSocket.end();
      }
    });
  }

  private handleTcpConnection(socket: net.Socket | tls.TLSSocket): void {
    let buffer = Buffer.alloc(0);
    const peerAddr = socket.remoteAddress || "unknown";

    socket.on("close", () => this.removeTcpConnection(socket));
    socket.on("error", (err) => {
      this.removeTcpConnection(socket);
    });

    if (this.isRateLimited(peerAddr)) {
      socket.destroy();
      return;
    }

    socket.on("data", (data: Buffer) => {
      if (buffer.length + data.length > MAX_TCP_BUFFER_SIZE) {
        socket.destroy();
        return;
      }

      const combined = Buffer.concat([buffer, data]);
      buffer = combined;

      while (buffer.length >= 2) {
        const length = buffer.readUInt16BE(0);

        if (buffer.length < 2 + length) continue; 

        const query = buffer.subarray(2, 2 + length);
        buffer = buffer.subarray(2 + length);

        try {
          const response = this.server.resolve(query, peerAddr);
          if (response) {
            if (response.length > 0) {
              const prefixed = Buffer.alloc(2 + response.length);
              prefixed.writeUInt16BE(response.length, 0);
              response.copy(prefixed, 2);
              socket.write(prefixed);
            } else {
              socket.end();
            }
          } else {
            if (this.fallbackDns) {
              this.forwardTcpQuery(query, socket, peerAddr);
            } else {
              const nx = this.server.generateErrorResponse(query, DNS_RCODE.NXDOMAIN);
              const p = Buffer.alloc(2 + nx.length);
              p.writeUInt16BE(nx.length, 0);
              nx.copy(p, 2);
              socket.write(p);
              socket.end();
            }
          }
        } catch (err) {
          socket.end();
        }
      }
    });
  }

  getPort(): number {
    return this.port;
  }
}
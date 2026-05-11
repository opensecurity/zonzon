import dgram, { RemoteInfo } from "dgram";
import * as net from "net";
import { DevDnsServer, DnsWireFormat, extractQuestions } from "./dns-service.js";
import { ServerConfig, DNS_RCODE } from "./types.js";
import { RateLimiter } from "./rate-limiter.js";
import { audit } from "./audit.js";
import { firewallEngine } from "./firewall.js";

const MAX_TCP_BUFFER_SIZE = 64 * 1024; 

export class DnsHandler {
  private server: DevDnsServer;
  private udpServer: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private port: number;
  private fallbackDns: string | undefined;
  private config: ServerConfig;

  private activeTcpConnections = new Map<net.Socket, { timeoutId?: ReturnType<typeof setTimeout> }>();
  private maxTcpConnections: number;
  private tcpIdleTimeoutMs: number;

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
  }

  async stop(): Promise<void> {
    if (this.udpServer) {
      await new Promise<void>((resolve) => {
        this.udpServer?.close(() => resolve());
      });
      this.udpServer = null;
    }
    if (this.tcpServer) {
      await new Promise<void>((resolve) => {
        this.tcpServer?.close(() => resolve());
      });
      this.tcpServer = null;
    }
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

      tcpServer.on("close", () => {
        for (const [socket] of this.activeTcpConnections) {
          if (!socket.destroyed) socket.destroy();
        }
        this.activeTcpConnections.clear();
      });

      tcpServer.on("listening", () => {
        this.tcpServer = tcpServer;
        resolve();
      });

      tcpServer.listen(this.port, "0.0.0.0");
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

  private forwardUdpQuery(data: Buffer, clientInfo: RemoteInfo): void {
    if (!this.fallbackDns || !this.udpServer) return;

    const fwdSocket = dgram.createSocket("udp4");
    let handled = false;

    const timeout = setTimeout(() => {
      if (!handled) {
        handled = true;
        fwdSocket.close();
        const ref = this.server.generateErrorResponse(data, DNS_RCODE.SERVFAIL);
        this.udpServer?.send(ref, 0, ref.length, clientInfo.port, clientInfo.address);
      }
    }, 3000);

    fwdSocket.on("message", (resp) => {
      if (!handled) {
        handled = true;
        clearTimeout(timeout);
        
        const ips = this.parseResolvedIpv4s(resp);
        let blockedIp = null;
        
        for (const ip of ips) {
          if (firewallEngine.evaluateIp(ip, this.config.firewall) === "DENY") {
            blockedIp = ip;
            break;
          }
        }

        if (blockedIp) {
          const ref = this.server.generateErrorResponse(data, DNS_RCODE.REFUSED);
          this.udpServer?.send(ref, 0, ref.length, clientInfo.port, clientInfo.address);
        } else {
          this.udpServer?.send(resp, 0, resp.length, clientInfo.port, clientInfo.address);
        }
        fwdSocket.close();
      }
    });

    fwdSocket.on("error", (err) => {
      if (!handled) {
        handled = true;
        clearTimeout(timeout);
        fwdSocket.close();
        const ref = this.server.generateErrorResponse(data, DNS_RCODE.SERVFAIL);
        this.udpServer?.send(ref, 0, ref.length, clientInfo.port, clientInfo.address);
      }
    });

    fwdSocket.send(data, 0, data.length, 53, this.fallbackDns);
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

  private removeTcpConnection(socket: net.Socket): void {
    const entry = this.activeTcpConnections.get(socket);
    if (entry?.timeoutId) clearTimeout(entry.timeoutId);
    this.activeTcpConnections.delete(socket);
  }

  private forwardTcpQuery(query: Buffer, clientSocket: net.Socket, peerAddr: string): void {
    if (!this.fallbackDns) return;

    const fwd = net.createConnection(53, this.fallbackDns, () => {
      const prefixed = Buffer.alloc(2 + query.length);
      prefixed.writeUInt16BE(query.length, 0);
      query.copy(prefixed, 2);
      fwd.write(prefixed);
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

      if (blockedIp) {
        if (!clientSocket.destroyed) {
          const ref = this.server.generateErrorResponse(query, DNS_RCODE.REFUSED);
          const p = Buffer.alloc(2 + ref.length);
          p.writeUInt16BE(ref.length, 0);
          ref.copy(p, 2);
          clientSocket.write(p);
          clientSocket.end();
        }
      } else {
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

  private handleTcpConnection(socket: net.Socket): void {
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
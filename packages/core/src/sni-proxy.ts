import * as net from "net";
import * as dns from "dns/promises";
import { ServerConfig } from "./types.js";
import { firewallEngine } from "./firewall.js";
import { audit } from "./audit.js";

const MAX_CLIENT_HELLO_SIZE = 16384; 

export class SniProxyService {
  private port: number;
  private config: ServerConfig;
  private server: net.Server | null = null;
  private activeConnections = new Set<net.Socket>();
  private idleTimeoutMs: number;

  constructor(config: ServerConfig, port?: number) {
    this.config = config;
    this.port = config.httpsPort ?? port ?? 443;
    this.idleTimeoutMs = config.tcpIdleTimeoutMs ?? 30000;
  }

  private extractSNI(data: Buffer): string | null {
    try {
      if (data.length < 5 || data[0] !== 0x16 || data[5] !== 0x01) {
        return null;
      }

      let offset = 43; 
      if (offset >= data.length) return null;

      const sessionIdLength = data[offset];
      offset += 1 + sessionIdLength;
      if (offset >= data.length) return null;

      if (offset + 2 > data.length) return null;
      const cipherSuitesLength = data.readUInt16BE(offset);
      offset += 2 + cipherSuitesLength;
      if (offset >= data.length) return null;

      const compressionMethodsLength = data[offset];
      offset += 1 + compressionMethodsLength;
      if (offset + 2 > data.length) return null;

      const extensionsLength = data.readUInt16BE(offset);
      offset += 2;
      const extensionsEnd = offset + extensionsLength;

      while (offset < extensionsEnd && offset + 4 <= data.length) {
        const extType = data.readUInt16BE(offset);
        const extLength = data.readUInt16BE(offset + 2);
        offset += 4;

        if (extType === 0x0000) {
          let sniOffset = offset;
          sniOffset += 2;
          
          if (sniOffset >= data.length) return null;
          const nameType = data[sniOffset];
          
          if (nameType === 0) {
            sniOffset += 1;
            if (sniOffset + 2 > data.length) return null;
            const nameLength = data.readUInt16BE(sniOffset);
            sniOffset += 2;
            if (sniOffset + nameLength > data.length) return null;
            return data.toString("utf8", sniOffset, sniOffset + nameLength);
          }
        }
        offset += extLength;
      }
    } catch {
      return null;
    }
    return null;
  }

  private async handleConnection(clientSocket: net.Socket): Promise<void> {
    const clientIp = clientSocket.remoteAddress || "unknown";
    let buffer = Buffer.alloc(0);
    let isHandled = false;
    let upstreamSocket: net.Socket | null = null;

    clientSocket.setTimeout(this.idleTimeoutMs);
    clientSocket.on("timeout", () => {
      audit.error(`SNI Client tunnel idle timeout reached for ${clientIp}`);
      clientSocket.destroy();
    });

    const absoluteHandshakeTimeout = setTimeout(() => {
      if (!isHandled && !clientSocket.destroyed) {
        audit.http(clientIp, "TLS", "UNKNOWN", `:${this.port}`, 408, "Dropped: ClientHello absolute timeout (Slowloris)");
        clientSocket.destroy();
      }
    }, 5000);

    clientSocket.on("data", async (chunk: Buffer) => {
      if (isHandled) return;

      if (buffer.length + chunk.length > MAX_CLIENT_HELLO_SIZE) {
        audit.http(clientIp, "TLS", "UNKNOWN", `:${this.port}`, 413, "Dropped: ClientHello exceeded maximum permitted size");
        clientSocket.destroy();
        clearTimeout(absoluteHandshakeTimeout);
        return;
      }

      buffer = Buffer.concat([buffer, chunk]);

      if (buffer.length < 5) return;
      const recordLength = buffer.readUInt16BE(3);
      if (buffer.length < 5 + recordLength) return;

      isHandled = true;
      clearTimeout(absoluteHandshakeTimeout);

      const sni = this.extractSNI(buffer);

      if (!sni) {
        audit.http(clientIp, "TLS", "UNKNOWN", `:${this.port}`, 400, "Dropped: No SNI detected");
        clientSocket.destroy();
        return;
      }

      try {
        if (firewallEngine.evaluateDomain(sni, this.config.firewall) === "DENY") {
          throw new Error("Domain blocked by Firewall policy");
        }

        const records = await dns.resolve(sni);
        const targetIps = records.filter(ip => typeof ip === "string");

        if (targetIps.length === 0) {
          throw new Error("NXDOMAIN on upstream resolution");
        }

        const targetIp = targetIps[0];
        
        if (firewallEngine.isRestrictedOutbound(targetIp)) {
          throw new Error(`Target IP ${targetIp} blocked by Strict SSRF proxy policy`);
        }

        if (firewallEngine.evaluateIp(targetIp, this.config.firewall) === "DENY") {
          throw new Error(`Target IP ${targetIp} blocked by Firewall policy`);
        }

        audit.http(clientIp, "TLS-SNI", sni, `:${this.port}`, 200, `Tunneled to ${targetIp}`);

        upstreamSocket = net.connect(443, targetIp, () => {
          upstreamSocket!.write(buffer);
          clientSocket.pipe(upstreamSocket!);
          upstreamSocket!.pipe(clientSocket);
        });

        upstreamSocket.setTimeout(this.idleTimeoutMs);
        upstreamSocket.on("timeout", () => {
          audit.error(`SNI Upstream tunnel idle timeout reached for ${sni}:${targetIp}`);
          upstreamSocket!.destroy();
        });

        this.activeConnections.add(upstreamSocket);
        upstreamSocket.on("close", () => {
          this.activeConnections.delete(upstreamSocket!);
        });

        upstreamSocket.on("error", (err) => {
          audit.error(`Upstream tunnel fault on ${sni}:443 - ${err.message}`);
          if (!clientSocket.destroyed) clientSocket.destroy();
        });

      } catch (err: any) {
        audit.http(clientIp, "TLS-SNI", sni, `:${this.port}`, 403, `Blocked: ${err.message}`);
        clientSocket.destroy();
      }
    });

    clientSocket.on("error", (err) => {
      audit.error(`Client tunnel fault from ${clientIp} - ${err.message}`);
      if (upstreamSocket && !upstreamSocket.destroyed) {
        upstreamSocket.destroy();
      }
      clearTimeout(absoluteHandshakeTimeout);
    });

    clientSocket.on("close", () => {
      if (upstreamSocket && !upstreamSocket.destroyed) {
        upstreamSocket.destroy();
      }
      clearTimeout(absoluteHandshakeTimeout);
    });
  }

  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket: net.Socket) => {
        this.activeConnections.add(socket);
        socket.on("close", () => this.activeConnections.delete(socket));
        this.handleConnection(socket);
      });

      this.server.on("error", (err) => reject(err));

      this.server.listen(this.port, "0.0.0.0", () => {
        resolve();
      });
    });
  }

  public async stop(): Promise<void> {
    if (this.server) {
      if ('closeIdleConnections' in this.server) {
         (this.server as any).closeIdleConnections();
      }
      
      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      
      this.activeConnections.clear();
      this.server = null;
    }
  }
}
import * as http from "http";
import type { IncomingMessage, ServerResponse } from "http";
import * as net from "net";
import * as dns from "dns/promises";
import { DevDnsServer } from "./dns-service.js";
import { HttpProxyService } from "./http-proxy.js";
import { HostConfig, ServerConfig } from "./types.js";
import { audit } from "./audit.js";
import { firewallEngine } from "./firewall.js";

enum CircuitState { CLOSED, OPEN, HALF_OPEN }

class ProxyCircuitBreaker {
  private state = CircuitState.CLOSED;
  private failures = 0;
  private lastFailureTime = 0;
  private readonly threshold = 5;
  private readonly resetTimeoutMs = 10000;

  async execute<T>(action: () => Promise<T>): Promise<T> {
    const now = Date.now();

    if (this.state === CircuitState.OPEN) {
      if (now - this.lastFailureTime > this.resetTimeoutMs) {
        this.state = CircuitState.HALF_OPEN;
      } else {
        throw new Error("Target Offline");
      }
    }

    try {
      const result = await action();
      if (this.state === CircuitState.HALF_OPEN) {
        this.reset();
      }
      return result;
    } catch (error) {
      this.recordFailure(now);
      throw error;
    }
  }

  private recordFailure(time: number) {
    this.failures++;
    this.lastFailureTime = time;
    if (this.failures >= this.threshold) {
      this.state = CircuitState.OPEN;
    }
  }

  private reset() {
    this.state = CircuitState.CLOSED;
    this.failures = 0;
  }
}

export class HttpHandler {
  private dnsServer: DevDnsServer;
  private proxyService: HttpProxyService;
  private port: number;
  private config: ServerConfig;
  private server: http.Server | null = null;
  private circuitBreakers = new Map<string, ProxyCircuitBreaker>();
  private activeConnections = new Set<net.Socket>();

  constructor(dnsServer: DevDnsServer, config: ServerConfig, port: number = 80) {
    this.dnsServer = dnsServer;
    this.proxyService = new HttpProxyService();
    this.port = port;
    this.config = config;
  }

  private getCircuitBreaker(upstream: string): ProxyCircuitBreaker {
    if (!this.circuitBreakers.has(upstream)) {
      this.circuitBreakers.set(upstream, new ProxyCircuitBreaker());
    }
    return this.circuitBreakers.get(upstream)!;
  }

  private findWildcardHost(config: ServerConfig, hostname: string): HostConfig | undefined {
    const normalizedName = hostname.toLowerCase().replace(/\.$/, "");
    const labels = normalizedName.split(".");

    for (let i = 0; i < labels.length - 1; i++) {
      const suffix = labels.slice(i).join(".");
      const wildcardKey = "*." + suffix;
      if (config.hosts[wildcardKey]) {
        return config.hosts[wildcardKey];
      }
    }

    return undefined;
  }

  private injectCustomHeaders(responseHeaders: Headers, hostConfig: HostConfig): void {
    if (!hostConfig.http_proxy?.enabled) return;

    for (const [key, value] of Object.entries(hostConfig.http_proxy.headers)) {
      const sanitized = this.proxyService.sanitizeHeader(value);
      if (sanitized) {
        responseHeaders.set(key, sanitized);
      }
    }
  }

  private async handleConnect(req: IncomingMessage, clientSocket: net.Socket, head: Buffer): Promise<void> {
    const clientIp = req.socket.remoteAddress || "unknown";
    const targetUrl = req.url || "";

    const [hostname, portStr] = targetUrl.split(':');
    const port = portStr ? parseInt(portStr, 10) : 443;

    try {
      await this.proxyService.validateTargetFirewall(`https://${hostname}:${port}`, this.config.firewall);

      audit.http(clientIp, "CONNECT", hostname, `:${port}`, 200, "TCP Tunnel Established");

      const srvSocket = net.connect(port, hostname, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length > 0) {
          srvSocket.write(head);
        }
        srvSocket.pipe(clientSocket);
        clientSocket.pipe(srvSocket);
      });

      this.activeConnections.add(srvSocket);
      srvSocket.on('close', () => this.activeConnections.delete(srvSocket));

      srvSocket.on('error', (err) => {
        audit.error(`Upstream tunnel fault on ${hostname}:${port} - ${err.message}`);
        if (!clientSocket.destroyed) clientSocket.destroy();
      });

      clientSocket.on('error', (err) => {
        if (!srvSocket.destroyed) srvSocket.destroy();
      });

    } catch (err: any) {
      audit.http(clientIp, "CONNECT", hostname, `:${port}`, 403, "Blocked by Firewall");
      if (!clientSocket.destroyed) {
        clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        clientSocket.destroy();
      }
    }
  }

  private async handleForwardProxy(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const clientIp = req.socket.remoteAddress || "unknown";
    const reqMethod = req.method || "GET";
    const reqUrl = req.url || "/";

    const targetUrl = new URL(reqUrl);
    const hostname = targetUrl.hostname;

    try {
      await this.proxyService.validateTargetFirewall(targetUrl.toString(), this.config.firewall);
    } catch (fwErr: any) {
      audit.http(clientIp, reqMethod, hostname, targetUrl.pathname, 403, "Blocked by L3/L7 Firewall");
      res.writeHead(403, { "Content-Type": "text/html" });
      res.end(`<h1>403 Forbidden</h1><p>${fwErr.message}</p>`);
      return;
    }

    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (Array.isArray(v)) {
        headers.set(k, v.join(", "));
      } else if (typeof v === "string") {
        headers.set(k, v);
      }
    }

    const hopByHop = this.proxyService.getHopByHopHeaders();
    for (const h of hopByHop) {
      headers.delete(h);
    }

    const maxBodyBytes = 5 * 1024 * 1024;
    let bodyBuffer: Buffer | undefined = undefined;

    if (reqMethod !== "GET" && reqMethod !== "HEAD") {
      const chunks: Buffer[] = [];
      let totalSize = 0;
      for await (const chunk of req) {
        totalSize += chunk.length;
        if (totalSize > maxBodyBytes) {
          audit.http(clientIp, reqMethod, hostname, reqUrl, 413, targetUrl.hostname);
          res.writeHead(413, { "Content-Type": "text/html" });
          res.end("<h1>413 Payload Too Large</h1>");
          return;
        }
        chunks.push(chunk);
      }
      if (chunks.length > 0) {
        bodyBuffer = Buffer.concat(chunks);
      }
    }

    const proxiedReqInit: RequestInit = {
      method: reqMethod,
      headers,
    };

    if (bodyBuffer) {
      proxiedReqInit.body = bodyBuffer as unknown as BodyInit;
      (proxiedReqInit as any).duplex = "half";
    }

    const proxiedReq = new Request(targetUrl.toString(), proxiedReqInit);
    const breaker = this.getCircuitBreaker(targetUrl.hostname);

    try {
      const proxyResp = await breaker.execute(() => fetch(proxiedReq));
      const outHeaders: Record<string, string> = {};
      
      proxyResp.headers.forEach((value, key) => {
        if (!hopByHop.includes(key.toLowerCase())) {
           outHeaders[key] = value;
        }
      });

      audit.http(clientIp, reqMethod, hostname, targetUrl.pathname, proxyResp.status, targetUrl.toString());
      res.writeHead(proxyResp.status, outHeaders);
      const responseBuffer = Buffer.from(await proxyResp.arrayBuffer());
      res.end(responseBuffer);
    } catch (err: any) {
      audit.http(clientIp, reqMethod, hostname, targetUrl.pathname, 502, "Upstream Timeout or Fault");
      res.writeHead(502, { "Content-Type": "text/html" });
      res.end(`<h1>502 Bad Gateway</h1>`);
    }
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const clientIp = req.socket.remoteAddress || "unknown";
    const reqMethod = req.method || "GET";
    const reqUrl = req.url || "/";

    if (reqUrl.startsWith("http://")) {
      return this.handleForwardProxy(req, res);
    }

    const rawHost = req.headers.host || "";
    const hostname = rawHost.split(":")[0];

    try {
      if (!hostname) {
        audit.http(clientIp, reqMethod, "UNKNOWN", reqUrl, 400, "Missing Host Header");
        res.writeHead(400);
        res.end("Bad Request");
        return;
      }

      let hostConfig = this.config.hosts[hostname];

      if (!hostConfig) {
        const wildConfig = this.findWildcardHost(this.config, hostname);
        if (wildConfig) hostConfig = wildConfig;
      }

      if (hostConfig) {
        const redirect = this.proxyService.checkRedirect(hostConfig);
        if (redirect) {
          try {
            await this.proxyService.validateTargetFirewall(redirect.target, this.config.firewall);
            audit.http(clientIp, reqMethod, hostname, reqUrl, redirect.code, redirect.target);
            res.writeHead(redirect.code, { Location: redirect.target });
            res.end();
            return;
          } catch (err) {
            audit.http(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by L3 Firewall");
            res.writeHead(403, { "Content-Type": "text/html" });
            res.end("<h1>403 Forbidden</h1>");
            return;
          }
        }

        if (hostConfig.http_proxy?.enabled && hostConfig.http_proxy.upstream) {
          const upstreamBase = new URL(hostConfig.http_proxy.upstream);

          try {
            await this.proxyService.validateTargetFirewall(upstreamBase.toString(), this.config.firewall);
          } catch (fwErr: any) {
            audit.http(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by L3 Firewall");
            res.writeHead(403, { "Content-Type": "text/html" });
            res.end(`<h1>403 Forbidden</h1><p>${fwErr.message}</p>`);
            return;
          }

          let safePath = "/";
          try {
            const parsedPath = new URL(reqUrl, "http://safe.local");
            safePath = parsedPath.pathname + parsedPath.search;
          } catch {
            safePath = "/"; 
          }

          const targetUrl = new URL(safePath, upstreamBase);
          const headers = new Headers();

          for (const [k, v] of Object.entries(req.headers)) {
            if (Array.isArray(v)) {
              headers.set(k, v.join(", "));
            } else if (typeof v === "string") {
              headers.set(k, v);
            }
          }

          const shouldForwardBody = hostConfig.http_proxy.forwardRequestBody;
          const maxBodyBytes = hostConfig.http_proxy.maxRequestBodyBytes ?? 5 * 1024 * 1024;
          let bodyBuffer: Buffer | undefined = undefined;

          if (reqMethod !== "GET" && reqMethod !== "HEAD") {
            const chunks: Buffer[] = [];
            let totalSize = 0;
            for await (const chunk of req) {
              totalSize += chunk.length;
              if (totalSize > maxBodyBytes) {
                audit.http(clientIp, reqMethod, hostname, reqUrl, 413, upstreamBase.hostname);
                res.writeHead(413, { "Content-Type": "text/html" });
                res.end("<h1>413 Payload Too Large</h1>");
                return;
              }
              chunks.push(chunk);
            }
            if (chunks.length > 0) {
              bodyBuffer = Buffer.concat(chunks);
            }
          }

          const proxiedReqInit: RequestInit = {
            method: reqMethod,
            headers,
          };

          if (shouldForwardBody && bodyBuffer) {
            proxiedReqInit.body = bodyBuffer as unknown as BodyInit;
            (proxiedReqInit as any).duplex = "half";
          }

          const proxiedReq = new Request(targetUrl.toString(), proxiedReqInit);
          const breaker = this.getCircuitBreaker(upstreamBase.hostname);

          const proxyResp = await breaker.execute(() => fetch(proxiedReq));
          const responseHeaders = new Headers(proxyResp.headers);
          
          this.injectCustomHeaders(responseHeaders, hostConfig);

          const outHeaders: Record<string, string> = {};
          responseHeaders.forEach((value, key) => {
            outHeaders[key] = value;
          });

          audit.http(clientIp, reqMethod, hostname, safePath, proxyResp.status, targetUrl.toString());
          res.writeHead(proxyResp.status, outHeaders);
          const responseBuffer = Buffer.from(await proxyResp.arrayBuffer());
          res.end(responseBuffer);
          return;
        }
      }

      if (firewallEngine.evaluateDomain(hostname, this.config.firewall) === "DENY") {
         audit.http(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by Domain Firewall");
         res.writeHead(403);
         res.end("Forbidden");
         return;
      }

      const records = await dns.resolve(hostname);
      const targetIps = records.filter(ip => typeof ip === "string");
      if (targetIps.length === 0) throw new Error("NXDOMAIN");

      const targetIp = targetIps[0];

      if (firewallEngine.evaluateIp(targetIp, this.config.firewall) === "DENY") {
         audit.http(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked by IP Firewall");
         res.writeHead(403);
         res.end("Forbidden");
         return;
      }

      const targetUrl = new URL(reqUrl, `http://${hostname}`);
      const headers = new Headers();

      for (const [k, v] of Object.entries(req.headers)) {
        if (Array.isArray(v)) headers.set(k, v.join(", "));
        else if (typeof v === "string") headers.set(k, v);
      }

      const proxiedReqInit: RequestInit = { method: reqMethod, headers };
      
      if (reqMethod !== "GET" && reqMethod !== "HEAD") {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk);
        if (chunks.length > 0) {
          proxiedReqInit.body = Buffer.concat(chunks) as unknown as BodyInit;
          (proxiedReqInit as any).duplex = "half";
        }
      }

      const proxiedReq = new Request(targetUrl.toString(), proxiedReqInit);
      const breaker = this.getCircuitBreaker(targetUrl.hostname);
      const proxyResp = await breaker.execute(() => fetch(proxiedReq));
      
      const outHeaders: Record<string, string> = {};
      proxyResp.headers.forEach((value, key) => { outHeaders[key] = value; });

      audit.http(clientIp, reqMethod, hostname, reqUrl, proxyResp.status, targetIp);
      res.writeHead(proxyResp.status, outHeaders);
      res.end(Buffer.from(await proxyResp.arrayBuffer()));

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      audit.error(`HTTP request failed: ${message}`);

      if (message.includes("Security Block") || message.includes("Firewall") || message.includes("Blocked")) {
        audit.http(clientIp, reqMethod, hostname, reqUrl, 403, "Blocked for Security (SSRF/Firewall)");
        res.writeHead(403, { "Content-Type": "text/html" });
        res.end(`<h1>403 Forbidden</h1>`);
        return;
      }
      
      audit.http(clientIp, reqMethod, hostname, reqUrl, 502, "Upstream Offline/Timeout");
      res.writeHead(502, { "Content-Type": "text/html" });
      res.end(`<h1>502 Bad Gateway</h1>`);
      return;
    }
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
        this.handleRequest(req, res).catch((err) => {
          audit.error(`HTTP interface critical error: ${err}`);
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "text/html" });
            res.end("<h1>500 Internal Server Error</h1>");
          }
        });
      });

      this.server.on("connect", (req: IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
        this.handleConnect(req, clientSocket, head).catch((err) => {
          audit.error(`TCP CONNECT critical error: ${err}`);
          if (!clientSocket.destroyed) {
            clientSocket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
            clientSocket.destroy();
          }
        });
      });

      this.server.on("connection", (socket: net.Socket) => {
        this.activeConnections.add(socket);
        socket.on("close", () => {
          this.activeConnections.delete(socket);
        });
      });

      this.server.on('error', (err) => reject(err));

      this.server.listen(this.port, "0.0.0.0", () => {
        audit.system(`L7 Sandbox Firewall routing internally on boundary :${this.port}`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      for (const socket of this.activeConnections) {
        socket.destroy();
      }
      this.activeConnections.clear();

      if ('closeAllConnections' in this.server) {
         (this.server as any).closeAllConnections();
      }

      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      this.server = null;
    }
  }

  getPort(): number {
    return this.port;
  }
}
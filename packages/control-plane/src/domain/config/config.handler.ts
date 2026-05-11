import * as http from "http";
import { createHash, createHmac, timingSafeEqual, hkdfSync } from "crypto";
import { audit } from "@opensecurity/zonzon-core";
import { ConfigService } from "./config.service.js";
import { ApiAuthHeaderSchema } from "./config.schema.js";
import { ConfigContext } from "./config.types.js";
import { contextStorage } from "./context.js";

export class ConfigHandler {
  private service: ConfigService;
  private blindIndexSalt: string;
  private expectedApiKeyHash: string;
  private seenNonces = new Set<string>();
  private currentPoWWindow = 0;

  constructor(service: ConfigService, rawApiKey: string, blindIndexSalt: string) {
    this.service = service;
    this.blindIndexSalt = blindIndexSalt;
    const apiKeySecret = hkdfSync("sha256", this.blindIndexSalt, Buffer.alloc(0), "api_key_derivation", 32);
    this.expectedApiKeyHash = createHmac("sha256", Buffer.from(apiKeySecret)).update(rawApiKey).digest("hex");
  }

  private readBodyStrict(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let length = 0;
      req.on("data", (chunk: Buffer) => {
        length += chunk.length;
        if (length > 1048576) {
          req.destroy();
          reject(new Error("Payload size limit exceeded"));
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      req.on("error", reject);
    });
  }

  private verifyProofOfWork(nonce: string): void {
    const timeWindow = Math.floor(Date.now() / 300000);
    
    if (this.currentPoWWindow !== timeWindow) {
      this.currentPoWWindow = timeWindow;
      this.seenNonces.clear();
    }

    if (this.seenNonces.has(nonce)) {
      throw new Error("Proof of Work challenge nonce already used");
    }

    const challenge = `${this.blindIndexSalt}:${timeWindow}`;
    const hash = createHash("sha256").update(challenge + nonce).digest("hex");
    if (!hash.startsWith("0000")) {
      throw new Error("Invalid Proof of Work Challenge");
    }

    this.seenNonces.add(nonce);
  }

  private extractContext(req: http.IncomingMessage, isMutation: boolean): ConfigContext {
    const rawHeaders = {
      "x-api-key": req.headers["x-api-key"],
      "x-device-id": req.headers["x-device-id"],
      "x-pow-nonce": req.headers["x-pow-nonce"],
    };

    const parsed = ApiAuthHeaderSchema.safeParse(rawHeaders);
    if (!parsed.success) {
      const issueString = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
      throw new Error(`Authentication Validation Failed (${issueString})`);
    }

    const validatedHeaders = parsed.data;

    const providedKey = validatedHeaders["x-api-key"] || "";
    if (!providedKey) {
      throw new Error("Missing API Key");
    }

    const apiKeySecret = hkdfSync("sha256", this.blindIndexSalt, Buffer.alloc(0), "api_key_derivation", 32);
    const providedHash = createHmac("sha256", Buffer.from(apiKeySecret)).update(providedKey).digest("hex");
    const expectedBuffer = Buffer.from(this.expectedApiKeyHash, "utf8");
    const providedBuffer = Buffer.from(providedHash, "utf8");

    if (expectedBuffer.length !== providedBuffer.length || !timingSafeEqual(expectedBuffer, providedBuffer)) {
      throw new Error("Unauthorized Access");
    }

    if (isMutation) {
      if (!validatedHeaders["x-pow-nonce"]) {
        throw new Error("Mutation endpoint requires x-pow-nonce header");
      }
      this.verifyProofOfWork(validatedHeaders["x-pow-nonce"]);
    }

    const deviceSecret = hkdfSync("sha256", this.blindIndexSalt, Buffer.alloc(0), "device_id_derivation", 32);
    const deviceHash = createHmac("sha256", Buffer.from(deviceSecret)).update(validatedHeaders["x-device-id"]).digest("hex");

    return {
      tenantId: "system-tenant-001",
      deviceHash: deviceHash,
    };
  }

  public async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const clientIp = req.socket.remoteAddress || "unknown";
    const method = req.method || "GET";
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    if (url.pathname !== "/api/v1/config") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Endpoint Not Found" }));
      return;
    }

    try {
      const isMutation = method === "PUT" || method === "POST";
      const context = this.extractContext(req, isMutation);

      await contextStorage.run(context, async () => {
        if (method === "GET") {
          const config = await this.service.getConfig();
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(config));
          audit.http(clientIp, "GET", "control-plane", url.pathname, 200, "Config retrieved");
          return;
        }

        if (method === "PUT") {
          const bodyStr = await this.readBodyStrict(req);
          const rawConfig = JSON.parse(bodyStr);
          await this.service.updateConfig(rawConfig);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, timestamp: Date.now() }));
          audit.http(clientIp, "PUT", "control-plane", url.pathname, 200, "Config updated");
          return;
        }

        res.writeHead(405, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Method Not Allowed" }));
      });

    } catch (error: any) {
      const message = error.message || "Internal Server Error";
      
      let statusCode = 400;
      if (message.includes("Payload size limit")) {
        statusCode = 413;
      } else if (message.includes("Authentication Validation Failed") || message.includes("Unauthorized") || message.includes("API Key") || message.includes("x-pow-nonce")) {
        statusCode = 401;
      } else if (message.includes("Invalid Proof of Work") || message.includes("already used")) {
        statusCode = 403;
      }

      audit.error(`Control Plane API Fault: HTTP ${statusCode} | ${message} | Client: ${clientIp}`);

      res.writeHead(statusCode, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: message }));
    }
  }
}
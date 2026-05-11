import * as http from "http";
import * as fs from "node:fs";
import { ServerConfig, audit } from "@opensecurity/zonzon-core";
import { ConfigService } from "./domain/config/config.service.js";
import { ConfigHandler } from "./domain/config/config.handler.js";

export interface ControlPlaneOptions {
  port?: number;
  socketPath?: string;
  apiKey: string;
  blindIndexSalt: string;
  initialConfig: ServerConfig;
  configFilePath: string;
}

export class ControlPlane {
  private service: ConfigService;
  private server: http.Server | null = null;
  private options: ControlPlaneOptions;

  constructor(options: ControlPlaneOptions) {
    this.options = options;
    this.service = new ConfigService(options.initialConfig, options.configFilePath);
  }

  public subscribe(callback: (config: ServerConfig) => void): void {
    this.service.subscribe(callback);
  }

  public async start(): Promise<void> {
    const handler = new ConfigHandler(this.service, this.options.apiKey, this.options.blindIndexSalt);
    
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        handler.handleRequest(req, res).catch(err => {
          audit.error(`Control Plane Native Fault: ${err.message}`);
          if (!res.headersSent) {
            res.writeHead(500);
            res.end(JSON.stringify({ error: "Internal Server Fault" }));
          }
        });
      });

      this.server.on("error", reject);

      if (this.options.socketPath) {
        if (fs.existsSync(this.options.socketPath)) {
          fs.unlinkSync(this.options.socketPath);
        }
        this.server.listen(this.options.socketPath, () => {
          fs.chmodSync(this.options.socketPath!, 0o600);
          audit.system(`Control Plane locked strictly to Unix Domain Socket at ${this.options.socketPath}`);
          resolve();
        });
      } else {
        this.server.listen(this.options.port || 8080, "127.0.0.1", () => {
          audit.system(`Control Plane locked strictly to loopback interface on port ${this.options.port || 8080}`);
          resolve();
        });
      }
    });
  }

  public async stop(): Promise<void> {
    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      this.server = null;
    }
  }
}
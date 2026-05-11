import * as http from "http";
import { ServerConfig, validateServerConfig, audit } from "@opensecurity/zonzon-core";
import { ConfigService } from "./domain/config/config.service.js";
import { ConfigHandler } from "./domain/config/config.handler.js";

export interface ControlPlaneOptions {
  port: number;
  apiKey: string;
  blindIndexSalt: string;
  initialConfig: ServerConfig;
}

export class ControlPlane {
  private service: ConfigService;
  private server: http.Server | null = null;
  private options: ControlPlaneOptions;

  constructor(options: ControlPlaneOptions) {
    this.options = options;
    this.service = new ConfigService(options.initialConfig);
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

      this.server.listen(this.options.port, "127.0.0.1", () => {
        audit.system(`Control Plane locked strictly to loopback interface on port ${this.options.port}`);
        resolve();
      });
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
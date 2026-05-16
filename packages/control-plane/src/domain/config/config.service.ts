import { promises as fs } from "node:fs";
import * as path from "node:path";
import { ServerConfig, validateServerConfig, audit, encryptSecret, isEncrypted } from "@opensecurity/zonzon-core";
import { getContext } from "./context.js";

class PessimisticLock {
  private locked = false;
  private queue: Array<() => void> = [];

  public acquire(): Promise<void> {
    if (!this.locked) {
      this.locked = true;
      return Promise.resolve();
    }
    return new Promise(resolve => this.queue.push(resolve));
  }

  public release(): void {
    if (this.queue.length > 0) {
      const next = this.queue.shift();
      if (next) next();
    } else {
      this.locked = false;
    }
  }
}

export class ConfigService {
  private config: ServerConfig;
  private configFilePath: string;
  private lock = new PessimisticLock();
  private subscribers: Array<(config: ServerConfig) => void> = [];

  constructor(initialConfig: ServerConfig, configFilePath: string) {
    this.config = validateServerConfig(initialConfig);
    this.configFilePath = path.resolve(configFilePath);
  }

  public subscribe(callback: (config: ServerConfig) => void): void {
    this.subscribers.push(callback);
  }

  public async getConfig(): Promise<ServerConfig> {
    const ctx = getContext();
    if (!ctx.tenantId) {
      throw new Error("Security Exception: Missing Tenant Context");
    }
    return this.config;
  }

  public async updateConfig(rawConfig: unknown): Promise<void> {
    const ctx = getContext();
    if (!ctx.tenantId) {
      throw new Error("Security Exception: Missing Tenant Context");
    }

    await this.lock.acquire();
    try {
      const validatedConfig = validateServerConfig(rawConfig);
      
      for (const host of Object.values(validatedConfig.hosts)) {
        if (host.http_proxy && host.http_proxy.headers) {
          for (const [key, value] of Object.entries(host.http_proxy.headers)) {
            if (!isEncrypted(value)) {
              host.http_proxy.headers[key] = encryptSecret(value);
            }
          }
        }
      }

      const tempPath = `${this.configFilePath}.tmp.${Date.now()}`;
      await fs.writeFile(tempPath, JSON.stringify(validatedConfig, null, 2), { mode: 0o600, encoding: "utf8" });
      await fs.rename(tempPath, this.configFilePath);

      this.config = validatedConfig;

      for (const callback of this.subscribers) {
        try {
          callback(this.config);
        } catch (err) {
          audit.error(`Subscriber failed to process configuration update: ${err}`);
        }
      }
    } finally {
      this.lock.release();
    }
  }
}
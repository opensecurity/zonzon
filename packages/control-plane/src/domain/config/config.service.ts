import { ServerConfig, validateServerConfig, audit } from "@opensecurity/zonzon-core";
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
  private lock = new PessimisticLock();
  private subscribers: Array<(config: ServerConfig) => void> = [];

  constructor(initialConfig: ServerConfig) {
    this.config = validateServerConfig(initialConfig);
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
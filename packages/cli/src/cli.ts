#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parseArgs } from "util";
import { randomBytes } from "crypto";
import {
  DevDnsServer,
  DnsHandler,
  HttpHandler,
  SniProxyService,
  ServerConfig,
  validateServerConfig,
  audit
} from "@opensecurity/zonzon-core";
import { ControlPlane } from "@opensecurity/zonzon-control-plane";

const CONFIG_DIR = path.join(os.homedir(), ".zonzon");
const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

function ensureConfigDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

function loadConfig(configPath: string): any {
  if (!fs.existsSync(configPath)) {
    return {};
  }
  try {
    const fileContents = fs.readFileSync(configPath, "utf8");
    return JSON.parse(fileContents) || {};
  } catch (err: any) {
    audit.error(`Failed to parse configuration file at ${configPath}: ${err.message}`);
    process.exit(1);
  }
}

function saveConfig(configPath: string, data: any): void {
  ensureConfigDir();
  try {
    const jsonStr = JSON.stringify(data, null, 2);
    fs.writeFileSync(configPath, jsonStr, { encoding: "utf8", mode: 0o600 });
  } catch (err: any) {
    audit.error(`Failed to write configuration file at ${configPath}: ${err.message}`);
    process.exit(1);
  }
}

function setDeepValue(obj: any, pathStr: string, value: any): void {
  const parts = pathStr.split(".");
  const last = parts.pop()!;
  let current = obj;
  for (const part of parts) {
    if (!current[part] || typeof current[part] !== "object") {
      current[part] = {};
    }
    current = current[part];
  }
  
  if (value === "true") current[last] = true;
  else if (value === "false") current[last] = false;
  else if (!isNaN(Number(value))) current[last] = Number(value);
  else current[last] = value;
}

function printUsage(): void {
  console.log(`
zonzon core engine (v0.1.0)
Usage: zonzon <command> [options]

Commands:
  init        Initialize the default configuration file at ~/.zonzon/config.json
  start       Boot the routing engine and control plane
  config      Manage configuration state

Config Commands:
  zonzon config view                   Print the current configuration
  zonzon config set <key> <value>      Set a configuration value using dot notation
                                       Example: zonzon config set port 53
                                       Example: zonzon config set controlPlane.port 8081

Global Options:
  --config, -c   Override path to configuration file (default: ~/.zonzon/config.json)
  `);
  process.exit(0);
}

async function handleInit(configPath: string): Promise<void> {
  if (fs.existsSync(configPath)) {
    audit.error(`Configuration already exists at ${configPath}`);
    process.exit(1);
  }
  
  const defaultConf = {
    port: 53,
    httpPort: 80,
    httpsPort: 443,
    fallbackDns: "1.1.1.1",
    maxTcpConnections: 100,
    tcpIdleTimeoutMs: 30000,
    controlPlane: {
      enabled: true,
      port: 8080
    },
    firewall: {
      defaultPolicy: "deny",
      allowlist_ips: ["127.0.0.1"]
    },
    hosts: {}
  };

  saveConfig(configPath, defaultConf);
  audit.system(`Initialized secure default configuration at ${configPath}`);
  audit.system(`Security Notice: Default HTTP/HTTPS ports mapped to 80/443.`);
  audit.system(`If executing within a non-root sandbox, mutate config.json to unprivileged ports (e.g. 8080/8443) to prevent EACCES binding faults.`);
  process.exit(0);
}

async function handleConfig(configPath: string, args: string[]): Promise<void> {
  const subCmd = args[0];
  if (subCmd === "view") {
    if (!fs.existsSync(configPath)) {
      audit.error(`No configuration found at ${configPath}. Run 'zonzon init' first.`);
      process.exit(1);
    }
    const fileContents = fs.readFileSync(configPath, "utf8");
    console.log(fileContents);
    process.exit(0);
  }

  if (subCmd === "set") {
    const key = args[1];
    const value = args[2];
    if (!key || value === undefined) {
      audit.error("Usage: zonzon config set <key> <value>");
      process.exit(1);
    }

    const currentConfig = loadConfig(configPath);
    setDeepValue(currentConfig, key, value);
    saveConfig(configPath, currentConfig);
    audit.system(`Updated configuration: ${key} = ${value}`);
    process.exit(0);
  }

  printUsage();
}

class ZonzonDaemon {
  private dnsHandler: DnsHandler | null = null;
  private httpHandler: HttpHandler | null = null;
  private sniProxy: SniProxyService | null = null;

  public async start(config: ServerConfig): Promise<void> {
    try {
      const dnsServer = new DevDnsServer(config);
      
      this.dnsHandler = new DnsHandler(dnsServer, config);
      await this.dnsHandler.start();
      audit.system(`DNS Listener actively enforcing Zero-Trust boundaries on port ${config.port}`);

      this.httpHandler = new HttpHandler(dnsServer, config, config.httpPort ?? 80);
      await this.httpHandler.start();
      audit.system(`HTTP L7 Sandbox Router active on port ${config.httpPort ?? 80}`);

      this.sniProxy = new SniProxyService(config, config.httpsPort ?? 443);
      await this.sniProxy.start();
      audit.system(`SNI Proxy active on port ${config.httpsPort ?? 443}`);

    } catch (err: any) {
      audit.error(`Fatal bind error during initialization: ${err.message}`);
      await this.stop();
      process.exit(1);
    }
  }

  public async stop(): Promise<void> {
    if (this.dnsHandler) {
      await this.dnsHandler.stop();
      this.dnsHandler = null;
    }
    if (this.httpHandler) {
      await this.httpHandler.stop();
      this.httpHandler = null;
    }
    if (this.sniProxy) {
      await this.sniProxy.stop();
      this.sniProxy = null;
    }
    audit.system("Subsystems halted. Sockets closed.");
  }
}

async function startEngine(configPath: string, portOverride?: string, cpPortOverride?: string): Promise<void> {
  const rawConfig = loadConfig(configPath);

  if (portOverride) {
    rawConfig.port = parseInt(portOverride, 10);
  }

  if (cpPortOverride) {
    if (!rawConfig.controlPlane) rawConfig.controlPlane = {};
    rawConfig.controlPlane.port = parseInt(cpPortOverride, 10);
  }

  let config: ServerConfig;
  try {
    config = validateServerConfig(rawConfig);
  } catch (err: any) {
    audit.error(`Configuration Schema Violation: ${err.message}`);
    process.exit(1);
  }

  const daemon = new ZonzonDaemon();
  await daemon.start(config);

  const isCpEnabled = config.controlPlane?.enabled !== false;
  let controlPlane: ControlPlane | null = null;
  let isEphemeralKey = false;
  let activeApiKey = "";

  if (isCpEnabled) {
    activeApiKey = config.controlPlane?.apiKey || "";
    if (!activeApiKey) {
      activeApiKey = randomBytes(32).toString("hex");
      isEphemeralKey = true;
    }

    const blindIndexSalt = randomBytes(16).toString("hex");
    const cpPort = config.controlPlane?.port || 8080;

    controlPlane = new ControlPlane({
      port: cpPort,
      apiKey: activeApiKey,
      blindIndexSalt: blindIndexSalt,
      initialConfig: config,
    });

    controlPlane.subscribe(async (newConfig: ServerConfig) => {
      audit.system("Applying dynamic configuration update from Control Plane...");
      await daemon.stop();
      await daemon.start(newConfig);
    });

    await controlPlane.start();
    if (isEphemeralKey) {
      audit.system(`[SECURITY] Generated Ephemeral API Key for this session: ${activeApiKey}`);
      audit.system(`[SECURITY] Do not lose this key. It will not be shown again.`);
    } else {
      audit.system(`[SECURITY] Control Plane using static API Key from configuration.`);
    }
  }

  audit.system("Initialization complete. Awaiting connections...");

  const shutdown = async () => {
    audit.system("Initiating graceful shutdown sequence...");
    await daemon.stop();
    if (controlPlane) {
      await controlPlane.stop();
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    options: {
      config: {
        type: "string",
        short: "c",
      },
      port: {
        type: "string",
        short: "p",
      },
      "cp-port": {
        type: "string",
      },
    },
    strict: false,
    allowPositionals: true
  });

  const command = positionals[0];
  const configPath = values.config 
    ? path.resolve(process.cwd(), values.config as string)
    : DEFAULT_CONFIG_PATH;

  switch (command) {
    case "init":
      await handleInit(configPath);
      break;
    case "config":
      await handleConfig(configPath, positionals.slice(1));
      break;
    case "start":
      await startEngine(configPath, values.port as string, values["cp-port"] as string);
      break;
    default:
      printUsage();
      break;
  }
}

main().catch((err) => {
  audit.error(`Unhandled execution fault: ${err.message}`);
  process.exit(1);
});
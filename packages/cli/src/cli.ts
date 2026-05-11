#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parseArgs } from "util";
import { randomBytes } from "crypto";
import * as yaml from "js-yaml";
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
const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, "config.yaml");

function ensureConfigDir() {
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
    return yaml.load(fileContents) || {};
  } catch (err: any) {
    audit.error(`Failed to parse configuration file at ${configPath}: ${err.message}`);
    process.exit(1);
  }
}

function saveConfig(configPath: string, data: any): void {
  ensureConfigDir();
  try {
    const yamlStr = yaml.dump(data, { indent: 2, noRefs: true });
    fs.writeFileSync(configPath, yamlStr, { encoding: "utf8", mode: 0o600 });
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

function printUsage() {
  console.log(`
zonzon core engine (v0.1.0)
Usage: zonzon <command> [options]

Commands:
  init        Initialize the default configuration file at ~/.zonzon/config.yaml
  start       Boot the routing engine and control plane
  config      Manage configuration state

Config Commands:
  zonzon config view                   Print the current configuration
  zonzon config set <key> <value>      Set a configuration value using dot notation
                                       Example: zonzon config set port 53
                                       Example: zonzon config set controlPlane.port 8081

Global Options:
  --config, -c   Override path to configuration file (default: ~/.zonzon/config.yaml)
  `);
  process.exit(0);
}

async function handleInit(configPath: string) {
  if (fs.existsSync(configPath)) {
    audit.error(`Configuration already exists at ${configPath}`);
    process.exit(1);
  }
  
  const defaultConf = {
    port: 53,
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
  process.exit(0);
}

async function handleConfig(configPath: string, args: string[]) {
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

async function startEngine(configPath: string, portOverride?: string, cpPortOverride?: string) {
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

  const dnsServer = new DevDnsServer(config);
  const dnsHandler = new DnsHandler(dnsServer, config);
  const httpHandler = new HttpHandler(dnsServer, config, 80);
  const sniProxy = new SniProxyService(config, 443);

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

    controlPlane.subscribe((newConfig) => {
      audit.system("Applying dynamic configuration update from Control Plane...");
    });
  }

  const shutdown = async () => {
    audit.system("Initiating graceful shutdown sequence...");
    await dnsHandler.stop();
    await httpHandler.stop();
    await sniProxy.stop();
    if (controlPlane) {
      await controlPlane.stop();
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  try {
    await dnsHandler.start();
    audit.system(`DNS Listener actively enforcing Zero-Trust boundaries on port ${config.port}`);

    await httpHandler.start();
    audit.system(`HTTP L7 Sandbox Router active on port 80`);

    await sniProxy.start();
    audit.system(`SNI Proxy active on port 443`);

    if (controlPlane) {
      await controlPlane.start();
      if (isEphemeralKey) {
        audit.system(`[SECURITY] Generated Ephemeral API Key for this session: ${activeApiKey}`);
        audit.system(`[SECURITY] Do not lose this key. It will not be shown again.`);
      } else {
        audit.system(`[SECURITY] Control Plane using static API Key from configuration.`);
      }
    }

    audit.system("Initialization complete. Awaiting connections...");
  } catch (err: any) {
    audit.error(`Fatal bind error during initialization: ${err.message}`);
    await shutdown();
  }
}

async function main() {
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
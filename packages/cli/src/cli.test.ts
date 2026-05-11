import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const execAsync = promisify(exec);

const PROJECT_ROOT = process.cwd();
const CLI_PATH = path.resolve(PROJECT_ROOT, "packages/cli/src/cli.ts");

async function runCli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const { stdout, stderr } = await execAsync(`npx tsx ${CLI_PATH} ${args.join(" ")}`);
    return { stdout, stderr, code: 0 };
  } catch (error: any) {
    return { stdout: error.stdout || "", stderr: error.stderr || "", code: error.code || 1 };
  }
}

describe("CLI Integration Tests", () => {
  let tempDir: string;
  let testConfigPath: string;

  before(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "zonzon-cli-test-"));
    testConfigPath = path.join(tempDir, "config.json");
  });

  after(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("fails to run without a command and prints usage", async () => {
    const { stdout, code } = await runCli([]);
    assert.strictEqual(code, 0); 
    assert.ok(stdout.includes("Usage: zonzon <command>"));
  });

  it("initializes a new configuration file", async () => {
    const { stdout, code } = await runCli(["init", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 0);
    
    const output = JSON.parse(stdout);
    assert.strictEqual(output.success, true);
    assert.strictEqual(output.action, "init");
    
    const fileContent = await fs.readFile(testConfigPath, "utf8");
    const config = JSON.parse(fileContent);
    assert.strictEqual(config.port, 53);
    assert.strictEqual(config.controlPlane.enabled, true);
  });

  it("refuses to overwrite an existing configuration", async () => {
    const { stdout, code } = await runCli(["init", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 1);
    
    const output = JSON.parse(stdout);
    assert.strictEqual(output.success, false);
    assert.ok(output.error.includes("already exists"));
  });

  it("views the current configuration", async () => {
    const { stdout, code } = await runCli(["config", "view", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 0);
    
    const config = JSON.parse(stdout);
    assert.strictEqual(config.port, 53);
    assert.strictEqual(config.httpPort, 80);
  });

  it("mutates a top level configuration value using numeric casting", async () => {
    const { stdout, code } = await runCli(["config", "set", "port", "5353", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 0);
    
    const output = JSON.parse(stdout);
    assert.strictEqual(output.success, true);
    
    const { stdout: viewOut } = await runCli(["config", "view", "--config", testConfigPath, "--json"]);
    const config = JSON.parse(viewOut);
    assert.strictEqual(config.port, 5353);
  });

  it("mutates a nested configuration value using boolean casting", async () => {
    const { code } = await runCli(["config", "set", "controlPlane.enabled", "false", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 0);
    
    const fileContent = await fs.readFile(testConfigPath, "utf8");
    const config = JSON.parse(fileContent);
    assert.strictEqual(config.controlPlane.enabled, false);
  });

  it("mutates a nested configuration value with standard strings", async () => {
    const { code } = await runCli(["config", "set", "fallbackDns", "8.8.8.8", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 0);
    
    const fileContent = await fs.readFile(testConfigPath, "utf8");
    const config = JSON.parse(fileContent);
    assert.strictEqual(config.fallbackDns, "8.8.8.8");
  });

  it("creates nested objects natively if they do not exist", async () => {
    const { code } = await runCli(["config", "set", "firewall.allowlist_ips.0", "10.0.0.1", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 0);
    
    const fileContent = await fs.readFile(testConfigPath, "utf8");
    const config = JSON.parse(fileContent);
    assert.strictEqual(config.firewall.allowlist_ips[0], "10.0.0.1");
  });

  it("fails to view configuration if file is missing", async () => {
    const missingPath = path.join(tempDir, "missing.json");
    const { stdout, code } = await runCli(["config", "view", "--config", missingPath, "--json"]);
    assert.strictEqual(code, 1);
    
    const output = JSON.parse(stdout);
    assert.strictEqual(output.success, false);
    assert.ok(output.error.includes("No configuration found"));
  });

  it("fails to set configuration if parameters are missing", async () => {
    const { stdout, code } = await runCli(["config", "set", "port", "--config", testConfigPath, "--json"]);
    assert.strictEqual(code, 1);
    
    const output = JSON.parse(stdout);
    assert.strictEqual(output.success, false);
    assert.ok(output.error.includes("Missing key or value"));
  });
});
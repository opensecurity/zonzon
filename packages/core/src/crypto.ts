import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { audit } from "./audit.js";

const PREFIX = "v1:";
let MASTER_KEY: Buffer | null = null;

function getMasterKey(): Buffer {
  if (MASTER_KEY) return MASTER_KEY;
  
  if (process.env.ZONZON_MASTER_KEY) {
    MASTER_KEY = crypto.createHash("sha256").update(process.env.ZONZON_MASTER_KEY).digest();
    return MASTER_KEY;
  }
  
  const isTest = process.argv.includes("--test") || process.env.NODE_ENV === "test";
  const keyDir = isTest ? os.tmpdir() : path.resolve(process.cwd(), "config");
  const keyPath = path.join(keyDir, ".zonzon-master-key");
  
  try {
    if (fs.existsSync(keyPath)) {
      const fileKey = fs.readFileSync(keyPath, "utf8").trim();
      MASTER_KEY = crypto.createHash("sha256").update(fileKey).digest();
      return MASTER_KEY;
    }
  } catch (err: any) {
    audit.error(`Cryptographic warning: Unable to read persistent master key. ${err.message}`);
  }

  try {
    const generatedKey = crypto.randomBytes(32).toString("hex");
    if (!fs.existsSync(keyDir)) fs.mkdirSync(keyDir, { recursive: true });
    fs.writeFileSync(keyPath, generatedKey, { mode: 0o600, encoding: "utf8" });
    MASTER_KEY = crypto.createHash("sha256").update(generatedKey).digest();
    audit.system(`[SECURITY] ZONZON_MASTER_KEY not set. Generated persistent key at ${keyPath}`);
  } catch (err: any) {
    MASTER_KEY = crypto.randomBytes(32);
    audit.error(`[SECURITY] Unable to persist master key. Using ephemeral fallback! Secrets will be lost on restart. ${err.message}`);
  }
  
  return MASTER_KEY;
}

export function isEncrypted(value: string): boolean {
  if (typeof value !== "string") return false;
  const parts = value.split(":");
  return parts.length === 4 && parts[0] === "v1" && parts[1].length === 24 && parts[2].length === 32;
}

export function encryptSecret(plaintext: string): string {
  if (isEncrypted(plaintext)) return plaintext;
  
  const nonce = crypto.randomBytes(12);
  const key = getMasterKey();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  
  let ciphertext = cipher.update(plaintext, "utf8", "hex");
  ciphertext += cipher.final("hex");
  
  const authTag = cipher.getAuthTag().toString("hex");
  
  return `${PREFIX}${nonce.toString("hex")}:${authTag}:${ciphertext}`;
}

export function decryptSecret(encrypted: string): string {
  if (!isEncrypted(encrypted)) return encrypted; 
  
  const parts = encrypted.split(":");
  const nonce = Buffer.from(parts[1], "hex");
  const authTag = Buffer.from(parts[2], "hex");
  const ciphertext = parts[3];
  
  const key = getMasterKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(authTag);
  
  try {
    let plaintext = decipher.update(ciphertext, "hex", "utf8");
    plaintext += decipher.final("utf8");
    return plaintext;
  } catch (err: any) {
    throw new Error(`AEAD Decryption Fault: Integrity violation or Master Key mismatch. Payload rejected.`);
  }
}
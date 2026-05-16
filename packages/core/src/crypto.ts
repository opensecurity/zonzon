import * as crypto from "node:crypto";
import { audit } from "./audit.js";

const PREFIX = "v1:";
let MASTER_KEY: Buffer | null = null;

function getMasterKey(): Buffer {
  if (MASTER_KEY) return MASTER_KEY;
  
  if (process.env.ZONZON_MASTER_KEY) {
    MASTER_KEY = crypto.createHash("sha256").update(process.env.ZONZON_MASTER_KEY).digest();
  } else {
    MASTER_KEY = crypto.randomBytes(32);
    audit.system("[SECURITY] ZONZON_MASTER_KEY not set. Using ephemeral AES-256-GCM key. Configuration secrets will be lost on container restart.");
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
  
  try {
    const parts = encrypted.split(":");
    const nonce = Buffer.from(parts[1], "hex");
    const authTag = Buffer.from(parts[2], "hex");
    const ciphertext = parts[3];
    
    const key = getMasterKey();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(authTag);
    
    let plaintext = decipher.update(ciphertext, "hex", "utf8");
    plaintext += decipher.final("utf8");
    
    return plaintext;
  } catch (err) {
    audit.error(`AEAD Decryption Fault: Integrity violation or Master Key mismatch. Stripping secret.`);
    return ""; 
  }
}
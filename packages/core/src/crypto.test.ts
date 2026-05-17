import { describe, it } from "node:test";
import assert from "node:assert";
import { encryptSecret, decryptSecret, isEncrypted } from "./crypto.js";

describe("AEAD Configuration Cryptography", () => {
  it("encrypts and decrypts a secret cleanly", () => {
    const plaintext = "super-secret-token";
    const ciphertext = encryptSecret(plaintext);
    assert.strictEqual(isEncrypted(ciphertext), true);
    assert.notStrictEqual(ciphertext, plaintext);
    
    const decrypted = decryptSecret(ciphertext);
    assert.strictEqual(decrypted, plaintext);
  });

  it("returns original string if not encrypted during decryption", () => {
    const plaintext = "plaintext-header";
    const decrypted = decryptSecret(plaintext);
    assert.strictEqual(decrypted, plaintext);
  });

  it("throws an error on forged ciphertext", () => {
    const plaintext = "sensitive-data";
    const ciphertext = encryptSecret(plaintext);
    const parts = ciphertext.split(":");
    parts[3] = "0000000000000000"; 
    const forged = parts.join(":");
    
    assert.throws(() => decryptSecret(forged), /AEAD Decryption Fault/);
  });
});
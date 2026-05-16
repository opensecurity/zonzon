import { describe, it } from "node:test";
import assert from "node:assert";
import { apply0x20Encoding, extractQuestions } from "./dns-service.js";
import { DNS_TYPES, DNS_CLASSES } from "./types.js";

function buildQuery(name: string): Buffer {
  const encoder = new (class {
    buf = Buffer.alloc(256);
    offset = 0;

    writeUint16(v: number) {
      this.buf.writeUInt16BE(v, this.offset);
      this.offset += 2;
    }

    writeUint8(v: number) {
      this.buf.writeUInt8(v, this.offset);
      this.offset += 1;
    }

    writeDomainName(nm: string) {
      for (const label of nm.split(".")) {
        if (label.length === 0) continue;
        this.writeUint8(label.length);
        Buffer.from(label).copy(this.buf, this.offset);
        this.offset += label.length;
      }
      this.writeUint8(0);
    }

    finish(): Buffer {
      return this.buf.subarray(0, this.offset);
    }
  })();

  encoder.writeUint16(0x1234);
  encoder.writeUint16(0x0100); 
  encoder.writeUint16(1);
  encoder.writeUint16(0);
  encoder.writeUint16(0);
  encoder.writeUint16(0);

  encoder.writeDomainName(name);
  encoder.writeUint16(DNS_TYPES.A);
  encoder.writeUint16(DNS_CLASSES.IN);

  return encoder.finish();
}

describe("0x20 Bit Encoding for DNS Cache Poisoning Mitigation", () => {
  it("randomizes capitalization of single query names", () => {
    const original = buildQuery("www.opensecurity.loop");
    const { query: encodedQuery, expectedNames } = apply0x20Encoding(original);
    
    assert.strictEqual(expectedNames.length, 1);
    assert.strictEqual(expectedNames[0].toLowerCase(), "www.opensecurity.loop");
    
    assert.notStrictEqual(expectedNames[0], "www.opensecurity.loop");
    assert.notStrictEqual(expectedNames[0], "WWW.OPENSECURITY.LOOP");

    const parsedQuestions = extractQuestions(encodedQuery);
    assert.strictEqual(parsedQuestions[0].name, expectedNames[0]);
  });

  it("handles non-alphabetic characters safely without corruption", () => {
    const original = buildQuery("a1b2-c3d4.test.loop");
    const { query: encodedQuery, expectedNames } = apply0x20Encoding(original);
    
    assert.strictEqual(expectedNames.length, 1);
    assert.strictEqual(expectedNames[0].toLowerCase(), "a1b2-c3d4.test.loop");

    const parsedQuestions = extractQuestions(encodedQuery);
    assert.strictEqual(parsedQuestions[0].name, expectedNames[0]);
    assert.ok(expectedNames[0].includes("1"));
    assert.ok(expectedNames[0].includes("2"));
    assert.ok(expectedNames[0].includes("-"));
  });

  it("preserves exact structural length and format post-encoding", () => {
    const original = buildQuery("structure.test.local");
    const { query: encodedQuery } = apply0x20Encoding(original);
    
    assert.strictEqual(original.length, encodedQuery.length);
    assert.strictEqual(original.readUInt16BE(0), encodedQuery.readUInt16BE(0));
    assert.strictEqual(original.readUInt16BE(2), encodedQuery.readUInt16BE(2));
    assert.strictEqual(original.readUInt16BE(4), encodedQuery.readUInt16BE(4)); 
  });

  it("handles empty or structurally incomplete buffers safely", () => {
    const smallBuffer = Buffer.alloc(10);
    const { query: encodedQuery, expectedNames } = apply0x20Encoding(smallBuffer);
    
    assert.strictEqual(expectedNames.length, 0);
    assert.strictEqual(encodedQuery.length, 10);
  });
});
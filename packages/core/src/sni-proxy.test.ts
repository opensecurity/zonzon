import { describe, it } from "node:test";
import assert from "node:assert";
import { SniProxyService } from "./sni-proxy.js";
import { ServerConfig } from "./types.js";

function buildClientHello(sni: string): Buffer {
  const sniBuffer = Buffer.from(sni, "utf8");
  const extLength = sniBuffer.length + 9;
  const buf = Buffer.alloc(100 + extLength);

  buf[0] = 0x16; 
  buf[5] = 0x01; 

  buf[43] = 0x00;

  buf.writeUInt16BE(0x0002, 44);
  buf[46] = 0x00;
  buf[47] = 0x00;

  buf[48] = 0x01;
  buf[49] = 0x00;

  buf.writeUInt16BE(extLength, 50);

  buf.writeUInt16BE(0x0000, 52); 
  buf.writeUInt16BE(sniBuffer.length + 5, 54); 
  buf.writeUInt16BE(sniBuffer.length + 3, 56); 
  buf[58] = 0x00; 
  buf.writeUInt16BE(sniBuffer.length, 59); 
  sniBuffer.copy(buf, 61);

  return buf;
}

describe("SniProxyService - Protocol Extraction", () => {
  const dummyConfig: ServerConfig = {
    port: 53,
    hosts: {}
  };

  it("extracts SNI from valid TLS ClientHello structure", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = buildClientHello("secure.internal.loop");
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, "secure.internal.loop");
  });

  it("returns null for non-TLS packets", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, null);
  });

  it("returns null for TLS packets without ServerName extension", () => {
    const service = new SniProxyService(dummyConfig);
    const buf = Buffer.alloc(100);
    buf[0] = 0x16;
    buf[5] = 0x01;
    buf[43] = 0x00; 
    buf.writeUInt16BE(0x0002, 44); 
    buf[48] = 0x01; 
    buf.writeUInt16BE(0x0004, 50); 
    buf.writeUInt16BE(0x000A, 52); 
    buf.writeUInt16BE(0x0000, 54); 
    
    const extracted = (service as any).extractSNI(buf);
    assert.strictEqual(extracted, null);
  });

  it("gracefully handles truncated packets without throwing", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = buildClientHello("secure.internal.loop").subarray(0, 50);
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, null);
  });

  it("gracefully handles corrupt length markers without throwing", () => {
    const service = new SniProxyService(dummyConfig);
    const packet = buildClientHello("secure.internal.loop");
    packet.writeUInt16BE(0xFFFF, 44); 
    const extracted = (service as any).extractSNI(packet);
    assert.strictEqual(extracted, null);
  });
});
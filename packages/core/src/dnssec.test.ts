import { describe, it, mock, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import { DnssecValidator } from "./dnssec.js";
import { DnsWireFormat } from "./dns-service.js";
import { DNS_TYPES, DNS_CLASSES, RESPONSE_FLAGS, DNS_RCODE } from "./types.js";
import * as crypto from "node:crypto";
import { audit } from "./audit.js";

function generateEcdsaKeys(): { publicKey: Buffer, privateKey: crypto.KeyObject } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
  });
  
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const rawKey = spkiDer.subarray(27);

  return { publicKey: rawKey, privateKey };
}

function buildDnssecResponse(
  name: string,
  recordType: number,
  rdata: Buffer,
  privateKey: crypto.KeyObject,
  publicKeyRaw: Buffer,
  tamperSignature: boolean = false
): Buffer {
  const encoder = new DnsWireFormat();
  encoder.writeUint16(0xABCD);
  encoder.writeUint16(RESPONSE_FLAGS.QR | RESPONSE_FLAGS.AA | DNS_RCODE.NOERROR);
  encoder.writeUint16(1); 
  encoder.writeUint16(1); 
  encoder.writeUint16(0);
  encoder.writeUint16(2); 

  encoder.writeDomainName(name);
  encoder.writeUint16(recordType);
  encoder.writeUint16(DNS_CLASSES.IN);

  encoder.writeDomainName(name);
  encoder.writeUint16(recordType);
  encoder.writeUint16(DNS_CLASSES.IN);
  encoder.writeUint32(3600);
  encoder.writeUint16(rdata.length);
  encoder.writeBytes(rdata);

  const dnskeyRdata = Buffer.alloc(4 + publicKeyRaw.length);
  dnskeyRdata.writeUInt16BE(256, 0); 
  dnskeyRdata[2] = 3;
  dnskeyRdata[3] = 13;
  publicKeyRaw.copy(dnskeyRdata, 4);

  let keyTag = 0;
  for (let i = 0; i < dnskeyRdata.length; i++) {
    keyTag += (i & 1) ? dnskeyRdata[i] : (dnskeyRdata[i] << 8);
  }
  keyTag += (keyTag >> 16) & 0xffff;
  keyTag &= 0xffff;

  encoder.writeDomainName(name);
  encoder.writeUint16(DNS_TYPES.DNSKEY);
  encoder.writeUint16(DNS_CLASSES.IN);
  encoder.writeUint32(3600);
  encoder.writeUint16(dnskeyRdata.length);
  encoder.writeBytes(dnskeyRdata);

  const rrsigPrefix = Buffer.alloc(18);
  rrsigPrefix.writeUInt16BE(recordType, 0);
  rrsigPrefix[2] = 13; 
  rrsigPrefix[3] = name.split(".").filter(l => l.length > 0).length;
  rrsigPrefix.writeUInt32BE(3600, 4); 
  
  const now = Math.floor(Date.now() / 1000);
  rrsigPrefix.writeUInt32BE(now + 86400, 8); 
  rrsigPrefix.writeUInt32BE(now - 86400, 12); 
  rrsigPrefix.writeUInt16BE(keyTag, 16);

  const signerNameEncoder = new DnsWireFormat();
  signerNameEncoder.writeDomainName(name);
  const signerNameCanonical = signerNameEncoder.finish();

  const ownerCanonicalEncoder = new DnsWireFormat();
  ownerCanonicalEncoder.writeDomainName(name);
  const ownerCanonical = ownerCanonicalEncoder.finish();

  const rrHeader = Buffer.alloc(10);
  rrHeader.writeUInt16BE(recordType, 0);
  rrHeader.writeUInt16BE(DNS_CLASSES.IN, 2);
  rrHeader.writeUInt32BE(3600, 4);
  rrHeader.writeUInt16BE(rdata.length, 8);

  const payloadToSign = Buffer.concat([
    rrsigPrefix,
    signerNameCanonical,
    ownerCanonical,
    rrHeader,
    rdata
  ]);

  const sign = crypto.createSign('SHA256');
  sign.update(payloadToSign);
  sign.end();
  let signature = sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });

  if (tamperSignature) {
    signature[10] ^= 0xFF;
  }

  const rrsigRdata = Buffer.concat([
    rrsigPrefix,
    signerNameCanonical,
    signature
  ]);

  encoder.writeDomainName(name);
  encoder.writeUint16(DNS_TYPES.RRSIG);
  encoder.writeUint16(DNS_CLASSES.IN);
  encoder.writeUint32(3600);
  encoder.writeUint16(rrsigRdata.length);
  encoder.writeBytes(rrsigRdata);

  return encoder.finish();
}

describe("DNSSEC Cryptographic Validator", () => {
  beforeEach(() => {
    mock.method(audit, "error", () => {});
    mock.method(audit, "system", () => {});
  });

  afterEach(() => {
    mock.restoreAll();
  });

  it("returns true for a response lacking RRSIG records", () => {
    const encoder = new DnsWireFormat();
    encoder.writeUint16(0x1234);
    encoder.writeUint16(RESPONSE_FLAGS.QR | RESPONSE_FLAGS.AA);
    encoder.writeUint16(1); 
    encoder.writeUint16(1); 
    encoder.writeUint16(0); 
    encoder.writeUint16(0); 

    encoder.writeDomainName("unsigned.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(DNS_CLASSES.IN);

    encoder.writeDomainName("unsigned.loop");
    encoder.writeUint16(DNS_TYPES.A);
    encoder.writeUint16(DNS_CLASSES.IN);
    encoder.writeUint32(300);
    encoder.writeUint16(4);
    encoder.writeBytes(Buffer.from([127, 0, 0, 1]));

    const buffer = encoder.finish();
    const isValid = DnssecValidator.verifyResponse(buffer);
    assert.strictEqual(isValid, true);
  });

  it("successfully validates an authentic ECDSA P-256 RRSIG signature over an A record RRset", () => {
    const { publicKey, privateKey } = generateEcdsaKeys();
    const rdata = Buffer.from([10, 0, 0, 1]); 
    const response = buildDnssecResponse("secure.zonzon.loop", DNS_TYPES.A, rdata, privateKey, publicKey, false);

    const isValid = DnssecValidator.verifyResponse(response);
    assert.strictEqual(isValid, true);
  });

  it("deterministically rejects a tampered RRSIG signature (Cache Poisoning Mitigation)", () => {
    const { publicKey, privateKey } = generateEcdsaKeys();
    const rdata = Buffer.from([10, 0, 0, 1]); 
    const response = buildDnssecResponse("secure.zonzon.loop", DNS_TYPES.A, rdata, privateKey, publicKey, true);

    const isValid = DnssecValidator.verifyResponse(response);
    assert.strictEqual(isValid, false);
  });

  it("deterministically rejects a valid signature if the underlying RRset data was altered", () => {
    const { publicKey, privateKey } = generateEcdsaKeys();
    const authenticRdata = Buffer.from([192, 168, 1, 100]); 
    const response = buildDnssecResponse("finance.zonzon.loop", DNS_TYPES.A, authenticRdata, privateKey, publicKey, false);

    let foundA = false;
    for (let i = 12; i < response.length - 4; i++) {
      if (response[i] === 192 && response[i+1] === 168 && response[i+2] === 1 && response[i+3] === 100) {
        response[i] = 10; 
        foundA = true;
        break;
      }
    }
    
    assert.ok(foundA, "Could not locate A record in binary buffer for mutation");
    const isValid = DnssecValidator.verifyResponse(response);
    assert.strictEqual(isValid, false);
  });
});
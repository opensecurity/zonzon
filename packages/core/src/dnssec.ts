import * as crypto from "node:crypto";
import { DnsWireFormat } from "./dns-service.js";
import { DNS_TYPES, DNS_CLASSES } from "./types.js";
import { audit } from "./audit.js";

interface ParsedRecord {
  name: string;
  type: number;
  dclass: number;
  ttl: number;
  rdlength: number;
  rdata: Buffer;
  offset: number;
}

interface RRSIG {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  signatureExpiration: number;
  signatureInception: number;
  keyTag: number;
  signerName: string;
  signature: Buffer;
  rawRdata: Buffer;
}

interface DNSKEY {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: Buffer;
}

export class DnssecValidator {
  private static parseDomainName(decoder: DnsWireFormat): string {
    return decoder.readDomainName().toLowerCase();
  }

  private static buildSpkiP256(publicKeyRaw: Buffer): Buffer {
    const prefix = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004", "hex");
    return Buffer.concat([prefix, publicKeyRaw]);
  }

  private static buildSpkiRsa(publicKeyRaw: Buffer): Buffer {
    let expLen = publicKeyRaw[0];
    let offset = 1;
    if (expLen === 0) {
      expLen = publicKeyRaw.readUInt16BE(1);
      offset = 3;
    }
    const exponent = publicKeyRaw.subarray(offset, offset + expLen);
    const modulus = publicKeyRaw.subarray(offset + expLen);

    const rsaJwk = {
      kty: "RSA",
      e: exponent.toString("base64url"),
      n: modulus.toString("base64url"),
    };

    const key = crypto.createPublicKey({
      key: rsaJwk,
      format: "jwk"
    });

    return Buffer.from(key.export({ type: "spki", format: "der" }));
  }

  private static extractRecords(buffer: Buffer): { 
    questions: number; 
    answers: ParsedRecord[]; 
    authorities: ParsedRecord[]; 
    additionals: ParsedRecord[]; 
  } {
    const decoder = new DnsWireFormat(buffer);
    decoder.offset = 4;
    const qdcount = decoder.readUint16();
    const ancount = decoder.readUint16();
    const nscount = decoder.readUint16();
    const arcount = decoder.readUint16();

    for (let i = 0; i < qdcount; i++) {
      decoder.readDomainName();
      decoder.offset += 4; 
    }

    const parseSection = (count: number) => {
      const records: ParsedRecord[] = [];
      for (let i = 0; i < count; i++) {
        if (decoder.offset >= buffer.length) break;
        const name = this.parseDomainName(decoder);
        const type = decoder.readUint16();
        const dclass = decoder.readUint16();
        const ttl = decoder.readUint32();
        const rdlength = decoder.readUint16();
        
        const rdata = buffer.subarray(decoder.offset, decoder.offset + rdlength);
        const recordOffset = decoder.offset;
        decoder.offset += rdlength;
        
        records.push({ name, type, dclass, ttl, rdlength, rdata, offset: recordOffset });
      }
      return records;
    };

    return {
      questions: qdcount,
      answers: parseSection(ancount),
      authorities: parseSection(nscount),
      additionals: parseSection(arcount),
    };
  }

  private static parseRrsig(rdata: Buffer): RRSIG | null {
    if (rdata.length < 18) return null;
    const decoder = new DnsWireFormat(rdata);
    
    const typeCovered = decoder.readUint16();
    const algorithm = decoder.readUint8();
    const labels = decoder.readUint8();
    const originalTtl = decoder.readUint32();
    const signatureExpiration = decoder.readUint32();
    const signatureInception = decoder.readUint32();
    const keyTag = decoder.readUint16();
    
    const signerName = this.parseDomainName(decoder);
    const signature = rdata.subarray(decoder.offset);

    return {
      typeCovered,
      algorithm,
      labels,
      originalTtl,
      signatureExpiration,
      signatureInception,
      keyTag,
      signerName,
      signature,
      rawRdata: rdata
    };
  }

  private static parseDnskey(rdata: Buffer): DNSKEY | null {
    if (rdata.length < 4) return null;
    const flags = rdata.readUInt16BE(0);
    const protocol = rdata[2];
    const algorithm = rdata[3];
    const publicKey = rdata.subarray(4);

    return { flags, protocol, algorithm, publicKey };
  }

  private static encodeCanonicalName(name: string): Buffer {
    const encoder = new DnsWireFormat();
    encoder.writeDomainName(name);
    return encoder.finish();
  }

  private static verifySignature(rrsig: RRSIG, rrset: ParsedRecord[], dnskey: DNSKEY): boolean {
    const now = Math.floor(Date.now() / 1000);
    if (now > rrsig.signatureExpiration || now < rrsig.signatureInception) {
      audit.error(`DNSSEC Temporal Fault: RRSIG outside validity window`);
      return false;
    }

    const rrsigPrefixLength = 18;
    const rrsigPrefix = rrsig.rawRdata.subarray(0, rrsigPrefixLength);
    const signerNameCanonical = this.encodeCanonicalName(rrsig.signerName);
    
    const signedDataChunks: Buffer[] = [rrsigPrefix, signerNameCanonical];

    const sortedRrset = rrset.sort((a, b) => {
      const len = Math.min(a.rdata.length, b.rdata.length);
      for (let i = 0; i < len; i++) {
        if (a.rdata[i] !== b.rdata[i]) return a.rdata[i] - b.rdata[i];
      }
      return a.rdata.length - b.rdata.length;
    });

    for (const rr of sortedRrset) {
      const ownerCanonical = this.encodeCanonicalName(rr.name);
      const header = Buffer.alloc(10);
      header.writeUInt16BE(rr.type, 0);
      header.writeUInt16BE(rr.dclass, 2);
      header.writeUInt32BE(rrsig.originalTtl, 4);
      header.writeUInt16BE(rr.rdlength, 8);

      signedDataChunks.push(ownerCanonical, header, rr.rdata);
    }

    const payload = Buffer.concat(signedDataChunks);
    let verifyAlgo = "";
    let spkiBuffer: Buffer;

    if (rrsig.algorithm === 8) {
      verifyAlgo = "RSA-SHA256";
      try {
        spkiBuffer = this.buildSpkiRsa(dnskey.publicKey);
      } catch {
        return false;
      }
    } else if (rrsig.algorithm === 13) {
      verifyAlgo = "SHA256"; 
      if (dnskey.publicKey.length !== 64) {
        return false;
      }
      spkiBuffer = this.buildSpkiP256(dnskey.publicKey);
    } else {
      audit.system(`DNSSEC Skipped: Unsupported cryptographic algorithm ${rrsig.algorithm}`);
      return true; 
    }

    try {
      const key = crypto.createPublicKey({
        key: spkiBuffer,
        format: "der",
        type: "spki"
      });

      let verifyOptions: any = key;
      if (rrsig.algorithm === 13) {
        verifyOptions = { key, dsaEncoding: 'ieee-p1363' };
      }

      return crypto.verify(verifyAlgo, payload, verifyOptions, rrsig.signature);
    } catch (err) {
      return false;
    }
  }

  public static verifyResponse(buffer: Buffer): boolean {
    if (buffer.length < 12) return false;

    const parsed = this.extractRecords(buffer);
    const allRecords = [...parsed.answers, ...parsed.authorities, ...parsed.additionals];

    const dnskeys = allRecords.filter(r => r.type === DNS_TYPES.DNSKEY);
    const rrsigs = allRecords.filter(r => r.type === DNS_TYPES.RRSIG);

    if (rrsigs.length === 0) {
      return true;
    }

    let validationCovered = false;

    for (const sigRecord of rrsigs) {
      const rrsig = this.parseRrsig(sigRecord.rdata);
      if (!rrsig) continue;

      const coveredRrset = parsed.answers.filter(r => r.name === sigRecord.name && r.type === rrsig.typeCovered);
      if (coveredRrset.length === 0) continue;

      const matchingDnskey = dnskeys.find(k => {
        const parsedKey = this.parseDnskey(k.rdata);
        if (!parsedKey) return false;
        
        let tag = 0;
        if (parsedKey.algorithm === 1) {
          tag = (parsedKey.publicKey[parsedKey.publicKey.length - 3] << 8) + parsedKey.publicKey[parsedKey.publicKey.length - 2];
        } else {
          let ac = 0;
          for (let i = 0; i < k.rdata.length; i++) {
            ac += (i & 1) ? k.rdata[i] : (k.rdata[i] << 8);
          }
          ac += (ac >> 16) & 0xffff;
          tag = ac & 0xffff;
        }
        return tag === rrsig.keyTag;
      });

      if (!matchingDnskey) {
        continue;
      }

      const key = this.parseDnskey(matchingDnskey.rdata);
      if (!key) continue;

      const isValid = this.verifySignature(rrsig, coveredRrset, key);
      if (!isValid) {
        audit.error(`DNSSEC Cryptographic Fault: Signature validation failed for ${sigRecord.name}`);
        return false; 
      }
      validationCovered = true;
    }

    return true;
  }
}
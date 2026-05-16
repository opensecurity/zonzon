import { ServerConfig, DNS_TYPES, DNS_CLASSES, RESPONSE_FLAGS, DNS_RCODE } from "./types.js";
import { audit } from "./audit.js";
import { firewallEngine } from "./firewall.js";

export class DnsWireFormat {
  public buf: Buffer;
  public offset: number = 0;

  constructor(buffer?: Buffer) {
    this.buf = buffer || Buffer.alloc(4096);
  }

  writeUint16(val: number): void {
    this.buf.writeUInt16BE(val, this.offset);
    this.offset += 2;
  }

  writeUint8(val: number): void {
    this.buf.writeUInt8(val, this.offset);
    this.offset += 1;
  }

  writeBytes(data: Uint8Array): void {
    Buffer.from(data).copy(this.buf, this.offset);
    this.offset += data.length;
  }

  writeDomainName(name: string): void {
    const labels = name.toLowerCase().split(".");
    for (const label of labels) {
      if (label.length === 0) continue;
      this.writeUint8(label.length);
      this.writeBytes(Buffer.from(label));
    }
    this.writeUint8(0); 
  }

  readUint16(): number {
    const val = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return val;
  }

  readUint8(): number {
    const val = this.buf.readUInt8(this.offset);
    this.offset += 1;
    return val;
  }

  readDomainName(): string {
    const labels: string[] = [];
    let jumped = false;
    let jumpOffset = -1;
    let jumps = 0;
    const MAX_JUMPS = 5;

    while (true) {
      if (jumped && jumpOffset >= 0) {
        this.offset = jumpOffset;
        jumped = false;
        jumpOffset = -1;
      }

      if (this.offset >= this.buf.length) {
        return labels.join(".");
      }

      const len = this.readUint8();
      if (len === 0) break;

      if ((len & 0xc0) === 0xc0) {
        jumps++;
        if (jumps > MAX_JUMPS) {
          return labels.join(".");
        }
        if (this.offset >= this.buf.length) {
          return labels.join(".");
        }
        jumpOffset = ((len & 0x3f) << 8) | this.readUint8();
        jumped = true;
        continue;
      }

      if (len > 63 || this.offset + len > this.buf.length) {
        return labels.join(".");
      }

      const labelBytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        labelBytes[i] = this.readUint8();
      }
      labels.push(new TextDecoder().decode(labelBytes));
    }

    return labels.join(".");
  }

  readUint32(): number {
    const val = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return val;
  }

  finish(): Buffer {
    return this.buf.subarray(0, this.offset);
  }

  writeUint32(val: number): void {
    this.buf.writeUInt32BE(val, this.offset);
    this.offset += 4;
  }
}

function encodeARecord(address: string): Buffer {
  const parts = address.split(".");
  return Buffer.from(parts.map((p) => Number(p)));
}

function encodeAAAARecord(address: string): Buffer {
  let expanded = address;
  if (expanded.includes("::")) {
    const [left, right] = expanded.split("::");
    const leftParts = left ? left.split(":") : [];
    const rightParts = right ? right.split(":") : [];
    const missing = 8 - leftParts.length - rightParts.length;
    const parts: string[] = [...leftParts];
    for (let i = 0; i < missing; i++) parts.push("0");
    parts.push(...rightParts);
    expanded = parts.map((p) => p.padStart(4, "0")).join(":");
  }
  const segments = expanded.split(":");
  return Buffer.concat(segments.map((seg) => {
    const val = parseInt(seg, 16);
    return Buffer.from([Math.floor(val / 256), val % 256]);
  }));
}

function encodeCNAME(target: string): Buffer {
  const encoder = new DnsWireFormat();
  encoder.writeDomainName(target);
  return encoder.finish();
}

function encodeTXT(data: string[]): Buffer {
  const encoder = new DnsWireFormat();
  for (const txt of data) {
    const bytes = new TextEncoder().encode(txt);
    encoder.writeUint8(bytes.length);
    encoder.writeBytes(bytes);
  }
  return encoder.finish();
}

function encodeMX(priority: number, exchange: string): Buffer {
  const encoder = new DnsWireFormat();
  encoder.writeUint16(priority);
  encoder.writeDomainName(exchange);
  return encoder.finish();
}

function encodeNS(target: string): Buffer {
  const encoder = new DnsWireFormat();
  encoder.writeDomainName(target);
  return encoder.finish();
}

function encodeSRV(priority: number, weight: number, port: number, target: string): Buffer {
  const encoder = new DnsWireFormat();
  encoder.writeUint16(priority);
  encoder.writeUint16(weight);
  encoder.writeUint16(port);
  encoder.writeDomainName(target);
  return encoder.finish();
}

function encodePTR(target: string): Buffer {
  const encoder = new DnsWireFormat();
  encoder.writeDomainName(target);
  return encoder.finish();
}

interface ParsedQuestion {
  name: string;
  type: number;
  nextOffset: number;
}

function parseQuestion(query: Buffer, baseOffset: number): ParsedQuestion | null {
  const decoder = new DnsWireFormat();
  decoder.buf = query;
  decoder.offset = baseOffset;

  const name = decoder.readDomainName();
  if (decoder.offset > query.length - 4) return null;

  const type = decoder.readUint16();
  const dclass = decoder.readUint16();

  if (dclass !== DNS_CLASSES.IN && dclass !== 255) return null;

  return { name, type, nextOffset: decoder.offset };
}

export function extractQuestions(query: Buffer): ParsedQuestion[] {
  const qdcount = query.readUInt16BE(4);
  const questions: ParsedQuestion[] = [];
  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    const question = parseQuestion(query, offset);
    if (!question) break;
    questions.push(question);
    offset = question.nextOffset;
  }

  return questions;
}

export function apply0x20Encoding(originalQuery: Buffer): { query: Buffer, expectedNames: string[] } {
  const query = Buffer.from(originalQuery);
  if (query.length < 12) return { query, expectedNames: [] };

  const qdcount = query.readUInt16BE(4);
  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    while (offset < query.length) {
      const len = query[offset];
      if (len === 0) { 
         offset++; 
         break; 
      }
      if ((len & 0xc0) === 0xc0) { 
         offset += 2; 
         break; 
      }
      
      offset++;
      for (let j = 0; j < len; j++) {
        if (offset + j >= query.length) break;
        let charCode = query[offset + j];
        if ((charCode >= 0x41 && charCode <= 0x5a) || (charCode >= 0x61 && charCode <= 0x7a)) {
          if (Math.random() > 0.5) charCode |= 0x20;
          else charCode &= ~0x20;
          query[offset + j] = charCode;
        }
      }
      offset += len;
    }
    if (offset + 4 <= query.length) {
      offset += 4;
    }
  }
  
  const expectedNames = extractQuestions(query).map(q => q.name);
  return { query, expectedNames };
}

function buildResponsePacket(
  id: number,
  flags: number,
  rcode: number,
  qdcount: number,
  questions: ParsedQuestion[],
  answerBuffers: Buffer[]
): Buffer {
  const encoder = new DnsWireFormat();
  encoder.buf = Buffer.alloc(4096);

  const combinedFlags = (flags & ~0x8000) | RESPONSE_FLAGS.QR | RESPONSE_FLAGS.AA | rcode;

  encoder.writeUint16(id);
  encoder.writeUint16(combinedFlags);
  encoder.writeUint16(qdcount);

  const answerCountOffset = encoder.offset;
  encoder.buf.writeUInt16BE(0, answerCountOffset);
  encoder.offset += 2;
  encoder.writeUint16(0); 
  encoder.writeUint16(0); 

  for (const q of questions) {
    encoder.writeDomainName(q.name);
    encoder.writeUint16(q.type);
    encoder.writeUint16(DNS_CLASSES.IN);
  }

  let ancount = 0;
  for (const answer of answerBuffers) {
    if (answer.length < 12) continue; 

    const ansDecoder = new DnsWireFormat();
    ansDecoder.buf = answer;
    ansDecoder.offset = 0;

    const recordType = ansDecoder.readUint16();
    const recordClass = ansDecoder.readUint16();
    const ttl = ansDecoder.readUint32();
    const rdlength = ansDecoder.readUint16();

    encoder.writeUint8(0xc0);
    encoder.writeUint8(0x0c);
    encoder.writeUint16(recordType);
    encoder.writeUint16(recordClass);
    encoder.writeUint32(ttl);
    encoder.writeUint16(rdlength);

    const rdata = new Uint8Array(ansDecoder.buf.buffer, ansDecoder.buf.byteOffset + ansDecoder.offset, rdlength);
    encoder.writeBytes(rdata);
    ancount++;
  }

  encoder.buf.writeUInt16BE(ancount, answerCountOffset);

  return encoder.finish();
}

function buildNoErrorResponse(id: number, flags: number, questions: ParsedQuestion[]): Buffer {
  const encoder = new DnsWireFormat();
  encoder.buf = Buffer.alloc(4096);

  const combinedFlags = (flags & ~0x8000) | RESPONSE_FLAGS.QR | RESPONSE_FLAGS.AA | DNS_RCODE.NOERROR;
  const qdcount = questions.length;

  encoder.writeUint16(id);
  encoder.writeUint16(combinedFlags);
  encoder.writeUint16(qdcount);

  const answerOffsetPlaceholder = encoder.offset;
  encoder.buf.writeUInt16BE(0, encoder.offset);
  encoder.offset += 2;
  encoder.writeUint16(0); 
  encoder.writeUint16(0); 

  for (const q of questions) {
    encoder.writeDomainName(q.name);
    encoder.writeUint16(q.type);
    encoder.writeUint16(DNS_CLASSES.IN);
  }

  encoder.buf.writeUInt16BE(0, answerOffsetPlaceholder);
  return encoder.finish();
}

type HostConfig = import("./types.js").HostConfig;
type DnsRecord = import("./types.js").DnsRecord;

interface CacheEntry {
  response: Buffer;
  insertedAt: number; 
  ttlMs: number; 
}

export class DevDnsServer {
  private config: ServerConfig;
  private cacheMap = new Map<string, CacheEntry>();
  private dnsCacheMaxSize: number;
  private dnsCacheTtlMs: number;

  constructor(config: ServerConfig) {
    this.config = config;
    this.dnsCacheMaxSize = config.dnsCacheMaxSize ?? 1024;
    this.dnsCacheTtlMs = config.dnsCacheTtlMs ?? 0;
  }

  private normalizeHost(name: string): string {
    return name.toLowerCase().replace(/\.$/, "");
  }

  private findHostConfig(normalizedName: string): HostConfig | undefined {
    for (const [key, value] of Object.entries(this.config.hosts)) {
      if (key !== "*" && !key.startsWith("*.") && key.toLowerCase() === normalizedName) {
        return value;
      }
    }

    const labels = normalizedName.split(".");
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join(".");
      const wildcardKey = "*." + suffix;
      if (this.config.hosts[wildcardKey]) {
        return this.config.hosts[wildcardKey];
      }
    }

    if (this.config.hosts["*"]) {
      return this.config.hosts["*"];
    }

    return undefined;
  }

  private generateCacheKey(questions: ParsedQuestion[]): string {
    return questions.map((q) => `${q.name}:${q.type}`).join("|");
  }

  private evictCacheEntry(): void {
    const oldestKey = this.cacheMap.keys().next().value;
    if (oldestKey !== undefined) {
      this.cacheMap.delete(oldestKey);
    }
  }

  private getFromCache(key: string): CacheEntry | null {
    const entry = this.cacheMap.get(key);
    if (!entry) return null;

    if (this.dnsCacheTtlMs > 0 && Date.now() - entry.insertedAt >= this.dnsCacheTtlMs) {
      this.cacheMap.delete(key);
      return null;
    }

    this.cacheMap.delete(key);
    this.cacheMap.set(key, entry);

    const remainingTtlMs = Math.max(0, this.dnsCacheTtlMs - (Date.now() - entry.insertedAt));
    entry.ttlMs = remainingTtlMs;

    return entry;
  }

  private addToCache(key: string, response: Buffer): void {
    if (this.dnsCacheTtlMs <= 0) return; 

    while (this.cacheMap.size >= this.dnsCacheMaxSize) {
      this.evictCacheEntry();
    }

    const remainingSeconds = Math.max(1, Math.floor(this.dnsCacheTtlMs / 1000));
    const modifiedResponse = this.rewriteResponseTtl(response, remainingSeconds);

    const entry: CacheEntry = {
      response: modifiedResponse,
      insertedAt: Date.now(),
      ttlMs: this.dnsCacheTtlMs,
    };

    this.cacheMap.delete(key);
    this.cacheMap.set(key, entry);
  }

  private skipQuestionSection(buffer: Buffer, offset: number): number {
    const savedOffset = offset;
    while (offset < buffer.length) {
      const len = buffer[offset];
      if (len === 0) { offset++; break; }
      if ((len & 0xc0) === 0xc0) {
        if (offset + 1 >= buffer.length) return savedOffset;
        offset += 2; 
        break;
      }
      if (offset + 1 + len > buffer.length) return savedOffset;
      offset += 1 + len;
    }
    if (offset + 4 > buffer.length) return savedOffset;
    return offset + 4;
  }

  private rewriteResponseTtl(response: Buffer, newTtl: number): Buffer {
    if (response.length < 12) return response;

    const result = Buffer.alloc(response.length);
    response.copy(result, 0);

    const qdcount = response.readUInt16BE(4);
    let offset = 12;

    for (let i = 0; i < qdcount; i++) {
      const nextOffset = this.skipQuestionSection(response, offset);
      if (nextOffset === offset) break; 
      offset = nextOffset;
    }

    const ancount = response.readUInt16BE(6);
    for (let i = 0; i < ancount && offset + 12 <= response.length; i++) {
      offset += 2; 
      offset += 2; 
      offset += 2; 
      const ttlOffset = offset; 
      result.writeUInt32BE(newTtl, ttlOffset); 
      offset += 4; 
      const rdlength = response.readUInt16BE(offset);
      offset += 2 + rdlength; 
    }

    return result;
  }

  private buildSingleAnswer(record: DnsRecord): Buffer {
    let rdata: Buffer = Buffer.alloc(0);

    switch (record.type) {
      case "A":
        rdata = encodeARecord((record as { type: "A"; address: string }).address);
        break;
      case "AAAA":
        rdata = encodeAAAARecord((record as { type: "AAAA"; address: string }).address);
        break;
      case "CNAME":
        rdata = encodeCNAME((record as { type: "CNAME"; target: string }).target);
        break;
      case "TXT":
        rdata = encodeTXT((record as { type: "TXT"; data: string[] }).data);
        break;
      case "MX":
        rdata = encodeMX((record as { type: "MX"; priority: number; exchange: string }).priority, (record as { type: "MX"; priority: number; exchange: string }).exchange);
        break;
      case "NS":
        rdata = encodeNS((record as { type: "NS"; target: string }).target);
        break;
      case "SRV": {
        const srv = record as { type: "SRV"; priority: number; weight: number; port: number; target: string };
        rdata = encodeSRV(srv.priority, srv.weight, srv.port, srv.target);
        break;
      }
    }

    const entry = Buffer.alloc(10 + rdata.length);
    let pos = 0;
    entry.writeUInt16BE(this.toTypeNumber(record.type), pos); pos += 2;
    entry.writeUInt16BE(DNS_CLASSES.IN, pos); pos += 2;
    entry.writeUInt32BE(300, pos); pos += 4; 
    entry.writeUInt16BE(rdata.length, pos); pos += 2;
    rdata.copy(entry, pos);

    return entry;
  }

  private buildAnswers(hostConfig: HostConfig, recordType: number): Buffer[] {
    const answers: Buffer[] = [];
    for (const record of hostConfig.records) {
      if (this.toTypeNumber(record.type) === recordType) {
        answers.push(this.buildSingleAnswer(record));
      }
    }

    return answers;
  }

  public generateErrorResponse(query: Buffer, rcode: number): Buffer {
    if (query.length < 12) return Buffer.alloc(0);
    const id = query.readUInt16BE(0);
    const flags = query.readUInt16BE(2);
    const questions = extractQuestions(query);

    const encoder = new DnsWireFormat();
    encoder.buf = Buffer.alloc(4096);
    const combinedFlags = (flags & ~0x8000) | RESPONSE_FLAGS.QR | RESPONSE_FLAGS.AA | rcode;

    encoder.writeUint16(id);
    encoder.writeUint16(combinedFlags);
    encoder.writeUint16(questions.length);

    const answerOffsetPlaceholder = encoder.offset;
    encoder.buf.writeUInt16BE(0, encoder.offset);
    encoder.offset += 2;
    encoder.writeUint16(0); 
    encoder.writeUint16(0); 

    for (const q of questions) {
      encoder.writeDomainName(q.name);
      encoder.writeUint16(q.type);
      encoder.writeUint16(DNS_CLASSES.IN);
    }

    encoder.buf.writeUInt16BE(0, answerOffsetPlaceholder);
    return encoder.finish();
  }

  resolve(query: Buffer, sourceIp: string = "system"): Buffer | null {
    if (query.length < 12) {
      return Buffer.alloc(0);
    }

    const id = query.readUInt16BE(0);
    const flags = query.readUInt16BE(2);

    if ((flags & 0x8000) !== 0) {
      return Buffer.alloc(0);
    }

    if ((flags & 0x0100) === 0) {
      return Buffer.alloc(0);
    }

    const qdcount = query.readUInt16BE(4);
    const ancount = query.readUInt16BE(6);
    const nscount = query.readUInt16BE(8);

    if (qdcount === 0 || ancount > 0 || nscount > 0) {
      return Buffer.alloc(0);
    }

    const questions = extractQuestions(query);

    const cacheKey = this.generateCacheKey(questions);
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      const cachedRcode = cached.response.length >= 4 ? cached.response.readUInt16BE(2) & 0xf : 0;
      audit.dns(sourceIp, questions, cachedRcode, true);
      return cached.response;
    }
    
    if (questions.length === 0) {
      return this.generateErrorResponse(query, DNS_RCODE.NXDOMAIN);
    }

    const answers: Buffer[] = [];
    let hasAnyMatch = false;
    let allQuestionsUnknown = true;

    for (const question of questions) {
      const normalizedName = this.normalizeHost(question.name);
      let hostConfig = this.findHostConfig(normalizedName);

      if (!hostConfig) continue;

      allQuestionsUnknown = false;

      const recordAnswers = this.buildAnswers(hostConfig, question.type);
      if (recordAnswers.length > 0) {
        answers.push(...recordAnswers);
        hasAnyMatch = true;
      }
    }

    if (!hasAnyMatch && allQuestionsUnknown) {
      let allowed = true;
      for (const q of questions) {
        if (firewallEngine.evaluateDomain(q.name, this.config.firewall) === "DENY") {
          allowed = false;
          break;
        }
      }

      if (!allowed) {
        audit.firewall(sourceIp, questions.map(q => q.name).join(", "), "DENY", "Domain Blocked");
        return this.generateErrorResponse(query, DNS_RCODE.REFUSED);
      }

      if (!this.config.fallbackDns) {
        const response = this.generateErrorResponse(query, DNS_RCODE.NXDOMAIN);
        this.addToCache(cacheKey, response);
        audit.dns(sourceIp, questions, DNS_RCODE.NXDOMAIN, false);
        return response;
      }

      return null;
    }

    if (answers.length > 0) {
      const response = buildResponsePacket(id, flags, DNS_RCODE.NOERROR, questions.length, questions, answers);
      this.addToCache(cacheKey, response);
      audit.dns(sourceIp, questions, DNS_RCODE.NOERROR, false);
      return response;
    }

    if (!allQuestionsUnknown) {
      const response = buildNoErrorResponse(id, flags, questions);
      this.addToCache(cacheKey, response);
      audit.dns(sourceIp, questions, DNS_RCODE.NOERROR, false);
      return response;
    }

    return null;
  }

  hasRecord(name: string, type: number): boolean {
    const normalizedName = this.normalizeHost(name);
    const hostConfig = this.findHostConfig(normalizedName);
    if (!hostConfig) return false;

    return hostConfig.records.some((r) => this.toTypeNumber(r.type) === type);
  }

  private toTypeNumber(recordType: string): number {
    const upper = recordType.toUpperCase();
    switch (upper) {
      case "A": return DNS_TYPES.A;
      case "AAAA": return DNS_TYPES.AAAA;
      case "CNAME": return DNS_TYPES.CNAME;
      case "TXT": return DNS_TYPES.TXT;
      case "MX": return DNS_TYPES.MX;
      case "NS": return DNS_TYPES.NS;
      case "SRV": return DNS_TYPES.SRV;
      case "PTR": return DNS_TYPES.PTR;
      default: return 0;
    }
  }
}
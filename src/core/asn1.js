'use strict';
// A small DER reader and writer, written for this extension. Enough for X.509 certificates, CSRs, keys, PKCS#7 and
// PKCS#12. Lengths are checked against the buffer: a broken file throws an Asn1Error with the offset, never reads
// past the end.

class Asn1Error extends Error {}

const TAG = { BOOLEAN: 1, INTEGER: 2, BIT_STRING: 3, OCTET_STRING: 4, NULL: 5, OID: 6, UTF8: 12, SEQUENCE: 16, SET: 17, PRINTABLE: 19, T61: 20, IA5: 22, UTC_TIME: 23, GEN_TIME: 24, VISIBLE: 26, UNIVERSAL: 28, BMP: 30 };

/** Reads one TLV at offset `at` of `buf` (a Uint8Array / Buffer). Children of constructed values are read lazily. */
function readNode(buf, at = 0, end = buf.length, depth = 0) {
  if (depth > 40) throw new Asn1Error('the data is nested too deeply');
  if (at + 2 > end) throw new Asn1Error(`the data ends early (offset ${at})`);
  const first = buf[at];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = at + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (let i = 0; ; i++) {
      if (p >= end || i > 4) throw new Asn1Error(`bad tag at offset ${at}`);
      const b = buf[p++];
      tag = tag * 128 + (b & 0x7f);
      if (!(b & 0x80)) break;
    }
  }
  if (p >= end) throw new Asn1Error(`the data ends early (offset ${at})`);
  let len = buf[p++];
  let indefinite = false;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) { indefinite = true; len = -1; }
    else {
      if (n > 4 || p + n > end) throw new Asn1Error(`bad length at offset ${at}`);
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
    }
  }
  const node = { buf, cls, tag, constructed, start: at, hdr: p - at, depth };
  if (indefinite) {
    // BER indefinite length (some PKCS#7 and PKCS#12 writers use it): read children until 00 00.
    if (!constructed) throw new Asn1Error(`indefinite length on a primitive value at offset ${at}`);
    const kids = [];
    let q = p;
    for (;;) {
      if (q + 2 > end) throw new Asn1Error(`the data ends early (offset ${q})`);
      if (buf[q] === 0 && buf[q + 1] === 0) { q += 2; break; }
      const k = readNode(buf, q, end, depth + 1);
      kids.push(k);
      q = k.end;
    }
    node.len = q - 2 - p;
    node.end = q;
    node.indefinite = true;
    node._kids = kids;
  } else {
    if (p + len > end) throw new Asn1Error(`a value runs past the end of the data (offset ${at}, ${len} bytes)`);
    node.len = len;
    node.end = p + len;
  }
  return node;
}

/** Content bytes of a node (without tag and length). */
function content(n) { return n.buf.subarray(n.start + n.hdr, n.start + n.hdr + n.len); }
/** The whole TLV bytes of a node. */
function raw(n) { return n.buf.subarray(n.start, n.end); }

/** Children of a constructed node. */
function kids(n) {
  if (n._kids) return n._kids;
  if (!n.constructed) throw new Asn1Error(`expected a constructed value at offset ${n.start}`);
  const out = [];
  let p = n.start + n.hdr;
  while (p < n.end) { const k = readNode(n.buf, p, n.end, n.depth + 1); out.push(k); p = k.end; }
  n._kids = out;
  return out;
}

/** Parses a whole buffer: one value, which must fill the buffer (trailing zero bytes and whitespace allowed). */
function parse(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const n = readNode(u8, 0, u8.length);
  for (let i = n.end; i < u8.length; i++) if (u8[i] !== 0 && u8[i] !== 0x0a && u8[i] !== 0x0d && u8[i] !== 0x20) throw new Asn1Error(`extra data after the value (offset ${n.end})`);
  return n;
}

const is = (n, tag, cls = 0) => !!n && n.tag === tag && n.cls === cls;
function expect(n, tag, what, cls = 0) {
  if (!is(n, tag, cls)) throw new Asn1Error(`${what}: unexpected value at offset ${n ? n.start : '?'}`);
  return n;
}
function seq(n, what = 'sequence') { return kids(expect(n, TAG.SEQUENCE, what)); }

function oid(n) {
  const b = content(expect(n, TAG.OID, 'object identifier'));
  if (!b.length) throw new Asn1Error('empty object identifier');
  const parts = [];
  let v = 0;
  for (let i = 0; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      if (!parts.length) { const a = v < 40 ? 0 : v < 80 ? 1 : 2; parts.push(a, v - a * 40); } else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

/** INTEGER as a BigInt. */
function bigint(n) {
  const b = content(n);
  if (!b.length) return 0n;
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  if (b[0] & 0x80) v -= 1n << BigInt(b.length * 8);
  return v;
}
function int(n) { return Number(bigint(expect(n, TAG.INTEGER, 'integer'))); }
/** INTEGER bytes without the leading sign zero. */
function uintBytes(n) { let b = content(n); while (b.length > 1 && b[0] === 0) b = b.subarray(1); return b; }

function bitString(n) {
  const b = content(expect(n, TAG.BIT_STRING, 'bit string'));
  if (!b.length) throw new Asn1Error('empty bit string');
  return { unused: b[0], bytes: b.subarray(1) };
}
function octets(n) {
  if (n.constructed && n.tag === TAG.OCTET_STRING) return Buffer.concat(kids(n).map((k) => Buffer.from(octets(k)))); // BER constructed
  return content(expect(n, TAG.OCTET_STRING, 'octet string'));
}

function bmpToString(b) { let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]); return s; }
/** Any ASN.1 string type to a JS string. */
function str(n) {
  const b = Buffer.from(content(n));
  if (n.tag === TAG.BMP) return bmpToString(b);
  if (n.tag === TAG.UNIVERSAL) { let s = ''; for (let i = 0; i + 3 < b.length; i += 4) s += String.fromCodePoint(b.readUInt32BE(i)); return s; }
  if (n.tag === TAG.UTF8) return b.toString('utf8');
  return b.toString('latin1');
}

function time(n) {
  const s = Buffer.from(content(n)).toString('latin1');
  let m;
  if (n.tag === TAG.UTC_TIME && (m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s))) {
    const y = Number(m[1]);
    return new Date(Date.UTC(y < 50 ? 2000 + y : 1900 + y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0)));
  }
  if (n.tag === TAG.GEN_TIME && (m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.\d+)?Z$/.exec(s))) {
    return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  throw new Asn1Error(`unreadable date "${s.slice(0, 20)}"`);
}

// ---------- writer ----------
function lenBytes(n) {
  if (n < 0x80) return [n];
  const out = [];
  while (n > 0) { out.unshift(n & 0xff); n = Math.floor(n / 256); }
  return [0x80 | out.length, ...out];
}
/** One TLV. tagByte is the full first byte (class, constructed bit and tag number below 31). */
function tlv(tagByte, body) {
  const b = Buffer.isBuffer(body) ? body : Buffer.from(body || []);
  return Buffer.concat([Buffer.from([tagByte, ...lenBytes(b.length)]), b]);
}
const w = {
  seq: (...items) => tlv(0x30, Buffer.concat(items.flat().filter(Boolean))),
  set: (...items) => tlv(0x31, Buffer.concat(items.flat().filter(Boolean))),
  /** SET OF in DER order (sorted by encoding). */
  setOf: (items) => tlv(0x31, Buffer.concat([...items].sort(Buffer.compare))),
  null: () => Buffer.from([5, 0]),
  bool: (v) => tlv(1, [v ? 0xff : 0]),
  octets: (b) => tlv(4, Buffer.from(b)),
  utf8: (s) => tlv(12, Buffer.from(String(s), 'utf8')),
  bmp: (s) => { const b = Buffer.alloc(String(s).length * 2); for (let i = 0; i < s.length; i++) b.writeUInt16BE(s.charCodeAt(i), i * 2); return tlv(30, b); },
  /** Non-negative integer from a Number, BigInt or bytes. */
  int: (v) => {
    let b;
    if (typeof v === 'number' || typeof v === 'bigint') {
      let x = BigInt(v); const arr = [];
      do { arr.unshift(Number(x & 0xffn)); x >>= 8n; } while (x > 0n);
      b = Buffer.from(arr);
    } else b = Buffer.from(v);
    while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return tlv(2, b);
  },
  oid: (s) => {
    const p = String(s).split('.').map(Number);
    const out = [];
    for (const v of [p[0] * 40 + p[1], ...p.slice(2)]) {
      const enc = [v & 0x7f]; let x = Math.floor(v / 128);
      while (x > 0) { enc.unshift((x & 0x7f) | 0x80); x = Math.floor(x / 128); }
      out.push(...enc);
    }
    return tlv(6, out);
  },
  /** [n] EXPLICIT */
  ctx: (n, ...items) => tlv(0xa0 | n, Buffer.concat(items.flat().filter(Boolean))),
  /** [n] IMPLICIT primitive */
  ctxPrim: (n, bytes) => tlv(0x80 | n, Buffer.from(bytes)),
  raw: (b) => Buffer.from(b),
  tlv,
};

module.exports = { Asn1Error, TAG, readNode, parse, kids, content, raw, is, expect, seq, oid, bigint, int, uintBytes, bitString, octets, str, time, w };

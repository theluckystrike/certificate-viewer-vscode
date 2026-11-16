'use strict';
// Finds PEM blocks in any text: plain PEM, PEM inside JSON strings (\n escapes), PEM inside YAML block scalars,
// base64 of a whole PEM (Kubernetes secrets: "LS0tLS1CRUdJTi..."), and bare base64 DER certificates ("MII...",
// as in the x5c field of a JWK). Each block keeps its character range in the text for hovers and jumps.

const BEGIN_B64 = 'LS0tLS1CRUdJTi'; // base64 of "-----BEGIN"
const PEM_RE = /-----BEGIN ([A-Z0-9 #]{1,40})-----([\s\S]*?)-----END \1-----/g;

function cleanBody(body) {
  const headers = {};
  let b = body.replace(/\\r\\n|\\n|\\r/g, '\n');
  // RFC 1421 headers (legacy encrypted keys): "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-256-CBC,..."
  b = b.replace(/^[ \t>"'|-]*([A-Za-z][A-Za-z-]+): *([^\n]*)\n/gm, (m, k, v) => { headers[k] = v.trim(); return ''; });
  return { b64: b.replace(/[^A-Za-z0-9+/=]/g, ''), headers };
}

/** PEM blocks in text: [{ type, der, start, end, encoding: 'pem' | 'json' | 'base64-pem' | 'base64-der', headers }] */
function findBlocks(text, opts = {}) {
  const out = [];
  const max = opts.max || 500;
  const add = (type, body, start, end, encoding) => {
    const { b64, headers } = cleanBody(body);
    let der = null;
    try { der = Buffer.from(b64, 'base64'); } catch (e) { der = null; }
    out.push({ type, der: der && der.length ? der : null, start, end, encoding, headers, b64len: b64.length });
  };
  PEM_RE.lastIndex = 0;
  let m;
  while ((m = PEM_RE.exec(text)) && out.length < max) {
    const encoding = /\\n/.test(m[2]) ? 'json' : 'pem';
    add(m[1], m[2], m.index, m.index + m[0].length, encoding);
  }
  if (opts.base64 !== false && text.indexOf(BEGIN_B64) >= 0) {
    const re = /LS0tLS1CRUdJTi[A-Za-z0-9+/=]{20,}/g;
    while ((m = re.exec(text)) && out.length < max) {
      let inner;
      try { inner = Buffer.from(m[0], 'base64').toString('latin1'); } catch (e) { continue; }
      PEM_RE.lastIndex = 0;
      let k;
      while ((k = PEM_RE.exec(inner)) && out.length < max) add(k[1], k[2], m.index, m.index + m[0].length, 'base64-pem');
    }
  }
  if (opts.bareDer !== false && text.indexOf('MII') >= 0) {
    const re = /(^|[^A-Za-z0-9+/])(MII[A-Za-z0-9+/]{300,}={0,2})(?![A-Za-z0-9+/=])/g;
    while ((m = re.exec(text)) && out.length < max) {
      const s = m.index + m[1].length;
      if (out.some((b) => s >= b.start && s < b.end)) continue;
      const der = Buffer.from(m[2], 'base64');
      // Only certificates: SEQUENCE { SEQUENCE { [0] version ... } }
      if (der.length > 200 && der[0] === 0x30 && der[1] === 0x82 && der[4] === 0x30) out.push({ type: 'CERTIFICATE', der, start: s, end: s + m[2].length, encoding: 'base64-der', headers: {}, guess: true });
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

/** Every block whose range holds character offset `at` (a base64 PEM can hold a whole chain), in text order. */
function blocksAt(text, at, opts) {
  // Only the region around the offset is searched, so a hover in a large file stays cheap.
  const from = Math.max(0, at - 200000);
  const to = Math.min(text.length, at + 200000);
  const part = text.slice(from, to);
  return findBlocks(part, opts).filter((b) => at >= from + b.start && at <= from + b.end).map((b) => ({ ...b, start: from + b.start, end: from + b.end }));
}
/** The first block whose range holds character offset `at`, or null. */
function blockAt(text, at, opts) { return blocksAt(text, at, opts)[0] || null; }

function toPem(type, der) {
  const b64 = Buffer.from(der).toString('base64');
  return `-----BEGIN ${type}-----\n${b64.replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END ${type}-----\n`;
}

/** True when the bytes look like text (PEM or base64), false for DER and other binary data. */
function looksText(bytes) {
  const n = Math.min(bytes.length, 4096);
  if (!n) return true;
  // DER is full of control bytes (tags 0x02, 0x06, short lengths); PEM and base64 text has none.
  let ctl = 0;
  for (let i = 0; i < n; i++) { const c = bytes[i]; if (c < 9 || (c > 13 && c < 32) || c === 127) ctl++; }
  return ctl <= n / 200;
}

module.exports = { findBlocks, blockAt, blocksAt, toPem, looksText, cleanBody, BEGIN_B64 };

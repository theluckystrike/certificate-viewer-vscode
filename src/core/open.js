'use strict';
// Reads a file's bytes into items: certificates, requests, keys, public keys and the parts it cannot show.
// Formats: PEM (any number of blocks, also inside YAML, JSON and .env text), base64 DER without PEM lines, DER
// (certificate, request, keys, PKCS#7, PKCS#12). PKCS#12 and encrypted keys need a password: the caller passes it,
// and it is never kept here.
const path = require('path');
const A = require('./asn1');
const X = require('./x509');
const pem = require('./pem');
const P12 = require('./pkcs12');
const P7 = require('./pkcs7');

const CERT_TYPES = new Set(['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE']);
const CSR_TYPES = new Set(['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST']);

function item(kind, extra) { return { kind, ...extra }; }
const errText = (e) => String((e && e.message) || e).replace(/^Error: /, '');

/** One DER blob whose type is known from a PEM label (or guessed). Returns items (PKCS#7 gives several). */
function fromDer(der, label, opts, ctx) {
  const now = opts.now || Date.now();
  const src = ctx.source || {};
  try {
    switch (label) {
      case 'CERTIFICATE': case 'X509 CERTIFICATE': case 'TRUSTED CERTIFICATE': return [item('cert', { cert: X.parseCertificate(der, now), source: src })];
      case 'CERTIFICATE REQUEST': case 'NEW CERTIFICATE REQUEST': return [item('csr', { csr: X.parseCsr(der), source: src })];
      case 'PRIVATE KEY': return [item('key', { key: X.parsePrivateKey(der), source: src })];
      case 'RSA PRIVATE KEY': case 'EC PRIVATE KEY': {
        if (ctx.headers && /ENCRYPTED/i.test(ctx.headers['Proc-Type'] || '')) return [item('key', { key: { kind: 'key', format: `${label.split(' ')[0]} (legacy PEM encryption)`, encrypted: true, legacyPem: true, scheme: `legacy PEM encryption, ${ctx.headers['DEK-Info'] ? ctx.headers['DEK-Info'].split(',')[0] : 'unknown cipher'}`, key: null, title: 'Encrypted private key', der: null }, source: src })];
        return [item('key', { key: X.parsePrivateKey(der, label.split(' ')[0]), source: src })];
      }
      case 'ENCRYPTED PRIVATE KEY': {
        const k = X.parseEncryptedKey(der, P12.describeAlg);
        if (opts.password !== undefined && opts.password !== null) {
          try { const plain = P12.decryptPkcs8(der, opts.password); const pk = X.parsePrivateKey(plain); pk.wasEncrypted = k.scheme; return [item('key', { key: pk, source: src })]; } catch (e) { if (e instanceof P12.PasswordError) ctx.wrongPassword = true; else throw e; }
        }
        ctx.lockedKey = true;
        return [item('key', { key: k, source: src })];
      }
      case 'PUBLIC KEY': return [item('pubkey', { pub: X.parsePublicKey(der), source: src })];
      case 'RSA PUBLIC KEY': return [item('pubkey', { pub: X.parsePublicKey(der, true), source: src })];
      case 'PKCS7': case 'CMS': {
        const p = P7.parseP7(der);
        if (p.crls) ctx.warnings.push(`This bundle also holds ${p.crls} revocation list${p.crls === 1 ? '' : 's'}, not shown.`);
        if (p.signers) ctx.warnings.push(`This is a signed message with ${p.signers} signer${p.signers === 1 ? '' : 's'}. The certificates are shown; the signature is not checked.`);
        if (!p.certs.length) ctx.warnings.push('This PKCS#7 file holds no certificates.');
        return p.certs.map((c, i) => item('cert', { cert: X.parseCertificate(c, now), source: { ...src, p7: i } }));
      }
      case 'X509 CRL': return [item('other', { title: 'Certificate revocation list', note: 'Revocation lists (CRL) are not shown in this version.', source: src })];
      case 'OPENSSH PRIVATE KEY': return [item('other', { title: 'OpenSSH private key', note: 'An OpenSSH key, not an X.509 key. Its contents are not shown.', source: src })];
      case 'DSA PRIVATE KEY': return [item('key', { key: { kind: 'key', format: 'DSA (traditional)', encrypted: false, key: { type: 'DSA', label: 'DSA', bits: 0 }, title: 'DSA private key', der: null }, source: src })];
      default: return [item('other', { title: `${label.charAt(0)}${label.slice(1).toLowerCase()}`, note: `A "${label}" block. This viewer reads certificates, requests and keys.`, source: src })];
    }
  } catch (e) {
    return [item('error', { title: `Unreadable ${label.toLowerCase()}`, error: errText(e), source: src })];
  }
}

/** Guesses what a DER blob is. */
function sniffDer(der) {
  const root = A.parse(der);
  if (!A.is(root, A.TAG.SEQUENCE)) throw new A.Asn1Error('the file does not start with an ASN.1 sequence');
  const k = A.kids(root);
  if (k.length >= 2 && A.is(k[0], A.TAG.INTEGER) && A.int(k[0]) === 3 && A.is(k[1], A.TAG.SEQUENCE)) {
    const t = A.kids(k[1])[0];
    if (t && t.tag === A.TAG.OID && A.oid(t).startsWith('1.2.840.113549.1.7.')) return 'PKCS12';
  }
  if (k.length >= 1 && A.is(k[0], A.TAG.OID)) return A.oid(k[0]).startsWith('1.2.840.113549.1.7.') ? 'PKCS7' : 'UNKNOWN';
  if (k.length === 3 && A.is(k[0], A.TAG.SEQUENCE) && A.is(k[2], A.TAG.BIT_STRING)) {
    const body = A.kids(k[0]);
    if (body[0] && body[0].cls === 2 && body[0].tag === 0) return 'CERTIFICATE';
    if (body.length >= 6 && A.is(body[0], A.TAG.INTEGER) && A.is(body[2], A.TAG.SEQUENCE)) return 'CERTIFICATE'; // v1
    if (body.length >= 3 && A.is(body[0], A.TAG.INTEGER) && A.is(body[1], A.TAG.SEQUENCE) && A.is(body[2], A.TAG.SEQUENCE)) return 'CERTIFICATE REQUEST';
  }
  if (k.length === 2 && A.is(k[0], A.TAG.SEQUENCE) && A.is(k[1], A.TAG.BIT_STRING)) return 'PUBLIC KEY';
  if (k.length === 2 && A.is(k[0], A.TAG.SEQUENCE) && A.is(k[1], A.TAG.OCTET_STRING)) return 'ENCRYPTED PRIVATE KEY';
  if (k.length >= 3 && A.is(k[0], A.TAG.INTEGER) && A.is(k[1], A.TAG.SEQUENCE) && A.is(k[2], A.TAG.OCTET_STRING)) return 'PRIVATE KEY';
  if (k.length >= 9 && k.every((x) => A.is(x, A.TAG.INTEGER))) return 'RSA PRIVATE KEY';
  if (k.length >= 2 && A.is(k[0], A.TAG.INTEGER) && A.is(k[1], A.TAG.OCTET_STRING)) return 'EC PRIVATE KEY';
  if (k.length === 2 && k.every((x) => A.is(x, A.TAG.INTEGER))) return 'RSA PUBLIC KEY';
  return 'UNKNOWN';
}

/**
 * bytes: Buffer/Uint8Array; name: file name; opts: { password (string|null|undefined), now }
 * -> { format, isText, items, warnings, errors, locked, lockedKey, wrongPassword, pfx }
 */
function openBytes(bytes, name = '', opts = {}) {
  const buf = Buffer.from(bytes.buffer ? Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength) : bytes);
  const ext = path.extname(name).toLowerCase();
  const ctx = { warnings: [], errors: [], lockedKey: false, wrongPassword: false };
  const res = { format: '', isText: false, items: [], warnings: ctx.warnings, errors: ctx.errors, locked: false, lockedKey: false, wrongPassword: false, pfx: null };
  if (!buf.length) { res.errors.push('The file is empty.'); return res; }
  const text = pem.looksText(buf);
  res.isText = text;
  if (text) {
    const s = buf.toString('utf8');
    const blocks = pem.findBlocks(s);
    if (blocks.length) {
      const encs = new Set(blocks.map((b) => b.encoding));
      res.format = encs.has('pem') && encs.size === 1 ? 'PEM' : 'Text with PEM blocks';
      blocks.forEach((b, i) => {
        if (!b.der && !(b.headers && b.headers['Proc-Type'])) { res.items.push(item('error', { title: `Unreadable ${b.type.toLowerCase()}`, error: 'The block holds no base64 data.', source: { block: i, start: b.start, end: b.end, encoding: b.encoding } })); return; }
        const c = { ...ctx, headers: b.headers, source: { block: i, start: b.start, end: b.end, encoding: b.encoding } };
        res.items.push(...fromDer(b.der, b.guess ? 'CERTIFICATE' : b.type, opts, c));
        if (c.lockedKey) res.lockedKey = true;
        if (c.wrongPassword) res.wrongPassword = true;
      });
      if (/-----BEGIN [A-Z0-9 ]+-----/.test(s) && blocks.filter((b) => b.encoding === 'pem' || b.encoding === 'json').length < (s.match(/-----BEGIN [A-Z0-9 ]+-----/g) || []).length) res.warnings.push('A PEM block in this file has no matching END line and was skipped.');
    } else {
      // base64 DER without PEM lines (some .cer and .crt files), or a broken PEM.
      const t = s.trim();
      if (/^-----BEGIN /m.test(t)) { res.errors.push('This PEM file is cut off: a BEGIN line has no matching END line.'); return res; }
      if (/^[A-Za-z0-9+/=\s]+$/.test(t) && t.length > 40) {
        try { return openDer(Buffer.from(t.replace(/\s+/g, ''), 'base64'), name, opts, res, 'Base64 DER'); } catch (e) { res.errors.push(`The file looks like base64, but it holds no certificate or key: ${errText(e)}`); return res; }
      }
      res.errors.push(`No certificate, key or request found in this file. It is text without "-----BEGIN" lines${ext ? ` (a ${ext} file)` : ''}.`);
    }
    return res;
  }
  try { return openDer(buf, name, opts, res, ''); } catch (e) {
    res.errors.push(`This is not a certificate, key or bundle this viewer can read: ${errText(e)}.`);
    return res;
  }
}

function openDer(der, name, opts, res, prefix) {
  const ctx = { warnings: res.warnings, errors: res.errors, lockedKey: false, wrongPassword: false, source: { der: true } };
  const kind = sniffDer(der);
  if (kind === 'UNKNOWN') throw new A.Asn1Error('the ASN.1 data is not a certificate, request, key, PKCS#7 or PKCS#12 structure');
  if (kind === 'PKCS12') {
    res.format = 'PKCS#12 (PFX)';
    res.pfx = { mac: null, encrypted: [] };
    if (opts.password === undefined) {
      // Try no password first (many exports have none); otherwise wait for the user.
      try { return fillPfx(res, P12.parsePfx(der, ''), opts); } catch (e) { if (!(e instanceof P12.PasswordError)) throw e; }
      res.locked = true;
      return res;
    }
    try { return fillPfx(res, P12.parsePfx(der, opts.password), opts); } catch (e) {
      if (e instanceof P12.PasswordError) { res.locked = true; res.wrongPassword = true; return res; }
      throw e;
    }
  }
  res.format = (prefix ? `${prefix} ` : 'DER ') + ({ CERTIFICATE: 'certificate', 'CERTIFICATE REQUEST': 'certificate request', PKCS7: 'PKCS#7 bundle', 'PUBLIC KEY': 'public key', 'RSA PUBLIC KEY': 'RSA public key', 'PRIVATE KEY': 'private key (PKCS#8)', 'ENCRYPTED PRIVATE KEY': 'encrypted private key', 'RSA PRIVATE KEY': 'RSA private key', 'EC PRIVATE KEY': 'EC private key' }[kind] || kind);
  if (!prefix) res.format = res.format.replace(/^DER PKCS#7/, 'PKCS#7');
  res.items.push(...fromDer(der, kind, opts, ctx));
  res.lockedKey = ctx.lockedKey;
  res.wrongPassword = ctx.wrongPassword;
  return res;
}

function fillPfx(res, p, opts) {
  const now = opts.now || Date.now();
  res.pfx = { mac: p.mac, encrypted: p.encrypted };
  res.warnings.push(...p.warnings);
  for (const o of p.other) res.warnings.push(`This file also holds ${o}, not shown.`);
  p.certs.forEach((c, i) => {
    try { const cert = X.parseCertificate(c.der, now); res.items.push(item('cert', { cert, friendlyName: c.friendlyName || '', localKeyId: c.localKeyId || '', source: { bag: i } })); } catch (e) { res.items.push(item('error', { title: 'Unreadable certificate', error: errText(e), source: { bag: i } })); }
  });
  p.keys.forEach((k, i) => {
    try { const key = X.parsePrivateKey(k.der); key.wasEncrypted = k.scheme; res.items.push(item('key', { key, friendlyName: k.friendlyName || '', localKeyId: k.localKeyId || '', source: { keyBag: i } })); } catch (e) { res.items.push(item('error', { title: 'Unreadable private key', error: errText(e), source: { keyBag: i } })); }
  });
  if (!p.certs.length && !p.keys.length) res.warnings.push('This PFX file is empty.');
  return res;
}

/** All parsed certificates of an open result. */
const certsOf = (res) => res.items.filter((i) => i.kind === 'cert').map((i) => i.cert);

module.exports = { openBytes, sniffDer, fromDer, certsOf, CERT_TYPES, CSR_TYPES };

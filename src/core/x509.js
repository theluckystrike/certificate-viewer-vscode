'use strict';
// X.509 certificates, PKCS#10 requests and public and private keys, read with our own DER reader (asn1.js).
// Private keys: only the type, the size and the public half are taken out. The private numbers are never copied
// into a result, a message or a log.
const crypto = require('crypto');
const A = require('./asn1');
const O = require('./oids');

const hex = (b, sep = ':') => Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase()).join(sep);
const DAY = 86400000;

// ---------- names ----------
function escapeDn(v) { return String(v).replace(/([,+"\\<>;])/g, '\\$1').replace(/^([ #])/, '\\$1').replace(/ $/, '\\ '); }

/** Name (RDNSequence) -> { attrs: [{ type, oid, value }] in file order, text (CN first), cn, raw } */
function parseName(n) {
  const attrs = [];
  for (const rdn of A.kids(A.expect(n, A.TAG.SEQUENCE, 'name'))) {
    for (const atv of A.kids(rdn)) {
      const [t, v] = A.kids(atv);
      const o = A.oid(t);
      let value;
      try { value = A.str(v); } catch (e) { value = '#' + hex(A.raw(v), ''); }
      attrs.push({ type: O.DN[o] || o, oid: o, value });
    }
  }
  const text = attrs.slice().reverse().map((a) => `${a.type}=${escapeDn(a.value)}`).join(', ');
  const get = (t) => { const a = attrs.filter((x) => x.type === t); return a.length ? a[a.length - 1].value : ''; };
  return { attrs, text, cn: get('CN'), o: get('O'), raw: Buffer.from(A.raw(n)), short: get('CN') || get('OU') || get('O') || text || '(empty name)' };
}

// ---------- general names ----------
function ipText(b) {
  if (b.length === 4) return Array.from(b).join('.');
  if (b.length === 16) {
    const g = []; for (let i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
    let s = g.join(':');
    const m = s.match(/(^|:)0(:0)+(:|$)/g);
    if (m) { const longest = m.sort((a, c) => c.length - a.length)[0]; s = s.replace(longest, '::'); }
    return s.replace(/:{3,}/, '::');
  }
  if (b.length === 8 || b.length === 32) { const h = b.length / 2; return `${ipText(b.subarray(0, h))}/${ipText(b.subarray(h))}`; }
  return hex(b);
}
function generalName(n) {
  if (n.cls !== 2) return { type: 'other', value: hex(A.raw(n)) };
  const c = A.content(n);
  switch (n.tag) {
    case 0: {
      const [t, v] = A.kids(n);
      const o = A.oid(t);
      let value = '';
      try { const inner = A.kids(v)[0]; value = A.str(inner); } catch (e) { value = hex(A.content(v)); }
      return { type: o === '1.3.6.1.4.1.311.20.2.3' ? 'UPN' : `otherName ${o}`, value };
    }
    case 1: return { type: 'Email', value: Buffer.from(c).toString('latin1') };
    case 2: return { type: 'DNS', value: Buffer.from(c).toString('latin1') };
    case 4: return { type: 'DirName', value: parseName(A.kids(n)[0]).text };
    case 6: return { type: 'URI', value: Buffer.from(c).toString('latin1') };
    case 7: return { type: 'IP', value: ipText(c) };
    case 8: { const tmp = Buffer.concat([Buffer.from([6]), Buffer.from([c.length]), Buffer.from(c)]); return { type: 'RID', value: A.oid(A.parse(tmp)) }; }
    default: return { type: `[${n.tag}]`, value: hex(c) };
  }
}
const generalNames = (n) => A.kids(n).map(generalName);
const gnText = (g) => `${g.type}: ${g.value}`;

// ---------- public keys ----------
/** SubjectPublicKeyInfo node or DER -> { type, bits, curve, spki (DER Buffer), sha256 (hex), pin (base64), exponent? } */
function parseSpki(nodeOrDer) {
  const n = Buffer.isBuffer(nodeOrDer) || nodeOrDer instanceof Uint8Array ? A.parse(nodeOrDer) : nodeOrDer;
  const [alg, bits] = A.seq(n, 'public key');
  const algKids = A.seq(alg, 'public key algorithm');
  const o = A.oid(algKids[0]);
  const key = A.bitString(bits).bytes;
  const out = { type: O.KEY[o] || o, oid: o, bits: 0, curve: '' };
  try {
    if (o === '1.2.840.113549.1.1.1' || o === '1.2.840.113549.1.1.10') {
      const [mod, e] = A.seq(A.parse(key), 'RSA key');
      const m = A.uintBytes(mod);
      out.bits = m.length * 8 - Math.clz32(m[0]) + 24;
      out.exponent = Number(A.bigint(e));
      out.modulus = hex(m, '');
    } else if (o === '1.2.840.10045.2.1') {
      const p = algKids[1];
      if (p && p.tag === A.TAG.OID) { const c = O.CURVE[A.oid(p)]; out.curve = c ? c.name : A.oid(p); out.bits = c ? c.bits : 0; } else out.curve = 'explicit parameters';
      out.point = hex(key, '');
    } else if (o === '1.3.101.112' || o === '1.3.101.110') { out.bits = 256; out.point = hex(key, ''); }
    else if (o === '1.3.101.113') { out.bits = 456; } else if (o === '1.3.101.111') { out.bits = 448; }
    else if (o === '1.2.840.10040.4.1') { const [p] = A.kids(algKids[1]); const pb = A.uintBytes(p); out.bits = pb.length * 8 - Math.clz32(pb[0]) + 24; }
  } catch (e) { /* key details unreadable: type only */ }
  out.spki = Buffer.from(A.raw(n));
  out.sha256 = crypto.createHash('sha256').update(out.spki).digest('hex');
  out.pin = crypto.createHash('sha256').update(out.spki).digest('base64');
  out.label = keyLabel(out);
  return out;
}
function keyLabel(k) {
  if (k.type === 'EC') return `EC ${k.curve || ''}`.trim();
  if (k.type === 'RSA' || k.type === 'RSA-PSS' || k.type === 'DSA') return `${k.type} ${k.bits} bits`;
  return k.type;
}

// ---------- extensions ----------
function decodeExtension(o, v) {
  const n = () => A.parse(v);
  switch (o) {
    case '2.5.29.19': {
      const k = A.seq(n(), 'basic constraints');
      let ca = false, path = null;
      for (const x of k) { if (x.tag === A.TAG.BOOLEAN) ca = A.content(x)[0] !== 0; else if (x.tag === A.TAG.INTEGER) path = A.int(x); }
      return { lines: [`CA: ${ca ? 'yes' : 'no'}${path !== null ? `, path length ${path}` : ''}`], data: { ca, pathLen: path } };
    }
    case '2.5.29.15': {
      const { bytes } = A.bitString(n());
      const list = O.KU.filter((_, i) => (bytes[i >> 3] || 0) & (0x80 >> (i & 7)));
      return { lines: [list.join(', ') || '(none)'], data: list };
    }
    case '2.5.29.37': {
      const list = A.seq(n()).map((x) => { const id = A.oid(x); return { oid: id, name: O.EKU[id] || id }; });
      return { lines: [list.map((x) => x.name).join(', ')], data: list };
    }
    case '2.5.29.17': case '2.5.29.18': {
      const list = generalNames(n());
      return { lines: list.map(gnText), data: list };
    }
    case '2.5.29.14': { const id = hex(A.octets(n())); return { lines: [id], data: id }; }
    case '2.5.29.35': {
      const d = {}; const lines = [];
      for (const x of A.seq(n())) {
        if (x.cls !== 2) continue;
        if (x.tag === 0) { d.keyId = hex(A.content(x)); lines.push(`Key ID: ${d.keyId}`); }
        if (x.tag === 1) { d.issuer = A.kids(x).map(generalName); lines.push(...d.issuer.map((g) => `Issuer ${gnText(g)}`)); }
        if (x.tag === 2) { d.serial = hex(A.content(x)); lines.push(`Serial: ${d.serial}`); }
      }
      return { lines, data: d };
    }
    case '2.5.29.31': case '2.5.29.46': {
      const urls = [];
      for (const dp of A.seq(n())) {
        for (const x of A.kids(dp)) {
          if (x.cls === 2 && x.tag === 0) for (const y of A.kids(x)) { if (y.cls === 2 && y.tag === 0) urls.push(...A.kids(y).map(generalName)); }
          if (x.cls === 2 && x.tag === 2) urls.push(...A.kids(x).map((g) => ({ type: 'CRL issuer', value: generalName(g).value })));
        }
      }
      return { lines: urls.map(gnText), data: urls };
    }
    case '1.3.6.1.5.5.7.1.1': case '1.3.6.1.5.5.7.1.11': {
      const list = A.seq(n()).map((ad) => { const [m, loc] = A.kids(ad); const id = A.oid(m); const g = generalName(loc); return { method: O.AIA[id] || id, type: g.type, value: g.value }; });
      return { lines: list.map((x) => `${x.method}: ${x.value}`), data: list };
    }
    case '2.5.29.32': {
      const list = A.seq(n()).map((pi) => {
        const [id, quals] = A.kids(pi);
        const p = A.oid(id);
        const extra = [];
        if (quals) for (const q of A.kids(quals)) { const [qid, qv] = A.kids(q); if (A.oid(qid) === '1.3.6.1.5.5.7.2.1') { try { extra.push(`CPS: ${A.str(qv)}`); } catch (e) { /* skip */ } } else extra.push('User notice'); }
        return { oid: p, name: O.POLICY[p] || p, extra };
      });
      return { lines: list.map((x) => (x.name === x.oid ? x.oid : `${x.name} (${x.oid})`) + (x.extra.length ? `; ${x.extra.join('; ')}` : '')), data: list };
    }
    case '2.5.29.30': {
      const lines = [];
      for (const x of A.seq(n())) {
        const label = x.tag === 0 ? 'Permitted' : 'Excluded';
        for (const st of A.kids(x)) lines.push(`${label}: ${gnText(generalName(A.kids(st)[0]))}`);
      }
      return { lines, data: lines };
    }
    case '1.3.6.1.4.1.11129.2.4.2': {
      const b = Buffer.from(A.octets(n()));
      const scts = [];
      let p = 2;
      const total = b.readUInt16BE(0);
      while (p + 2 <= Math.min(b.length, total + 2)) {
        const l = b.readUInt16BE(p); const s = b.subarray(p + 2, p + 2 + l); p += 2 + l;
        if (s.length >= 41) scts.push({ log: s.subarray(1, 33).toString('base64'), time: new Date(Number(s.readBigUInt64BE(33))).toISOString().replace('.000', '') });
      }
      return { lines: [`${scts.length} timestamp${scts.length === 1 ? '' : 's'}`, ...scts.map((s) => `Log ${s.log.slice(0, 16)}... at ${s.time}`)], data: scts };
    }
    case '1.3.6.1.4.1.11129.2.4.3': return { lines: ['Present: this is a precertificate, not for use by a server'], data: true };
    case '1.3.6.1.5.5.7.1.24': return { lines: [A.seq(n()).map((x) => (A.int(x) === 5 ? 'status_request (OCSP Must-Staple)' : `feature ${A.int(x)}`)).join(', ')], data: null };
    case '2.16.840.1.113730.1.13': return { lines: [A.str(n())], data: null };
    case '2.16.840.1.113730.1.1': {
      const { bytes } = A.bitString(n());
      const names = ['SSL client', 'SSL server', 'S/MIME', 'Object signing', 'Reserved', 'SSL CA', 'S/MIME CA', 'Object signing CA'].filter((_, i) => (bytes[0] || 0) & (0x80 >> i));
      return { lines: [names.join(', ') || '(none)'], data: names };
    }
    case '1.3.6.1.4.1.311.21.1': { const v = A.int(n()); return { lines: [`Certificate ${v & 0xffff}, key ${v >> 16}`], data: v }; }
    case '2.5.29.16': {
      const lines = A.seq(n()).map((x) => `${x.tag === 0 ? 'Not before' : 'Not after'}: ${Buffer.from(A.content(x)).toString('latin1')}`);
      return { lines, data: null };
    }
    case '2.5.29.54': return { lines: [`Skip certificates: ${A.int(n())}`], data: null };
    case '1.3.6.1.4.1.311.20.2': return { lines: [A.str(n())], data: null };
    default: return null;
  }
}

function parseExtensions(n) {
  const out = [];
  for (const e of A.seq(n, 'extensions')) {
    const k = A.kids(e);
    const o = A.oid(k[0]);
    let critical = false, val = k[1];
    if (val.tag === A.TAG.BOOLEAN) { critical = A.content(val)[0] !== 0; val = k[2]; }
    const v = Buffer.from(A.octets(val));
    let dec = null, error = '';
    try { dec = decodeExtension(o, v); } catch (err) { error = String(err.message || err); }
    const lines = dec ? dec.lines : [hex(v.subarray(0, 96)) + (v.length > 96 ? ` ... (${v.length} bytes)` : '')];
    out.push({ oid: o, name: O.EXT[o] || o, critical, lines, data: dec ? dec.data : null, error, known: !!dec });
  }
  return out;
}

// ---------- signature ----------
function sigAlg(n) {
  const k = A.seq(n, 'signature algorithm');
  const o = A.oid(k[0]);
  const s = O.SIG[o] || { name: o, hash: '', key: '' };
  const out = { oid: o, name: s.name, hash: s.hash, key: s.key };
  if (o === '1.2.840.113549.1.1.10') {
    out.hash = 'sha1'; out.saltLength = 20;
    if (k[1] && k[1].tag === A.TAG.SEQUENCE) {
      for (const p of A.kids(k[1])) {
        if (p.cls !== 2) continue;
        const inner = A.kids(p)[0];
        if (p.tag === 0) out.hash = O.HASH[A.oid(A.kids(inner)[0])] || 'sha1';
        if (p.tag === 2) out.saltLength = A.int(inner);
      }
    }
    out.name = `RSA-PSS with ${out.hash.toUpperCase().replace('SHA', 'SHA-')}`;
  }
  return out;
}

/** Verifies `sig` over `tbs` with a public key (SPKI DER). true, false, or null when the runtime cannot check it. */
function verifySignature(alg, tbs, sig, spkiDer) {
  let key;
  try { key = crypto.createPublicKey({ key: Buffer.from(spkiDer), format: 'der', type: 'spki' }); } catch (e) {
    // BoringSSL (VS Code's Electron) cannot read an RSA-PSS public key: the same numbers as a plain RSA key verify
    // the same PSS signature.
    try {
      const k = parseSpki(Buffer.from(spkiDer));
      if (k.oid !== '1.2.840.113549.1.1.10' || !k.modulus) return null;
      key = crypto.createPublicKey({ key: rsaSpki(Buffer.from(k.modulus, 'hex'), k.exponent), format: 'der', type: 'spki' });
    } catch (e2) { return null; }
  }
  try {
    if (alg.key === 'rsa-pss') return crypto.verify(alg.hash, tbs, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: alg.saltLength }, sig);
    if (alg.key === 'rsa') return crypto.verify(alg.hash, tbs, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig);
    if (alg.key === 'ec' || alg.key === 'dsa') return crypto.verify(alg.hash, tbs, key, sig);
    if (alg.key === 'ed25519' || alg.key === 'ed448') return crypto.verify(null, tbs, key, sig);
  } catch (e) { return alg.key === 'rsa' || alg.key === 'ec' ? false : null; }
  return null;
}

// ---------- certificate ----------
function daysLeft(notAfter, now = Date.now()) { return Math.floor((notAfter.getTime() - now) / DAY); }
function status(notBefore, notAfter, now = Date.now()) {
  if (now > notAfter.getTime()) return 'expired';
  if (now < notBefore.getTime()) return 'not-yet';
  return daysLeft(notAfter, now) < 30 ? 'soon' : 'ok';
}
function statusText(c, now = Date.now()) {
  const d = daysLeft(c.notAfter, now);
  if (c.status === 'expired') { const ago = Math.max(0, Math.floor((now - c.notAfter.getTime()) / DAY)); return ago === 0 ? 'Expired today' : `Expired ${ago} day${ago === 1 ? '' : 's'} ago`; }
  if (c.status === 'not-yet') { const t = Math.ceil((c.notBefore.getTime() - now) / DAY); return `Not valid yet (starts in ${t} day${t === 1 ? '' : 's'})`; }
  return `${d} day${d === 1 ? '' : 's'} left`;
}

/** DER of a certificate -> parsed certificate. Throws Asn1Error on a broken certificate. */
function parseCertificate(der, now = Date.now()) {
  const buf = Buffer.from(der);
  const root = A.readNode(new Uint8Array(buf.buffer, buf.byteOffset, buf.length), 0, buf.length);
  const [tbsN, algN, sigN] = A.seq(root, 'certificate');
  if (!tbsN || !algN || !sigN) throw new A.Asn1Error('this is not a certificate (missing parts)');
  const t = A.seq(tbsN, 'certificate body');
  let i = 0;
  let version = 1;
  if (t[0].cls === 2 && t[0].tag === 0) { version = A.int(A.kids(t[0])[0]) + 1; i = 1; }
  const serialN = t[i++];
  const serial = hex(A.uintBytes(A.expect(serialN, A.TAG.INTEGER, 'serial number')));
  const innerAlg = t[i++];
  const issuer = parseName(t[i++]);
  const [nb, na] = A.seq(t[i++], 'validity');
  const subject = parseName(t[i++]);
  const key = parseSpki(t[i++]);
  let extensions = [];
  for (; i < t.length; i++) if (t[i].cls === 2 && t[i].tag === 3) extensions = parseExtensions(A.kids(t[i])[0]);
  const derAll = buf.subarray(0, root.end);
  const c = {
    kind: 'cert', version, serial, issuer, subject, key, extensions,
    notBefore: A.time(nb), notAfter: A.time(na),
    sigAlg: sigAlg(algN), innerAlgMatches: Buffer.compare(Buffer.from(A.raw(innerAlg)), Buffer.from(A.raw(algN))) === 0,
    tbs: Buffer.from(A.raw(tbsN)), signature: Buffer.from(A.bitString(sigN).bytes),
    der: Buffer.from(derAll),
    sha1: hex(crypto.createHash('sha1').update(derAll).digest()),
    sha256: hex(crypto.createHash('sha256').update(derAll).digest()),
  };
  const ext = (o) => extensions.find((e) => e.oid === o);
  const san = ext('2.5.29.17');
  c.san = san && san.data ? san.data : [];
  const bc = ext('2.5.29.19');
  c.ca = !!(bc && bc.data && bc.data.ca);
  c.pathLen = bc && bc.data ? bc.data.pathLen : null;
  const ku = ext('2.5.29.15'); c.keyUsage = ku && ku.data ? ku.data : null;
  const eku = ext('2.5.29.37'); c.extKeyUsage = eku && eku.data ? eku.data.map((x) => x.name) : null;
  const ski = ext('2.5.29.14'); c.ski = ski && ski.data ? ski.data : '';
  const aki = ext('2.5.29.35'); c.aki = aki && aki.data ? aki.data.keyId || '' : '';
  const aia = ext('1.3.6.1.5.5.7.1.1'); c.caIssuers = aia && aia.data ? aia.data.filter((x) => x.method === 'CA issuers').map((x) => x.value) : [];
  c.selfIssued = Buffer.compare(issuer.raw, subject.raw) === 0;
  c.selfSigned = c.selfIssued && verifySignature(c.sigAlg, c.tbs, c.signature, key.spki) === true;
  c.status = status(c.notBefore, c.notAfter, now);
  c.daysLeft = daysLeft(c.notAfter, now);
  c.title = subject.cn || (c.san.find((g) => g.type === 'DNS') || {}).value || subject.short;
  c.role = c.ca ? (c.selfIssued ? 'Root CA' : 'Intermediate CA') : (c.selfSigned ? 'Self-signed' : 'End entity');
  return c;
}

// ---------- CSR ----------
function parseCsr(der) {
  const buf = Buffer.from(der);
  const root = A.readNode(new Uint8Array(buf.buffer, buf.byteOffset, buf.length), 0, buf.length);
  const [infoN, algN, sigN] = A.seq(root, 'certificate request');
  const info = A.seq(infoN, 'request body');
  const version = A.int(info[0]) + 1;
  const subject = parseName(info[1]);
  const key = parseSpki(info[2]);
  const attributes = [];
  let extensions = [];
  if (info[3] && info[3].cls === 2 && info[3].tag === 0) {
    for (const at of A.kids(info[3])) {
      const [t, vals] = A.kids(at);
      const o = A.oid(t);
      if (o === '1.2.840.113549.1.9.14') extensions = parseExtensions(A.kids(vals)[0]);
      else if (o === '1.2.840.113549.1.9.7') attributes.push({ name: 'Challenge password', value: '(set, not shown)' });
      else { let v = ''; try { v = A.str(A.kids(vals)[0]); } catch (e) { v = hex(A.raw(vals)).slice(0, 80); } attributes.push({ name: O.DN[o] || o, value: v }); }
    }
  }
  const alg = sigAlg(algN);
  const tbs = Buffer.from(A.raw(infoN));
  const signature = Buffer.from(A.bitString(sigN).bytes);
  const derAll = buf.subarray(0, root.end);
  const san = extensions.find((e) => e.oid === '2.5.29.17');
  return {
    kind: 'csr', version, subject, key, attributes, extensions, sigAlg: alg,
    san: san && san.data ? san.data : [],
    signatureOk: verifySignature(alg, tbs, signature, key.spki),
    der: Buffer.from(derAll),
    sha256: hex(crypto.createHash('sha256').update(derAll).digest()),
    title: subject.cn || subject.short,
  };
}

// ---------- private keys ----------
function rsaSpki(n, e) { const w = A.w; return w.seq(w.seq(w.oid('1.2.840.113549.1.1.1'), w.null()), w.tlv(3, Buffer.concat([Buffer.from([0]), w.seq(w.int(n), w.int(e))]))); }
function ecSpki(curveOid, point) { const w = A.w; return w.seq(w.seq(w.oid('1.2.840.10045.2.1'), w.oid(curveOid)), w.tlv(3, Buffer.concat([Buffer.from([0]), Buffer.from(point)]))); }

/** Public half of a private key via the runtime's crypto, as SPKI DER, or null. */
function cryptoSpki(der, type) {
  try {
    const k = crypto.createPrivateKey({ key: Buffer.from(der), format: 'der', type });
    return crypto.createPublicKey(k).export({ type: 'spki', format: 'der' });
  } catch (e) { return null; }
}

/** PKCS#1 RSAPrivateKey, SEC1 ECPrivateKey or PKCS#8 PrivateKeyInfo -> { kind: 'key', format, key (public info) } */
function parsePrivateKey(der, hint = '') {
  const buf = Buffer.from(der);
  const root = A.readNode(new Uint8Array(buf.buffer, buf.byteOffset, buf.length), 0, buf.length);
  const k = A.seq(root, 'private key');
  let format, spki = null, label = '';
  if (hint === 'RSA' || (k.length >= 9 && k.every((x) => x.tag === A.TAG.INTEGER))) {
    format = 'PKCS#1 RSA';
    spki = rsaSpki(A.uintBytes(k[1]), A.uintBytes(k[2]));
  } else if (hint === 'EC' || (k[0].tag === A.TAG.INTEGER && k[1] && k[1].tag === A.TAG.OCTET_STRING && A.int(k[0]) === 1 && !(k[1] && k[2] && k[2].tag === A.TAG.SEQUENCE))) {
    format = 'SEC1 EC';
    let curve = '', pub = null;
    for (const x of k.slice(2)) { if (x.cls === 2 && x.tag === 0) curve = A.oid(A.kids(x)[0]); if (x.cls === 2 && x.tag === 1) pub = A.bitString(A.kids(x)[0]).bytes; }
    if (curve && pub) spki = ecSpki(curve, pub);
    else spki = cryptoSpki(buf.subarray(0, root.end), 'sec1');
    if (!spki && curve) label = `EC ${(O.CURVE[curve] || { name: curve }).name}`;
  } else if (k[0].tag === A.TAG.INTEGER && k[1] && k[1].tag === A.TAG.SEQUENCE && k[2] && k[2].tag === A.TAG.OCTET_STRING) {
    format = 'PKCS#8';
    const algK = A.kids(k[1]);
    const o = A.oid(algK[0]);
    const inner = A.octets(k[2]);
    try {
      if (o === '1.2.840.113549.1.1.1' || o === '1.2.840.113549.1.1.10') {
        const r = A.seq(A.parse(inner));
        // RSA-PSS keys keep their own algorithm identifier (with any parameters), as in their certificate.
        spki = o === '1.2.840.113549.1.1.1' ? rsaSpki(A.uintBytes(r[1]), A.uintBytes(r[2]))
          : A.w.seq(Buffer.from(A.raw(k[1])), A.w.tlv(3, Buffer.concat([Buffer.from([0]), A.w.seq(A.w.int(A.uintBytes(r[1])), A.w.int(A.uintBytes(r[2])))])));
      } else if (o === '1.2.840.10045.2.1') {
        const r = A.seq(A.parse(inner));
        let pub = null; for (const x of r.slice(2)) if (x.cls === 2 && x.tag === 1) pub = A.bitString(A.kids(x)[0]).bytes;
        if (pub && algK[1] && algK[1].tag === A.TAG.OID) spki = ecSpki(A.oid(algK[1]), pub);
      }
    } catch (e) { /* use the runtime below */ }
    if (!spki) spki = cryptoSpki(buf.subarray(0, root.end), 'pkcs8');
    // A PKCS#8 key may carry its public key in [1].
    if (!spki) for (const x of k.slice(3)) if (x.cls === 2 && x.tag === 1 && (o === '1.3.101.112' || o === '1.3.101.113')) { const w = A.w; spki = w.seq(w.seq(w.oid(o)), w.tlv(3, Buffer.concat([Buffer.from([0]), Buffer.from(A.content(x)).subarray(1)]))); }
    if (!spki) label = O.KEY[o] || o;
  } else throw new A.Asn1Error('this is not a private key structure this viewer knows');
  const key = spki ? parseSpki(spki) : { type: label || 'unknown', label: label || 'unknown key type', bits: 0, curve: '', spki: null, sha256: '', pin: '' };
  return { kind: 'key', format, key, encrypted: false, title: `${key.label} private key`, der: Buffer.from(buf.subarray(0, root.end)) };
}

/** EncryptedPrivateKeyInfo -> { kind: 'key', encrypted: true, scheme } (decrypt with pkcs12.decryptPkcs8). */
function parseEncryptedKey(der, describeAlg) {
  const buf = Buffer.from(der);
  const root = A.readNode(new Uint8Array(buf.buffer, buf.byteOffset, buf.length), 0, buf.length);
  const [alg] = A.seq(root, 'encrypted private key');
  return { kind: 'key', format: 'PKCS#8 encrypted', encrypted: true, scheme: describeAlg ? describeAlg(alg) : A.oid(A.kids(alg)[0]), key: null, title: 'Encrypted private key', der: Buffer.from(buf.subarray(0, root.end)) };
}

function parsePublicKey(der, rsaPkcs1 = false) {
  if (rsaPkcs1) { const [n, e] = A.seq(A.parse(der)); der = rsaSpki(A.uintBytes(n), A.uintBytes(e)); }
  const key = parseSpki(Buffer.from(der));
  return { kind: 'pubkey', key, title: `${key.label} public key`, der: Buffer.from(key.spki) };
}

module.exports = {
  hex, DAY, parseName, generalName, ipText, parseSpki, parseExtensions, sigAlg, verifySignature, parseCertificate, parseCsr,
  parsePrivateKey, parseEncryptedKey, parsePublicKey, rsaSpki, ecSpki, daysLeft, status, statusText, keyLabel,
};

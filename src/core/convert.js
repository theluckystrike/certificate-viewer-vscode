'use strict';
// Pro tool "Convert": PEM, DER, PKCS#7 (P7B) and PKCS#12 (PFX/P12) in any direction, split a bundle into one file
// per certificate, merge files into one bundle in chain order. Pure functions over DER buffers; the extension writes
// the files.
const A = require('./asn1');
const X = require('./x509');
const C = require('./chain');
const pem = require('./pem');
const P7 = require('./pkcs7');
const P12 = require('./pkcs12');

/** A private key item's DER as PKCS#8 (PFX needs PKCS#8). */
function toPkcs8(key) {
  if (!key || !key.der) throw new Error('the private key is not available');
  if (key.format === 'PKCS#8') return Buffer.from(key.der);
  const w = A.w;
  if (key.format === 'PKCS#1 RSA') return w.seq(w.int(0), w.seq(w.oid('1.2.840.113549.1.1.1'), w.null()), w.octets(key.der));
  if (key.format === 'SEC1 EC') {
    const k = A.seq(A.parse(key.der));
    let curve = '';
    for (const x of k.slice(2)) if (x.cls === 2 && x.tag === 0) curve = A.oid(A.kids(x)[0]);
    if (!curve) throw new Error('the EC key does not name its curve');
    return w.seq(w.int(0), w.seq(w.oid('1.2.840.10045.2.1'), w.oid(curve)), w.octets(key.der));
  }
  throw new Error(`a ${key.format} key cannot go into a PFX`);
}

const safeName = (s) => String(s || 'certificate').replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'certificate';

/** Leaf-first chain order of parsed certs (the input order for anything not in the main chain). */
function chainOrder(certs) { return C.expectedOrder(certs).map((i) => certs[i]); }

/** Removes repeated certificates (same DER), keeping the first. */
function unique(certs) { const seen = new Set(); return certs.filter((c) => { const k = c.sha256; if (seen.has(k)) return false; seen.add(k); return true; }); }

function pemBundle(certs, keys = []) {
  return certs.map((c) => `# ${c.subject.text}\n# Expires ${c.notAfter.toISOString().slice(0, 10)}, issuer ${c.issuer.short}\n${pem.toPem('CERTIFICATE', c.der)}`).join('')
    + keys.map((k) => pem.toPem('PRIVATE KEY', toPkcs8(k))).join('');
}

function p7b(certs) { return P7.writeP7(certs.map((c) => c.der)); }

/** certs: parsed (leaf first), key: parsed private key or null, password: string. */
function pfx(certs, key, password, friendlyName) {
  let list = certs;
  if (key && key.key && key.key.sha256) {
    const leaf = certs.find((c) => c.key.sha256 === key.key.sha256);
    if (!leaf) throw new Error('the private key does not belong to any of the certificates');
    list = [leaf].concat(chainOrder(certs).filter((c) => c !== leaf));
  }
  return P12.writePfx({ certs: list.map((c) => c.der), key: key ? toPkcs8(key) : null, password, friendlyName: friendlyName || (list[0] ? list[0].title : '') });
}

/** One file per certificate: [{ name, data }] with names from the common name, numbered when they repeat. */
function split(certs, ext = 'pem') {
  const used = new Map();
  return certs.map((c, i) => {
    let base = `${String(i + 1).padStart(2, '0')}-${safeName(c.title)}`;
    const n = used.get(base) || 0; used.set(base, n + 1); if (n) base += `-${n + 1}`;
    return { name: `${base}.${ext}`, data: ext === 'der' || ext === 'cer' ? Buffer.from(c.der) : Buffer.from(pem.toPem('CERTIFICATE', c.der)) };
  });
}

/** Re-reads written bytes to confirm what they hold: { certs, keys }. */
function verifyOutput(bytes, name, password) {
  const { openBytes } = require('./open');
  const r = openBytes(bytes, name, { password });
  return { certs: r.items.filter((i) => i.kind === 'cert').length, keys: r.items.filter((i) => i.kind === 'key' && !i.key.encrypted).length, locked: r.locked, errors: r.errors };
}

module.exports = { toPkcs8, safeName, chainOrder, unique, pemBundle, p7b, pfx, split, verifyOutput, X };

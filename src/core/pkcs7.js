'use strict';
// PKCS#7 / CMS certificate bundles (.p7b, .p7c): reads the certificates (and counts the CRLs and signers) of a
// SignedData, and writes a "certs-only" bundle the way OpenSSL crl2pkcs7 -nocrl does.
const A = require('./asn1');
const O = require('./oids');

/** DER of a ContentInfo -> { certs: [DER], crls, signers, contentType } */
function parseP7(der) {
  const root = A.parse(der);
  const [t, v] = A.seq(root, 'PKCS#7');
  const type = A.oid(t);
  if (type !== O.PKCS.signedData) throw new A.Asn1Error(type === O.PKCS.envelopedData ? 'this PKCS#7 file is an encrypted message, not a certificate bundle' : `this PKCS#7 file holds ${type}, not a certificate bundle`);
  if (!v) return { certs: [], crls: 0, signers: 0, contentType: type };
  const sd = A.kids(A.kids(v)[0]);
  const certs = [];
  let crls = 0, signers = 0;
  for (const x of sd.slice(3)) {
    if (x.cls === 2 && x.tag === 0) for (const c of A.kids(x)) { if (c.tag === A.TAG.SEQUENCE && c.cls === 0) certs.push(Buffer.from(A.raw(c))); }
    else if (x.cls === 2 && x.tag === 1) crls = A.kids(x).length;
    else if (x.tag === A.TAG.SET) signers = A.kids(x).length;
  }
  return { certs, crls, signers, contentType: type };
}

/** Certificates (DER) -> a degenerate SignedData ContentInfo (DER). */
function writeP7(certs) {
  const w = A.w;
  return w.seq(w.oid(O.PKCS.signedData), w.ctx(0, w.seq(
    w.int(1), w.set(), w.seq(w.oid(O.PKCS.data)),
    w.tlv(0xa0, Buffer.concat(certs.map((c) => Buffer.from(c)))),
    w.set())));
}

module.exports = { parseP7, writeP7 };

'use strict';
// PKCS#12 / PFX reader and writer (RFC 7292), written for this extension. Reads PBES2 (PBKDF2 with AES or 3DES) and
// the legacy PKCS#12 schemes (SHA-1 with 3DES, RC2 or RC4) and checks the MAC. Writes the OpenSSL 3 default: PBES2
// with PBKDF2-HMAC-SHA256 and AES-256-CBC, 2048 iterations, HMAC-SHA256 MAC.
// The password stays in the caller's memory: nothing here stores, logs or returns it.
const crypto = require('crypto');
const A = require('./asn1');
const O = require('./oids');
const rc2 = require('./rc2');

const P = O.PKCS;
class PasswordError extends Error {}

const HASH_INFO = { sha1: [20, 64], sha224: [28, 64], sha256: [32, 64], sha384: [48, 128], sha512: [64, 128], md5: [16, 64] };

/** Password as a PKCS#12 BMPString with the two trailing zero bytes. null = no password at all (zero bytes). */
function bmpPassword(pw) {
  if (pw === null) return Buffer.alloc(0);
  const b = Buffer.alloc((pw.length + 1) * 2);
  for (let i = 0; i < pw.length; i++) b.writeUInt16BE(pw.charCodeAt(i), i * 2);
  return b;
}

/** RFC 7292 appendix B key derivation. id: 1 key, 2 IV, 3 MAC key. */
function kdf(hash, passBmp, salt, iterations, id, n) {
  const [u, v] = HASH_INFO[hash] || HASH_INFO.sha1;
  const D = Buffer.alloc(v, id);
  const fill = (src) => { if (!src.length) return Buffer.alloc(0); const len = v * Math.ceil(src.length / v); const o = Buffer.alloc(len); for (let i = 0; i < len; i++) o[i] = src[i % src.length]; return o; };
  const I = Buffer.concat([fill(Buffer.from(salt)), fill(passBmp)]);
  const out = [];
  const c = Math.ceil(n / u);
  for (let i = 0; i < c; i++) {
    let Ai = crypto.createHash(hash).update(D).update(I).digest();
    for (let r = 1; r < iterations; r++) Ai = crypto.createHash(hash).update(Ai).digest();
    out.push(Ai);
    const B = fill(Ai);
    for (let j = 0; j < I.length; j += v) {
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) { const s = I[j + k] + B[k] + carry; I[j + k] = s & 0xff; carry = s >> 8; }
    }
  }
  return Buffer.concat(out).subarray(0, n);
}

function rc4(key, data) {
  const S = new Uint8Array(256); for (let i = 0; i < 256; i++) S[i] = i;
  for (let i = 0, j = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
  const out = Buffer.alloc(data.length);
  for (let k = 0, i = 0, j = 0; k < data.length; k++) { i = (i + 1) & 255; j = (j + S[i]) & 255; [S[i], S[j]] = [S[j], S[i]]; out[k] = data[k] ^ S[(S[i] + S[j]) & 255]; }
  return out;
}

const PRF = { [P.hmacSha1]: 'sha1', [P.hmacSha224]: 'sha224', [P.hmacSha256]: 'sha256', [P.hmacSha384]: 'sha384', [P.hmacSha512]: 'sha512' };
const CIPHERS = { [P.aes128cbc]: ['aes-128-cbc', 16, 'AES-128-CBC'], [P.aes192cbc]: ['aes-192-cbc', 24, 'AES-192-CBC'], [P.aes256cbc]: ['aes-256-cbc', 32, 'AES-256-CBC'], [P.desEde3cbc]: ['des-ede3-cbc', 24, '3DES-CBC'], [P.desCbc]: ['des-cbc', 8, 'DES-CBC'] };

/** Human text for an AlgorithmIdentifier of password-based encryption. */
function describeAlg(algN) {
  const k = A.kids(algN);
  const o = A.oid(k[0]);
  if (o === P.pbes2) {
    try {
      const [kdfN, encN] = A.kids(k[1]);
      const kp = A.kids(A.kids(kdfN)[1]);
      const iter = A.int(kp[1]);
      let prf = 'sha1';
      for (const x of kp.slice(2)) if (x.tag === A.TAG.SEQUENCE) prf = PRF[A.oid(A.kids(x)[0])] || A.oid(A.kids(x)[0]);
      const enc = A.oid(A.kids(encN)[0]);
      return `PBES2: PBKDF2 HMAC-${prf.toUpperCase().replace('SHA', 'SHA-')}, ${(CIPHERS[enc] || [0, 0, enc])[2]}, ${iter} iterations`;
    } catch (e) { return 'PBES2'; }
  }
  if (O.PBE_NAMES[o]) { let it = ''; try { it = `, ${A.int(A.kids(k[1])[1])} iterations`; } catch (e) { /* none */ } return O.PBE_NAMES[o] + it; }
  return `unknown scheme ${o}`;
}

/** Decrypts data with a password-based AlgorithmIdentifier. Throws PasswordError on a wrong password. */
function pbeDecrypt(algN, data, password) {
  const k = A.kids(algN);
  const o = A.oid(k[0]);
  const fail = () => { throw new PasswordError('wrong password'); };
  if (o === P.pbes2) {
    const [kdfN, encN] = A.kids(k[1]);
    if (A.oid(A.kids(kdfN)[0]) !== P.pbkdf2) throw new Error('this file uses a key derivation other than PBKDF2');
    const kp = A.kids(A.kids(kdfN)[1]);
    const salt = A.octets(kp[0]);
    const iter = A.int(kp[1]);
    let prf = 'sha1', keyLen = 0;
    for (const x of kp.slice(2)) { if (x.tag === A.TAG.INTEGER) keyLen = A.int(x); else if (x.tag === A.TAG.SEQUENCE) prf = PRF[A.oid(A.kids(x)[0])] || 'sha1'; }
    const encK = A.kids(encN);
    const c = CIPHERS[A.oid(encK[0])];
    if (!c) throw new Error(`this file uses a cipher this viewer does not read (${A.oid(encK[0])})`);
    const iv = A.octets(encK[1]);
    const key = crypto.pbkdf2Sync(Buffer.from(password || '', 'utf8'), Buffer.from(salt), iter, keyLen || c[1], prf);
    try { const d = crypto.createDecipheriv(c[0], key, iv); return Buffer.concat([d.update(data), d.final()]); } catch (e) { return fail(); }
  }
  const [saltN, iterN] = A.kids(k[1]);
  const salt = A.octets(saltN);
  const iter = A.int(iterN);
  const pw = bmpPassword(password === null ? null : password || '');
  const pick = { [P.pbeSha13Des]: ['des-ede3-cbc', 24, 8], [P.pbeSha12Des]: ['des-ede-cbc', 16, 8], [P.pbeSha1Rc2_40]: ['rc2', 5, 8, 40], [P.pbeSha1Rc2_128]: ['rc2', 16, 8, 128], [P.pbeSha1Rc4_128]: ['rc4', 16, 0], [P.pbeSha1Rc4_40]: ['rc4', 5, 0] }[o];
  if (!pick) throw new Error(`this file uses an encryption scheme this viewer does not read (${o})`);
  const key = kdf('sha1', pw, salt, iter, 1, pick[1]);
  if (pick[0] === 'rc4') return rc4(key, data);
  const iv = kdf('sha1', pw, salt, iter, 2, pick[2]);
  try {
    if (pick[0] === 'rc2') return rc2.decryptCbc(key, pick[3], iv, Buffer.from(data));
    const d = crypto.createDecipheriv(pick[0], key, iv); return Buffer.concat([d.update(data), d.final()]);
  } catch (e) { return fail(); }
}

/** PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC: returns { alg (DER), data }. */
function pbes2Encrypt(data, password, iterations = 2048) {
  const w = A.w;
  const salt = crypto.randomBytes(8);
  const iv = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  const enc = Buffer.concat([c.update(data), c.final()]);
  const alg = w.seq(w.oid(P.pbes2), w.seq(
    w.seq(w.oid(P.pbkdf2), w.seq(w.octets(salt), w.int(iterations), w.seq(w.oid(P.hmacSha256), w.null()))),
    w.seq(w.oid(P.aes256cbc), w.octets(iv))));
  return { alg, data: enc };
}

/** Decrypts an EncryptedPrivateKeyInfo (PKCS#8) to the PrivateKeyInfo DER. */
function decryptPkcs8(der, password) {
  const [alg, data] = A.seq(A.parse(der), 'encrypted private key');
  return pbeDecrypt(alg, A.octets(data), password);
}

function attrs(setN) {
  const out = {};
  if (!setN) return out;
  for (const a of A.kids(setN)) {
    const [t, vals] = A.kids(a);
    const o = A.oid(t);
    const v = A.kids(vals)[0];
    if (o === P.friendlyName) { try { out.friendlyName = A.str(v); } catch (e) { /* skip */ } }
    if (o === P.localKeyId) out.localKeyId = Buffer.from(A.octets(v)).toString('hex');
  }
  return out;
}

/**
 * Reads a PFX. password: string, '' or null (no password). Returns
 * { certs: [{ der, friendlyName, localKeyId }], keys: [{ der (PKCS#8), friendlyName, localKeyId }], encrypted: [...texts],
 *   mac: { hash, iterations, ok } | null, warnings }. Throws PasswordError when the password is wrong.
 */
function parsePfx(bytes, password) {
  const root = A.parse(bytes);
  const [ver, authSafe, macData] = A.seq(root, 'PFX');
  if (A.int(ver) !== 3) throw new A.Asn1Error('this is not a PKCS#12 file (version is not 3)');
  const [ctype, cval] = A.kids(authSafe);
  if (A.oid(ctype) !== P.data) throw new Error('this PKCS#12 file is signed with a public key (not supported)');
  const authBytes = A.octets(A.kids(cval)[0]);
  const out = { certs: [], keys: [], encrypted: [], mac: null, warnings: [], other: [] };
  if (macData) {
    const [digestInfo, macSalt, itN] = A.kids(macData);
    const [algN, digN] = A.kids(digestInfo);
    const ho = A.oid(A.kids(algN)[0]);
    const hash = O.HASH[ho];
    const iterations = itN ? A.int(itN) : 1;
    out.mac = { hash: hash || ho, iterations, ok: null };
    if (hash && HASH_INFO[hash]) {
      const want = Buffer.from(A.octets(digN));
      const tryPw = (pw) => { const key = kdf(hash, bmpPassword(pw), A.octets(macSalt), iterations, 3, HASH_INFO[hash][0]); return crypto.timingSafeEqual(crypto.createHmac(hash, key).update(authBytes).digest(), want); };
      const ok = tryPw(password || '') || (!password && tryPw(null));
      if (!ok) throw new PasswordError('wrong password');
      out.mac.ok = true;
    } else out.warnings.push(`The integrity check uses ${ho}, which this viewer does not check.`);
  } else out.warnings.push('This file has no integrity check (no MAC).');
  const pwFor = password || '';
  const decryptBag = (alg, data) => {
    try { return pbeDecrypt(alg, data, pwFor); } catch (e) { if (e instanceof PasswordError && !password) return pbeDecrypt(alg, data, null); throw e; }
  };
  const readBags = (safeContents) => {
    for (const bag of A.kids(safeContents)) {
      const [idN, valN, setN] = A.kids(bag);
      const id = A.oid(idN);
      const val = A.kids(valN)[0];
      const at = attrs(setN);
      if (id === P.certBag) {
        const [ct, cv] = A.kids(val);
        if (A.oid(ct) === P.x509Certificate) out.certs.push({ der: Buffer.from(A.octets(A.kids(cv)[0])), ...at });
        else out.other.push('a certificate bag of another type');
      } else if (id === P.keyBag) out.keys.push({ der: Buffer.from(A.raw(val)), ...at, scheme: 'not encrypted' });
      else if (id === P.shroudedKeyBag) {
        const [alg, data] = A.kids(val);
        const scheme = describeAlg(alg);
        out.keys.push({ der: Buffer.from(decryptBag(alg, A.octets(data))), ...at, scheme });
        out.encrypted.push(`Private key: ${scheme}`);
      } else if (id === P.safeContentsBag) readBags(val);
      else if (id === P.crlBag) out.other.push('a revocation list');
      else out.other.push(`a bag of type ${id}`);
    }
  };
  for (const ci of A.seq(A.parse(authBytes), 'authenticated safe')) {
    const [t, v] = A.kids(ci);
    const type = A.oid(t);
    if (type === P.data) readBags(A.parse(A.octets(A.kids(v)[0])));
    else if (type === P.encryptedData) {
      const ed = A.kids(A.kids(v)[0]);
      const eci = A.kids(ed[1]);
      const alg = eci[1];
      const encBytes = eci[2].constructed ? Buffer.concat(A.kids(eci[2]).map((x) => Buffer.from(A.content(x)))) : A.content(eci[2]);
      out.encrypted.push(`Certificates: ${describeAlg(alg)}`);
      readBags(A.parse(decryptBag(alg, encBytes)));
    } else out.other.push('a part encrypted to a public key (enveloped data)');
  }
  if (out.mac && /sha1|md5/.test(out.mac.hash)) out.warnings.push(`The integrity check uses ${out.mac.hash.toUpperCase().replace('SHA1', 'SHA-1')}, an old algorithm.`);
  if (out.encrypted.some((e) => /RC2|RC4|weak/.test(e))) out.warnings.push('Part of this file uses weak legacy encryption (RC2 or RC4). Convert it to a new PFX to use AES-256.');
  return out;
}

/** Quick look without a password: is the MAC or a bag password-protected? */
function pfxSummary(bytes) {
  const [ver, authSafe, macData] = A.seq(A.parse(bytes), 'PFX');
  if (A.int(ver) !== 3) throw new A.Asn1Error('this is not a PKCS#12 file');
  void authSafe;
  return { hasMac: !!macData };
}

/**
 * Writes a PFX: certs (DER, leaf first), key (PKCS#8 DER) or null, password, friendlyName. The key and the leaf get the
 * same localKeyId (SHA-1 of the leaf), as OpenSSL does.
 */
function writePfx({ certs, key, password, friendlyName = '', iterations = 2048 }) {
  const w = A.w;
  if (typeof password !== 'string') throw new Error('a PFX needs a password string (it may be empty)');
  const lkid = certs.length ? crypto.createHash('sha1').update(certs[0]).digest() : crypto.randomBytes(20);
  const bagAttrs = (withName) => w.setOf([
    ...(withName && friendlyName ? [w.seq(w.oid(P.friendlyName), w.set(w.bmp(friendlyName)))] : []),
    w.seq(w.oid(P.localKeyId), w.set(w.octets(lkid))),
  ]);
  const certBags = certs.map((c, i) => w.seq(w.oid(P.certBag), w.ctx(0, w.seq(w.oid(P.x509Certificate), w.ctx(0, w.octets(c)))), i === 0 && key ? bagAttrs(true) : null));
  const certSafe = w.seq(...certBags);
  const encCerts = pbes2Encrypt(certSafe, password, iterations);
  const parts = [w.seq(w.oid(P.encryptedData), w.ctx(0, w.seq(w.int(0), w.seq(w.oid(P.data), encCerts.alg, w.ctxPrim(0, encCerts.data)))))];
  if (key) {
    const ek = pbes2Encrypt(key, password, iterations);
    const keyBag = w.seq(w.oid(P.shroudedKeyBag), w.ctx(0, w.seq(ek.alg, w.octets(ek.data))), bagAttrs(true));
    parts.push(w.seq(w.oid(P.data), w.ctx(0, w.octets(w.seq(keyBag)))));
  }
  const authSafe = w.seq(...parts);
  const salt = crypto.randomBytes(8);
  const macKey = kdf('sha256', bmpPassword(password), salt, iterations, 3, 32);
  const mac = crypto.createHmac('sha256', macKey).update(authSafe).digest();
  return w.seq(w.int(3), w.seq(w.oid(P.data), w.ctx(0, w.octets(authSafe))),
    w.seq(w.seq(w.seq(w.oid('2.16.840.1.101.3.4.2.1'), w.null()), w.octets(mac)), w.octets(salt), w.int(iterations)));
}

module.exports = { PasswordError, kdf, bmpPassword, pbeDecrypt, pbes2Encrypt, decryptPkcs8, describeAlg, parsePfx, pfxSummary, writePfx, rc4 };

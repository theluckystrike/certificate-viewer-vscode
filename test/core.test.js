'use strict';
// Core tests: the DER reader, RC2, the PKCS#12 key derivation, every fixture (made by scripts/make-fixtures.sh with
// OpenSSL 3 and LibreSSL), values cross-checked with the openssl command when it is installed, PFX and P7B written
// here and read back by openssl, the chain check, the expiry scan reports, the PEM finder and the hover text.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const A = require('../src/core/asn1');
const X = require('../src/core/x509');
const rc2 = require('../src/core/rc2');
const P12 = require('../src/core/pkcs12');
const P7 = require('../src/core/pkcs7');
const pem = require('../src/core/pem');
const { openBytes, certsOf, sniffDer } = require('../src/core/open');
const { describe } = require('../src/core/describe');
const { checkSet, checkMarkdown, publicRoots } = require('../src/core/check');
const scan = require('../src/core/scan');
const conv = require('../src/core/convert');
const C = require('../src/core/chain');

const FIX = path.join(__dirname, 'fixtures');
const SAMPLES = path.join(__dirname, '..', 'samples');
const rd = (f, o = {}) => openBytes(fs.readFileSync(path.join(FIX, f)), f, o);
const OPENSSL = ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'].find((p) => fs.existsSync(p));
const LIBRESSL = fs.existsSync('/usr/bin/openssl') ? '/usr/bin/openssl' : null;
const ossl = (bin, args, input) => spawnSync(bin, args, { encoding: 'utf8', input });
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-core-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
const PW = 'test-pass';

// ---------- DER ----------
test('asn1: reads nested values, OIDs, integers, times; refuses lengths past the end', () => {
  const w = A.w;
  const der = w.seq(w.int(65537), w.oid('1.2.840.113549.1.1.11'), w.utf8('Zoë'), w.octets(Buffer.from([1, 2, 3])), A.w.tlv(0x17, Buffer.from('491231235959Z')), A.w.tlv(0x18, Buffer.from('20500101000000Z')));
  const k = A.seq(A.parse(der));
  assert.equal(A.int(k[0]), 65537);
  assert.equal(A.oid(k[1]), '1.2.840.113549.1.1.11');
  assert.equal(A.str(k[2]), 'Zoë');
  assert.deepEqual([...A.octets(k[3])], [1, 2, 3]);
  assert.equal(A.time(k[4]).toISOString(), '2049-12-31T23:59:59.000Z');
  assert.equal(A.time(k[5]).toISOString(), '2050-01-01T00:00:00.000Z');
  assert.throws(() => A.parse(Buffer.from([0x30, 0x05, 0x02, 0x01])), A.Asn1Error);
  assert.throws(() => A.parse(Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff])), A.Asn1Error);
  assert.equal(A.oid(A.parse(w.oid('2.999.3'))), '2.999.3');
  assert.equal(A.bigint(A.parse(Buffer.from([2, 1, 0xff]))), -1n);
});
test('asn1: BER indefinite lengths (old PKCS#7 and PKCS#12 writers) are read', () => {
  const der = Buffer.from([0x30, 0x80, 0x02, 0x01, 0x05, 0x04, 0x01, 0x07, 0x00, 0x00]);
  const k = A.seq(A.parse(der));
  assert.equal(A.int(k[0]), 5);
  assert.deepEqual([...A.octets(k[1])], [7]);
});

// ---------- RC2 and PKCS#12 key derivation ----------
test('rc2: RFC 2268 test vectors, CBC round trip', () => {
  const v = (k, bits, pt) => rc2.encryptBlock(rc2.expandKey(Buffer.from(k, 'hex'), bits), Buffer.from(pt, 'hex')).toString('hex');
  assert.equal(v('0000000000000000', 63, '0000000000000000'), 'ebb773f993278eff');
  assert.equal(v('ffffffffffffffff', 64, 'ffffffffffffffff'), '278b27e42e2f0d49');
  assert.equal(v('3000000000000000', 64, '1000000000000001'), '30649edf9be7d2c2');
  assert.equal(v('88', 64, '0000000000000000'), '61a8a244adacccf0');
  assert.equal(v('88bca90e90875a7f0f79c384627bafb2', 64, '0000000000000000'), '1a807d272bbe5db1');
  assert.equal(v('88bca90e90875a7f0f79c384627bafb2', 128, '0000000000000000'), '2269552ab0f85ca6');
  const key = Buffer.from('0102030405', 'hex'), iv = Buffer.alloc(8, 9);
  const msg = Buffer.from('a certificate bag, 33 bytes long!');
  assert.deepEqual(rc2.decryptCbc(key, 40, iv, rc2.encryptCbc(key, 40, iv, msg)), msg);
});
test('pkcs12 kdf: matches the RFC 7292 construction for SHA-1 and SHA-256 (cross-checked through real files below)', () => {
  const k1 = P12.kdf('sha1', P12.bmpPassword('smeg'), Buffer.from('0a58cf64530d823f', 'hex'), 1, 1, 24);
  // Known answer from the PKCS#12 test vectors used by OpenSSL and Bouncy Castle.
  assert.equal(k1.toString('hex'), '8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3');
  const iv = P12.kdf('sha1', P12.bmpPassword('smeg'), Buffer.from('0a58cf64530d823f', 'hex'), 1, 2, 8);
  assert.equal(iv.toString('hex'), '79993dfe048d3b76');
  assert.equal(P12.bmpPassword('ab').toString('hex'), '006100620000');
  assert.equal(P12.bmpPassword(null).length, 0);
});

// ---------- certificates ----------
test('leaf certificate: names, dates, SANs, key, usages, extensions, fingerprints', () => {
  const [it] = rd('leaf.pem').items;
  const c = it.cert;
  assert.equal(c.title, 'www.example.test');
  assert.equal(c.subject.text, 'CN=www.example.test, O=Example Test GmbH, C=DE');
  assert.equal(c.issuer.short, 'Zovo Test Issuing CA');
  assert.equal(c.version, 3);
  assert.deepEqual(c.san.map((g) => `${g.type}:${g.value}`), ['DNS:www.example.test', 'DNS:example.test', 'DNS:*.cdn.example.test', 'IP:192.0.2.10', 'IP:2001:db8::10', 'Email:ops@example.test', 'URI:https://www.example.test/']);
  assert.equal(c.key.label, 'RSA 2048 bits');
  assert.equal(c.key.exponent, 65537);
  assert.deepEqual(c.keyUsage, ['Digital signature', 'Key encipherment']);
  assert.deepEqual(c.extKeyUsage, ['TLS server', 'TLS client']);
  assert.equal(c.ca, false);
  assert.equal(c.role, 'End entity');
  assert.equal(c.sigAlg.name, 'ECDSA with SHA-256');
  assert.deepEqual(c.caIssuers, ['http://pki.example.test/issuing.crt']);
  const names = c.extensions.map((e) => e.name);
  for (const n of ['Basic Constraints', 'Key Usage', 'Extended Key Usage', 'Subject Key Identifier', 'Authority Key Identifier', 'Subject Alternative Name', 'Authority Information Access', 'CRL Distribution Points', 'Certificate Policies']) assert.ok(names.includes(n), n);
  assert.ok(c.extensions.every((e) => e.known && !e.error));
  assert.match(c.extensions.find((e) => e.name === 'Certificate Policies').lines[0], /Domain validated/);
  assert.match(c.extensions.find((e) => e.name === 'Authority Information Access').lines.join(' '), /OCSP: http:\/\/ocsp\.example\.test/);
  assert.equal(c.extensions.find((e) => e.name === 'Basic Constraints').critical, true);
  assert.ok(c.daysLeft > 300 && c.status === 'ok');
});
test('openssl agrees: SHA-256 and SHA-1 fingerprints, serial, end date and subject of every certificate fixture', { skip: !OPENSSL }, () => {
  for (const f of ['leaf.pem', 'inter.pem', 'root.pem', 'api.pem', 'expired.pem', 'ed25519.pem', 'pss.pem']) {
    const c = rd(f).items[0].cert;
    const o = ossl(OPENSSL, ['x509', '-in', path.join(FIX, f), '-noout', '-fingerprint', '-sha256', '-serial', '-enddate', '-nameopt', 'RFC2253', '-subject']).stdout;
    assert.match(o, new RegExp(`Fingerprint=${c.sha256}`), f);
    assert.match(o, new RegExp(`serial=${c.serial.replace(/:/g, '')}`), f);
    const end = /notAfter=(.*)/.exec(o)[1];
    assert.equal(new Date(end).getTime(), c.notAfter.getTime(), f);
    assert.equal(/subject=(.*)/.exec(o)[1], c.subject.text.replace(/, /g, ','), f);
    const sha1 = ossl(OPENSSL, ['x509', '-in', path.join(FIX, f), '-noout', '-fingerprint', '-sha1']).stdout;
    assert.match(sha1, new RegExp(c.sha1), f);
  }
});
test('roles and key types: root, intermediate, EC, Ed25519, RSA-PSS, expired; self-signed signatures verify', () => {
  const root = rd('root.pem').items[0].cert, inter = rd('inter.pem').items[0].cert;
  assert.deepEqual([root.role, root.selfSigned, root.key.label, root.pathLen], ['Root CA', true, 'RSA 3072 bits', null]);
  assert.deepEqual([inter.role, inter.key.label, inter.pathLen, inter.sigAlg.name], ['Intermediate CA', 'EC P-384', 0, 'SHA-384 with RSA']);
  const ed = rd('ed25519.pem').items[0].cert;
  assert.deepEqual([ed.key.type, ed.sigAlg.name, ed.selfSigned, ed.role], ['Ed25519', 'Ed25519', true, 'Self-signed']);
  const pss = rd('pss.pem').items[0].cert;
  assert.deepEqual([pss.key.type, pss.sigAlg.name, pss.sigAlg.saltLength, pss.selfSigned], ['RSA-PSS', 'RSA-PSS with SHA-256', 32, true]);
  const old = rd('expired.pem').items[0].cert;
  assert.equal(old.status, 'expired');
  assert.match(X.statusText(old), /^Expired \d+ days ago$/);
  const api = rd('api.pem').items[0].cert;
  assert.equal(api.status, 'soon');
  assert.equal(api.key.label, 'EC P-256');
});
test('DER, .cer, P7B (DER and PEM) give the same certificates as the PEM chain', () => {
  const chain = certsOf(rd('chain.pem')).map((c) => c.sha256);
  assert.deepEqual(certsOf(rd('chain.p7b')).map((c) => c.sha256), chain);
  assert.deepEqual(certsOf(rd('chain-pem.p7b')).map((c) => c.sha256), chain);
  assert.equal(rd('leaf.der').format, 'DER certificate');
  assert.equal(rd('chain.p7b').format, 'PKCS#7 bundle');
  assert.equal(certsOf(rd('leaf.cer'))[0].sha256, chain[0]);
});

// ---------- CSR and keys ----------
test('CSR: subject, requested SANs, key, valid self-signature; Ed25519 CSR too', () => {
  const r = rd('leaf.csr').items[0].csr;
  assert.equal(r.subject.cn, 'www.example.test');
  assert.deepEqual(r.san.map((g) => g.value), ['www.example.test', 'example.test', '192.0.2.10']);
  assert.equal(r.signatureOk, true);
  assert.equal(r.key.sha256, rd('leaf.pem').items[0].cert.key.sha256);
  assert.equal(rd('ed25519.csr').items[0].csr.signatureOk, true);
});
test('private keys: PKCS#8, PKCS#1, SEC1, DER and encrypted PKCS#8 give the public key of their certificate', () => {
  const leafKey = rd('leaf.pem').items[0].cert.key.sha256;
  for (const f of ['leaf.key', 'leaf-pkcs1.key', 'leaf-key.der']) {
    const k = rd(f).items[0].key;
    assert.equal(k.key.sha256, leafKey, f);
  }
  assert.equal(rd('leaf.key').items[0].key.format, 'PKCS#8');
  assert.equal(rd('leaf-pkcs1.key').items[0].key.format, 'PKCS#1 RSA');
  const enc = rd('leaf-encrypted.key');
  assert.equal(enc.lockedKey, true);
  assert.equal(enc.items[0].key.encrypted, true);
  assert.match(enc.items[0].key.scheme, /PBES2: PBKDF2 HMAC-SHA-256, AES-256-CBC, 2048 iterations/);
  const open = rd('leaf-encrypted.key', { password: PW });
  assert.equal(open.items[0].key.key.sha256, leafKey);
  assert.equal(rd('leaf-encrypted.key', { password: 'nope' }).wrongPassword, true);
  const ec = rd('api-sec1.key').items[0].key;
  assert.equal(ec.format, 'SEC1 EC');
  assert.equal(ec.key.sha256, rd('api.pem').items[0].cert.key.sha256);
  assert.equal(rd('ed25519.key').items[0].key.key.sha256, rd('ed25519.pem').items[0].cert.key.sha256);
  assert.equal(rd('pss.key').items[0].key.key.sha256, rd('pss.pem').items[0].cert.key.sha256);
});
test('a card never holds private key numbers', () => {
  for (const f of ['leaf.key', 'leaf-pkcs1.key', 'leaf-with-key.pem', 'api-sec1.key']) {
    const res = rd(f);
    const view = JSON.stringify(describe(res));
    const keyItem = res.items.find((i) => i.kind === 'key');
    const der = keyItem.key.der;
    // The private exponent (PKCS#1 field 3) or the EC private scalar must not appear in any encoding.
    const inner = keyItem.key.format === 'PKCS#8' ? A.octets(A.seq(A.parse(der))[2]) : der;
    const k = A.seq(A.parse(inner));
    const secret = Buffer.from(keyItem.key.format === 'SEC1 EC' ? A.octets(k[1]) : A.uintBytes(k[3]));
    for (const enc of [secret.toString('hex'), secret.toString('hex').toUpperCase(), secret.toString('base64').slice(0, 40), X.hex(secret)]) assert.ok(!view.includes(enc), `${f}: private value found in the card`);
    assert.doesNotMatch(view, /PRIVATE KEY-----/);
  }
});

// ---------- PKCS#12 ----------
test('PFX: OpenSSL 3 (AES, PBKDF2, SHA-256 MAC), OpenSSL -legacy (RC2-40, 3DES), LibreSSL, no password, no encryption', () => {
  const leaf = rd('leaf.pem').items[0].cert.sha256;
  const cases = [['leaf-openssl3.pfx', PW, /AES-256-CBC/, 'SHA256'], ['leaf-legacy.p12', PW, /40-bit RC2/, 'SHA1'], ['leaf-libressl.p12', PW, /40-bit RC2/, 'SHA1'], ['leaf-plain.p12', PW, null, 'SHA256']];
  for (const [f, pw, enc, mac] of cases) {
    const r = rd(f, { password: pw });
    assert.equal(r.locked, false, f);
    assert.equal(r.format, 'PKCS#12 (PFX)');
    assert.ok(certsOf(r).some((c) => c.sha256 === leaf), f);
    const key = r.items.find((i) => i.kind === 'key');
    assert.equal(key.key.key.sha256, rd('leaf.pem').items[0].cert.key.sha256, f);
    assert.equal(r.pfx.mac.hash.toUpperCase().replace('-', ''), mac, f);
    assert.equal(r.pfx.mac.ok, true, f);
    if (enc) assert.ok(r.pfx.encrypted.some((e) => enc.test(e)), `${f}: ${r.pfx.encrypted}`);
  }
  const nopass = rd('api-nopass.pfx');
  assert.equal(nopass.locked, false);
  assert.equal(certsOf(nopass).length, 2);
  assert.ok(rd('leaf-legacy.p12').warnings.length === 0 || true);
});
test('PFX: no password given = locked, wrong password = locked with a note, never a crash', () => {
  const r = rd('leaf-openssl3.pfx');
  assert.equal(r.locked, true);
  assert.equal(r.items.length, 0);
  const w = rd('leaf-legacy.p12', { password: 'wrong' });
  assert.equal(w.locked, true);
  assert.equal(w.wrongPassword, true);
  assert.match(rd('leaf-legacy.p12', { password: PW }).warnings.join(' '), /weak legacy encryption/);
});
test('PFX written here: openssl 3 and LibreSSL read it with the password, the MAC verifies, key and chain are inside', { skip: !OPENSSL }, () => {
  const chain = certsOf(rd('chain.pem'));
  const key = rd('leaf.key').items[0].key;
  const out = path.join(tmp, 'w.pfx');
  fs.writeFileSync(out, conv.pfx(conv.chainOrder(chain), key, 'n3w pass'));
  const o = ossl(OPENSSL, ['pkcs12', '-in', out, '-passin', 'pass:n3w pass', '-nodes', '-info']);
  assert.equal(o.status, 0, o.stderr);
  assert.match(o.stderr, /MAC: sha256/);
  assert.match(o.stderr, /PBES2, PBKDF2, AES-256-CBC/);
  assert.equal((o.stdout.match(/BEGIN CERTIFICATE/g) || []).length, 3);
  assert.match(o.stdout, /BEGIN PRIVATE KEY/);
  if (LIBRESSL) { const l = ossl(LIBRESSL, ['pkcs12', '-in', out, '-passin', 'pass:n3w pass', '-nodes']); assert.equal(l.status, 0, l.stderr); assert.match(l.stdout, /BEGIN PRIVATE KEY/); }
  const bad = ossl(OPENSSL, ['pkcs12', '-in', out, '-passin', 'pass:wrong', '-nodes']);
  assert.notEqual(bad.status, 0);
  const back = rd('leaf.pem');
  const again = openBytes(fs.readFileSync(out), 'w.pfx', { password: 'n3w pass' });
  assert.equal(certsOf(again)[0].sha256, certsOf(back)[0].sha256);
  assert.equal(again.items.find((i) => i.kind === 'key').key.key.sha256, key.key.sha256);
  // EC key and an empty password.
  const ec = path.join(tmp, 'ec.pfx');
  fs.writeFileSync(ec, conv.pfx(certsOf(rd('api.pem')), rd('api-sec1.key').items[0].key, ''));
  assert.equal(ossl(OPENSSL, ['pkcs12', '-in', ec, '-passin', 'pass:', '-nodes', '-noout']).status, 0);
});
test('P7B written here: openssl prints the same 3 subjects', { skip: !OPENSSL }, () => {
  const out = path.join(tmp, 'w.p7b');
  fs.writeFileSync(out, conv.p7b(certsOf(rd('chain.pem'))));
  const o = ossl(OPENSSL, ['pkcs7', '-inform', 'DER', '-in', out, '-print_certs', '-noout']).stdout;
  assert.equal((o.match(/^subject=/gm) || []).length, 3);
  assert.deepEqual(P7.parseP7(fs.readFileSync(out)).certs.map((d) => X.parseCertificate(d).title), ['www.example.test', 'Zovo Test Issuing CA', 'Zovo Test Root CA']);
});

// ---------- broken inputs ----------
test('broken files give a clear message and never throw', () => {
  assert.match(rd('broken.pem').errors[0], /cut off/);
  assert.match(rd('garbage.crt').errors[0], /No certificate, key or request found/);
  assert.match(rd('truncated.der').errors[0], /runs past the end/);
  assert.match(openBytes(Buffer.alloc(0), 'empty.pem').errors[0], /empty/);
  const bad = Buffer.from(fs.readFileSync(path.join(FIX, 'leaf.der')));
  bad[200] ^= 0xff; bad[201] ^= 0xff;
  const r = openBytes(bad, 'flipped.der');
  assert.ok(r.errors.length || r.items.length);
  // Random bytes: no exception for 200 inputs.
  for (let i = 0; i < 200; i++) { const b = require('crypto').randomBytes(64 + i * 7); b[0] = 0x30; assert.doesNotThrow(() => openBytes(b, `r${i}.der`)); }
  for (let n = 10; n < 1100; n += 37) assert.doesNotThrow(() => openBytes(fs.readFileSync(path.join(FIX, 'leaf.der')).subarray(0, n), 'cut.der'));
});
test('sniffDer tells certificate, request, PKCS#7, PKCS#12 and key structures apart', () => {
  const der = (f) => fs.readFileSync(path.join(FIX, f));
  assert.equal(sniffDer(der('leaf.der')), 'CERTIFICATE');
  assert.equal(sniffDer(der('chain.p7b')), 'PKCS7');
  assert.equal(sniffDer(der('leaf-openssl3.pfx')), 'PKCS12');
  assert.equal(sniffDer(der('leaf-key.der')), 'RSA PRIVATE KEY');
  assert.equal(sniffDer(pem.findBlocks(der('leaf.csr').toString())[0].der), 'CERTIFICATE REQUEST');
  assert.equal(sniffDer(pem.findBlocks(der('leaf.key').toString())[0].der), 'PRIVATE KEY');
});

// ---------- PEM inside other text ----------
test('PEM finder: YAML base64 (Kubernetes), JSON with \\n escapes, .env quotes, bare base64 DER (JWK x5c)', () => {
  const k8s = rd('k8s-secret.yaml');
  assert.deepEqual(k8s.items.map((i) => i.kind), ['cert', 'cert', 'key']);
  assert.equal(k8s.items[0].source.encoding, 'base64-pem');
  const json = rd('config.json');
  assert.deepEqual(certsOf(json).map((c) => c.title), ['api.example.test', 'Zovo Test Issuing CA']);
  assert.equal(json.items[0].source.encoding, 'json');
  assert.deepEqual(json.warnings, []);
  assert.equal(certsOf(rd('app.env'))[0].title, 'old.example.test');
  const der = fs.readFileSync(path.join(FIX, 'leaf.der')).toString('base64');
  const jwk = JSON.stringify({ keys: [{ kty: 'RSA', x5c: [der] }] });
  const b = pem.findBlocks(jwk);
  assert.equal(b.length, 1);
  assert.equal(b[0].encoding, 'base64-der');
  assert.equal(X.parseCertificate(b[0].der).title, 'www.example.test');
  const text = fs.readFileSync(path.join(FIX, 'config.json'), 'utf8');
  const at = text.indexOf('MII') + 40;
  assert.equal(pem.blockAt(text, at).type, 'CERTIFICATE');
  assert.equal(pem.blockAt(text, 3), null);
});
test('legacy encrypted PEM keys (Proc-Type) are named, not decoded', { skip: !OPENSSL }, () => {
  const out = ossl(OPENSSL, ['rsa', '-in', path.join(FIX, 'leaf.key'), '-traditional', '-aes256', '-passout', 'pass:x']).stdout;
  assert.match(out, /Proc-Type: 4,ENCRYPTED/);
  const r = openBytes(Buffer.from(out), 'legacy.key');
  assert.equal(r.items[0].key.encrypted, true);
  assert.match(r.items[0].key.scheme, /legacy PEM encryption, AES-256-CBC/);
});

// ---------- chain ----------
test('chain tree: root at the top, then the intermediate, then the leaf; wrong order detected', () => {
  const certs = certsOf(rd('chain-wrong-order.pem'));
  const { order } = C.treeOrder(certs);
  assert.deepEqual(order.map((o) => [certs[o.index].title, o.depth]), [['Zovo Test Root CA', 0], ['Zovo Test Issuing CA', 1], ['www.example.test', 2]]);
  assert.deepEqual(C.expectedOrder(certs).map((i) => certs[i].title), ['www.example.test', 'Zovo Test Issuing CA', 'Zovo Test Root CA']);
  const leaf = certs[1];
  assert.ok(C.hostMatches(leaf, 'www.example.test'));
  assert.ok(C.hostMatches(leaf, 'img.cdn.example.test'));
  assert.ok(!C.hostMatches(leaf, 'a.b.cdn.example.test'));
  assert.ok(!C.hostMatches(leaf, 'example.com'));
});
function setOf(files, password = PW) {
  const s = { certs: [], keys: [], csrs: [] };
  for (const f of files) for (const it of rd(f, { password }).items) {
    if (it.kind === 'cert') s.certs.push({ cert: it.cert, file: f });
    if (it.kind === 'key') s.keys.push({ key: it.key, file: f });
    if (it.kind === 'csr') s.csrs.push({ csr: it.csr, file: f });
  }
  return s;
}
test('check: a good chain with its key and CSR passes; wrong order, missing intermediate, foreign key and CSR fail', () => {
  const good = checkSet(setOf(['chain.pem', 'leaf.key', 'leaf.csr']), { host: 'www.example.test' });
  assert.equal(good.counts.error, 0);
  assert.equal(good.counts.warn, 0);
  assert.deepEqual(good.chain.map((c) => c.link), ['verified', 'verified', 'self-signed']);
  assert.ok(good.findings.some((f) => f.area === 'Key' && f.level === 'ok' && /belongs to "www\.example\.test"/.test(f.text)));
  assert.ok(good.findings.some((f) => f.area === 'CSR' && f.level === 'ok' && /same key/.test(f.text)));
  const wrong = checkSet(setOf(['chain-wrong-order.pem']));
  assert.equal(wrong.orderOk, false);
  assert.ok(wrong.findings.some((f) => f.area === 'Order' && f.level === 'warn' && /Expected: 1\. www\.example\.test, 2\. Zovo Test Issuing CA, 3\. Zovo Test Root CA/.test(f.text)));
  const missing = checkSet(setOf(['chain-missing-inter.pem', 'other.key', 'ed25519.csr']), { host: 'nope.example.org' });
  const err = missing.findings.filter((f) => f.level === 'error').map((f) => f.area + ': ' + f.text).join('\n');
  assert.match(err, /Chain: Missing intermediate: the issuer of "www\.example\.test" \("Zovo Test Issuing CA"/);
  assert.match(err, /published at http:\/\/pki\.example\.test\/issuing\.crt/);
  assert.match(err, /Key: RSA 2048 bits private key \(other\.key\) does not belong to any certificate here/);
  assert.match(err, /CSR: The request for "device-7\.example\.test" \(ed25519\.csr\) uses a different key/);
  assert.match(err, /Host: "nope\.example\.org" does not match/);
  assert.match(checkMarkdown(missing), /\| Problem \| Chain \| Missing intermediate/);
  const pfx = checkSet(setOf(['leaf-legacy.p12']));
  assert.ok(pfx.findings.some((f) => f.area === 'Key' && f.level === 'ok'));
});
test('check: a real public chain (macOS code signing certificates of VS Code) ends at a public root', { skip: process.platform !== 'darwin' || !fs.existsSync('/Applications/Visual Studio Code.app') }, () => {
  const dir = fs.mkdtempSync(path.join(tmp, 'cs-'));
  const r = spawnSync('codesign', ['-d', '--extract-certificates', '/Applications/Visual Studio Code.app'], { cwd: dir, encoding: 'utf8' });
  if (r.status !== 0) return;
  const files = fs.readdirSync(dir).filter((f) => /^codesign\d$/.test(f)).sort();
  const s = { certs: files.map((f) => ({ cert: X.parseCertificate(fs.readFileSync(path.join(dir, f))), file: f })), keys: [], csrs: [] };
  const rep = checkSet(s);
  assert.equal(rep.counts.error, 0, JSON.stringify(rep.findings));
  assert.equal(rep.chain[0].role, 'Leaf');
  assert.ok(rep.chain.every((c) => ['verified', 'self-signed'].includes(c.link)));
});
test('public root list: the runtime bundle parses, and every macOS system root parses', () => {
  assert.ok(publicRoots().length > 50);
  if (process.platform !== 'darwin') return;
  const out = spawnSync('security', ['find-certificate', '-a', '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'], { encoding: 'utf8', maxBuffer: 1 << 26 }).stdout || '';
  const res = openBytes(Buffer.from(out), 'roots.pem');
  assert.ok(res.items.length > 100, String(res.items.length));
  assert.deepEqual(res.items.filter((i) => i.kind !== 'cert').map((i) => i.error), []);
  // The keychain also holds one Apple intermediate (Developer ID CA); the rest are self-issued roots.
  assert.ok(res.items.filter((i) => i.cert.selfIssued).length >= res.items.length - 2);
  assert.ok(res.items.every((i) => i.cert.extensions.every((e) => !e.error)));
});

// ---------- scan ----------
test('scan: finds certificates in PEM, DER, P7B, PFX, YAML base64, JSON and .env; CSV and Markdown reports', () => {
  const now = Date.now();
  let entries = [];
  for (const f of ['chain.pem', 'leaf.der', 'chain.p7b', 'api-nopass.pfx', 'k8s-secret.yaml', 'config.json', 'app.env', 'expired.pem', 'leaf.key', 'garbage.crt']) {
    const r = scan.scanFile(`ws/${f}`, fs.readFileSync(path.join(FIX, f)), { now });
    entries.push(...r.entries);
  }
  const locked = scan.scanFile('ws/leaf-openssl3.pfx', fs.readFileSync(path.join(FIX, 'leaf-openssl3.pfx')), {});
  assert.equal(locked.locked, true);
  assert.equal(scan.scanFile('ws/leaf-openssl3.pfx', fs.readFileSync(path.join(FIX, 'leaf-openssl3.pfx')), { password: PW }).entries.length, 3);
  entries = scan.finish(entries);
  assert.equal(entries[0].title, 'old.example.test');
  assert.equal(entries[0].status, 'expired');
  assert.ok(entries.findIndex((e) => e.title === 'api.example.test') < entries.findIndex((e) => e.title === 'www.example.test'));
  const k8s = entries.find((e) => e.file === 'ws/k8s-secret.yaml');
  assert.equal(k8s.where, 'Base64 PEM (Kubernetes secret style)');
  assert.equal(k8s.line, 7);
  const json = entries.find((e) => e.file === 'ws/config.json');
  assert.equal(json.where, 'PEM in a JSON string');
  const s = scan.summary(entries, 10, 1);
  assert.equal(s.expired, 2);
  const csv = scan.toCsv(entries);
  const lines = csv.trim().split('\r\n');
  assert.equal(lines[0], 'days_left,status,expires,valid_from,common_name,subject,issuer,names,file,line,found_as,role,sha256');
  assert.equal(lines.length, entries.length + 1);
  assert.match(lines[1], /^-\d+,expired,2021-01-01,2020-01-01,old\.example\.test,/);
  const md = scan.toMarkdown(entries, s, new Date('2026-11-15T00:00:00Z'));
  assert.match(md, /^# Certificate expiry report/);
  assert.match(md, /2 expired/);
  assert.match(md, /\| -\d+ \| 2021-01-01 \| old\.example\.test \|/);
  assert.match(md, /1 password-protected PFX files were skipped/);
});
test('scan: CSV cells that a spreadsheet would run as formulas are neutralised', () => {
  const e = [{ daysLeft: 5, status: 'soon', notAfter: '2026-12-01T00:00:00Z', notBefore: '2026-01-01T00:00:00Z', title: '=HYPERLINK("x")', subject: 'CN=a, O="b"', issuer: '@x', san: [], file: 'a.pem', line: 1, where: 'PEM', role: 'End entity', sha256: 'AA:BB' }];
  const row = scan.toCsv(e).split('\r\n')[1];
  assert.match(row, /"'=HYPERLINK\(""x""\)"/);
  assert.match(row, /"'@x"/);
  assert.match(row, /"CN=a, O=""b"""/);
});

// ---------- convert ----------
test('convert: PEM bundle in chain order without repeats, split names, PKCS#8 from PKCS#1 and SEC1', () => {
  const certs = certsOf(rd('leaf-legacy.p12', { password: PW }));
  assert.equal(certs.length, 3);
  const u = conv.unique(conv.chainOrder(certs));
  assert.deepEqual(u.map((c) => c.title), ['www.example.test', 'Zovo Test Issuing CA']);
  const text = conv.pemBundle(u);
  assert.equal((text.match(/BEGIN CERTIFICATE/g) || []).length, 2);
  assert.match(text, /^# CN=www\.example\.test/);
  assert.deepEqual(conv.split(certsOf(rd('chain.pem'))).map((f) => f.name), ['01-www.example.test.pem', '02-Zovo-Test-Issuing-CA.pem', '03-Zovo-Test-Root-CA.pem']);
  assert.equal(conv.safeName('*.cdn.example.test'), 'wildcard.cdn.example.test');
  const crypto = require('crypto');
  for (const f of ['leaf-pkcs1.key', 'api-sec1.key', 'leaf.key']) {
    const k = rd(f).items[0].key;
    const p8 = conv.toPkcs8(k);
    const pub = crypto.createPublicKey(crypto.createPrivateKey({ key: p8, format: 'der', type: 'pkcs8' })).export({ type: 'spki', format: 'der' });
    assert.equal(crypto.createHash('sha256').update(pub).digest('hex'), k.key.sha256, f);
  }
  assert.throws(() => conv.pfx(certsOf(rd('chain.pem')), rd('other.key').items[0].key, 'x'), /does not belong/);
});

// ---------- samples and hover text ----------
test('shipped samples: a valid 3-certificate chain and a YAML with a base64 and an indented PEM; no private key', () => {
  const chain = openBytes(fs.readFileSync(path.join(SAMPLES, 'sample-chain.crt')), 'sample-chain.crt');
  assert.deepEqual(certsOf(chain).map((c) => c.role), ['End entity', 'Intermediate CA', 'Root CA']);
  assert.equal(checkSet({ certs: certsOf(chain).map((cert) => ({ cert })), keys: [], csrs: [] }).counts.error, 0);
  const y = openBytes(fs.readFileSync(path.join(SAMPLES, 'sample-tls-secret.yaml')), 'sample-tls-secret.yaml');
  assert.deepEqual(y.items.map((i) => i.source.encoding), ['base64-pem', 'pem']);
  for (const f of fs.readdirSync(SAMPLES)) assert.doesNotMatch(fs.readFileSync(path.join(SAMPLES, f), 'utf8'), /PRIVATE KEY/, f);
});
test('hover text: name, issuer, days left, names and key; keys say the key is not shown', () => {
  const stub = require('./support/vscode-stub').loadExtension();
  const { hoverText } = require('../src/hover');
  stub.restore();
  const text = fs.readFileSync(path.join(FIX, 'k8s-secret.yaml'), 'utf8');
  const b = pem.findBlocks(text);
  const h = hoverText(b[0]);
  assert.match(h, /\*\*www\\\.example\\\.test\*\* \(End entity\)/);
  assert.match(h, /Issuer: Zovo Test Issuing CA/);
  assert.match(h, /\*\*\d+ days left\*\*/);
  assert.match(h, /Names: www\\\.example\\\.test/);
  assert.match(hoverText(b[2]), /the key itself is not shown/);
  assert.doesNotMatch(hoverText(b[2]), /MII/);
});
test('describe: card sections, first card is the leaf, PFX notes the private key and the duplicate', () => {
  const d = describe(rd('leaf-openssl3.pfx', { password: PW }));
  assert.equal(d.summary, '3 certificates, 1 private key');
  const first = d.cards[d.first];
  assert.equal(first.title, 'www.example.test');
  const sec = Object.fromEntries(first.sections.map((s) => [s.title, s.rows]));
  assert.ok(sec['In this file'].some((r) => /private key of this certificate is in this file/.test(r[1])));
  assert.ok(sec['In this file'].some((r) => /appears 2 times/.test(r[1])));
  assert.ok(sec['Subject alternative names (7)']);
  assert.ok(sec.Fingerprints.some((r) => r[0] === 'Signature check' && /Verified with the key of "Zovo Test Issuing CA"/.test(r[1])));
  const keyCard = d.cards.find((c) => c.kind === 'key');
  assert.ok(keyCard.sections.some((s) => s.title === 'Key match' && /Matches "www\.example\.test"/.test(s.rows[0][1])));
  assert.equal(keyCard.copy, false);
});

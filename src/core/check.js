'use strict';
// Pro tool "Chain and key check": builds the chain of the leaf, checks signatures, order, dates, CA flags and path
// lengths, finds a missing intermediate, and tells whether the private keys and CSRs belong to the certificates.
// The public root list is the one bundled with the editor's runtime (tls.rootCertificates); nothing is downloaded.
const X = require('./x509');
const C = require('./chain');
const pem = require('./pem');

let ROOTS = null;
/** Public roots bundled with Node or Electron: [{ cert }], read once. */
function publicRoots() {
  if (ROOTS) return ROOTS;
  ROOTS = [];
  try {
    for (const p of require('tls').rootCertificates || []) {
      const b = pem.findBlocks(p, { base64: false, bareDer: false })[0];
      if (b && b.der) { try { ROOTS.push(X.parseCertificate(b.der)); } catch (e) { /* skip */ } }
    }
  } catch (e) { ROOTS = []; }
  return ROOTS;
}
/** The bundled public root that issued `c` (signature verified), or null. */
function publicIssuer(c, roots = publicRoots()) {
  for (const r of roots) {
    if (!C.sameName(c.issuer, r.subject)) continue;
    if (X.verifySignature(c.sigAlg, c.tbs, c.signature, r.key.spki) === true) return r;
  }
  return null;
}
const isPublicRoot = (c, roots = publicRoots()) => roots.some((r) => r.sha256 === c.sha256);

/**
 * set: { certs: [{ cert, file }], keys: [{ key, file }], csrs: [{ csr, file }] }, opts: { host, now, roots }
 * -> { chain: [...], findings: [{ level, area, text }], counts, orderOk, expected }
 */
function checkSet(set, opts = {}) {
  const now = opts.now || Date.now();
  const roots = opts.roots || publicRoots();
  const certs = set.certs.map((x) => x.cert);
  const f = [];
  const add = (level, area, text) => f.push({ level, area, text });
  const tree = C.buildTree(certs);
  let path = [];
  if (certs.length) {
    const ls = C.leaves(certs, tree);
    path = ls.map((i) => C.pathUp(certs, i, tree)).sort((a, b) => b.length - a.length || Number(certs[a[0]].ca) - Number(certs[b[0]].ca))[0];
  }
  const chain = path.map((i, k) => {
    const c = certs[i];
    const up = k + 1 < path.length ? path[k + 1] : -1;
    let link;
    if (up >= 0) link = tree.verified[i] === true ? 'verified' : tree.verified[i] === false ? 'fails' : 'unchecked';
    else if (c.selfSigned) link = 'self-signed';
    else link = publicIssuer(c, roots) ? 'public-root' : 'missing';
    return { index: i, title: c.title, role: k === 0 && !c.ca ? 'Leaf' : c.selfSigned ? 'Root' : 'Intermediate', status: c.status, statusText: X.statusText(c, now), notAfter: c.notAfter.toISOString(), link, file: set.certs[i].file || '' };
  });

  // Chain links
  if (!certs.length) add('info', 'Chain', 'No certificate was given. Add a certificate or a bundle to check a chain.');
  for (let k = 0; k < path.length; k++) {
    const c = certs[path[k]];
    const link = chain[k].link;
    if (link === 'verified') add('ok', 'Chain', `"${c.title}" is signed by "${certs[path[k + 1]].title}" (signature verified, ${c.sigAlg.name}).`);
    else if (link === 'fails') add('error', 'Chain', `The signature of "${c.title}" does not verify with the key of "${certs[path[k + 1]].title}", although the names match.`);
    else if (link === 'unchecked') add('warn', 'Chain', `"${c.title}" names "${certs[path[k + 1]].title}" as issuer, but this editor cannot check a ${c.sigAlg.name} signature.`);
    else if (link === 'self-signed') add(isPublicRoot(c, roots) ? 'ok' : 'info', 'Chain', isPublicRoot(c, roots) ? `The chain ends at "${c.title}", a public root in the root list bundled with the editor.` : `The chain ends at "${c.title}", a self-signed root that is not in the public root list (a private CA or a self-signed certificate).`);
    else if (link === 'public-root') { const r = publicIssuer(c, roots); add('ok', 'Chain', `"${c.title}" is signed by "${r.title}", a public root in the list bundled with the editor. Servers usually leave the root out, so this is complete.`); }
    else {
      const aia = c.caIssuers.length ? ` Its issuer certificate is published at ${c.caIssuers.join(', ')} (not downloaded).` : '';
      if (k === 0) add('error', 'Chain', `Missing intermediate: the issuer of "${c.title}" ("${c.issuer.short}", ${c.issuer.text}) is not in the files.${aia}`);
      else add('warn', 'Chain', `The issuer of "${c.title}" ("${c.issuer.short}") is not in the files and not a public root. If it is your private root, add it to check the whole chain.${aia}`);
    }
  }
  certs.forEach((c, i) => { if (!path.includes(i)) add('warn', 'Chain', `"${c.title}" is not part of the chain of "${chain.length ? chain[0].title : ''}".`); });

  // Order
  const expected = certs.length ? C.expectedOrder(certs, tree) : [];
  const orderOk = expected.every((v, i) => v === i);
  if (certs.length > 1) {
    if (orderOk) add('ok', 'Order', 'The certificates are in the right order: the leaf first, then each issuer.');
    else add('warn', 'Order', `Wrong order. Expected: ${expected.map((i, k) => `${k + 1}. ${certs[i].title}`).join(', ')}. Found: ${certs.map((c, k) => `${k + 1}. ${c.title}`).join(', ')}. Many servers send the chain exactly as the file lists it.`);
    const root = path.length > 1 && certs[path[path.length - 1]].selfSigned;
    if (root) add('info', 'Order', 'The root certificate is included. Servers normally send only the leaf and the intermediates; clients already have the root.');
  }

  // Dates
  for (const i of path) {
    const c = certs[i];
    if (c.status === 'expired') add('error', 'Dates', `"${c.title}" expired on ${c.notAfter.toISOString().slice(0, 10)}.`);
    else if (c.status === 'not-yet') add('error', 'Dates', `"${c.title}" is not valid before ${c.notBefore.toISOString().slice(0, 10)}.`);
    else if (c.status === 'soon') add('warn', 'Dates', `"${c.title}" expires in ${X.statusText(c, now).replace(' left', '')}, on ${c.notAfter.toISOString().slice(0, 10)}.`);
  }
  for (let k = 0; k + 1 < path.length; k++) {
    const c = certs[path[k]], p = certs[path[k + 1]];
    if (c.notAfter > p.notAfter) add('warn', 'Dates', `"${c.title}" is valid until ${c.notAfter.toISOString().slice(0, 10)}, after its issuer "${p.title}" expires (${p.notAfter.toISOString().slice(0, 10)}).`);
  }
  if (path.length && !path.some((i) => ['expired', 'not-yet', 'soon'].includes(certs[i].status))) add('ok', 'Dates', `Every certificate in the chain is valid today; the first to expire is "${certs[path.slice().sort((a, b) => certs[a].notAfter - certs[b].notAfter)[0]].title}" in ${X.statusText(certs[path.slice().sort((a, b) => certs[a].notAfter - certs[b].notAfter)[0]], now).replace(' left', '')}.`);

  // CA flags, key usage, path length
  for (let k = 1; k < path.length; k++) {
    const p = certs[path[k]];
    if (!p.ca) add('error', 'Usage', `"${p.title}" signs other certificates but is not marked as a CA (basic constraints).`);
    if (p.keyUsage && !p.keyUsage.includes('Certificate signing')) add('error', 'Usage', `"${p.title}" signs other certificates but its key usage lacks "Certificate signing".`);
    const below = k - 1; // CA certificates between it and the leaf
    if (p.pathLen !== null && p.pathLen !== undefined && below > p.pathLen) add('error', 'Usage', `"${p.title}" allows ${p.pathLen} CA certificate${p.pathLen === 1 ? '' : 's'} below it (path length), but the chain has ${below}.`);
  }
  if (path.length) {
    const leaf = certs[path[0]];
    if (leaf.extKeyUsage && !leaf.extKeyUsage.some((u) => /TLS server|Any/.test(u))) add('info', 'Usage', `"${leaf.title}" is not for TLS servers (extended key usage: ${leaf.extKeyUsage.join(', ')}).`);
    if (/sha1|md5/.test(leaf.sigAlg.hash || '')) add('warn', 'Usage', `"${leaf.title}" is signed with ${leaf.sigAlg.name}, which browsers reject.`);
    if (path.length > 1 && !path.slice(1).some((i) => !certs[i].ca) && path.every((i) => certs[i].ca || i === path[0])) add('ok', 'Usage', 'Every issuer in the chain is a CA allowed to sign certificates.');
  }

  // Keys
  const keyText = (x) => `${x.key.title}${x.file ? ` (${x.file})` : ''}`;
  for (const k of set.keys) {
    if (k.key.encrypted) { add('warn', 'Key', `${keyText(k)} is encrypted; enter its password to compare it.`); continue; }
    const s = k.key.key && k.key.key.sha256;
    const c = s ? certs.find((x) => x.key.sha256 === s) : null;
    if (c) add('ok', 'Key', `${keyText(k)} belongs to "${c.title}" (same public key).`);
    else if (s) add('error', 'Key', `${keyText(k)} does not belong to any certificate here.`);
    else add('warn', 'Key', `${keyText(k)}: its public key could not be computed, so it was not compared.`);
  }
  if (path.length && set.keys.length && !set.keys.some((k) => k.key.key && k.key.key.sha256 === certs[path[0]].key.sha256)) add('error', 'Key', `No private key for "${certs[path[0]].title}" was given.`);

  // CSRs
  for (const r of set.csrs) {
    const csr = r.csr;
    const name = `The request for "${csr.title}"${r.file ? ` (${r.file})` : ''}`;
    if (csr.signatureOk === false) add('error', 'CSR', `${name} has a signature that does not verify.`);
    const c = certs.find((x) => x.key.sha256 === csr.key.sha256);
    if (c) add('ok', 'CSR', `${name} uses the same key as "${c.title}".`);
    else if (certs.length) add('error', 'CSR', `${name} uses a different key than ${path.length ? `"${certs[path[0]].title}"` : 'the certificates'}.`);
    const kmatch = set.keys.find((k) => k.key.key && k.key.key.sha256 === csr.key.sha256);
    if (kmatch) add('ok', 'CSR', `${name} was made from ${kmatch.key.title}${kmatch.file ? ` (${kmatch.file})` : ''}.`);
    else if (set.keys.length) add('error', 'CSR', `${name} was not made from any private key here.`);
    const target = c || (path.length ? certs[path[0]] : null);
    if (target) {
      if (target.subject.text !== csr.subject.text) add('info', 'CSR', `Subject differs: request "${csr.subject.text}", certificate "${target.subject.text}".`);
      const a = new Set(csr.san.map((g) => `${g.type}:${g.value.toLowerCase()}`));
      const b = new Set(target.san.map((g) => `${g.type}:${g.value.toLowerCase()}`));
      const onlyReq = [...a].filter((x) => !b.has(x)), onlyCert = [...b].filter((x) => !a.has(x));
      if (onlyReq.length || onlyCert.length) add('info', 'CSR', `Alternative names differ.${onlyReq.length ? ` Only in the request: ${onlyReq.join(', ')}.` : ''}${onlyCert.length ? ` Only in the certificate: ${onlyCert.join(', ')}.` : ''}`);
    }
  }

  // Host name
  if (opts.host && path.length) {
    const leaf = certs[path[0]];
    if (C.hostMatches(leaf, opts.host)) add('ok', 'Host', `"${opts.host}" matches "${leaf.title}".`);
    else add('error', 'Host', `"${opts.host}" does not match "${leaf.title}" (names: ${leaf.san.map((g) => g.value).join(', ') || leaf.subject.cn}).`);
  }

  const counts = { ok: 0, info: 0, warn: 0, error: 0 };
  for (const x of f) counts[x.level]++;
  return { chain, findings: f, counts, orderOk, expected };
}

/** Markdown text of a check report (Copy as Markdown in the panel). */
function checkMarkdown(r, title = 'Chain and key check') {
  const icon = { ok: 'OK', info: 'Note', warn: 'Warning', error: 'Problem' };
  const lines = [`# ${title}`, '', `${r.counts.error} problems, ${r.counts.warn} warnings, ${r.counts.ok} passed.`, '', '## Chain', ''];
  r.chain.forEach((c, i) => lines.push(`${i + 1}. ${c.title} (${c.role}, ${c.statusText})`));
  lines.push('', '## Findings', '', '| Result | Area | Finding |', '|---|---|---|');
  for (const x of r.findings) lines.push(`| ${icon[x.level]} | ${x.area} | ${x.text.replace(/\|/g, '\\|')} |`);
  return lines.join('\n') + '\n';
}

module.exports = { checkSet, checkMarkdown, publicRoots, publicIssuer, isPublicRoot };

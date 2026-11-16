'use strict';
// Turns an open result (open.js) into the plain data the viewer draws: one card per item with titled sections of
// label/value rows, and the chain tree order. No private key number ever goes into a card.
const X = require('./x509');
const C = require('./chain');

const fmtDate = (d) => `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

function nameRows(n) { return n.attrs.length ? n.attrs.slice().reverse().map((a) => [a.type, a.value]) : [['Name', '(empty)']]; }

function keyRows(k) {
  const rows = [['Type', k.type]];
  if (k.curve) rows.push(['Curve', k.curve]);
  if (k.bits) rows.push(['Size', `${k.bits} bits`]);
  if (k.exponent) rows.push(['Exponent', String(k.exponent)]);
  if (k.sha256) rows.push(['SHA-256 of the public key', k.sha256.toUpperCase().replace(/(..)(?!$)/g, '$1:'), { mono: true, copy: true }]);
  if (k.pin) rows.push(['Pin (SHA-256, base64)', k.pin, { mono: true, copy: true }]);
  return rows;
}

function weakNotes(c) {
  const out = [];
  if (/sha1|md5/i.test(c.sigAlg.hash || '')) out.push(`Signed with ${c.sigAlg.name}, which browsers no longer accept for TLS.`);
  if ((c.key.type === 'RSA' || c.key.type === 'RSA-PSS') && c.key.bits && c.key.bits < 2048) out.push(`The RSA key has only ${c.key.bits} bits.`);
  if (c.version < 3 && !c.selfSigned) out.push(`This is a version ${c.version} certificate without extensions.`);
  if (!c.innerAlgMatches) out.push('The two signature algorithm fields of the certificate differ.');
  return out;
}

function certCard(c, ctx) {
  const sec = [];
  const head = { status: c.status, statusText: X.statusText(c, ctx.now), role: c.role, daysLeft: c.daysLeft };
  sec.push({ title: 'Subject', rows: nameRows(c.subject) });
  sec.push({ title: 'Issuer', rows: nameRows(c.issuer).concat(c.selfIssued ? [['', 'Same as the subject (self-issued)']] : []) });
  sec.push({ title: 'Validity', rows: [['Valid from', fmtDate(c.notBefore)], ['Valid to', fmtDate(c.notAfter)], ['Status', head.statusText, { status: c.status }]] });
  if (c.san.length) sec.push({ title: `Subject alternative names (${c.san.length})`, rows: c.san.map((g) => [g.type, g.value, { copy: true }]) });
  sec.push({ title: 'Public key', rows: keyRows(c.key) });
  const use = [];
  use.push(['Certificate authority', c.ca ? `Yes${c.pathLen !== null && c.pathLen !== undefined ? `, path length ${c.pathLen}` : ''}` : 'No']);
  use.push(['Key usage', c.keyUsage ? c.keyUsage.join(', ') || '(none)' : '(not set)']);
  use.push(['Extended key usage', c.extKeyUsage ? c.extKeyUsage.join(', ') : '(not set)']);
  sec.push({ title: 'Usage', rows: use });
  const sig = [['Signature algorithm', c.sigAlg.name], ['Serial number', c.serial, { mono: true, copy: true }], ['Version', String(c.version)]];
  if (ctx.signedBy) sig.push(['Signature check', ctx.signedBy]);
  sec.push({ title: 'Fingerprints', rows: [['SHA-256', c.sha256, { mono: true, copy: true }], ['SHA-1', c.sha1, { mono: true, copy: true }]].concat(sig) });
  if (c.extensions.length) sec.push({ title: `Extensions (${c.extensions.length})`, rows: c.extensions.map((e) => [`${e.name}${e.critical ? ' (critical)' : ''}`, e.lines.join('\n') + (e.error ? `\n(unreadable: ${e.error})` : ''), { ext: true, oid: e.oid }]) });
  const notes = weakNotes(c);
  if (ctx.extra) sec.unshift({ title: 'In this file', rows: ctx.extra });
  return { kind: 'cert', title: c.title, subtitle: c.issuer.short === c.subject.short && c.selfIssued ? 'Self-issued' : `Issued by ${c.issuer.short}`, ...head, notes, sections: sec, copy: true };
}

function csrCard(r) {
  const sec = [{ title: 'Subject', rows: nameRows(r.subject) }];
  if (r.san.length) sec.push({ title: `Requested alternative names (${r.san.length})`, rows: r.san.map((g) => [g.type, g.value, { copy: true }]) });
  sec.push({ title: 'Public key', rows: keyRows(r.key) });
  sec.push({ title: 'Request', rows: [['Signature algorithm', r.sigAlg.name], ['Signature', r.signatureOk === true ? 'Valid (signed by its own key)' : r.signatureOk === false ? 'Does not verify' : 'Not checked'], ['SHA-256', r.sha256, { mono: true, copy: true }]].concat(r.attributes.map((a) => [a.name, a.value])) });
  const other = r.extensions.filter((e) => e.oid !== '2.5.29.17');
  if (other.length) sec.push({ title: `Requested extensions (${other.length})`, rows: other.map((e) => [`${e.name}${e.critical ? ' (critical)' : ''}`, e.lines.join('\n'), { ext: true }]) });
  return { kind: 'csr', title: r.title, subtitle: 'Certificate request (CSR)', role: 'Request', status: r.signatureOk === false ? 'expired' : 'ok', statusText: r.signatureOk === false ? 'Signature does not verify' : 'Signature valid', sections: sec, notes: [], copy: true };
}

function keyCard(k, ctx) {
  const rows = [];
  if (k.encrypted) {
    rows.push(['Format', k.format], ['Encrypted with', k.scheme || 'unknown scheme']);
    return { kind: 'key', title: k.title, subtitle: 'Encrypted private key', role: 'Private key', status: 'locked', statusText: 'Password needed', sections: [{ title: 'Private key', rows }], notes: k.legacyPem ? ['Keys with legacy PEM encryption (Proc-Type headers) cannot be opened here. Convert them with "openssl pkcs8 -topk8".'] : [], copy: false, locked: !k.legacyPem };
  }
  rows.push(['Format', k.format]);
  if (k.wasEncrypted) rows.push(['Encrypted with', k.wasEncrypted]);
  const sec = [{ title: 'Private key', rows }];
  if (k.key && k.key.spki) sec.push({ title: 'Public key', rows: keyRows(k.key) });
  if (ctx.match !== undefined) sec.push({ title: 'Key match', rows: [['Certificate', ctx.match || 'No certificate in this file uses this key']] });
  return { kind: 'key', title: k.title, subtitle: 'Private key', role: 'Private key', status: 'key', statusText: k.key && k.key.label ? k.key.label : '', sections: sec, notes: ['The private key numbers are not shown and never leave this computer.'], copy: false };
}

function pubCard(p) {
  return { kind: 'pubkey', title: p.title, subtitle: 'Public key', role: 'Public key', status: 'key', statusText: p.key.label, sections: [{ title: 'Public key', rows: keyRows(p.key) }], notes: [], copy: true };
}

/** res (open.js) -> { cards, order: [{ index, depth }], summary } */
function describe(res, opts = {}) {
  const now = opts.now || Date.now();
  const certIdx = res.items.map((it, i) => (it.kind === 'cert' ? i : -1)).filter((i) => i >= 0);
  const certs = certIdx.map((i) => res.items[i].cert);
  const { order, tree } = C.treeOrder(certs);
  const spkiOf = (it) => (it.kind === 'key' && it.key.key && it.key.key.sha256) || '';
  const cards = res.items.map((it, i) => {
    const extra = [];
    if (it.friendlyName) extra.push(['Friendly name', it.friendlyName]);
    if (it.kind === 'cert') {
      const ci = certIdx.indexOf(i);
      const p = tree.parent[ci];
      let signedBy = '';
      if (p >= 0) signedBy = tree.verified[ci] === true ? `Verified with the key of "${certs[p].title}" in this file` : tree.verified[ci] === false ? `Does not verify with "${certs[p].title}"` : `Issuer "${certs[p].title}" is in this file (signature not checked)`;
      else if (it.cert.selfSigned) signedBy = 'Self-signed, the signature is valid';
      else signedBy = 'The issuer is not in this file';
      const keys = res.items.filter((k) => k.kind === 'key' && spkiOf(k) && spkiOf(k) === it.cert.key.sha256);
      if (keys.length) extra.push(['Private key', 'The private key of this certificate is in this file']);
      const dup = certIdx.filter((j) => j !== i && Buffer.compare(res.items[j].cert.der, it.cert.der) === 0);
      if (dup.length) extra.push(['Duplicate', `The same certificate appears ${dup.length + 1} times in this file`]);
      return certCard(it.cert, { now, signedBy, extra: extra.length ? extra : null });
    }
    if (it.kind === 'csr') return csrCard(it.csr);
    if (it.kind === 'key') {
      const s = spkiOf(it);
      let match;
      if (s && certs.length) { const c = certs.find((x) => x.key.sha256 === s); match = c ? `Matches "${c.title}"` : ''; }
      const card = keyCard(it.key, { match });
      if (extra.length) card.sections.unshift({ title: 'In this file', rows: extra });
      return card;
    }
    if (it.kind === 'pubkey') return pubCard(it.pub);
    if (it.kind === 'error') return { kind: 'error', title: it.title, subtitle: 'Could not be read', role: 'Error', status: 'expired', statusText: 'Unreadable', sections: [{ title: 'Problem', rows: [['', it.error]] }], notes: [], copy: false };
    return { kind: 'other', title: it.title, subtitle: '', role: 'Other', status: 'other', statusText: '', sections: [{ title: 'Note', rows: [['', it.note || '']] }], notes: [], copy: false };
  });
  cards.forEach((c, i) => { c.index = i; c.source = res.items[i].source || {}; });
  const listOrder = order.map((o) => ({ index: certIdx[o.index], depth: o.depth }));
  res.items.forEach((it, i) => { if (it.kind !== 'cert') listOrder.push({ index: i, depth: 0 }); });
  const counts = {};
  for (const it of res.items) counts[it.kind] = (counts[it.kind] || 0) + 1;
  const parts = [];
  if (counts.cert) parts.push(plural(counts.cert, 'certificate'));
  if (counts.csr) parts.push(plural(counts.csr, 'request'));
  if (counts.key) parts.push(plural(counts.key, 'private key'));
  if (counts.pubkey) parts.push(plural(counts.pubkey, 'public key'));
  if (counts.other) parts.push(plural(counts.other, 'other block'));
  if (counts.error) parts.push(`${counts.error} unreadable`);
  // The card to show first: the leaf (end entity) of the longest chain, else the first item.
  let first = 0;
  if (certs.length) { const ex = C.expectedOrder(certs, tree); first = certIdx[ex[0]]; }
  return { cards, order: listOrder, summary: parts.join(', '), first };
}

module.exports = { describe, certCard, csrCard, keyCard, fmtDate };

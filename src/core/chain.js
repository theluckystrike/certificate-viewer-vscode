'use strict';
// Chain building over a set of parsed certificates: who issued whom (name match plus a verified signature), the tree
// for the viewer, the expected bundle order (leaf first) and the checks of the Pro chain tool.
const X = require('./x509');

const sameName = (a, b) => Buffer.compare(a.raw, b.raw) === 0;

/** The index of the certificate in `certs` that issued certs[i] (signature verified), or -1. Self-signed: -1. */
function issuerIndex(certs, i) {
  const c = certs[i];
  if (c.selfIssued && c.selfSigned) return -1;
  let fallback = -1;
  for (let j = 0; j < certs.length; j++) {
    if (j === i) continue;
    const p = certs[j];
    if (!sameName(c.issuer, p.subject)) continue;
    if (c.aki && p.ski && c.aki !== p.ski) continue;
    if (Buffer.compare(c.der, p.der) === 0) continue;
    const ok = X.verifySignature(c.sigAlg, c.tbs, c.signature, p.key.spki);
    if (ok === true) return j;
    if (ok === null && fallback < 0) fallback = j;
  }
  return fallback;
}

/** { parent: [index or -1], roots: [index], children: [[index]], verified: [true|false|null] } */
function buildTree(certs) {
  const parent = certs.map((_, i) => issuerIndex(certs, i));
  const children = certs.map(() => []);
  parent.forEach((p, i) => { if (p >= 0) children[p].push(i); });
  // A loop (two certificates that sign each other) would hide both: break it at the first one.
  const roots = [];
  const seen = new Set();
  const walk = (i) => { seen.add(i); for (const k of children[i]) if (!seen.has(k)) walk(k); };
  certs.forEach((_, i) => { if (parent[i] < 0) { roots.push(i); walk(i); } });
  certs.forEach((_, i) => { if (!seen.has(i)) { parent[i] = -1; roots.push(i); walk(i); } });
  const verified = certs.map((c, i) => (parent[i] >= 0 ? X.verifySignature(c.sigAlg, c.tbs, c.signature, certs[parent[i]].key.spki) : (c.selfSigned ? true : null)));
  return { parent, roots, children, verified };
}

/** Depth-first order of the tree (root first), with depth, for the viewer's chain list. */
function treeOrder(certs) {
  const t = buildTree(certs);
  const out = [];
  const seen = new Set();
  const walk = (i, d) => { if (seen.has(i)) return; seen.add(i); out.push({ index: i, depth: d }); for (const k of t.children[i]) walk(k, d + 1); };
  for (const r of t.roots) walk(r, 0);
  return { order: out, tree: t };
}

/** The leaf-first path from certs[i] up to the top of what is in the set. */
function pathUp(certs, i, tree = buildTree(certs)) {
  const path = [i];
  const seen = new Set([i]);
  let p = tree.parent[i];
  while (p >= 0 && !seen.has(p)) { path.push(p); seen.add(p); p = tree.parent[p]; }
  return path;
}

/** Leaves: certificates that issued nothing in the set (end entities first). */
function leaves(certs, tree = buildTree(certs)) {
  const l = certs.map((_, i) => i).filter((i) => tree.children[i].length === 0);
  return l.sort((a, b) => Number(certs[a].ca) - Number(certs[b].ca));
}

/** Expected order of a bundle: the longest leaf path first, then anything left in file order. */
function expectedOrder(certs, tree = buildTree(certs)) {
  if (!certs.length) return [];
  const ls = leaves(certs, tree);
  const best = ls.map((i) => pathUp(certs, i, tree)).sort((a, b) => b.length - a.length)[0] || [0];
  const rest = certs.map((_, i) => i).filter((i) => !best.includes(i));
  return best.concat(rest);
}

/** Wildcard-aware host name match against the DNS and IP SANs (CN only when there are no SANs). */
function hostMatches(cert, host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  const names = cert.san.filter((g) => g.type === 'DNS' || g.type === 'IP').map((g) => g.value.toLowerCase());
  if (!cert.san.length && cert.subject.cn) names.push(cert.subject.cn.toLowerCase());
  return names.some((n) => {
    if (n === h) return true;
    if (n.startsWith('*.')) { const rest = n.slice(1); return h.endsWith(rest) && h.indexOf('.') === h.length - rest.length; }
    return false;
  });
}

module.exports = { issuerIndex, buildTree, treeOrder, pathUp, leaves, expectedOrder, hostMatches, sameName };

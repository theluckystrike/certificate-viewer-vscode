'use strict';
// Pro tool "Workspace expiry scan": every certificate in a set of files (certificate files, and PEM blocks inside
// YAML, JSON, .env, Kubernetes secrets and other text), sorted by days to expiry, with CSV and Markdown reports.
const { openBytes } = require('./open');
const pem = require('./pem');
const X = require('./x509');

const CERT_EXT = ['pem', 'crt', 'cer', 'der', 'p7b', 'p7c', 'p12', 'pfx', 'csr', 'key', 'cert', 'ca-bundle'];
const TEXT_EXT = ['yaml', 'yml', 'json', 'env', 'conf', 'cfg', 'cnf', 'ini', 'toml', 'properties', 'tf', 'tfvars', 'txt', 'xml', 'config', 'tpl', 'j2', 'hcl', 'js', 'ts', 'mjs', 'cjs', 'py', 'go', 'java', 'cs', 'rb', 'php', 'sh', 'md', 'jwks'];
// One brace level only: VS Code's glob reads {a,b} groups but not groups inside groups.
const INCLUDE = `**/{${CERT_EXT.concat(TEXT_EXT).map((e) => `*.${e}`).concat(['.env', '.env.*']).join(',')}}`;
const EXCLUDE = '**/{node_modules,.git,.hg,.svn,dist,out,build,.venv,venv,__pycache__,.terraform,.next,target,vendor}/**';

const lineOf = (text, at) => { let n = 1; for (let i = 0; i < at && i < text.length; i++) if (text.charCodeAt(i) === 10) n++; return n; };
const WHERE = { pem: 'PEM', json: 'PEM in a JSON string', 'base64-pem': 'Base64 PEM (Kubernetes secret style)', 'base64-der': 'Base64 DER' };

/**
 * One file -> { entries: [...], locked: bool, error: string }. opts: { password, now, certFile: bool }
 * Entries: { file, line, where, title, subject, issuer, notBefore, notAfter, daysLeft, status, sha256, serial, san, ca, selfSigned }
 */
function scanFile(rel, bytes, opts = {}) {
  const now = opts.now || Date.now();
  const ext = (rel.split('.').pop() || '').toLowerCase();
  const isCertFile = CERT_EXT.includes(ext);
  const out = { entries: [], locked: false, error: '' };
  const isText = pem.looksText(bytes);
  if (!isText && !isCertFile) return out;
  const text = isText ? Buffer.from(bytes).toString('utf8') : '';
  if (isText && !isCertFile && text.indexOf('-----BEGIN') < 0 && text.indexOf(pem.BEGIN_B64) < 0 && text.indexOf('MII') < 0) return out;
  const res = openBytes(bytes, rel, { password: opts.password, now });
  if (res.locked) { out.locked = true; return out; }
  if (isCertFile && res.errors.length && !res.items.length) { out.error = res.errors[0]; return out; }
  for (const it of res.items) {
    if (it.kind !== 'cert') continue;
    const c = it.cert;
    const s = it.source || {};
    out.entries.push({
      file: rel,
      line: isText && typeof s.start === 'number' ? lineOf(text, s.start) : 0,
      where: res.pfx ? 'PFX / PKCS#12' : isText ? WHERE[s.encoding] || 'PEM' : (s.p7 !== undefined ? 'PKCS#7' : 'DER'),
      title: c.title, subject: c.subject.text, issuer: c.issuer.short,
      notBefore: c.notBefore.toISOString(), notAfter: c.notAfter.toISOString(),
      daysLeft: X.daysLeft(c.notAfter, now), status: c.status, statusText: X.statusText(c, now),
      sha256: c.sha256, serial: c.serial, san: c.san.filter((g) => g.type === 'DNS' || g.type === 'IP').map((g) => g.value), ca: c.ca, selfSigned: c.selfSigned, role: c.role,
    });
  }
  return out;
}

/** Sorts by days left (expired first) and marks the same certificate seen in several places. */
function finish(entries) {
  const seen = new Map();
  for (const e of entries) seen.set(e.sha256, (seen.get(e.sha256) || 0) + 1);
  for (const e of entries) e.copies = seen.get(e.sha256);
  return entries.sort((a, b) => a.daysLeft - b.daysLeft || a.file.localeCompare(b.file) || a.line - b.line);
}

function summary(entries, files, locked) {
  const n = (f) => entries.filter(f).length;
  return {
    total: entries.length, unique: new Set(entries.map((e) => e.sha256)).size, files,
    expired: n((e) => e.status === 'expired'), d30: n((e) => e.status !== 'expired' && e.daysLeft < 30), d90: n((e) => e.daysLeft >= 30 && e.daysLeft < 90), locked,
  };
}

// Cells that a spreadsheet would run as a formula (=, +, -, @) get a leading apostrophe; plain numbers stay numbers.
const csvCell = (v) => {
  let s = String(v === undefined || v === null ? '' : v);
  if (/^[=+\-@]/.test(s) && !/^-?\d+$/.test(s)) s = `'${s}`;
  return /[",\n\r']/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
function toCsv(entries) {
  const head = ['days_left', 'status', 'expires', 'valid_from', 'common_name', 'subject', 'issuer', 'names', 'file', 'line', 'found_as', 'role', 'sha256'];
  const rows = entries.map((e) => [e.daysLeft, e.status, e.notAfter.slice(0, 10), e.notBefore.slice(0, 10), e.title, e.subject, e.issuer, e.san.join(' '), e.file, e.line || '', e.where, e.role, e.sha256.replace(/:/g, '')]);
  return [head, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

const md = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
function toMarkdown(entries, s, when = new Date()) {
  const lines = [`# Certificate expiry report`, '', `Scanned ${s.files} files on ${when.toISOString().slice(0, 10)}: ${s.total} certificates (${s.unique} different). ${s.expired} expired, ${s.d30} expire within 30 days, ${s.d90} within 90 days.${s.locked ? ` ${s.locked} password-protected PFX files were skipped.` : ''}`, '',
    '| Days left | Expires | Common name | Issuer | File | Found as |', '|---:|---|---|---|---|---|'];
  for (const e of entries) lines.push(`| ${e.daysLeft} | ${e.notAfter.slice(0, 10)} | ${md(e.title)} | ${md(e.issuer)} | ${md(e.file)}${e.line ? `:${e.line}` : ''} | ${md(e.where)} |`);
  return lines.join('\n') + '\n';
}

module.exports = { scanFile, finish, summary, toCsv, toMarkdown, INCLUDE, EXCLUDE, CERT_EXT, TEXT_EXT, lineOf };

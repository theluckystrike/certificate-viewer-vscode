'use strict';
// Extension tests with the vscode stub: listing, activation, the custom editor's messages (password, copy, reveal),
// the hover, the three Pro tools (the panel's "shown" answer is simulated like the real panel), tries and the Pro
// panel, README, support links and the network rules.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadExtension, tmpDir, cleanup } = require('./support/vscode-stub');
const { editorHtml, panelHtml } = require('../src/html');
const { openBytes } = require('../src/core/open');

const ROOT = path.join(__dirname, '..');
const FIX = path.join(__dirname, 'fixtures');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 3000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await tick(10); } return f(); };
test.after(() => cleanup());

function activate(folder) {
  const s = loadExtension();
  if (folder) s.vscode.workspace.workspaceFolders = [{ uri: s.vscode.Uri.file(folder), name: 'ws' }];
  s.api = s.ext.activate(s.context);
  // The tool panel answers like the real one: "shown" after a result with content.
  s.log.onPost = (panel, m) => {
    if (m.type === 'scan' && m.entries.length) panel.send({ type: 'shown' });
    if (m.type === 'check' && m.report.findings.length) panel.send({ type: 'shown' });
    if (m.type === 'convert' && m.outputs.some((o) => o.ok)) panel.send({ type: 'shown' });
  };
  return s;
}
function ws() {
  const dir = tmpDir('cert-ws-');
  fs.mkdirSync(path.join(dir, 'tls', 'deep'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'k8s'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'node_modules', 'x'), { recursive: true });
  for (const f of ['chain.pem', 'leaf.key', 'leaf.csr', 'expired.pem', 'api-nopass.pfx', 'leaf-openssl3.pfx', 'chain.p7b', 'garbage.crt', 'other.key', 'chain-wrong-order.pem']) fs.copyFileSync(path.join(FIX, f), path.join(dir, 'tls', f));
  fs.copyFileSync(path.join(FIX, 'leaf.der'), path.join(dir, 'tls', 'deep', 'leaf.cer'));
  fs.copyFileSync(path.join(FIX, 'k8s-secret.yaml'), path.join(dir, 'k8s', 'secret.yaml'));
  fs.copyFileSync(path.join(FIX, 'config.json'), path.join(dir, 'config.json'));
  fs.copyFileSync(path.join(FIX, 'app.env'), path.join(dir, '.env'));
  fs.copyFileSync(path.join(FIX, 'api.pem'), path.join(dir, 'node_modules', 'x', 'ignored.pem'));
  return dir;
}
function fakePanel() {
  let onMsg;
  const posted = [];
  return {
    posted, viewColumn: 1, active: true,
    webview: { options: {}, html: '', cspSource: 'vscode-resource:', asWebviewUri: (u) => u, postMessage: async (m) => { posted.push(m); return true; }, onDidReceiveMessage: (f) => { onMsg = f; return { dispose() {} }; } },
    onDidChangeViewState: () => ({ dispose() {} }), onDidDispose: () => ({ dispose() {} }), reveal() {},
    send: (m) => onMsg(m),
  };
}
async function openEditor(s, file) {
  const prov = s.providers.custom.p;
  const handle = await prov.openCustomDocument(s.vscode.Uri.file(file));
  const panel = fakePanel();
  await prov.resolveCustomEditor(handle, panel);
  await panel.send({ type: 'ready' });
  return { prov, handle, panel, doc: handle._doc, last: () => panel.posted.filter((m) => m.type === 'doc').pop() };
}

// ---------- package.json and listing ----------
test('listing: display name with the phrase first, 30 characters or less, 5 keywords, engines for Cursor and Windsurf', () => {
  assert.equal(pkg.displayName, 'Certificate Viewer, X509 & PEM');
  assert.ok(pkg.displayName.length <= 30);
  assert.ok(pkg.description.startsWith('Certificate viewer'));
  assert.deepEqual(pkg.keywords, ['certificate viewer', 'x509', 'pem', 'ssl certificate', 'pfx']);
  assert.equal(pkg.engines.vscode, '^1.75.0');
  assert.equal(`${pkg.publisher}.${pkg.name}`, 'zovo.zovo-certificate-viewer');
  assert.equal(pkg.repository.url, 'https://github.com/theluckystrike/certificate-viewer-vscode');
  assert.equal(pkg.license, 'MIT');
  assert.ok(pkg.activationEvents.includes('onUri'));
  assert.deepEqual(pkg.contributes.customEditors[0].selector.map((s) => s.filenamePattern), ['*.pem', '*.crt', '*.cer', '*.der', '*.p7b', '*.p7c', '*.p12', '*.pfx', '*.csr', '*.key']);
  const png = fs.readFileSync(path.join(ROOT, 'icon.png'));
  assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [128, 128]);
});
test('every contributed command is registered, and every registered certViewer command is contributed', () => {
  const s = activate();
  const contributed = pkg.contributes.commands.map((c) => c.command);
  for (const c of contributed) assert.ok(s.commands.has(c), `not registered: ${c}`);
  for (const c of s.commands.keys()) if (c.startsWith('certViewer.')) assert.ok(contributed.includes(c), `not in package.json: ${c}`);
  const menus = Object.values(pkg.contributes.menus).flat().map((m) => m.command);
  for (const c of menus) assert.ok(contributed.includes(c), `menu names an unknown command: ${c}`);
});
test('activation shows nothing: no message, no panel, no editor, no URL; the hover provider is registered', () => {
  const s = activate();
  assert.equal(s.log.info.length + s.log.warn.length + s.log.error.length, 0);
  assert.equal(s.log.panel, undefined);
  assert.equal(s.log.opened.length, 0);
  assert.equal(s.log.external.length, 0);
  assert.equal(s.providers.hover.length, 1);
});
test('Open in Certificate Viewer: certificate files open in the viewer, YAML shows its PEM blocks in a panel', async () => {
  const s = activate();
  await s.vscode.commands.executeCommand('certViewer.openWithViewer', s.vscode.Uri.file(path.join(FIX, 'leaf.der')));
  assert.deepEqual(s.log.commands.filter((c) => c[0] === 'vscode.openWith').map((c) => c[2]), ['certViewer.editor']);
  await s.vscode.commands.executeCommand('certViewer.openWithViewer', s.vscode.Uri.file(path.join(FIX, 'k8s-secret.yaml')));
  assert.equal(s.log.panel.id, 'certViewer.peek');
  const doc = await until(() => s.log.panel.posted.find((m) => m.type === 'doc'));
  assert.equal(doc.summary, '2 certificates, 1 private key');
});

// ---------- the viewer ----------
test('viewer: a chain sends cards, the tree (root, intermediate, leaf) and the leaf first', async () => {
  const s = activate();
  const { last } = await openEditor(s, path.join(FIX, 'chain-wrong-order.pem'));
  const d = last();
  assert.equal(d.format, 'PEM');
  assert.equal(d.summary, '3 certificates');
  assert.deepEqual(d.order.map((o) => [d.cards[o.index].title, o.depth]), [['Zovo Test Root CA', 0], ['Zovo Test Issuing CA', 1], ['www.example.test', 2]]);
  assert.equal(d.cards[d.first].title, 'www.example.test');
  assert.equal(d.isText, true);
  assert.equal(d.showPro, true);
});
test('viewer: a PFX asks for the password in the page; a wrong one says so; the right one is kept in memory only', async () => {
  const s = activate();
  const file = path.join(FIX, 'leaf-legacy.p12');
  const { panel, last, prov } = await openEditor(s, file);
  assert.equal(last().locked, true);
  assert.equal(last().cards.length, 0);
  await panel.send({ type: 'password', value: 'wrong' });
  assert.deepEqual(panel.posted[panel.posted.length - 1], { type: 'pwResult', ok: false });
  await panel.send({ type: 'password', value: 'test-pass' });
  const d = last();
  assert.equal(d.locked, false);
  assert.equal(d.summary, '3 certificates, 1 private key');
  assert.match(d.pfx.encrypted.join(' '), /40-bit RC2/);
  assert.match(d.pfx.mac, /SHA-1, 2048 iterations, verified/);
  // Opened again in this session: no question.
  const again = await openEditor(s, file);
  assert.equal(again.last().locked, false);
  // Nothing about the password in global state, workspace state, secrets or any message.
  const dump = JSON.stringify([...s.state.entries()]) + JSON.stringify(panel.posted) + JSON.stringify(again.panel.posted);
  assert.ok(!dump.includes('test-pass'));
  void prov;
});
test('viewer: an encrypted key shows its scheme, then its type after the password', async () => {
  const s = activate();
  const { panel, last } = await openEditor(s, path.join(FIX, 'leaf-encrypted.key'));
  assert.equal(last().lockedKey, true);
  assert.match(JSON.stringify(last().cards[0]), /PBES2: PBKDF2 HMAC-SHA-256, AES-256-CBC/);
  await panel.send({ type: 'password', value: 'test-pass' });
  assert.equal(last().cards[0].title, 'RSA 2048 bits private key');
  assert.equal(last().cards[0].copy, false);
});
test('viewer: copy as PEM and as DER base64 go to the clipboard; a key is never copied', async () => {
  const s = activate();
  const { panel, last } = await openEditor(s, path.join(FIX, 'leaf-with-key.pem'));
  const cards = last().cards;
  const ci = cards.findIndex((c) => c.kind === 'cert'), ki = cards.findIndex((c) => c.kind === 'key');
  await panel.send({ type: 'copy', index: ci, as: 'pem' });
  assert.equal(s.log.clipboard, fs.readFileSync(path.join(FIX, 'leaf.pem'), 'utf8'));
  await panel.send({ type: 'copy', index: ci, as: 'der' });
  assert.equal(s.log.clipboard, fs.readFileSync(path.join(FIX, 'leaf.der')).toString('base64'));
  s.log.clipboard = null;
  await panel.send({ type: 'copy', index: ki, as: 'pem' });
  assert.equal(s.log.clipboard, null);
});
test('viewer: broken, empty and too big files give a reason and count as a failure; DER opens as binary', async () => {
  const s = activate();
  const fails = [];
  s.api.provider.hooks.onFailure = () => fails.push(1);
  assert.match((await openEditor(s, path.join(FIX, 'broken.pem'))).last().error, /cut off/);
  assert.match((await openEditor(s, path.join(FIX, 'garbage.crt'))).last().error, /No certificate/);
  assert.match((await openEditor(s, path.join(FIX, 'truncated.der'))).last().error, /past the end/);
  assert.equal(fails.length, 3);
  const big = path.join(tmpDir('cert-big-'), 'big.pem');
  fs.writeFileSync(big, Buffer.alloc(1024 * 1024 + 10, 0x41));
  s.config.maxFileSizeMB = 1;
  assert.match((await openEditor(s, big)).last().error, /more than the 1 MB/);
  delete s.config.maxFileSizeMB;
  const der = (await openEditor(s, path.join(FIX, 'leaf.der'))).last();
  assert.equal(der.isText, false);
  assert.equal(der.format, 'DER certificate');
});
test('viewer: shown counts one success per document; Open as Text and reveal open the text with the block selected', async () => {
  const s = activate();
  const ok = [];
  s.api.provider.hooks.onSuccess = (d) => ok.push(d.name);
  const { panel } = await openEditor(s, path.join(FIX, 'chain.pem'));
  await panel.send({ type: 'shown' });
  await panel.send({ type: 'shown' });
  assert.deepEqual(ok, ['chain.pem']);
  await panel.send({ type: 'openText' });
  assert.deepEqual(s.log.commands.filter((c) => c[0] === 'vscode.openWith').map((c) => c[2]), ['default']);
  await panel.send({ type: 'reveal', index: 1 });
  assert.equal(s.log.opened.length, 1);
});

// ---------- hover ----------
test('hover: on a base64 PEM in YAML, in a JSON string and in .env; nothing outside a block; the setting turns it off', async () => {
  const s = activate();
  const hp = s.providers.hover[0];
  const at = (file, needle, add = 10) => { const t = fs.readFileSync(file, 'utf8'); const d = s.makeDoc(s.vscode.Uri.file(file), t, 'yaml'); return hp.provideHover(d, d.positionAt(t.indexOf(needle) + add)); };
  const y = at(path.join(FIX, 'k8s-secret.yaml'), 'LS0tLS1CRUdJTi');
  assert.match(y.contents.value, /\*\*www\\\.example\\\.test\*\*/);
  assert.match(y.contents.value, /command:certViewer\.showPemAt\?/);
  assert.match(y.contents.value, /base64 PEM with 2 blocks/);
  assert.match(y.contents.value, /\*\*Zovo Test Issuing CA\*\* \(Intermediate CA\)/);
  const j = at(path.join(FIX, 'config.json'), 'MII', 50);
  assert.match(j.contents.value, /api\\\.example\\\.test/);
  assert.match(j.contents.value, /\$\(warning\)/);
  const e = at(path.join(FIX, 'app.env'), 'MII', 50);
  assert.match(e.contents.value, /\$\(error\)/);
  assert.match(e.contents.value, /Expired \d+ days ago/);
  assert.equal(at(path.join(FIX, 'k8s-secret.yaml'), 'apiVersion', 2), undefined);
  s.config.hover = false;
  assert.equal(at(path.join(FIX, 'k8s-secret.yaml'), 'LS0tLS1CRUdJTi'), undefined);
});
test('hover link: showPemAt opens every block of the file in a panel with the hovered one selected', async () => {
  const s = activate();
  const file = path.join(FIX, 'config.json');
  const t = fs.readFileSync(file, 'utf8');
  const second = t.lastIndexOf('MII') + 5;
  await s.vscode.commands.executeCommand('certViewer.showPemAt', s.vscode.Uri.file(file).toString(), second);
  const d = await until(() => s.log.panel.posted.find((m) => m.type === 'doc'));
  assert.equal(d.cards[d.first].title, 'Zovo Test Issuing CA');
  assert.equal(d.fromText, true);
});

// ---------- HTML, network ----------
test('webview HTML: strict CSP, nonce scripts, no remote URLs, no blob images', () => {
  for (const html of [editorHtml({ cspSource: 'vscode-resource:', scriptUri: 'a.js', styleUri: 'a.css', title: '<x>' }), panelHtml({ cspSource: 'vscode-resource:', scriptUri: 'p.js', styleUri: 'p.css', title: 't' })]) {
    const csp = /content="([^"]+)"/.exec(html)[1];
    assert.match(csp, /default-src 'none'/);
    assert.doesNotMatch(csp, /connect-src|unsafe-eval|unsafe-inline|https?:|blob:/);
    const nonce = /'nonce-([^']+)'/.exec(csp)[1];
    for (const m of html.matchAll(/<script([^>]*)>/g)) assert.match(m[1], new RegExp(`nonce="${nonce}"`));
    assert.doesNotMatch(html, /<x>/);
  }
});
test('media scripts load nothing remote; no source file opens a network connection or logs', () => {
  for (const f of ['viewer.js', 'panel.js']) {
    const src = fs.readFileSync(path.join(ROOT, 'media', f), 'utf8');
    assert.doesNotMatch(src, /fetch\(|XMLHttpRequest|WebSocket|https?:\/\//);
    // Data from the extension is set with textContent; the only innerHTML is the footer template of our own HTML.
    assert.deepEqual(src.match(/innerHTML\s*=[^;]*/g) || [], f === 'viewer.js' ? ["innerHTML = tpl.innerHTML"] : []);
  }
  const files = ['extension.js', 'editor.js', 'tools.js', 'html.js', 'hover.js', 'passwords.js', 'pro.js'].concat(fs.readdirSync(path.join(ROOT, 'src', 'core')).map((f) => `core/${f}`));
  for (const f of files) {
    const src = fs.readFileSync(path.join(ROOT, 'src', f), 'utf8');
    assert.doesNotMatch(src, /require\(['"](https?|net|dgram|undici|http2)['"]\)|fetch\(/, f);
    assert.doesNotMatch(src, /console\.(log|info|warn|error|debug)/, f);
  }
});

// ---------- Pro tools ----------
test('Pro scan: workspace certificates sorted by days left, node_modules skipped, a locked PFX listed; the try counts when the table shows', async () => {
  const dir = ws();
  const s = activate(dir);
  const r = await s.api.tools.scanTool();
  const titles = r.entries.map((e) => `${e.title}@${e.file}`);
  assert.equal(r.entries[0].title, 'old.example.test');
  assert.ok(titles.includes('www.example.test@k8s/secret.yaml'));
  assert.ok(titles.includes('www.example.test@tls/deep/leaf.cer'));
  assert.ok(titles.includes('api.example.test@config.json'));
  assert.ok(titles.includes('old.example.test@.env'));
  assert.ok(titles.includes('api.example.test@tls/api-nopass.pfx'));
  assert.ok(!titles.some((t) => /node_modules/.test(t)));
  assert.deepEqual(r.locked, ['tls/leaf-openssl3.pfx']);
  assert.ok(r.errors.some((e) => /garbage\.crt/.test(e)));
  await until(() => s.api.pro.left('scan') === 0);
  assert.equal(s.api.pro.left('scan'), 0);
  assert.match(s.log.status.join('\n'), /the free try of "Workspace expiry scan" is used on this computer/);
  // Unlock the PFX from the panel: the input box asks once, its certificates join the table, no extra try.
  s.ui.input.push('test-pass');
  const panel = s.log.panel;
  await panel.send({ type: 'unlock', file: 'tls/leaf-openssl3.pfx' });
  await until(() => panel.posted.filter((m) => m.type === 'scan').length >= 2);
  const m = panel.posted.filter((x) => x.type === 'scan').pop();
  assert.deepEqual(m.locked, []);
  assert.ok(m.entries.some((e) => e.file === 'tls/leaf-openssl3.pfx'));
  assert.equal(s.api.pro.left('scan'), 0);
  // Save CSV and Markdown through the save dialog.
  const csv = path.join(dir, 'report.csv'), md = path.join(dir, 'report.md');
  s.ui.save.push(s.vscode.Uri.file(csv)); await panel.send({ type: 'save', format: 'csv' });
  await until(() => fs.existsSync(csv));
  s.ui.save.push(s.vscode.Uri.file(md)); await panel.send({ type: 'save', format: 'md' });
  await until(() => fs.existsSync(md));
  await tick(20);
  assert.match(fs.readFileSync(csv, 'utf8'), /^days_left,status,expires/);
  assert.match(fs.readFileSync(md, 'utf8'), /^# Certificate expiry report/);
});
test('Pro scan: no folder open gives a note and uses no try', async () => {
  const s = activate();
  assert.equal(await s.api.tools.scanTool(), undefined);
  assert.match(s.log.info[0].text, /Open a folder first/);
  assert.equal(s.api.pro.left('scan'), 1);
});
test('Pro check: chain, key and CSR from Explorer multi-select; host check; Markdown copy; fixed order written', async () => {
  const dir = ws();
  const s = activate(dir);
  const U = (f) => s.vscode.Uri.file(path.join(dir, 'tls', f));
  const rep = await s.api.tools.checkTool(U('chain.pem'), [U('chain.pem'), U('leaf.key'), U('leaf.csr')]);
  assert.equal(rep.counts.error, 0);
  await until(() => s.api.pro.left('check') === 0);
  const panel = s.log.panel;
  await panel.send({ type: 'host', host: 'img.cdn.example.test' });
  const m = await until(() => panel.posted.filter((x) => x.type === 'check').pop().host === 'img.cdn.example.test' && panel.posted.filter((x) => x.type === 'check').pop());
  assert.ok(m.report.findings.some((f) => f.area === 'Host' && f.level === 'ok'));
  await panel.send({ type: 'copyMd' });
  assert.match(s.log.clipboard, /^# Chain and key check/);
  assert.equal(s.api.pro.left('check'), 0);
  // The free try is used: the next check opens the Zovo Pro panel and shows no report.
  assert.equal(await s.api.tools.checkTool(U('chain-wrong-order.pem')), undefined);
  assert.ok(s.log.info.some((m) => /Chain and key check is part of Zovo Pro/.test(m.text) && /You used the free try of Chain and key check/.test(m.opts.detail)));
  // Wrong order (a new computer, so a new free try): "Save in the right order" writes a new bundle next to the file.
  const s2 = activate(dir);
  const wrong = await s2.api.tools.checkTool(U('chain-wrong-order.pem'));
  assert.equal(wrong.orderOk, false);
  await s2.log.panel.send({ type: 'fixOrder' });
  await until(() => fs.existsSync(path.join(dir, 'tls', 'chain-wrong-order-ordered.pem')));
  await tick(30);
  const fixed = openBytes(fs.readFileSync(path.join(dir, 'tls', 'chain-wrong-order-ordered.pem')), 'x.pem');
  assert.deepEqual(fixed.items.map((i) => i.cert.title), ['www.example.test', 'Zovo Test Issuing CA', 'Zovo Test Root CA']);
});
test('Pro check: a PFX asks its password once (input box); a foreign key is a problem', async () => {
  const dir = ws();
  const s = activate(dir);
  s.ui.input.push('test-pass');
  const U = (f) => s.vscode.Uri.file(path.join(dir, 'tls', f));
  const rep = await s.api.tools.checkTool(U('leaf-openssl3.pfx'), [U('leaf-openssl3.pfx'), U('other.key')]);
  assert.ok(rep.findings.some((f) => f.level === 'error' && /other\.key\) does not belong/.test(f.text)));
  assert.ok(rep.findings.some((f) => f.level === 'ok' && /leaf-openssl3\.pfx\) belongs to "www\.example\.test"/.test(f.text)));
  assert.equal(s.ui.input.length, 0);
});
test('Pro convert: PFX to P7B uses the free try; the 2nd use opens the Zovo Pro panel with the tries list and writes nothing', async () => {
  const dir = ws();
  const s = activate(dir);
  const U = (f) => s.vscode.Uri.file(path.join(dir, 'tls', f));
  s.ui.input.push('test-pass');
  s.ui.quick.push((it) => it.find((x) => x.id === 'p7b'));
  const out = await s.api.tools.convertTool(U('leaf-openssl3.pfx'));
  assert.equal(out[0].name, 'tls/leaf-openssl3.p7b');
  assert.equal(out[0].certs, 2);
  await until(() => s.api.pro.left('convert') === 0);
  assert.match(s.log.status.join('\n'), /the free try of "Convert PEM, DER, PFX or P7B" is used/);
  // 2nd use: the Zovo Pro panel, no pick, no file.
  const before = fs.readdirSync(path.join(dir, 'tls')).length;
  s.ui.quick.push((it) => it[0]);
  const r = await s.api.tools.convertTool(U('chain.pem'));
  assert.equal(r, undefined);
  assert.equal(fs.readdirSync(path.join(dir, 'tls')).length, before);
  const panel = s.log.info.find((m) => /Convert PEM, DER, PFX or P7B is part of Zovo Pro/.test(m.text));
  assert.ok(panel, JSON.stringify(s.log.info.map((m) => m.text)));
  assert.match(panel.opts.detail, /You used the free try of Convert PEM, DER, PFX or P7B on this computer/);
  // The other Pro tools with their tries (config.js pro_info), not only their names.
  assert.match(panel.opts.detail, /Other Pro tools in Certificate Viewer, X509 & PEM:\nWorkspace expiry scan: 0 of 1 free try used\nChain and key check: 0 of 1 free try used/);
  assert.equal(s.api.pro.left('scan'), 1);
});
test('Pro convert: PFX to a new PFX (key from the same file), and a chain to PFX with the key from another file; each read back', async () => {
  const dir = ws();
  let s = activate(dir);
  const U = (f) => s.vscode.Uri.file(path.join(dir, 'tls', f));
  s.ui.input.push('test-pass', 'n3w', 'n3w');
  s.ui.quick.push((it) => it.find((x) => x.id === 'pfx'));
  let out = await s.api.tools.convertTool(U('leaf-openssl3.pfx'));
  assert.equal(out[0].name, 'tls/leaf-openssl3.pfx'.replace('.pfx', '-2.pfx'));
  assert.deepEqual([out[0].certs, out[0].keys, out[0].ok], [2, 1, true]);
  assert.equal(openBytes(fs.readFileSync(path.join(dir, 'tls', 'leaf-openssl3-2.pfx')), 'x.pfx', { password: 'n3w' }).items.length, 3);
  s = activate(dir);
  s.ui.quick.push((it) => it.find((x) => x.id === 'pfx'));
  s.ui.open.push([U('leaf.key')]);
  s.ui.input.push('', '');
  out = await s.api.tools.convertTool(U('chain.pem'));
  assert.deepEqual([out[0].name, out[0].certs, out[0].keys], ['tls/chain.pfx', 3, 1]);
});
test('Pro convert: split, merge and DER (each on a fresh free try); Escape uses no try', async () => {
  const dir = ws();
  let s = activate(dir);
  const U = (f) => s.vscode.Uri.file(path.join(dir, 'tls', f));
  s.ui.quick.push(undefined);
  assert.equal(await s.api.tools.convertTool(U('chain.pem')), undefined);
  assert.equal(s.api.pro.left('convert'), 1);
  s.ui.quick.push((it) => it.find((x) => x.id === 'split'));
  let out = await s.api.tools.convertTool(U('chain.pem'));
  await until(() => s.api.pro.left('convert') === 0);
  assert.deepEqual(out.map((o) => o.name), ['tls/chain-certificates/01-www.example.test.pem', 'tls/chain-certificates/02-Zovo-Test-Issuing-CA.pem', 'tls/chain-certificates/03-Zovo-Test-Root-CA.pem']);
  s = activate(dir);
  s.ui.quick.push((it) => it.find((x) => x.id === 'merge'));
  s.ui.open.push([U('expired.pem'), U('chain.p7b')]);
  out = await s.api.tools.convertTool(U('deep/leaf.cer'));
  assert.equal(out[0].name, 'tls/deep/leaf-bundle.pem');
  assert.equal(out[0].certs, 4);
  s = activate(dir);
  s.ui.quick.push((it) => it.find((x) => x.id === 'der'));
  out = await s.api.tools.convertTool(U('chain-wrong-order.pem'));
  assert.deepEqual(out.map((o) => o.name), ['tls/chain-wrong-order-01-www.example.test.cer', 'tls/chain-wrong-order-02-Zovo-Test-Issuing-CA.cer', 'tls/chain-wrong-order-03-Zovo-Test-Root-CA.cer']);
  await until(() => s.api.pro.left('convert') === 0);
  assert.equal(s.api.pro.left('convert'), 0);
});
test('Pro convert: PEM with the key asks first; No writes nothing', async () => {
  const dir = ws();
  const s = activate(dir);
  fs.copyFileSync(path.join(FIX, 'leaf-with-key.pem'), path.join(dir, 'tls', 'both.pem'));
  const U = (f) => s.vscode.Uri.file(path.join(dir, 'tls', f));
  s.ui.quick.push((it) => it.find((x) => x.id === 'pemKey'));
  s.ui.warn.push(undefined);
  assert.equal(await s.api.tools.convertTool(U('both.pem')), undefined);
  assert.ok(!fs.existsSync(path.join(dir, 'tls', 'both-converted.pem')));
  s.ui.quick.push((it) => it.find((x) => x.id === 'pemKey'));
  s.ui.warn.push('Write the key');
  const out = await s.api.tools.convertTool(U('both.pem'));
  assert.deepEqual([out[0].certs, out[0].keys], [1, 1]);
});
test('Pro tools from the viewer toolbar row pass the toolbar surface; the row lists the 3 tools with 1 free try each', async () => {
  const s = activate();
  const html = (await openEditor(s, path.join(FIX, 'chain.pem'))).panel.webview.html;
  for (const t of ['Workspace expiry scan', 'Chain and key check', 'Convert PEM, DER, PFX or P7B']) assert.ok(html.includes(t), t);
  assert.ok((html.match(/1 free try/g) || []).length >= 3);
  assert.doesNotMatch(html, /3 free tries|tries left/);
});

// ---------- README and text ----------
test('README: first screen has the main use, a screenshot of this product, the free list and the price; by Zovo; no rival names', () => {
  const md = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const first = md.split('\n').slice(0, 30).join('\n');
  assert.match(first, /^# Certificate Viewer, X509 & PEM/);
  assert.match(first, /images\/screenshot\.png/);
  assert.match(first, /Zovo Pro: USD 19 once/);
  assert.match(md, /by Zovo/);
  assert.doesNotMatch(md, /jlcs|sandipchitale|wintersteiger|TimHeuer|pfx-view|peek509|\bcertview\b|x509-parser|show-x509/i);
  assert.ok(fs.existsSync(path.join(ROOT, 'images', 'screenshot.png')));
});
test('support links name this listing and related Zovo tools', () => {
  const support = require('../src/support');
  assert.equal(support.SELF_ID, 'zovo.zovo-certificate-viewer');
  assert.ok(support.RELATED.length >= 3 && !support.RELATED.includes(support.SELF_ID));
  assert.equal(support.PRO.getPro, 'certViewer.getPro');
  const products = fs.readdirSync(path.join(ROOT, '..'));
  void products;
});

'use strict';
// The three Zovo Pro tools: Workspace expiry scan, Chain and key check, Convert. Each checks pro.allowed() before it
// does anything and counts a free try with pro.produced() only after its result showed (the scan table or the check
// report drawn in the panel, the converted files written and read back and listed in the panel).
const vscode = require('vscode');
const path = require('path');
const { openBytes } = require('./core/open');
const scan = require('./core/scan');
const { checkSet, checkMarkdown } = require('./core/check');
const conv = require('./core/convert');
const pem = require('./core/pem');
const { panelHtml } = require('./html');
const passwords = require('./passwords');

const PREFIX = 'certViewer';
const setting = (k, d) => vscode.workspace.getConfiguration(PREFIX).get(k, d);
const CERT_FILTER = { 'Certificates and keys': ['pem', 'crt', 'cer', 'der', 'p7b', 'p7c', 'p12', 'pfx', 'csr', 'key'], 'All files': ['*'] };
const base = (u) => path.posix.basename(u.path);
const rel = (u) => { try { return vscode.workspace.asRelativePath(u, false); } catch (e) { return base(u); } };

function createTools({ context, provider, pro, reach }) {
  const panels = {};

  /** One panel per tool, reused. onMsg gets the panel's messages; 'shown' counts the try once per run. */
  function openPanel(kind, title) {
    let p = panels[kind];
    if (p) { try { p.reveal(vscode.ViewColumn.Active); } catch (e) { /* disposed */ } }
    if (!p || p._disposed) {
      const media = vscode.Uri.joinPath(context.extensionUri, 'media');
      p = vscode.window.createWebviewPanel(`certViewer.${kind}`, title, vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [media], enableCommandUris: reach ? reach.commandIds() : [] });
      p.webview.html = panelHtml({
        cspSource: p.webview.cspSource,
        scriptUri: p.webview.asWebviewUri(vscode.Uri.joinPath(media, 'panel.js')).toString(),
        styleUri: p.webview.asWebviewUri(vscode.Uri.joinPath(media, 'panel.css')).toString(),
        title, showSupportLinks: setting('showSupportLinks', true) !== false,
      });
      p.onDidDispose(() => { p._disposed = true; if (panels[kind] === p) delete panels[kind]; });
      p._ready = new Promise((r) => { p._readyResolve = r; });
      p.webview.onDidReceiveMessage((m) => {
        if (!m || typeof m !== 'object') return;
        if (m.type === 'ready') { p._readyResolve(); return; }
        if (m.type === 'shown' && p._pending) { const f = p._pending; p._pending = null; pro.produced(f); }
        if (p._onMsg) Promise.resolve(p._onMsg(m)).catch((e) => vscode.window.showErrorMessage(String((e && e.message) || e)));
      });
      panels[kind] = p;
    }
    p.title = title;
    return p;
  }
  async function show(p, feature, msg, onMsg) {
    if (onMsg) p._onMsg = onMsg;
    if (feature) p._pending = feature;
    await Promise.race([p._ready, new Promise((r) => setTimeout(r, 5000))]);
    await p.webview.postMessage(msg);
  }

  async function readUri(u) { const d = await vscode.workspace.fs.readFile(u); return Buffer.from(d.buffer, d.byteOffset, d.byteLength); }

  /** Opens a file with the session password, asking once when it is locked. null when the user cancelled. */
  async function openFile(u, why) {
    const bytes = await readUri(u);
    const name = base(u);
    let r = openBytes(bytes, name, { password: passwords.get(u) });
    for (let tries = 0; (r.locked || r.lockedKey) && tries < 3; tries++) {
      const pw = await vscode.window.showInputBox({ password: true, ignoreFocusOut: true, title: `Password for ${name}`, prompt: `${why}. ${r.wrongPassword && tries ? 'That password did not open it. ' : ''}The password stays in memory for this session only.`, placeHolder: 'Password' });
      if (pw === undefined) return { r, bytes, cancelled: true };
      const r2 = openBytes(bytes, name, { password: pw });
      if (!r2.wrongPassword && !r2.locked) { passwords.set(u, pw); r = r2; break; }
      r = { ...r, wrongPassword: true };
    }
    return { r, bytes };
  }

  /** The file a tool works on: the clicked file, the active viewer or text editor, or a pick. */
  async function targetUri(uri, title) {
    if (uri && uri.scheme) return uri;
    const d = provider.activeDoc();
    if (d && !d.sourceUri && d.uri.scheme !== 'untitled') return d.uri;
    if (d && d.sourceUri) return d.sourceUri;
    const ed = vscode.window.activeTextEditor;
    if (ed && ed.document.uri.scheme === 'file') return ed.document.uri;
    const picked = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: title, filters: CERT_FILTER });
    return picked && picked[0];
  }

  // ---------- 1. Workspace expiry scan ----------
  async function scanTool(folder) {
    if (!(await pro.allowed('scan'))) return undefined;
    const roots = folder && folder.scheme ? [folder] : (vscode.workspace.workspaceFolders || []).map((f) => f.uri);
    if (!roots.length) { vscode.window.showInformationMessage('Open a folder first: the expiry scan reads the certificates of the workspace.'); return undefined; }
    const result = await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Scanning for certificates' }, () => runScan(roots));
    const p = openPanel('scan', 'Certificate expiry');
    const rootText = roots.map((r) => (folder ? rel(r) : base(r))).join(', ');
    const scanMsg = (res) => ({ type: 'scan', entries: res.entries, locked: res.locked, errors: res.errors, files: res.files, summary: res.summary, root: rootText });
    const post = (res) => show(p, null, scanMsg(res));
    await show(p, 'scan', scanMsg(result), async (m) => {
      if (m.type === 'open' && typeof m.file === 'string') {
        const u = result.uris[m.file];
        if (!u) return;
        if (/\.(pem|crt|cer|der|p7b|p7c|p12|pfx|csr|key)$/i.test(m.file)) await vscode.commands.executeCommand('vscode.openWith', u, 'certViewer.editor');
        else {
          const td = await vscode.workspace.openTextDocument(u);
          const line = Math.max(0, (m.line | 0) - 1);
          const ed = await vscode.window.showTextDocument(td, { preview: false });
          const r = new vscode.Range(line, 0, line, 0); ed.selection = new vscode.Selection(r.start, r.end); ed.revealRange(r, vscode.TextEditorRevealType.InCenter);
        }
      } else if (m.type === 'save' && (m.format === 'csv' || m.format === 'md')) {
        const day = new Date().toISOString().slice(0, 10);
        const def = vscode.Uri.joinPath(roots[0], `certificate-expiry-${day}.${m.format}`);
        const to = await vscode.window.showSaveDialog({ defaultUri: def, filters: m.format === 'csv' ? { CSV: ['csv'] } : { Markdown: ['md'] }, saveLabel: 'Save report' });
        if (!to) return;
        const text = m.format === 'csv' ? scan.toCsv(result.entries) : scan.toMarkdown(result.entries, result.summary);
        await vscode.workspace.fs.writeFile(to, Buffer.from(text, 'utf8'));
        p.webview.postMessage({ type: 'saved', path: rel(to) });
        vscode.window.setStatusBarMessage(`Saved ${rel(to)}`, 5000);
      } else if (m.type === 'unlock' && typeof m.file === 'string' && result.uris[m.file]) {
        const u = result.uris[m.file];
        const { r, cancelled } = await openFile(u, 'Enter the PFX password to add its certificates to the scan');
        if (cancelled || r.locked) return;
        const one = scan.scanFile(m.file, await readUri(u), { password: passwords.get(u) });
        result.entries = scan.finish(result.entries.filter((e) => e.file !== m.file).concat(one.entries));
        result.locked = result.locked.filter((f) => f !== m.file);
        result.summary = scan.summary(result.entries, result.files, result.locked.length);
        await post(result);
      }
    });
    return result;
  }

  async function runScan(roots) {
    const entries = [], locked = [], errors = [];
    const uris = {};
    let files = 0;
    const known = passwords.all();
    for (const root of roots) {
      const found = await vscode.workspace.findFiles(new vscode.RelativePattern(root, scan.INCLUDE), scan.EXCLUDE, 20000);
      for (const u of found) {
        let st;
        try { st = await vscode.workspace.fs.stat(u); } catch (e) { continue; }
        if (st.size > 5 * 1024 * 1024 || st.size === 0) continue;
        files++;
        const name = rel(u);
        uris[name] = u;
        let bytes;
        try { bytes = await readUri(u); } catch (e) { errors.push(`${name}: ${e.message}`); continue; }
        let one = scan.scanFile(name, bytes, { password: passwords.get(u) });
        // Locked PFX: the passwords typed this session, then none.
        for (const pw of known) { if (!one.locked) break; const t = scan.scanFile(name, bytes, { password: pw }); if (!t.locked) { one = t; passwords.set(u, pw); } }
        if (one.locked) locked.push(name);
        if (one.error) errors.push(`${name}: ${one.error}`);
        entries.push(...one.entries);
      }
    }
    scan.finish(entries);
    return { entries, locked, errors, files, uris, summary: scan.summary(entries, files, locked.length) };
  }

  // ---------- 2. Chain and key check ----------
  async function checkTool(uri, uris) {
    if (!(await pro.allowed('check'))) return undefined;
    let list = Array.isArray(uris) && uris.length > 1 ? uris.filter((u) => u && u.scheme) : [];
    if (!list.length) { const u = await targetUri(uri, 'Check'); if (!u) return undefined; list = [u]; }
    const state = { files: [], host: '' };
    const set = { certs: [], keys: [], csrs: [] };
    const add = async (u) => {
      if (state.files.some((f) => f.uri.toString() === u.toString())) return;
      const { r } = await openFile(u, 'Enter the password to read this file for the check');
      const name = rel(u);
      state.files.push({ uri: u, name, format: r.format || 'unreadable', locked: r.locked });
      for (const it of r.items) {
        if (it.kind === 'cert') set.certs.push({ cert: it.cert, file: name });
        else if (it.kind === 'key') set.keys.push({ key: it.key, file: name });
        else if (it.kind === 'csr') set.csrs.push({ csr: it.csr, file: name });
      }
    };
    for (const u of list) await add(u);
    let report = checkSet(set, { host: state.host });
    const p = openPanel('check', 'Chain and key check');
    const msg = () => ({ type: 'check', report, files: state.files.map((f) => ({ name: f.name, format: f.format, locked: f.locked })), host: state.host, canFix: !report.orderOk && set.certs.length > 1 });
    await show(p, 'check', msg(), async (m) => {
      if (m.type === 'add') {
        const more = await vscode.window.showOpenDialog({ canSelectMany: true, openLabel: 'Add to the check', filters: CERT_FILTER });
        if (!more) return;
        for (const u of more) await add(u);
      } else if (m.type === 'host' && typeof m.host === 'string') state.host = m.host.trim().slice(0, 253);
      else if (m.type === 'copyMd') { await vscode.env.clipboard.writeText(checkMarkdown(report)); vscode.window.setStatusBarMessage('Copied the check report as Markdown', 4000); return; }
      else if (m.type === 'fixOrder') {
        const ordered = conv.unique(conv.chainOrder(set.certs.map((c) => c.cert)));
        const src = state.files[0].uri;
        const out = await freeName(vscode.Uri.joinPath(src, '..'), `${stem(src)}-ordered.pem`);
        await vscode.workspace.fs.writeFile(out, Buffer.from(conv.pemBundle(ordered), 'utf8'));
        p.webview.postMessage({ type: 'saved', path: rel(out) });
        return;
      } else return;
      report = checkSet(set, { host: state.host });
      await show(p, null, msg(), p._onMsg);
    });
    return report;
  }

  // ---------- 3. Convert ----------
  const stem = (u) => base(u).replace(/\.[^.]+$/, '');
  async function freeName(dir, name) {
    const ext = path.extname(name), st = name.slice(0, name.length - ext.length);
    for (let i = 0; i < 1000; i++) {
      const u = vscode.Uri.joinPath(dir, i ? `${st}-${i + 1}${ext}` : name);
      try { await vscode.workspace.fs.stat(u); } catch (e) { return u; }
    }
    throw new Error('no free file name');
  }
  async function newPassword(name) {
    const a = await vscode.window.showInputBox({ password: true, ignoreFocusOut: true, title: `Password for ${name}`, prompt: 'The new PFX is encrypted with AES-256 and this password. Leave it empty for no password.', placeHolder: 'New password' });
    if (a === undefined) return undefined;
    const b = await vscode.window.showInputBox({ password: true, ignoreFocusOut: true, title: `Password for ${name}`, prompt: 'Type the same password again.', placeHolder: 'Repeat the password', validateInput: (v) => (v === a ? '' : 'The two passwords differ.') });
    if (b === undefined || b !== a) return undefined;
    return a;
  }

  async function convertTool(uri) {
    if (!(await pro.allowed('convert'))) return undefined;
    const u = await targetUri(uri, 'Convert');
    if (!u) return undefined;
    const { r, cancelled } = await openFile(u, 'Enter the password to read this file for the conversion');
    if (cancelled) return undefined;
    const certs = r.items.filter((i) => i.kind === 'cert').map((i) => i.cert);
    const keys = r.items.filter((i) => i.kind === 'key' && !i.key.encrypted && i.key.der).map((i) => i.key);
    if (!certs.length && !keys.length) { vscode.window.showWarningMessage(`${base(u)} holds no certificate or key to convert.`); return undefined; }
    const n = certs.length;
    const items = [];
    if (n) items.push({ label: 'PEM (.pem)', description: n > 1 ? `${n} certificates in one text file, leaf first` : 'Base64 text with BEGIN/END lines', id: 'pem' });
    if (keys.length && n) items.push({ label: 'PEM with the private key (.pem)', description: 'Certificates, then the key as unencrypted PKCS#8', id: 'pemKey' });
    if (n) items.push({ label: n > 1 ? 'DER (.cer), one file per certificate' : 'DER (.cer)', description: 'Binary', id: 'der' });
    if (n) items.push({ label: 'P7B (.p7b)', description: 'PKCS#7 bundle of the certificates, no key', id: 'p7b' });
    if (n) items.push({ label: 'PFX / P12 (.pfx)', description: keys.length ? 'Certificates and the private key, AES-256' : 'Pick the private key file next', id: 'pfx' });
    if (n > 1) items.push({ label: 'Split into one PEM file per certificate', description: 'Into a new folder next to the file', id: 'split' });
    if (n) items.push({ label: 'Merge with other files into one PEM bundle', description: 'Chain order, repeats removed', id: 'merge' });
    if (!n && keys.length) items.push({ label: 'Private key as PKCS#8 PEM (.pem)', description: 'Unencrypted', id: 'keyPem' });
    const pick = await vscode.window.showQuickPick(items, { title: `Convert ${base(u)} (${r.format}, ${[n ? `${n} certificate${n === 1 ? '' : 's'}` : '', keys.length ? `${keys.length} key${keys.length === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ')})`, placeHolder: 'Convert to', ignoreFocusOut: true });
    if (!pick) return undefined;
    const dir = vscode.Uri.joinPath(u, '..');
    const ordered = conv.unique(conv.chainOrder(certs));
    const outputs = [];
    const write = async (uOut, data, kind, password) => {
      await vscode.workspace.fs.writeFile(uOut, data);
      const back = conv.verifyOutput(data, base(uOut), password);
      outputs.push({ name: rel(uOut), kind, bytes: data.length, certs: back.certs, keys: back.keys, ok: !back.errors.length && !back.locked, uri: uOut.toString() });
    };
    const id = pick.id;
    if (id === 'pem' || id === 'pemKey') {
      if (id === 'pemKey') {
        const ok = await vscode.window.showWarningMessage('The private key will be written without a password. Anyone who can read the file can use the key.', { modal: true }, 'Write the key');
        if (ok !== 'Write the key') return undefined;
      }
      const name = /\.pem$/i.test(base(u)) ? `${stem(u)}-converted.pem` : `${stem(u)}.pem`;
      await write(await freeName(dir, name), Buffer.from(conv.pemBundle(ordered, id === 'pemKey' ? keys.slice(0, 1) : []), 'utf8'), id === 'pemKey' ? 'PEM with key' : 'PEM');
    } else if (id === 'der') {
      if (ordered.length === 1) await write(await freeName(dir, `${stem(u)}.cer`), Buffer.from(ordered[0].der), 'DER');
      else for (const f of conv.split(ordered, 'cer')) await write(await freeName(dir, `${stem(u)}-${f.name}`), f.data, 'DER');
    } else if (id === 'p7b') {
      await write(await freeName(dir, `${stem(u)}.p7b`), conv.p7b(ordered), 'P7B');
    } else if (id === 'pfx') {
      let key = keys.find((k) => k.key && ordered.some((c) => c.key.sha256 === k.key.sha256)) || null;
      if (!key) {
        const picked = await vscode.window.showOpenDialog({ canSelectMany: false, openLabel: 'Use this private key', title: 'Pick the private key of the certificate', filters: { 'Private keys': ['key', 'pem', 'der', 'p8'], 'All files': ['*'] } });
        if (!picked) return undefined;
        const kr = await openFile(picked[0], 'Enter the password of the private key');
        if (kr.cancelled) return undefined;
        key = kr.r.items.filter((i) => i.kind === 'key' && !i.key.encrypted).map((i) => i.key).find((k) => k.key && ordered.some((c) => c.key.sha256 === k.key.sha256)) || null;
        if (!key) { vscode.window.showErrorMessage(`${base(picked[0])} holds no private key that belongs to these certificates. The chain and key check shows which key fits.`); return undefined; }
      }
      const out = await freeName(dir, `${stem(u)}.pfx`);
      const pw = await newPassword(base(out));
      if (pw === undefined) return undefined;
      await write(out, conv.pfx(ordered, key, pw), 'PFX', pw);
    } else if (id === 'split') {
      const folder = await freeName(dir, `${stem(u)}-certificates`);
      await vscode.workspace.fs.createDirectory(folder);
      for (const f of conv.split(ordered, 'pem')) await write(vscode.Uri.joinPath(folder, f.name), f.data, 'PEM');
    } else if (id === 'merge') {
      const more = await vscode.window.showOpenDialog({ canSelectMany: true, openLabel: 'Merge', title: 'Pick the files to merge with this one', filters: CERT_FILTER });
      if (!more) return undefined;
      const all = certs.slice();
      for (const m of more) { const o = await openFile(m, 'Enter the password to read this file'); if (!o.cancelled) all.push(...o.r.items.filter((i) => i.kind === 'cert').map((i) => i.cert)); }
      await write(await freeName(dir, `${stem(u)}-bundle.pem`), Buffer.from(conv.pemBundle(conv.unique(conv.chainOrder(all))), 'utf8'), 'PEM bundle');
    } else if (id === 'keyPem') {
      await write(await freeName(dir, `${stem(u)}-pkcs8.pem`), Buffer.from(pem.toPem('PRIVATE KEY', conv.toPkcs8(keys[0])), 'utf8'), 'PKCS#8 key');
    }
    const p = openPanel('convert', 'Converted certificates');
    await show(p, 'convert', { type: 'convert', source: rel(u), target: pick.label, outputs: outputs.map(({ uri: x, ...o }) => o) }, async (m) => {
      if (m.type === 'open' && typeof m.index === 'number' && outputs[m.index]) await vscode.commands.executeCommand('vscode.openWith', vscode.Uri.parse(outputs[m.index].uri), 'certViewer.editor');
    });
    return outputs;
  }

  return { scanTool, checkTool, convertTool, runScan, panels };
}

module.exports = { createTools };

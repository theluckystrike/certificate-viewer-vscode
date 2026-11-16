'use strict';
// Read-only custom editor for certificate files (.pem .crt .cer .der .p7b .p7c .p12 .pfx .csr .key) and the same view
// for PEM blocks found in any text file (hover > Show). The extension host reads and parses the file (src/core) and
// sends plain card data to the webview; private key numbers and passwords never go to the webview. Nothing leaves the
// computer: the webview has no network access (CSP default-src 'none').
const vscode = require('vscode');
const path = require('path');
const { openBytes } = require('./core/open');
const { describe } = require('./core/describe');
const pem = require('./core/pem');
const { editorHtml } = require('./html');
const passwords = require('./passwords');
const support = require('./support');

const VIEW_TYPE = 'certViewer.editor';
const PREFIX = 'certViewer';
const setting = (k, d) => vscode.workspace.getConfiguration(PREFIX).get(k, d);
const PEM_LABEL = { cert: 'CERTIFICATE', csr: 'CERTIFICATE REQUEST', pubkey: 'PUBLIC KEY' };

/** A file (or a text) opened in the viewer. */
class CertDocument {
  constructor(uri, opts = {}) {
    this.uri = uri; this.text = opts.text; this.sourceUri = opts.sourceUri || null; this.focus = opts.focus;
    this.name = opts.name || path.posix.basename(uri.path);
    this.res = null; this.view = null; this.error = ''; this.panels = new Set(); this.listeners = [];
  }
  async load() {
    this.error = ''; this.res = null; this.view = null;
    try {
      let bytes;
      if (typeof this.text === 'string') bytes = Buffer.from(this.text, 'utf8');
      else {
        const stat = await vscode.workspace.fs.stat(this.uri);
        const max = Math.max(1, Number(setting('maxFileSizeMB', 50)) || 50);
        if (stat.size > max * 1024 * 1024) { this.error = `This file is ${(stat.size / 1048576).toFixed(0)} MB, more than the ${max} MB set in "certViewer.maxFileSizeMB".`; return; }
        const data = await vscode.workspace.fs.readFile(this.uri);
        bytes = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
      }
      this.bytes = bytes;
      this.res = openBytes(bytes, this.name, { password: passwords.get(this.uri) });
      // A remembered password that no longer fits (the file changed): forget it and ask again.
      if (this.res.wrongPassword && passwords.has(this.uri)) { passwords.forget(this.uri); this.res = openBytes(bytes, this.name, {}); }
      this.view = describe(this.res);
      if (typeof this.focus === 'number') {
        const i = this.res.items.findIndex((it) => it.source && typeof it.source.start === 'number' && this.focus >= it.source.start && this.focus <= it.source.end);
        if (i >= 0) this.view.first = i;
      }
    } catch (e) {
      this.error = String((e && e.message) || e);
    }
  }
  /** Tries a password; true when it opened the file (then it is kept in memory for this session). */
  async unlock(pw) {
    if (!this.bytes) return false;
    const r = openBytes(this.bytes, this.name, { password: pw });
    if (r.wrongPassword || r.locked || (r.lockedKey && !r.items.some((i) => i.kind === 'key' && !i.key.encrypted))) return false;
    passwords.set(this.uri, pw);
    this.res = r;
    this.view = describe(r);
    return true;
  }
  /** Copy text for an item: PEM or one-line base64 DER. Private keys are never copied from here. */
  copyText(index, as) {
    const it = this.res && this.res.items[index];
    if (!it || !PEM_LABEL[it.kind]) return '';
    const der = it.kind === 'cert' ? it.cert.der : it.kind === 'csr' ? it.csr.der : it.pub.der;
    return as === 'der' ? Buffer.from(der).toString('base64') : pem.toPem(PEM_LABEL[it.kind], der);
  }
  dispose() { for (const l of this.listeners) l.dispose(); }
}

function message(doc) {
  if (!doc.res) return { type: 'doc', name: doc.name, error: doc.error || 'The file could not be read.', isText: false };
  const r = doc.res;
  return {
    type: 'doc', name: doc.name, format: r.format, isText: r.isText && typeof doc.text !== 'string', fromText: typeof doc.text === 'string',
    locked: r.locked, lockedKey: r.lockedKey, wrongPassword: r.wrongPassword, warnings: r.warnings, errors: r.errors,
    pfx: r.pfx ? { mac: r.pfx.mac ? `${String(r.pfx.mac.hash).toUpperCase().replace('SHA', 'SHA-')}, ${r.pfx.mac.iterations} iterations${r.pfx.mac.ok ? ', verified' : ''}` : 'none', encrypted: r.pfx.encrypted } : null,
    summary: doc.view.summary, cards: doc.view.cards, order: doc.view.order, first: doc.view.first,
    error: r.items.length ? '' : (r.errors[0] || (r.locked ? '' : 'Nothing to show in this file.')),
  };
}

class CertEditorProvider {
  constructor(context, hooks = {}) {
    this.context = context;
    this.hooks = hooks;
    this.docs = new Set();
    this.active = null;
    this._success = new WeakSet();
  }

  async openCustomDocument(uri) {
    const doc = new CertDocument(uri);
    await doc.load();
    this.docs.add(doc);
    if (uri.scheme === 'file') {
      try {
        const w = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(vscode.Uri.joinPath(uri, '..'), path.posix.basename(uri.path)));
        let timer = null;
        const reload = () => { clearTimeout(timer); timer = setTimeout(async () => { await doc.load(); for (const p of doc.panels) this.post(doc, p.webview); }, 250); };
        doc.listeners.push(w, w.onDidChange(reload), w.onDidCreate(reload));
      } catch (e) { /* no watcher: the view still works */ }
    }
    return { uri, dispose: () => { this.docs.delete(doc); doc.dispose(); if (this.active === doc) this.active = null; }, _doc: doc };
  }

  async resolveCustomEditor(handle, panel) { this.bind(handle._doc, panel); }

  /** Opens text (a PEM block's file) in a viewer panel, with the block at `focus` selected. */
  async showText({ text, name, sourceUri, focus }) {
    const uri = vscode.Uri.parse(`untitled:${name} (certificates)`);
    const doc = new CertDocument(uri, { text, name, sourceUri, focus });
    await doc.load();
    const panel = vscode.window.createWebviewPanel('certViewer.peek', `${name} (certificates)`, vscode.ViewColumn.Beside, { enableScripts: true, retainContextWhenHidden: true });
    this.docs.add(doc);
    panel.onDidDispose(() => { this.docs.delete(doc); doc.dispose(); });
    this.bind(doc, panel);
    return { doc, panel };
  }

  bind(doc, panel) {
    doc.panels.add(panel);
    const media = vscode.Uri.joinPath(this.context.extensionUri, 'media');
    const reach = this.hooks.reach ? this.hooks.reach() : null;
    panel.webview.options = {
      enableScripts: true, localResourceRoots: [media],
      enableCommandUris: (reach ? reach.commandIds() : []).concat(support.commandUris(PREFIX)),
    };
    panel.webview.html = editorHtml({
      cspSource: panel.webview.cspSource,
      scriptUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'viewer.js')).toString(),
      styleUri: panel.webview.asWebviewUri(vscode.Uri.joinPath(media, 'viewer.css')).toString(),
      title: doc.name,
      head: reach ? (n) => reach.headHtml(n) : undefined,
      showSupportLinks: setting('showSupportLinks', true) !== false,
    });
    if (reach) reach.attach(panel.webview, panel);
    const setActive = () => { if (panel.active) { this.active = doc; this.activePanel = panel; } };
    setActive();
    panel.onDidChangeViewState(setActive);
    panel.onDidDispose(() => { doc.panels.delete(panel); if (this.activePanel === panel) { this.activePanel = null; if (this.active === doc) this.active = null; } });
    panel.webview.onDidReceiveMessage(async (m) => {
      if (reach && reach.onMessage(m)) return;
      if (!m || typeof m !== 'object') return;
      if (m.type === 'ready') this.post(doc, panel.webview);
      else if (m.type === 'select' && typeof m.index === 'number') doc.selected = m.index;
      else if (m.type === 'password' && typeof m.value === 'string') {
        const ok = await doc.unlock(m.value);
        if (ok) { for (const p of doc.panels) this.post(doc, p.webview); } else this.send(panel.webview, { type: 'pwResult', ok: false });
      } else if (m.type === 'copy') {
        const text = typeof m.text === 'string' ? m.text.slice(0, 20000) : doc.copyText(m.index | 0, m.as);
        if (!text) return;
        await vscode.env.clipboard.writeText(text);
        vscode.window.setStatusBarMessage(m.as === 'der' ? 'Copied the certificate as DER base64' : m.as === 'pem' ? 'Copied the certificate as PEM' : 'Copied', 3000);
      } else if (m.type === 'openText') {
        if (doc.sourceUri) await this.reveal(doc, m.index);
        else await vscode.commands.executeCommand('vscode.openWith', doc.uri, 'default');
      } else if (m.type === 'reveal') await this.reveal(doc, m.index | 0);
      else if (m.type === 'shown') { if (!this._success.has(doc)) { this._success.add(doc); if (this.hooks.onSuccess) this.hooks.onSuccess(doc); } }
      else if (m.type === 'failed') { if (this.hooks.onFailure) this.hooks.onFailure(doc); }
    });
  }

  /** Opens the text of the file (or of the hover source) with the item's block selected. */
  async reveal(doc, index) {
    const it = doc.res && doc.res.items[index];
    const target = doc.sourceUri || doc.uri;
    const td = await vscode.workspace.openTextDocument(target);
    const s = it && it.source && typeof it.source.start === 'number' ? it.source : null;
    const ed = await vscode.window.showTextDocument(td, { preview: false, viewColumn: doc.sourceUri ? vscode.ViewColumn.One : undefined });
    if (s && ed) {
      const range = new vscode.Range(td.positionAt(s.start), td.positionAt(s.end));
      ed.selection = new vscode.Selection(range.start, range.end);
      ed.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
    }
  }

  send(webview, msg) { try { const r = webview.postMessage(msg); if (r && r.then) r.then(undefined, () => false); } catch (e) { /* disposed */ } }

  post(doc, webview) {
    const msg = message(doc);
    msg.showPro = setting('showProTools', true) !== false;
    this.send(webview, msg);
    if (!doc.res || (!doc.res.items.length && !doc.res.locked)) { if (this.hooks.onFailure) this.hooks.onFailure(doc); }
  }

  /** The document of the active viewer tab, if any. */
  activeDoc() { return this.active; }
}

module.exports = { CertEditorProvider, CertDocument, VIEW_TYPE, message };

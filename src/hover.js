'use strict';
// Hover on a PEM block in any file (YAML, JSON, .env, Terraform, source code...): plain PEM, PEM with \n escapes in a
// JSON string, base64 of a PEM (Kubernetes secrets) and bare base64 DER certificates. Shows the common name, issuer,
// expiry with days left and the names, with links to open the block in the viewer and to copy it. Parsing is local.
const vscode = require('vscode');
const path = require('path');
const pem = require('./core/pem');
const { fromDer } = require('./core/open');
const X = require('./core/x509');

const PREFIX = 'certViewer';
const md = (s) => String(s).replace(/[\\`*_{}[\]()#+\-.!|<>]/g, '\\$&');

/** Markdown lines for one block, or '' when it holds nothing to show. */
function hoverText(block, now = Date.now()) {
  if (!block.der) return '';
  const ctx = { warnings: [], errors: [], headers: block.headers, source: {} };
  const items = fromDer(block.der, block.guess ? 'CERTIFICATE' : block.type, {}, ctx);
  const lines = [];
  for (const it of items.slice(0, 4)) {
    if (it.kind === 'cert') {
      const c = it.cert;
      const icon = c.status === 'expired' ? '$(error)' : c.status === 'soon' || c.status === 'not-yet' ? '$(warning)' : '$(pass)';
      lines.push(`${icon} **${md(c.title)}** (${md(c.role)})  `);
      lines.push(`Issuer: ${md(c.issuer.short)}  `);
      lines.push(`Valid to: ${c.notAfter.toISOString().slice(0, 10)}, **${md(X.statusText(c, now))}**  `);
      const names = c.san.filter((g) => g.type === 'DNS' || g.type === 'IP').map((g) => g.value);
      if (names.length) lines.push(`Names: ${md(names.slice(0, 6).join(', '))}${names.length > 6 ? ` and ${names.length - 6} more` : ''}  `);
      lines.push(`Key: ${md(c.key.label)}, SHA-256 ${c.sha256.slice(0, 23)}...`);
    } else if (it.kind === 'csr') {
      lines.push(`$(file-text) **Certificate request** for ${md(it.csr.title)}  `, `Key: ${md(it.csr.key.label)}`);
    } else if (it.kind === 'key') {
      lines.push(`$(key) **${md(it.key.title)}** (the key itself is not shown)`);
    } else if (it.kind === 'pubkey') {
      lines.push(`$(key) **${md(it.pub.title)}**`);
    } else if (it.kind === 'error') {
      lines.push(`$(error) ${md(it.title)}: ${md(it.error)}`);
    } else lines.push(md(it.title));
    lines.push('');
  }
  if (items.length > 4) lines.push(`and ${items.length - 4} more`);
  return lines.join('\n');
}

function createHover({ context }) {
  const provider = {
    provideHover(document, position) {
      if (vscode.workspace.getConfiguration(PREFIX).get('hover', true) === false) return undefined;
      const text = document.getText();
      if (text.length > 20 * 1024 * 1024) return undefined;
      if (text.indexOf('-----BEGIN') < 0 && text.indexOf(pem.BEGIN_B64) < 0 && text.indexOf('MII') < 0) return undefined;
      const at = document.offsetAt(position);
      const all = pem.blocksAt(text, at);
      const b = all[0];
      if (!b) return undefined;
      const body = all.slice(0, 4).map((x) => hoverText(x)).filter(Boolean).join('\n---\n') + (all.length > 4 ? `\n\nand ${all.length - 4} more` : '');
      if (!body) return undefined;
      const args = encodeURIComponent(JSON.stringify([document.uri.toString(), b.start]));
      const where = b.encoding === 'base64-pem' ? `base64 PEM${all.length > 1 ? ` with ${all.length} blocks` : ''}` : b.encoding === 'json' ? 'PEM in a string' : b.encoding === 'base64-der' ? 'base64 DER' : 'PEM';
      const ms = new vscode.MarkdownString(`${body}\n[Open in Certificate Viewer](command:${PREFIX}.showPemAt?${args}) · ${where}`, true);
      ms.isTrusted = { enabledCommands: [`${PREFIX}.showPemAt`] };
      ms.supportThemeIcons = true;
      return new vscode.Hover(ms, new vscode.Range(document.positionAt(b.start), document.positionAt(b.end)));
    },
  };
  const d = vscode.languages.registerHoverProvider([{ scheme: 'file' }, { scheme: 'untitled' }, { scheme: 'vscode-remote' }], provider);
  context.subscriptions.push(d);
  return provider;
}

/** certViewer.showPemAt(uri string, offset): opens every block of that text file in the viewer, the hovered one first. */
async function showPemAt(provider, uriStr, offset) {
  let doc;
  if (typeof uriStr === 'string') doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(uriStr));
  else if (uriStr && uriStr.scheme) doc = await vscode.workspace.openTextDocument(uriStr);
  else if (vscode.window.activeTextEditor) { doc = vscode.window.activeTextEditor.document; offset = doc.offsetAt(vscode.window.activeTextEditor.selection.active); }
  if (!doc) { vscode.window.showInformationMessage('Open a file with a PEM block first.'); return undefined; }
  return provider.showText({ text: doc.getText(), name: path.posix.basename(doc.uri.path), sourceUri: doc.uri, focus: typeof offset === 'number' ? offset : undefined });
}

module.exports = { createHover, hoverText, showPemAt };

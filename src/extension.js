'use strict';
// Certificate Viewer, X509 & PEM by Zovo: opens .pem, .crt, .cer, .der, .p7b, .p7c, .p12, .pfx, .csr and .key files as
// a readable card, and shows a hover on PEM blocks in any file. No network, no telemetry. Activation shows nothing:
// no message, no popup. The viewer opens only for files the user opens.
const vscode = require('vscode');
const { CertEditorProvider, VIEW_TYPE } = require('./editor');
const { createHover, showPemAt } = require('./hover');
const { createTools } = require('./tools');
const { createPro } = require('./pro');
const { createRatingPrompt } = require('./rate');
const support = require('./support');
const { createReach } = require('./reach');
const reachConfig = require('./reach-config');
const passwords = require('./passwords');

const PREFIX = 'certViewer';
const EXT_ID = 'zovo.zovo-certificate-viewer';
const setting = (k, d) => vscode.workspace.getConfiguration(PREFIX).get(k, d);

function activate(context) {
  const sub = (d) => context.subscriptions.push(d);
  let rating = { success() {}, failure() {} };
  try { rating = createRatingPrompt({ vscode, context, extensionId: EXT_ID, section: PREFIX, name: 'Certificate Viewer' }); } catch (e) { /* rating is optional */ }
  support.registerSupport({ vscode, context, prefix: PREFIX, selfId: EXT_ID });
  const pro = createPro({ vscode, context });
  const reach = createReach({ vscode, ...reachConfig, context, licensed: () => !!pro.licensed, shown: () => setting('showProTools', true) !== false });
  reach.registerCtx();
  sub(pro.onDidChange(() => reach.refresh()));

  const provider = new CertEditorProvider(context, {
    reach: () => reach,
    onSuccess: (doc) => rating.success(doc.sourceUri || doc.uri),
    onFailure: () => rating.failure(),
  });
  sub(vscode.window.registerCustomEditorProvider(VIEW_TYPE, provider, { webviewOptions: { retainContextWhenHidden: true }, supportsMultipleEditorsPerDocument: true }));
  const hover = createHover({ context });
  const tools = createTools({ context, provider, pro, reach });

  const reg = (id, fn) => sub(vscode.commands.registerCommand(id, async (...a) => {
    try { return await fn(...a); } catch (e) { vscode.window.showErrorMessage(String((e && e.message) || e)); return undefined; }
  }));
  const target = (uri) => (uri && uri.scheme ? uri : undefined);
  reg(`${PREFIX}.openWithViewer`, (uri) => {
    const u = uri && uri.scheme ? uri : (vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.uri);
    if (!u) { vscode.window.showInformationMessage('Select a certificate, key or bundle file first.'); return undefined; }
    // YAML, JSON and .env files: show the PEM blocks they hold. Certificate files: the viewer.
    if (/\.(ya?ml|json|env)$/i.test(u.path) || /(^|\/)\.env[^/]*$/.test(u.path)) return showPemAt(provider, u.toString(), undefined);
    return vscode.commands.executeCommand('vscode.openWith', u, VIEW_TYPE);
  });
  reg(`${PREFIX}.openSample`, () => vscode.commands.executeCommand('vscode.openWith', vscode.Uri.joinPath(context.extensionUri, 'samples', 'sample-chain.crt'), VIEW_TYPE));
  reg(`${PREFIX}.openSampleYaml`, async () => {
    const d = await vscode.workspace.openTextDocument(vscode.Uri.joinPath(context.extensionUri, 'samples', 'sample-tls-secret.yaml'));
    return vscode.window.showTextDocument(d, { preview: false });
  });
  reg(`${PREFIX}.showPemAt`, (u, offset) => showPemAt(provider, u, offset));
  reg(`${PREFIX}.openWalkthrough`, () => vscode.commands.executeCommand('workbench.action.openWalkthrough', `${EXT_ID}#${PREFIX}.start`, false));
  reg(`${PREFIX}.scan`, reach.wrap((uri) => tools.scanTool(target(uri))));
  reg(`${PREFIX}.check`, reach.wrap((uri, uris) => tools.checkTool(target(uri), uris)));
  reg(`${PREFIX}.convert`, reach.wrap((uri) => tools.convertTool(target(uri))));
  sub(vscode.workspace.onDidChangeConfiguration((e) => { if (e.affectsConfiguration(`${PREFIX}.showProTools`)) reach.refresh(); }));
  sub(vscode.window.registerUriHandler({ handleUri: (uri) => pro.handleUri(uri) }));
  sub({ dispose: () => passwords.clear() });
  return { provider, tools, pro, hover };
}

function deactivate() { passwords.clear(); }

module.exports = { activate, deactivate };

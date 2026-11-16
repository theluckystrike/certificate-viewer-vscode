'use strict';
// Webview HTML for the certificate viewer and the Pro tool panels. No vscode import, so tests can check the CSP:
// no remote origin, no connect-src, scripts only with the page nonce, no images but our own.
const crypto = require('crypto');
const { footerHtml, FOOTER_CSS } = require('./support');

const PREFIX = 'certViewer';
const attr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function csp(cspSource, n) {
  return ["default-src 'none'", `style-src ${cspSource} 'nonce-${n}'`, `script-src 'nonce-${n}'`, `img-src ${cspSource} data:`, `font-src ${cspSource}`].join('; ');
}

/** p: { cspSource, scriptUri, styleUri, title, showSupportLinks, head?(nonce) } */
function editorHtml(p) {
  const n = p.nonce || crypto.randomBytes(18).toString('base64url');
  const footer = footerHtml(PREFIX, p.showSupportLinks !== false, '');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp(p.cspSource, n)}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${attr(p.styleUri)}">
${footer ? `<style nonce="${n}">${FOOTER_CSS}</style>` : ''}
${typeof p.head === 'function' ? p.head(n) : ''}
<title>${attr(p.title)}</title>
</head>
<body>
<div id="toolbar" role="toolbar" aria-label="Certificate viewer">
  <span id="fmt" class="chip" title="File format and contents"></span>
  <button class="tb" id="copyPem" title="Copy the selected certificate as PEM" hidden>Copy PEM</button>
  <button class="tb" id="copyDer" title="Copy the selected certificate as DER in base64 (one line)" hidden>Copy DER base64</button>
  <button class="tb" id="openText" title="Open this file in the text editor" hidden>Open as Text</button>
</div>
<div id="err" role="alert" hidden></div>
<div id="warn" hidden></div>
<form id="pwForm" hidden autocomplete="off">
  <label for="pw" id="pwLabel">This file is protected by a password.</label>
  <input type="password" id="pw" aria-label="Password" autocomplete="off" spellcheck="false">
  <button type="submit" class="tb primary" id="pwGo">Open</button>
  <span id="pwMsg" class="muted"></span>
  <div class="muted small">The password stays in memory for this session only. It is not saved and not sent anywhere.</div>
</form>
<div id="main">
  <nav id="list" aria-label="Certificates in this file"></nav>
  <section id="card" aria-label="Certificate details" tabindex="0"></section>
</div>
<div id="footer"></div>
<template id="zovo-footer">${footer}</template>
<script nonce="${n}" src="${attr(p.scriptUri)}"></script>
</body>
</html>`;
}

/** Panel of a Pro tool. p: { cspSource, scriptUri, styleUri, title, head?(nonce), showSupportLinks } */
function panelHtml(p) {
  const n = p.nonce || crypto.randomBytes(18).toString('base64url');
  const footer = footerHtml(PREFIX, p.showSupportLinks !== false, '');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp(p.cspSource, n)}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${attr(p.styleUri)}">
${footer ? `<style nonce="${n}">${FOOTER_CSS}</style>` : ''}
${typeof p.head === 'function' ? p.head(n) : ''}
<title>${attr(p.title)}</title>
</head>
<body>
<div id="toolbar" role="toolbar"><strong id="title"></strong><span id="actions"></span></div>
<div id="app"><p class="muted">Working...</p></div>
<div id="footer">${footer}</div>
<script nonce="${n}" src="${attr(p.scriptUri)}"></script>
</body>
</html>`;
}

module.exports = { editorHtml, panelHtml, csp };

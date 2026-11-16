// Zovo Pro tool panel: the expiry table, the chain and key check report and the list of converted files. Loads
// nothing; every action is a message to the extension. "shown" goes back once a result with content is on screen.
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined && text !== null) e.textContent = text; return e; };
  const btn = (label, fn, cls) => { const b = el('button', `tb ${cls || ''}`, label); b.type = 'button'; b.addEventListener('click', fn); return b; };
  const app = $('app');
  const actions = $('actions');
  let last = null;

  function shown(ok) { if (ok) vscode.postMessage({ type: 'shown' }); }
  function note(text) { const n = $('saved') || el('div', 'saved'); n.id = 'saved'; n.textContent = text; if (!n.parentNode) app.insertBefore(n, app.firstChild); }

  // ---------- expiry scan ----------
  let filter = 'all', query = '';
  function scanView(m) {
    $('title').textContent = `Certificate expiry: ${m.root}`;
    actions.textContent = '';
    actions.append(btn('Save CSV', () => vscode.postMessage({ type: 'save', format: 'csv' })), btn('Save Markdown', () => vscode.postMessage({ type: 'save', format: 'md' })));
    app.textContent = '';
    const s = m.summary;
    app.appendChild(el('p', 'summary', `${s.total} certificate${s.total === 1 ? '' : 's'} (${s.unique} different) in ${s.files} file${s.files === 1 ? '' : 's'} scanned. ${s.expired} expired, ${s.d30} expire within 30 days, ${s.d90} within 90 days.`));
    const bar = el('div', 'bar');
    const sel = el('select'); sel.id = 'show'; sel.setAttribute('aria-label', 'Show');
    for (const [v, t] of [['all', 'All certificates'], ['expired', 'Expired'], ['30', 'Expired or within 30 days'], ['90', 'Expired or within 90 days']]) { const o = el('option', null, t); o.value = v; if (v === filter) o.selected = true; sel.appendChild(o); }
    const q = el('input'); q.id = 'q'; q.type = 'search'; q.placeholder = 'Filter by name, issuer or file'; q.value = query;
    bar.append(sel, q);
    app.appendChild(bar);
    const table = el('table', 'grid'); table.id = 'rows';
    const head = el('tr');
    for (const h of ['Days left', 'Expires', 'Common name', 'Issuer', 'File', 'Found as']) head.appendChild(el('th', null, h));
    const thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
    const tbody = el('tbody'); table.appendChild(tbody);
    const fill = () => {
      tbody.textContent = '';
      const ql = query.toLowerCase();
      const rows = m.entries.filter((e) => (filter === 'all' || (filter === 'expired' ? e.status === 'expired' : e.daysLeft < Number(filter))) && (!ql || `${e.title} ${e.issuer} ${e.file} ${e.subject} ${e.san.join(' ')}`.toLowerCase().includes(ql)));
      for (const e of rows) {
        const tr = el('tr', e.status === 'expired' ? 'bad' : e.daysLeft < 30 ? 'soon' : e.daysLeft < 90 ? 'later' : '');
        tr.title = `${e.subject}\nSHA-256 ${e.sha256}${e.copies > 1 ? `\nFound ${e.copies} times in the workspace` : ''}`;
        tr.append(el('td', 'num', String(e.daysLeft)), el('td', null, e.notAfter.slice(0, 10)), el('td', 'name', e.title + (e.copies > 1 ? ` (x${e.copies})` : '')), el('td', null, e.issuer));
        const f = el('td', 'file'); const a = el('a', null, `${e.file}${e.line ? `:${e.line}` : ''}`); a.href = '#'; a.addEventListener('click', (ev) => { ev.preventDefault(); vscode.postMessage({ type: 'open', file: e.file, line: e.line }); }); f.appendChild(a);
        tr.append(f, el('td', 'muted', e.where));
        tbody.appendChild(tr);
      }
      $('count').textContent = rows.length === m.entries.length ? '' : `Showing ${rows.length} of ${m.entries.length}.`;
    };
    app.appendChild(table);
    app.appendChild(el('p', 'muted', '')).id = 'count';
    sel.addEventListener('change', () => { filter = sel.value; fill(); });
    q.addEventListener('input', () => { query = q.value; fill(); });
    fill();
    if (!m.entries.length) app.appendChild(el('p', 'muted', 'No certificates were found in this folder. The scan reads certificate files and PEM blocks in YAML, JSON, .env, config and source files; node_modules, .git and build folders are skipped.'));
    if (m.locked.length) {
      const box = el('div', 'locked');
      box.appendChild(el('p', null, `${m.locked.length} password-protected PFX file${m.locked.length === 1 ? ' was' : 's were'} skipped:`));
      for (const f of m.locked) { const r = el('div', 'lockrow'); r.append(el('span', null, f), btn('Unlock', () => vscode.postMessage({ type: 'unlock', file: f }))); box.appendChild(r); }
      app.appendChild(box);
    }
    if (m.errors.length) { const d = el('details', 'errs'); d.appendChild(el('summary', null, `${m.errors.length} file${m.errors.length === 1 ? '' : 's'} could not be read`)); for (const x of m.errors) d.appendChild(el('div', 'muted', x)); app.appendChild(d); }
    shown(m.entries.length > 0);
  }

  // ---------- chain and key check ----------
  const LEVEL = { ok: ['OK', 'lv-ok'], info: ['Note', 'lv-info'], warn: ['Warning', 'lv-warn'], error: ['Problem', 'lv-error'] };
  const LINK = { verified: 'signed by the next one, signature verified', fails: 'signature does NOT verify with the next one', unchecked: 'signature not checked', 'self-signed': 'self-signed root', 'public-root': 'issued by a public root (not in the file)', missing: 'issuer missing' };
  function checkView(m) {
    const r = m.report;
    $('title').textContent = 'Chain and key check';
    actions.textContent = '';
    actions.append(btn('Add files...', () => vscode.postMessage({ type: 'add' })), btn('Copy as Markdown', () => vscode.postMessage({ type: 'copyMd' })));
    if (m.canFix) actions.append(btn('Save in the right order', () => vscode.postMessage({ type: 'fixOrder' }), 'primary'));
    app.textContent = '';
    const c = r.counts;
    app.appendChild(el('p', `summary ${c.error ? 'lv-error' : c.warn ? 'lv-warn' : 'lv-ok'}`, `${c.error} problem${c.error === 1 ? '' : 's'}, ${c.warn} warning${c.warn === 1 ? '' : 's'}, ${c.ok} passed.`));
    const files = el('p', 'muted', `Files: ${m.files.map((f) => `${f.name} (${f.locked ? 'locked' : f.format})`).join(', ')}`);
    app.appendChild(files);
    const hb = el('form', 'bar'); hb.id = 'hostForm';
    const hi = el('input'); hi.id = 'host'; hi.placeholder = 'Host name to match, for example www.example.com'; hi.value = m.host || '';
    hb.append(hi, btn('Check host', () => hb.requestSubmit()));
    hb.addEventListener('submit', (e) => { e.preventDefault(); vscode.postMessage({ type: 'host', host: hi.value }); });
    hi.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); vscode.postMessage({ type: 'host', host: hi.value }); } });
    app.appendChild(hb);
    if (r.chain.length) {
      app.appendChild(el('h3', null, 'Chain'));
      const ol = el('ol', 'chain'); ol.id = 'chain';
      for (const x of r.chain) {
        const li = el('li', `link-${x.link}`);
        li.append(el('strong', null, x.title), el('span', 'muted', ` ${x.role}, ${x.statusText}${x.file ? `, ${x.file}` : ''}`), el('div', 'linktext', LINK[x.link] || x.link));
        ol.appendChild(li);
      }
      app.appendChild(ol);
    }
    app.appendChild(el('h3', null, 'Findings'));
    const t = el('table', 'grid'); t.id = 'findings';
    const hr = el('tr'); for (const h of ['Result', 'Area', 'Finding']) hr.appendChild(el('th', null, h));
    const th = el('thead'); th.appendChild(hr); t.appendChild(th);
    const tb = el('tbody');
    for (const f of r.findings) { const tr = el('tr', `row-${f.level}`); tr.append(el('td', LEVEL[f.level][1], LEVEL[f.level][0]), el('td', null, f.area), el('td', null, f.text)); tb.appendChild(tr); }
    t.appendChild(tb);
    app.appendChild(t);
    shown(m.files.some((f) => !f.locked) && r.findings.length > 0);
  }

  // ---------- convert ----------
  function convertView(m) {
    $('title').textContent = `Converted ${m.source}`;
    actions.textContent = '';
    app.textContent = '';
    app.appendChild(el('p', 'summary', `To ${m.target}: ${m.outputs.length} file${m.outputs.length === 1 ? '' : 's'} written next to the source. Each file was read back to check it.`));
    const t = el('table', 'grid'); t.id = 'outputs';
    const hr = el('tr'); for (const h of ['File', 'Format', 'Size', 'Read back', '']) hr.appendChild(el('th', null, h));
    const th = el('thead'); th.appendChild(hr); t.appendChild(th);
    const tb = el('tbody');
    m.outputs.forEach((o, i) => {
      const tr = el('tr', o.ok ? '' : 'bad');
      const what = [o.certs ? `${o.certs} certificate${o.certs === 1 ? '' : 's'}` : '', o.keys ? `${o.keys} private key${o.keys === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ') || 'nothing';
      tr.append(el('td', 'file', o.name), el('td', null, o.kind), el('td', 'num', `${o.bytes.toLocaleString('en-US')} bytes`), el('td', o.ok ? 'lv-ok' : 'lv-error', o.ok ? `OK: ${what}` : 'Could not be read back'));
      const td = el('td'); td.appendChild(btn('Open', () => vscode.postMessage({ type: 'open', index: i }))); tr.appendChild(td);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    app.appendChild(t);
    if (m.outputs.some((o) => o.keys)) app.appendChild(el('p', 'note', 'A file with a private key was written. Keep it out of version control.'));
    shown(m.outputs.some((o) => o.ok));
  }

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (!m || typeof m !== 'object') return;
    if (m.type === 'scan') { last = m; scanView(m); }
    else if (m.type === 'check') { last = m; checkView(m); }
    else if (m.type === 'convert') { last = m; convertView(m); }
    else if (m.type === 'saved') note(`Saved ${m.path}`);
  });
  void last;
  vscode.postMessage({ type: 'ready' });
})();

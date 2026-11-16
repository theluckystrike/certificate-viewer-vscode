// Certificate viewer webview: draws the chain list and the card the extension host sends. No network: this page
// loads nothing and sends messages only to the extension (copy, password, open as text, reveal).
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  let doc = null;
  let current = -1;
  let shownSent = false;

  const tpl = $('zovo-footer');
  if (tpl && tpl.innerHTML.trim()) $('footer').innerHTML = tpl.innerHTML;

  const STATUS_CLASS = { ok: 'st-ok', soon: 'st-soon', expired: 'st-bad', 'not-yet': 'st-soon', key: 'st-key', locked: 'st-soon', other: 'st-key' };

  function rowList(card) {
    const li = el('button', 'item');
    li.type = 'button';
    li.dataset.index = String(card.index);
    li.setAttribute('role', 'treeitem');
    const t = el('span', 'item-title', card.title || '(no name)');
    const sub = el('span', 'item-sub', card.role || '');
    const st = el('span', `pill ${STATUS_CLASS[card.status] || ''}`, card.kind === 'cert' ? (card.status === 'expired' ? 'Expired' : card.status === 'not-yet' ? 'Not yet valid' : `${card.daysLeft} d`) : (card.kind === 'key' ? 'Key' : card.kind === 'csr' ? 'CSR' : card.kind === 'pubkey' ? 'Public' : card.kind === 'error' ? 'Error' : ''));
    li.append(t, st, sub);
    li.addEventListener('click', () => select(card.index));
    return li;
  }

  function drawList() {
    const list = $('list');
    list.textContent = '';
    if (!doc || !doc.cards || doc.cards.length < 2) { list.hidden = true; return; }
    list.hidden = false;
    list.setAttribute('role', 'tree');
    const h = el('div', 'list-head', doc.order.some((o) => o.depth > 0) ? 'Chain' : 'In this file');
    list.appendChild(h);
    for (const o of doc.order) {
      const card = doc.cards[o.index];
      const r = rowList(card);
      r.style.paddingLeft = `${8 + o.depth * 16}px`;
      if (o.depth > 0) r.classList.add('child');
      list.appendChild(r);
    }
  }

  function copyBtn(text) {
    const b = el('button', 'copy', 'Copy');
    b.type = 'button';
    b.title = 'Copy this value';
    b.addEventListener('click', (e) => { e.stopPropagation(); vscode.postMessage({ type: 'copy', as: 'value', text }); b.textContent = 'Copied'; setTimeout(() => { b.textContent = 'Copy'; }, 1200); });
    return b;
  }

  function drawCard() {
    const box = $('card');
    box.textContent = '';
    const card = doc && doc.cards && doc.cards[current];
    if (!card) return;
    for (const b of document.querySelectorAll('#list .item')) b.classList.toggle('sel', Number(b.dataset.index) === current);
    const head = el('div', 'card-head');
    const title = el('h1', 'card-title', card.title || '(no name)');
    const meta = el('div', 'card-meta');
    meta.append(el('span', 'role', card.role || ''), el('span', `pill big ${STATUS_CLASS[card.status] || ''}`, card.statusText || ''));
    head.append(title, meta);
    if (card.subtitle) head.appendChild(el('div', 'muted sub', card.subtitle));
    box.appendChild(head);
    for (const n of card.notes || []) box.appendChild(el('div', 'note', n));
    for (const s of card.sections) {
      const sec = el('section', 'sec');
      const h = el('h2', null, s.title);
      sec.appendChild(h);
      const t = el('table', 'kv');
      for (const row of s.rows) {
        const [k, v, o] = row;
        const tr = el('tr', o && o.ext ? 'ext' : '');
        const th = el('th', null, k);
        const td = el('td', o && o.mono ? 'mono' : '');
        const lines = String(v).split('\n');
        lines.forEach((line, i) => { if (i) td.appendChild(el('br')); td.appendChild(document.createTextNode(line)); });
        if (o && o.status) td.className = STATUS_CLASS[o.status] || '';
        if (o && o.copy) td.appendChild(copyBtn(String(v)));
        tr.append(th, td);
        t.appendChild(tr);
      }
      sec.appendChild(t);
      box.appendChild(sec);
    }
    const src = card.source || {};
    if (doc.fromText || (doc.isText && typeof src.start === 'number')) {
      const a = el('button', 'tb link', doc.fromText ? 'Show this block in the file' : 'Show this block in the text');
      a.type = 'button';
      a.addEventListener('click', () => vscode.postMessage({ type: 'reveal', index: current }));
      box.appendChild(a);
    }
    $('copyPem').hidden = !card.copy;
    $('copyDer').hidden = !card.copy || card.kind === 'pubkey';
  }

  function select(i) {
    if (!doc || !doc.cards[i]) return;
    current = i;
    vscode.setState({ current, name: doc.name });
    vscode.postMessage({ type: 'select', index: i });
    drawCard();
  }

  function draw() {
    const err = $('err');
    const warn = $('warn');
    const form = $('pwForm');
    $('fmt').textContent = doc.error && !doc.cards ? doc.name : `${doc.format || ''}${doc.summary ? `: ${doc.summary}` : ''}`;
    $('openText').hidden = !(doc.isText || doc.fromText);
    $('openText').textContent = doc.fromText ? 'Show in File' : 'Open as Text';
    form.hidden = !(doc.locked || doc.lockedKey);
    if (!form.hidden) {
      $('pwLabel').textContent = doc.locked ? `${doc.name} is protected by a password.` : 'The private key in this file is encrypted.';
      $('pwMsg').textContent = doc.wrongPassword ? 'That password did not open it.' : '';
      setTimeout(() => $('pw').focus(), 50);
    }
    err.hidden = !doc.error;
    err.textContent = doc.error || '';
    const w = [];
    if (doc.pfx && !doc.locked) {
      if (doc.pfx.encrypted && doc.pfx.encrypted.length) w.push(...doc.pfx.encrypted.map((x) => `Encryption: ${x}`));
      w.push(`Integrity check (MAC): ${doc.pfx.mac}`);
    }
    w.push(...(doc.warnings || []));
    if (doc.errors && doc.cards && doc.cards.length) w.push(...doc.errors);
    warn.hidden = !w.length;
    warn.textContent = '';
    for (const x of w) warn.appendChild(el('div', null, x));
    drawList();
    const st = vscode.getState();
    current = st && doc.cards && doc.cards[st.current] && st.name === doc.name ? st.current : (doc.cards && doc.cards.length ? doc.first : -1);
    vscode.setState({ current, name: doc.name });
    drawCard();
    if (doc.cards && doc.cards.length && doc.cards.some((c) => c.kind !== 'error') && !shownSent) { shownSent = true; vscode.postMessage({ type: 'shown' }); }
    else if ((!doc.cards || !doc.cards.length) && !doc.locked && doc.error) vscode.postMessage({ type: 'failed' });
  }

  $('copyPem').addEventListener('click', () => vscode.postMessage({ type: 'copy', index: current, as: 'pem' }));
  $('copyDer').addEventListener('click', () => vscode.postMessage({ type: 'copy', index: current, as: 'der' }));
  $('openText').addEventListener('click', () => vscode.postMessage({ type: 'openText', index: current }));
  const sendPassword = () => {
    const v = $('pw').value;
    $('pwMsg').textContent = 'Opening...';
    vscode.postMessage({ type: 'password', value: v });
    $('pw').value = '';
  };
  $('pwForm').addEventListener('submit', (e) => { e.preventDefault(); sendPassword(); });
  // Enter in the field sends at once (some input methods never fire the form's implicit submit).
  $('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); sendPassword(); } });
  document.addEventListener('keydown', (e) => {
    if (!doc || !doc.order || document.activeElement === $('pw')) return;
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const pos = doc.order.findIndex((o) => o.index === current);
    const next = doc.order[pos + (e.key === 'ArrowDown' ? 1 : -1)];
    if (next) { e.preventDefault(); select(next.index); const b = document.querySelector(`#list .item[data-index="${next.index}"]`); if (b) b.focus(); }
  });
  window.addEventListener('message', (e) => {
    const m = e.data;
    if (!m || typeof m !== 'object') return;
    if (m.type === 'doc') { doc = m; draw(); }
    else if (m.type === 'pwResult' && !m.ok) { $('pwMsg').textContent = 'That password did not open it.'; $('pw').focus(); }
  });
  vscode.postMessage({ type: 'ready' });
})();

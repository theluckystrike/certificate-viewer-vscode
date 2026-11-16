'use strict';
// HOLDFIX (0.1.1): the publish job could not make the public source repo (its safety check refuses .pem files and
// private key blocks), so the README screenshot link answered 404. The repo now holds no fixtures and no .pem file.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

test('the shipped sample is sample-chain.crt, opened by the Open sample command, with no private key', () => {
  assert.ok(fs.existsSync(path.join(ROOT, 'samples', 'sample-chain.crt')));
  assert.ok(!fs.existsSync(path.join(ROOT, 'samples', 'sample-chain.pem')));
  assert.match(fs.readFileSync(path.join(ROOT, 'src', 'extension.js'), 'utf8'), /'samples', 'sample-chain\.crt'/);
  assert.match(fs.readFileSync(path.join(ROOT, 'scripts', 'make-samples.sh'), 'utf8'), /> \$S\/sample-chain\.crt/);
  for (const f of fs.readdirSync(path.join(ROOT, 'samples'))) {
    assert.doesNotMatch(f, /\.pem$/, f);
    assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'samples', f), 'utf8'), /PRIVATE KEY/, f);
  }
});

test('test fixtures are ignored by git and made by scripts/make-fixtures.sh when missing', () => {
  assert.match(fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8'), /^test\/fixtures\/$/m);
  const t = fs.readFileSync(path.join(ROOT, 'scripts', 'test.js'), 'utf8');
  assert.match(t, /make-fixtures\.sh/);
  assert.ok(fs.existsSync(path.join(ROOT, 'test', 'fixtures', 'leaf.pem')), 'fixtures present for this run');
});

test('0.1.1 is a packaging patch on 0.1.0', () => {
  assert.strictEqual(pkg.version, '0.1.1');
  assert.match(fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8'), /^# Changelog\n\n## 0\.1\.1\n\n- The sample chain behind "Open sample" is now sample-chain\.crt/);
  // the screenshot link the Marketplace page uses must point at a file in the repo
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const imgs = [...readme.matchAll(/!\[[^\]]*\]\((\S+?)\)/g)].map((m) => m[1]);
  for (const u of imgs) {
    const m = u.match(/^(?:https:\/\/github\.com\/theluckystrike\/certificate-viewer-vscode\/raw\/HEAD\/)?(images\/[^?#)]+)$/);
    if (m) assert.ok(fs.existsSync(path.join(ROOT, m[1])), m[1]);
  }
});

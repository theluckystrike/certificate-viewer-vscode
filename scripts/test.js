'use strict';
// npm test: runs every test/*.test.js with the Node test runner.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'test');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.test.js')).map((f) => path.join(dir, f));
// The test keys and certificates are not in the repository (a public repo holds no private keys, even throwaway ones).
// The first run makes them with scripts/make-fixtures.sh (needs zsh, OpenSSL 3 from Homebrew and the system LibreSSL).
const fix = path.join(dir, 'fixtures');
if (!fs.existsSync(path.join(fix, 'leaf.pem'))) {
  console.log('test/fixtures missing: running scripts/make-fixtures.sh');
  const m = spawnSync('zsh', [path.join(__dirname, 'make-fixtures.sh'), fix], { stdio: 'inherit' });
  if (m.status !== 0) process.exit(m.status === null ? 1 : m.status);
}
const env = { ...process.env, ZOVO_SPONSORS_MODULE: path.join(__dirname, '..', 'src', 'license', 'sponsors.js') };
const r = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', env });
process.exit(r.status === null ? 1 : r.status);

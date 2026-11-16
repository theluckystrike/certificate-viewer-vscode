'use strict';
// PFX/P12 and encrypted key passwords for this window session: a Map in memory, keyed by the file's URI. Never
// written to disk, to settings, to SecretStorage or to a log; gone when the window closes or the extension stops.
const store = new Map();

module.exports = {
  get: (uri) => store.get(String(uri)),
  has: (uri) => store.has(String(uri)),
  set: (uri, pw) => { if (typeof pw === 'string') store.set(String(uri), pw); },
  forget: (uri) => store.delete(String(uri)),
  /** Every password typed this session (the expiry scan tries them on locked PFX files of the workspace). */
  all: () => [...new Set(store.values())],
  clear: () => store.clear(),
};

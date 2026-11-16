'use strict';
// REACH1: this listing's Pro tools for the viewer toolbar row and the Explorer entries (src/reach.js).
module.exports = {
  prefix: 'certViewer',
  triesKey: 'certViewer.proTrial',
  slot: '#toolbar',
  tools: [
    { id: 'scan', title: 'Workspace expiry scan', command: 'certViewer.scan', folder: false },
    { id: 'check', title: 'Chain and key check', command: 'certViewer.check' },
    { id: 'convert', title: 'Convert PEM, DER, PFX or P7B', command: 'certViewer.convert' },
  ],
};

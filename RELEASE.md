# Certificate Viewer, X509 & PEM 0.1.0 (zovo.zovo-certificate-viewer)

Staged by lane NEWB11 on 15 Nov 2026. This is a new listing and is not published. A verifier that did not build it still has to record a PASS for this sha256 in VER-verdict.tsv.

- Vsix: `zovo.zovo-certificate-viewer-0.1.0.vsix`, 284,293 bytes, 48 files.
- sha256: `bcbe31863011ef0f8c69a7b08a2b6acee3411b148fc14d55def10c8f760f4a10`
- Source: factory/products/certificate-viewer-vscode, local git commit (no remote, nothing pushed).
- Listing: display name "Certificate Viewer, X509 & PEM" (30 characters), description starts with "Certificate viewer", keywords certificate viewer, x509, pem, ssl certificate, pfx; engines ^1.75.0; MIT; repository github.com/theluckystrike/certificate-viewer-vscode (not created yet).

## What it is

A read-only custom editor for .pem, .crt, .cer, .der, .p7b, .p7c, .p12, .pfx, .csr and .key files, plus a hover on PEM blocks in any text file. All parsing is our own code in `src/core`:

- a DER reader and writer;
- X.509, CSR and key parsing;
- PKCS#7 reading and writing;
- PKCS#12 reading (PBES2, and the legacy PKCS#12 schemes with 3DES, RC2 and RC4) and writing (PBES2 AES-256, HMAC-SHA256 MAC);
- an RC2 cipher (RFC 2268 test vectors pass).

Hashes, signatures and AES come from the editor's runtime `crypto`. There is no third-party code and no network code. The webviews use CSP `default-src 'none'` and nonce scripts.

Free core: a card per certificate with subject, issuer, validity and days left, SANs, key type and size, key usage and EKU, SHA-1 and SHA-256 fingerprints, serial, signature check and every extension. Bundles show a chain tree. PFX and P12 files and encrypted keys ask for the password in the page. The password is kept in memory for the window session only and is never logged or stored. Key cards show the type, the size, the public key fingerprint and the matching certificate; the private numbers are never sent to the webview. There are Copy PEM, Copy DER base64 and Open as Text buttons. The hover covers PEM, PEM in JSON strings, base64 PEM (Kubernetes secrets) and bare base64 DER (JWK x5c), and links to a viewer panel with every block of the file.

Zovo Pro tools, 3 free tries each, counted only after the result showed:

1. Workspace expiry scan: a table sorted by days left, with CSV and Markdown reports and an Unlock button for PFX files that need a password.
2. Chain and key check: signatures, order, a missing intermediate (its AIA link is shown, not fetched), dates, CA flags, path length, key and CSR match, a host name check, Add files, Copy as Markdown and Save in the right order.
3. Convert PEM, DER, PFX or P7B: in any direction, split and merge. Each output file is read back.

Modules: license 2026-11-14.offer (apply.sh with factory/sprint/license/proinfo/cert.json, tries key certViewer.proTrial), rating 2.3, and the support block (support.js copied from the HEIC listing with this listing's id; related: Hex Viewer, Dotenv, JSON Tree Viewer). The URI handler is registered and `onUri` is in activationEvents. `onStartupFinished` is also there, so the hover works in any file. Activation shows nothing.

## Samples used

| Sample | Source | License |
|---|---|---|
| samples/sample-chain.crt, samples/sample-tls-secret.yaml (shipped) | made by scripts/make-samples.sh with OpenSSL 3.5.9; no private key shipped | ours (MIT) |
| test/fixtures/* (not shipped): chains, DER, P7B, PFX from OpenSSL 3 default, OpenSSL -legacy, LibreSSL 3.3.6 and no-password, CSRs, keys in PKCS#8, PKCS#1, SEC1, encrypted PKCS#8, Ed25519, RSA-PSS, expired, broken files, a Kubernetes secret, JSON and .env | made by scripts/make-fixtures.sh; throwaway test keys only | ours (MIT) |
| macOS system roots (158), as PEM and as a P7B written by `security export` | /System/Library/Keychains/SystemRootCertificates.keychain, read offline | public CA certificates |
| /etc/ssl/cert.pem (128) | macOS | public CA certificates |
| certifi cacert.pem (188) | certifi 2026.10.19 (Homebrew Python 3.13) | MPL-2.0 (gate only, not shipped) |
| VS Code code signing chain (Developer ID Application: Microsoft Corporation, Developer ID CA, Apple Root CA), DER and PEM | `codesign --extract-certificates` on the installed VS Code app | public certificates |
| PKCS#12 keystore | written by OpenJDK keytool 26 with a test key | ours |

No certificate was fetched from a website, and no file was downloaded.

## Tests

- Unit tests: 252 of 252 pass with `node scripts/test.js` (Node 22). The core and extension tests (53) also pass under VS Code's own Electron runtime (`ELECTRON_RUN_AS_NODE`, Node 24 with BoringSSL).
- Values are checked against openssl: fingerprints, serials, end dates and subjects. PFX and P7B files written by us are read back by OpenSSL 3 and LibreSSL. All 158 macOS roots parse.
- Real-app gate, VS Code 1.142.0, port 9412, through buildslot, with the vsix installed (not a dev folder). Run r6 on this sha256 gave 78 PASS and 0 FAIL: out/NEWB11-data/cert/cert-gate-r6.json. A repeat run, r7, gave 77 PASS and 0 FAIL (it took no screenshot). The gate checks:
  - our samples, every format and a wrong then a right password;
  - that the private exponent never appears in the page;
  - three broken files with a clear message each;
  - all the real files above, with counts from openssl;
  - the hover in YAML and JSON, and its link;
  - all 3 Pro tools, with their files checked by openssl;
  - the tries countdown and the 4th-use Pro panel with the tries list;
  - the Zovo Pro info tab;
  - no toast, network request, socket, CSP or console error, and no URL opened.

## Known limits

- CRLs and OpenSSH keys are named, not shown. Keys with legacy PEM encryption (Proc-Type) show the cipher only.
- The signature of a signed PKCS#7 message is not checked; its certificates are shown.
- PKCS#12 files with the new PBMAC1 integrity check, or with parts encrypted to a public key, are not read.
- The public-root note in the chain check uses the runtime's bundled root list (Mozilla, about 120 roots). Apple Root CA is not in it, so a chain ending there is called "not in the public root list".
- The CSR and self-signed generator from the NICHE5 row was not built (3 of the 4 Pro tools).
- The README screenshot comes from gate r4 on an earlier build of the same day. The main view did not change after that build; only pro.js (the Pro panel tries list) and the hover changed.
- The README image needs the GitHub repo to exist (raw/HEAD/images/screenshot.png) before publishing.

# Changelog

## 0.1.1

- The sample chain behind "Open sample" is now sample-chain.crt (same three certificates, still no private key).
- The source repository no longer holds the test keys and certificates. `npm test` makes them with scripts/make-fixtures.sh (OpenSSL 3 and LibreSSL) the first time it runs.
- Nothing else changed: same viewer, same Pro tools and the same free features.

## 0.1.0

- First release. Opens .pem, .crt, .cer, .der, .p7b, .p7c, .pfx, .p12, .csr and .key files as a readable card, offline.
- Card: subject, issuer, dates with days left, alternative names, key type and size, key usage, fingerprints, serial and every extension.
- Bundles show the chain as a tree with each signature checked. PFX and P12 files ask for the password once and keep it in memory only.
- Private keys show their type, size and the certificate they belong to, never the key numbers.
- Hover on PEM blocks in any file, also base64 PEM in Kubernetes secrets. Copy as PEM or DER base64.
- Zovo Pro tools: Workspace expiry scan; Chain and key check; Convert PEM, DER, PFX or P7B (1 free try each).

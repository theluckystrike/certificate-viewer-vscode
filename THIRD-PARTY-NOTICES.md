# Third-party notices

## Code

No third-party code is included. The DER reader and writer, the X.509, PKCS#7 and PKCS#12 code and the RC2 cipher in `src/core` are written for this extension (MIT, see LICENSE). Hashes, signatures, AES, 3DES and PBKDF2 come from the `crypto` module of the editor's own runtime.

## Public root list

The chain check compares the top of a chain with the root certificates that ship with the editor's runtime (`tls.rootCertificates`). The list is not copied into this package.

## Sample certificates

`samples/sample-chain.pem` and `samples/sample-tls-secret.yaml` hold certificates made for this extension with OpenSSL by `scripts/make-samples.sh` (in the source repository). The names use the reserved `example.test` domain. No private key is included.

#!/bin/zsh
# Makes the test fixtures in test/fixtures with OpenSSL 3 (Homebrew) and LibreSSL (/usr/bin/openssl).
# Every private key here is a throwaway test key made by this script. Passwords: "test-pass".
# usage: scripts/make-fixtures.sh [out dir]   (default test/fixtures)
set -eu
O=${OPENSSL3:-/opt/homebrew/opt/openssl@3/bin/openssl}
L=/usr/bin/openssl
here=${0:A:h}
D=${1:-$here/../test/fixtures}
mkdir -p $D; cd $D
setopt null_glob; rm -f *.pem *.crt *.cer *.der *.key *.csr *.p7b *.p12 *.pfx *.yaml *.json *.env *.srl *.cnf; unsetopt null_glob
P=test-pass

cat > ca.cnf <<'EOF'
[root]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[inter]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = caIssuers;URI:http://pki.example.test/root.crt
crlDistributionPoints = URI:http://pki.example.test/root.crl
certificatePolicies = 2.23.140.1.2.1
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:www.example.test, DNS:example.test, DNS:*.cdn.example.test, IP:192.0.2.10, IP:2001:db8::10, email:ops@example.test, URI:https://www.example.test/
authorityInfoAccess = caIssuers;URI:http://pki.example.test/issuing.crt, OCSP;URI:http://ocsp.example.test
crlDistributionPoints = URI:http://pki.example.test/issuing.crl
certificatePolicies = 2.23.140.1.2.1
[ecleaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:api.example.test
authorityKeyIdentifier = keyid:always
[self]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, codeSigning
subjectAltName = DNS:device-7.example.test
[req]
distinguished_name = dn
req_extensions = reqext
prompt = no
[dn]
C = DE
O = Example Test GmbH
CN = www.example.test
[reqext]
subjectAltName = DNS:www.example.test, DNS:example.test, IP:192.0.2.10
EOF

# Root CA (RSA 3072), issuing CA (EC P-384), leaf (RSA 2048) and a short-lived EC P-256 leaf.
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root.key 2>/dev/null
$O req -x509 -new -key root.key -sha256 -days 3650 -subj "/C=DE/O=Zovo Test/CN=Zovo Test Root CA" -extensions root -config ca.cnf -out root.pem
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out inter.key
$O req -new -key inter.key -subj "/C=DE/O=Zovo Test/CN=Zovo Test Issuing CA" -out inter.csr
$O x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -sha384 -days 1825 -extfile ca.cnf -extensions inter -out inter.pem 2>/dev/null
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf.key 2>/dev/null
$O req -new -key leaf.key -config ca.cnf -out leaf.csr
$O x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key -CAcreateserial -sha256 -days 398 -extfile ca.cnf -extensions leaf -out leaf.pem 2>/dev/null
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out api.key
$O req -new -key api.key -subj "/O=Example Test GmbH/CN=api.example.test" -out api.csr
$O x509 -req -in api.csr -CA inter.pem -CAkey inter.key -CAcreateserial -sha256 -days 20 -extfile ca.cnf -extensions ecleaf -out api.pem 2>/dev/null
# Expired (2020 to 2021), Ed25519 and RSA-PSS self-signed.
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out old.key 2>/dev/null
$O req -x509 -new -key old.key -sha256 -subj "/O=Example Test GmbH/CN=old.example.test" -not_before 20200101000000Z -not_after 20210101000000Z -extensions self -config ca.cnf -out expired.pem
$O genpkey -algorithm ED25519 -out ed25519.key
$O req -x509 -new -key ed25519.key -subj "/O=Example Test GmbH/CN=device-7.example.test" -days 730 -extensions self -config ca.cnf -out ed25519.pem
$O genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out pss.key 2>/dev/null
$O req -x509 -new -key pss.key -subj "/CN=pss.example.test" -days 365 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sha256 -extensions self -config ca.cnf -out pss.pem
$O req -new -key ed25519.key -subj "/CN=device-7.example.test" -out ed25519.csr
# A key that matches nothing here.
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out other.key 2>/dev/null

# Key formats.
$O rsa -in leaf.key -traditional -out leaf-pkcs1.key 2>/dev/null
$O ec -in api.key -out api-sec1.key 2>/dev/null
$O pkcs8 -topk8 -in leaf.key -v2 aes-256-cbc -passout pass:$P -out leaf-encrypted.key
$O pkey -in leaf.key -outform DER -out leaf-key.der

# Certificate formats and bundles.
$O x509 -in leaf.pem -outform DER -out leaf.der
cp leaf.der leaf.cer
cp root.pem root.crt
cat leaf.pem inter.pem root.pem > chain.pem
cat root.pem leaf.pem inter.pem > chain-wrong-order.pem
cat leaf.pem root.pem > chain-missing-inter.pem
cat leaf.pem inter.pem > fullchain.pem
cat leaf.pem leaf.key > leaf-with-key.pem
$O crl2pkcs7 -nocrl -certfile chain.pem -outform DER -out chain.p7b
$O crl2pkcs7 -nocrl -certfile chain.pem -out chain-pem.p7b

# PKCS#12 / PFX: OpenSSL 3 default (AES-256, PBKDF2, HMAC-SHA256), OpenSSL 3 -legacy (RC2-40 and 3DES, SHA-1),
# LibreSSL default, no password, and a PFX without encryption.
$O pkcs12 -export -in leaf.pem -inkey leaf.key -certfile fullchain.pem -name "www.example.test" -passout pass:$P -out leaf-openssl3.pfx
$O pkcs12 -export -legacy -in leaf.pem -inkey leaf.key -certfile fullchain.pem -name "www.example.test" -passout pass:$P -out leaf-legacy.p12
$L pkcs12 -export -in leaf.pem -inkey leaf.key -certfile chain.pem -name "www.example.test" -passout pass:$P -out leaf-libressl.p12
$O pkcs12 -export -in api.pem -inkey api.key -certfile inter.pem -passout pass: -out api-nopass.pfx
$O pkcs12 -export -in leaf.pem -inkey leaf.key -keypbe NONE -certpbe NONE -passout pass:$P -out leaf-plain.p12

# PEM inside other files: a Kubernetes TLS secret (base64 of the PEM), JSON with \n escapes, a .env value.
b64() { base64 < $1 | tr -d '\n'; }
cat > k8s-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: www-tls
type: kubernetes.io/tls
data:
  tls.crt: $(b64 fullchain.pem)
  tls.key: $(b64 leaf.key)
EOF
node -e 'const fs=require("fs");process.stdout.write(JSON.stringify({ name: "api", tls: { cert: fs.readFileSync("api.pem","utf8"), ca: fs.readFileSync("inter.pem","utf8") } }, null, 2)+"\n")' > config.json
{ echo "APP_NAME=demo"; printf 'TLS_CERT="'; cat expired.pem | tr -d '\r'; echo '"'; echo "PORT=8443"; } > app.env

# Broken inputs.
head -c 600 leaf.pem > broken.pem
printf 'this is not a certificate\n' > garbage.crt
head -c 300 leaf.der > truncated.der

rm -f *.srl inter.csr ca.cnf api.csr
ls -1 | wc -l | xargs echo "fixtures:"

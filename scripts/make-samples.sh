#!/bin/zsh
# Makes the shipped samples in samples/: a 3-certificate chain (PEM text in a .crt file) and a Kubernetes YAML with a base64 TLS
# certificate and a CA PEM block. No private key is shipped: the keys are made in a temp folder and deleted.
# usage: scripts/make-samples.sh
set -eu
O=${OPENSSL3:-/opt/homebrew/opt/openssl@3/bin/openssl}
here=${0:A:h}
S=$here/../samples
T=$(mktemp -d)
trap 'rm -rf $T' EXIT
mkdir -p $S
cd $T
cat > x.cnf <<'EOF'
[root]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[inter]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = caIssuers;URI:http://pki.example.test/sample-root.crt
crlDistributionPoints = URI:http://pki.example.test/sample-root.crl
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:shop.example.test, DNS:www.shop.example.test, DNS:api.shop.example.test, IP:192.0.2.44
authorityInfoAccess = caIssuers;URI:http://pki.example.test/sample-issuing.crt, OCSP;URI:http://ocsp.example.test
crlDistributionPoints = URI:http://pki.example.test/sample-issuing.crl
certificatePolicies = 2.23.140.1.2.2
[soon]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:payments.example.test
authorityKeyIdentifier = keyid:always
EOF
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root.key 2>/dev/null
$O req -x509 -new -key root.key -sha256 -days 3650 -subj "/C=US/O=Example Sample Trust/CN=Example Sample Root CA" -extensions root -config x.cnf -out root.pem
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out inter.key
$O req -new -key inter.key -subj "/C=US/O=Example Sample Trust/CN=Example Sample TLS Issuing CA" -out inter.csr
$O x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -sha384 -days 1825 -extfile x.cnf -extensions inter -out inter.pem 2>/dev/null
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
$O req -new -key leaf.key -subj "/C=US/ST=Oregon/L=Portland/O=Example Shop Inc./CN=shop.example.test" -out leaf.csr
$O x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key -CAcreateserial -sha256 -days 397 -extfile x.cnf -extensions leaf -out leaf.pem 2>/dev/null
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out soon.key
$O req -new -key soon.key -subj "/O=Example Shop Inc./CN=payments.example.test" -out soon.csr
$O x509 -req -in soon.csr -CA inter.pem -CAkey inter.key -CAcreateserial -sha256 -days 21 -extfile x.cnf -extensions soon -out soon.pem 2>/dev/null
cat leaf.pem inter.pem root.pem > $S/sample-chain.crt
b64() { base64 < $1 | tr -d '\n'; }
cat > $S/sample-tls-secret.yaml <<EOF
# Sample Kubernetes objects for the Certificate Viewer hover. Rest the pointer on a certificate below.
# The certificates were made for this sample; no private key is included.
apiVersion: v1
kind: Secret
metadata:
  name: payments-tls
  namespace: shop
type: Opaque
data:
  # base64 of a PEM certificate, as kubectl writes it
  tls.crt: $(b64 soon.pem)
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: shop-ca
  namespace: shop
data:
  ca.crt: |
$(sed 's/^/    /' inter.pem)
EOF
echo "samples written: $(ls $S)"

'use strict';
// Names of the object identifiers a certificate viewer meets. Unknown ones show as their dotted number.

const DN = {
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.9': 'street',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.12': 'title', '2.5.4.13': 'description', '2.5.4.15': 'businessCategory', '2.5.4.17': 'postalCode',
  '2.5.4.42': 'GN', '2.5.4.43': 'initials', '2.5.4.44': 'generationQualifier', '2.5.4.46': 'dnQualifier', '2.5.4.65': 'pseudonym', '2.5.4.97': 'organizationIdentifier',
  '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST', '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
};

const SIG = {
  '1.2.840.113549.1.1.5': { name: 'SHA-1 with RSA', hash: 'sha1', key: 'rsa' },
  '1.2.840.113549.1.1.4': { name: 'MD5 with RSA', hash: 'md5', key: 'rsa' },
  '1.2.840.113549.1.1.11': { name: 'SHA-256 with RSA', hash: 'sha256', key: 'rsa' },
  '1.2.840.113549.1.1.12': { name: 'SHA-384 with RSA', hash: 'sha384', key: 'rsa' },
  '1.2.840.113549.1.1.13': { name: 'SHA-512 with RSA', hash: 'sha512', key: 'rsa' },
  '1.2.840.113549.1.1.14': { name: 'SHA-224 with RSA', hash: 'sha224', key: 'rsa' },
  '1.2.840.113549.1.1.10': { name: 'RSA-PSS', hash: '', key: 'rsa-pss' },
  '1.2.840.10045.4.1': { name: 'ECDSA with SHA-1', hash: 'sha1', key: 'ec' },
  '1.2.840.10045.4.3.1': { name: 'ECDSA with SHA-224', hash: 'sha224', key: 'ec' },
  '1.2.840.10045.4.3.2': { name: 'ECDSA with SHA-256', hash: 'sha256', key: 'ec' },
  '1.2.840.10045.4.3.3': { name: 'ECDSA with SHA-384', hash: 'sha384', key: 'ec' },
  '1.2.840.10045.4.3.4': { name: 'ECDSA with SHA-512', hash: 'sha512', key: 'ec' },
  '1.3.101.112': { name: 'Ed25519', hash: null, key: 'ed25519' },
  '1.3.101.113': { name: 'Ed448', hash: null, key: 'ed448' },
  '1.2.840.10040.4.3': { name: 'DSA with SHA-1', hash: 'sha1', key: 'dsa' },
  '2.16.840.1.101.3.4.3.2': { name: 'DSA with SHA-256', hash: 'sha256', key: 'dsa' },
};

const KEY = {
  '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.10': 'RSA-PSS', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  '1.3.101.110': 'X25519', '1.3.101.111': 'X448', '1.2.840.10040.4.1': 'DSA', '1.2.840.113549.1.3.1': 'DH',
};

const CURVE = {
  '1.2.840.10045.3.1.7': { name: 'P-256', bits: 256 }, '1.3.132.0.34': { name: 'P-384', bits: 384 }, '1.3.132.0.35': { name: 'P-521', bits: 521 },
  '1.3.132.0.10': { name: 'secp256k1', bits: 256 }, '1.2.840.10045.3.1.1': { name: 'P-192', bits: 192 }, '1.3.132.0.33': { name: 'P-224', bits: 224 },
  '1.3.36.3.3.2.8.1.1.7': { name: 'brainpoolP256r1', bits: 256 }, '1.3.36.3.3.2.8.1.1.11': { name: 'brainpoolP384r1', bits: 384 }, '1.3.36.3.3.2.8.1.1.13': { name: 'brainpoolP512r1', bits: 512 },
};

const HASH = {
  '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512', '2.16.840.1.101.3.4.2.4': 'sha224', '1.2.840.113549.2.5': 'md5',
};

const EXT = {
  '2.5.29.14': 'Subject Key Identifier', '2.5.29.15': 'Key Usage', '2.5.29.17': 'Subject Alternative Name', '2.5.29.18': 'Issuer Alternative Name',
  '2.5.29.19': 'Basic Constraints', '2.5.29.30': 'Name Constraints', '2.5.29.31': 'CRL Distribution Points', '2.5.29.32': 'Certificate Policies',
  '2.5.29.33': 'Policy Mappings', '2.5.29.35': 'Authority Key Identifier', '2.5.29.36': 'Policy Constraints', '2.5.29.37': 'Extended Key Usage',
  '2.5.29.46': 'Freshest CRL', '2.5.29.54': 'Inhibit Any Policy', '2.5.29.9': 'Subject Directory Attributes',
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access', '1.3.6.1.5.5.7.1.11': 'Subject Information Access', '1.3.6.1.5.5.7.1.3': 'Qualified Certificate Statements',
  '1.3.6.1.5.5.7.1.24': 'TLS Feature (OCSP Must-Staple)', '1.3.6.1.4.1.11129.2.4.2': 'Signed Certificate Timestamps', '1.3.6.1.4.1.11129.2.4.3': 'Precertificate Poison',
  '2.16.840.1.113730.1.1': 'Netscape Cert Type', '2.16.840.1.113730.1.13': 'Netscape Comment', '1.3.6.1.4.1.311.20.2': 'Certificate Template Name (Microsoft)',
  '1.3.6.1.4.1.311.21.7': 'Certificate Template (Microsoft)', '1.3.6.1.4.1.311.21.10': 'Application Policies (Microsoft)', '1.3.6.1.4.1.311.21.1': 'CA Version (Microsoft)',
  '1.3.6.1.5.5.7.48.1.5': 'OCSP No Check', '2.5.29.16': 'Private Key Usage Period', '1.2.840.113533.7.65.0': 'Entrust Version Info', '2.23.42.7.0': 'SET Hashed Root Key', '1.3.6.1.5.5.7.1.12': 'Logotype',
  '1.2.840.113635.100.6.1.33': 'Apple Developer ID Date', '1.2.840.113635.100.6.1.18': 'Apple Developer ID Kernel Extension', '1.2.840.113635.100.6.1.13': 'Apple Developer ID Application', '1.2.840.113635.100.6.2.6': 'Apple Developer ID CA',
};

const EKU = {
  '1.3.6.1.5.5.7.3.1': 'TLS server', '1.3.6.1.5.5.7.3.2': 'TLS client', '1.3.6.1.5.5.7.3.3': 'Code signing', '1.3.6.1.5.5.7.3.4': 'Email protection',
  '1.3.6.1.5.5.7.3.8': 'Time stamping', '1.3.6.1.5.5.7.3.9': 'OCSP signing', '1.3.6.1.5.5.7.3.5': 'IPsec end system', '1.3.6.1.5.5.7.3.6': 'IPsec tunnel',
  '1.3.6.1.5.5.7.3.7': 'IPsec user', '1.3.6.1.5.5.7.3.17': 'IPsec IKE', '2.5.29.37.0': 'Any', '1.3.6.1.4.1.311.10.3.4': 'Encrypting File System (Microsoft)',
  '1.3.6.1.4.1.311.20.2.2': 'Smart card logon (Microsoft)', '1.3.6.1.4.1.311.10.3.12': 'Document signing (Microsoft)', '1.3.6.1.5.2.3.5': 'Kerberos KDC',
  '1.3.6.1.4.1.11129.2.4.4': 'Certificate Transparency', '1.2.840.113635.100.4.13': 'Apple package signing',
};

const POLICY = {
  '2.23.140.1.2.1': 'Domain validated (CA/B Forum)', '2.23.140.1.2.2': 'Organization validated (CA/B Forum)', '2.23.140.1.2.3': 'Individual validated (CA/B Forum)',
  '2.23.140.1.1': 'Extended validation (CA/B Forum)', '2.5.29.32.0': 'Any policy', '2.23.140.1.3': 'EV code signing (CA/B Forum)', '2.23.140.1.4.1': 'Code signing (CA/B Forum)',
};

const AIA = { '1.3.6.1.5.5.7.48.1': 'OCSP', '1.3.6.1.5.5.7.48.2': 'CA issuers', '1.3.6.1.5.5.7.48.3': 'Time stamping', '1.3.6.1.5.5.7.48.5': 'CA repository' };

const KU = ['Digital signature', 'Non-repudiation', 'Key encipherment', 'Data encipherment', 'Key agreement', 'Certificate signing', 'CRL signing', 'Encipher only', 'Decipher only'];

const PKCS = {
  data: '1.2.840.113549.1.7.1', signedData: '1.2.840.113549.1.7.2', envelopedData: '1.2.840.113549.1.7.3', encryptedData: '1.2.840.113549.1.7.6',
  keyBag: '1.2.840.113549.1.12.10.1.1', shroudedKeyBag: '1.2.840.113549.1.12.10.1.2', certBag: '1.2.840.113549.1.12.10.1.3', crlBag: '1.2.840.113549.1.12.10.1.4',
  secretBag: '1.2.840.113549.1.12.10.1.5', safeContentsBag: '1.2.840.113549.1.12.10.1.6', x509Certificate: '1.2.840.113549.1.9.22.1',
  friendlyName: '1.2.840.113549.1.9.20', localKeyId: '1.2.840.113549.1.9.21', extensionRequest: '1.2.840.113549.1.9.14', challengePassword: '1.2.840.113549.1.9.7',
  pbes2: '1.2.840.113549.1.5.13', pbkdf2: '1.2.840.113549.1.5.12',
  pbeSha1Rc4_128: '1.2.840.113549.1.12.1.1', pbeSha1Rc4_40: '1.2.840.113549.1.12.1.2', pbeSha13Des: '1.2.840.113549.1.12.1.3', pbeSha12Des: '1.2.840.113549.1.12.1.4',
  pbeSha1Rc2_128: '1.2.840.113549.1.12.1.5', pbeSha1Rc2_40: '1.2.840.113549.1.12.1.6',
  hmacSha1: '1.2.840.113549.2.7', hmacSha224: '1.2.840.113549.2.8', hmacSha256: '1.2.840.113549.2.9', hmacSha384: '1.2.840.113549.2.10', hmacSha512: '1.2.840.113549.2.11',
  aes128cbc: '2.16.840.1.101.3.4.1.2', aes192cbc: '2.16.840.1.101.3.4.1.22', aes256cbc: '2.16.840.1.101.3.4.1.42', desEde3cbc: '1.2.840.113549.3.7', desCbc: '1.3.14.3.2.7', rc2cbc: '1.2.840.113549.3.2',
};

const PBE_NAMES = {
  [PKCS.pbeSha13Des]: 'SHA-1 and 3DES (legacy)', [PKCS.pbeSha12Des]: 'SHA-1 and 2-key 3DES (legacy)', [PKCS.pbeSha1Rc2_40]: 'SHA-1 and 40-bit RC2 (weak, legacy)',
  [PKCS.pbeSha1Rc2_128]: 'SHA-1 and 128-bit RC2 (legacy)', [PKCS.pbeSha1Rc4_128]: 'SHA-1 and 128-bit RC4 (legacy)', [PKCS.pbeSha1Rc4_40]: 'SHA-1 and 40-bit RC4 (weak, legacy)',
};

const name = (table, o) => (table[o] && (table[o].name || table[o])) || o;

module.exports = { DN, SIG, KEY, CURVE, HASH, EXT, EKU, POLICY, AIA, KU, PKCS, PBE_NAMES, name };

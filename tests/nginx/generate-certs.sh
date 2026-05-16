#!/bin/bash

# Enforce strict error handling
set -e

# Navigate to the script's directory securely
cd "$(dirname "$0")"

# Define Terminal Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "========================================================="
echo " opensecurity / zonzon Zero-Trust Engine"
echo " https://github.com/opensecurity/zonzon"
echo "=========================================================${NC}"

mkdir -p certs
cd certs

DOMAIN="secure.test.local"

echo -e "${GREEN}[+] Generating opensecurity Custom Root CA...${NC}"
openssl genrsa -out custom-ca.key 2048
chmod 600 custom-ca.key
openssl req -x509 -new -nodes -key custom-ca.key -sha256 -days 3650 -out custom-ca.crt \
  -subj "/C=US/ST=State/L=City/O=opensecurity/OU=zonzon Architecture/CN=zonzon Root CA"

echo -e "${GREEN}[+] Generating Nginx Server Key & CSR for ${DOMAIN}...${NC}"
openssl genrsa -out nginx.key 2048
chmod 600 nginx.key
openssl req -new -key nginx.key -out nginx.csr \
  -subj "/C=US/ST=State/L=City/O=opensecurity/OU=zonzon L7 Boundary/CN=${DOMAIN}"

cat > v3.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
EOF

echo -e "${GREEN}[+] Signing Nginx certificate with opensecurity custom CA...${NC}"
openssl x509 -req -in nginx.csr -CA custom-ca.crt -CAkey custom-ca.key -CAcreateserial \
  -out nginx.crt -days 825 -sha256 -extfile v3.ext

# Cleanup intermediate files
rm -f nginx.csr v3.ext custom-ca.srl

echo -e "${BLUE}[*] Cryptographic artifacts generated successfully in tests/nginx/certs/${NC}"
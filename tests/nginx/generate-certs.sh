#!/bin/bash

# Enforce strict error handling
set -e

# Navigate to the script's directory securely
cd "$(dirname "$0")"

# Define Terminal Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================================="
echo " opensecurity / zonzon Cryptographic Bootstrap"
echo "=========================================================${NC}"

mkdir -p certs
cd certs

DOMAIN="secure.test.local"
CLIENT_ID="zonzon-proxy-identity"

# 1. Generate Custom Root CA
echo -e "${GREEN}[+] Generating opensecurity Custom Root CA...${NC}"
openssl genrsa -out custom-ca.key 2048
chmod 600 custom-ca.key
openssl req -x509 -new -nodes -key custom-ca.key -sha256 -days 3650 -out custom-ca.crt \
  -subj "/C=US/ST=State/L=City/O=opensecurity/OU=zonzon Architecture/CN=zonzon Root CA"

# 2. Generate Nginx Server Certs
echo -e "${GREEN}[+] Generating Server Certificate for ${DOMAIN}...${NC}"
openssl genrsa -out nginx.key 2048
chmod 600 nginx.key
openssl req -new -key nginx.key -out nginx.csr \
  -subj "/C=US/ST=State/L=City/O=opensecurity/OU=zonzon Upstream/CN=${DOMAIN}"

cat > v3.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
EOF

openssl x509 -req -in nginx.csr -CA custom-ca.crt -CAkey custom-ca.key -CAcreateserial \
  -out nginx.crt -days 825 -sha256 -extfile v3.ext

# 3. Generate Proxy Client Certs (for mTLS)
echo -e "${GREEN}[+] Generating Client Certificate for Proxy mTLS Authentication...${NC}"
openssl genrsa -out client.key 2048
chmod 600 client.key
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=opensecurity/OU=zonzon Proxy Engine/CN=${CLIENT_ID}"

cat > client.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA custom-ca.crt -CAkey custom-ca.key -CAcreateserial \
  -out client.crt -days 825 -sha256 -extfile client.ext

# 4. Distribute certs to the proxy config directory
echo -e "${GREEN}[+] Deploying client certificates to proxy config volume...${NC}"
mkdir -p ../../../config
cp client.crt ../../../config/client.crt
cp client.key ../../../config/client.key
cp custom-ca.crt ../../../config/ca.crt

# Adjust permissions for the unprivileged Docker container user
chmod 644 ../../../config/client.crt ../../../config/client.key ../../../config/ca.crt

# Cleanup
rm -f *.csr *.ext *.srl

echo -e "${BLUE}[*] Cryptographic artifacts generated and deployed successfully.${NC}"
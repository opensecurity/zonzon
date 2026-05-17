#!/bin/bash
# 
# zonzon Cryptographic mTLS Verification Script
# Execute this script inside the llm_sandbox container:
# docker compose exec llm_sandbox bash /workspace/scripts/test-mtls.sh

set -e

PROXY_IP="172.20.0.53"
UPSTREAM_IP="172.21.0.100"
DOMAIN="secure-api.loop"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[SYSTEM] Interrogating Cryptographic mTLS Boundaries...${NC}\n"

echo -e "${BLUE}[1] Direct Connection to Upstream WITHOUT Client Cert (Should Fail)${NC}"
# We use -k here just to bypass the CA check temporarily; we want to test if the SERVER rejects US for lacking a client cert.
HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 3 https://${UPSTREAM_IP}:1234 || echo "Failed")
if [[ "$HTTP_CODE" == "400" || "$HTTP_CODE" == "Failed" || "$HTTP_CODE" == "000" ]]; then
    echo -e "${GREEN}[+] SUCCESS: Upstream correctly rejected anonymous TLS request.${NC}\n"
else
    echo -e "${RED}[!] FAILURE: Upstream accepted connection without mTLS (HTTP $HTTP_CODE)${NC}\n"
fi

echo -e "${BLUE}[2] Connection through zonzon Proxy (Should inject client cert and Succeed)${NC}"
# The proxy will use the clientTls configuration from hosts.json to satisfy the upstream requirement.
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 -H "Host: ${DOMAIN}" http://${PROXY_IP})
if [ "$HTTP_CODE" -eq 200 ]; then
    echo -e "${GREEN}[+] SUCCESS: Proxy successfully established mTLS tunnel.${NC}"
    echo "Response Payload:"
    curl -s --connect-timeout 3 -H "Host: ${DOMAIN}" http://${PROXY_IP}
else
    echo -e "${RED}[!] FAILURE: Proxy failed to establish mTLS tunnel (HTTP $HTTP_CODE)${NC}"
fi

echo -e "\n${BLUE}[SYSTEM] OpenSSL Raw Diagnostic (Testing SNI routing on Proxy TCP boundary)${NC}"
echo | openssl s_client -connect ${PROXY_IP}:443 -servername secure.test.local 2>/dev/null | grep -i "Verification" || true

echo -e "\n${GREEN}[SYSTEM] mTLS Boundary Verification Complete.${NC}"
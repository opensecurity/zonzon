#!/bin/bash
# 
# zonzon Comprehensive DNS Sandbox Test Script
# Execute this script inside the llm_sandbox container:
# docker compose exec llm_sandbox bash /path/to/test-dns.sh

set -e

DNS_SERVER="172.20.0.53"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[SYSTEM] Initializing Sandbox DNS Test Suite...${NC}"

if ! command -v dig &> /dev/null; then
    echo -e "${BLUE}[SYSTEM] 'dig' not found. Installing dnsutils...${NC}"
    apt-get update -qq && apt-get install -y -qq dnsutils
fi

if ! command -v curl &> /dev/null; then
    echo -e "${BLUE}[SYSTEM] 'curl' not found. Installing curl...${NC}"
    apt-get update -qq && apt-get install -y -qq curl ca-certificates
fi

echo -e "${BLUE}[SYSTEM] Tooling ready. Beginning boundary interrogations on $DNS_SERVER:53${NC}\n"

function run_query() {
    local record_type=$1
    local domain=$2
    
    echo -e "${GREEN}>>> Querying $record_type for $domain${NC}"
    
    local result=$(dig @$DNS_SERVER $record_type $domain +noall +answer +timeout=2)
    
    if [ -z "$result" ]; then
        echo -e "${RED}[!] NO ANSWER or TIMEOUT${NC}\n"
    else
        echo "$result"
        echo ""
    fi
}

run_query "A" "test-records.loop"
run_query "AAAA" "test-records.loop"
run_query "TXT" "test-records.loop"
run_query "MX" "test-records.loop"
run_query "NS" "test-records.loop"
run_query "CNAME" "cname.test-records.loop"
run_query "SRV" "_sip._tcp.test-records.loop"
run_query "PTR" "53.0.20.172.in-addr.arpa"
run_query "A" "random-subdomain.wildcard.loop"
run_query "A" "mock.ai.loop"
run_query "A" "redirect.loop"

echo -e "${GREEN}>>> Testing L4 SNI Custom Port Proxy (Air-gapped secure.test.local)${NC}"

# We resolve against zonzon (172.20.0.53) because sandbox_net cannot route to test_net directly.
# zonzon extracts the SNI, checks the config, and dials 172.21.0.100:1234 securely.
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 --resolve secure.test.local:443:172.20.0.53 https://secure.test.local)

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "SNI Proxy Response Payload:"
    curl -s --connect-timeout 3 --resolve secure.test.local:443:172.20.0.53 https://secure.test.local
    echo ""
else
    echo -e "${RED}[!] SNI Proxy Connection Failed (HTTP $HTTP_CODE)${NC}\n"
fi

echo -e "${BLUE}[SYSTEM] DNS Test Suite Execution Complete.${NC}"
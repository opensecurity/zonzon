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

# 1. Ensure testing tools are installed in the breached/sandbox environment
if ! command -v dig &> /dev/null; then
    echo -e "${BLUE}[SYSTEM] 'dig' not found. Installing dnsutils...${NC}"
    # Explicitly routing through the proxy boundary 
    apt-get update -qq && apt-get install -y -qq dnsutils
fi

echo -e "${BLUE}[SYSTEM] Tooling ready. Beginning boundary interrogations on $DNS_SERVER:53${NC}\n"

function run_query() {
    local record_type=$1
    local domain=$2
    
    echo -e "${GREEN}>>> Querying $record_type for $domain${NC}"
    
    # We use +noall +answer +timeout=2 to ensure strict output matching without noise
    local result=$(dig @$DNS_SERVER $record_type $domain +noall +answer +timeout=2)
    
    if [ -z "$result" ]; then
        echo -e "${RED}[!] NO ANSWER or TIMEOUT${NC}\n"
    else
        echo "$result"
        echo ""
    fi
}

# Standard Records
run_query "A" "test-records.loop"
run_query "AAAA" "test-records.loop"
run_query "TXT" "test-records.loop"
run_query "MX" "test-records.loop"
run_query "NS" "test-records.loop"

# Alias/Routing Records
run_query "CNAME" "cname.test-records.loop"
run_query "SRV" "_sip._tcp.test-records.loop"
run_query "PTR" "53.0.20.172.in-addr.arpa"

# Wildcard / Fallback Verification
run_query "A" "random-subdomain.wildcard.loop"

# HTTP Proxy and Redirect Resolutions
run_query "A" "mock.ai.loop"
run_query "A" "redirect.loop"

echo -e "${BLUE}[SYSTEM] DNS Test Suite Execution Complete.${NC}"
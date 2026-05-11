# @opensecurity/zonzon-mono

This repository contains the source code for the zonzon zero-trust dns and http proxy infrastructure. It provides dns resolution, http forwarding, sni proxying, and a control plane for dynamic configuration.

## Features currently implemented

* dns service: supports a, aaaa, cname, txt, mx, ns, srv, and ptr records.
* http proxy: includes request body forwarding with size limits and hop-by-hop header stripping.
* sni proxy: extracts sni from tls clienthello to route traffic via tcp tunneling.
* firewall engine: supports allowlist and blocklist matching for ips, cidr ranges, and domains.
* control plane: a basic http api to update the server configuration dynamically, requiring a proof of work challenge and api key hashing.
* caching: in-memory dns cache with ttl rewriting and basic eviction.
* rate limiting: tcp connection limits and ip-based request rate limiting using a sliding window.

## Requirements

* node.js v24 or higher
* npm v10 or higher
* docker (optional, for isolated sandbox execution)

## Installation

```bash
npm ci
npm run build

```

## Running the system

```bash
npm start

```

## Testing

```bash
npm test

```

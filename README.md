# zonzon

This repository contains the source code for the zonzon zero-trust dns and http proxy infrastructure. It provides dns resolution, http forwarding, sni proxying, and a control plane for dynamic configuration.

## Features currently implemented

* dns service: supports a, aaaa, cname, txt, mx, ns, srv, and ptr records. includes deterministic dnssec cryptographic validation and 0x20 bit encoding for cache poisoning mitigation. enforces strict boundary bounds checking for compression pointer resolution to prevent memory corruption.
* http proxy: includes streamed request body forwarding with size limits to prevent memory exhaustion and hop-by-hop header stripping. enforces mutual tls authentication with customizable client material and sni overriding. features deterministic l7 routing loop prevention using ephemeral cryptographic tracking headers to mitigate ssrf reflection.
* sni proxy: extracts sni from tls clienthello to route traffic via tcp tunneling, supporting custom target ips and ports via tls proxy configuration.
* firewall engine: supports allowlist and blocklist matching for ips, cidr ranges, and domains. includes strict outbound ssrf protection blocking rfc1918, link-local, and loopback addresses.
* control plane: an http api to update the server configuration dynamically. secured via proof of work challenges, hkdf-derived api key validation, and pessimistic locking. configuration secrets are encrypted in memory using aes-256-gcm.
* caching: in-memory dns cache with ttl rewriting and basic eviction.
* rate limiting: tcp connection limits and ip-based request rate limiting using a sliding window.

## Requirements

* node.js v24 or higher
* npm v10 or higher
* docker (optional, for isolated sandbox execution and mtls verification)

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

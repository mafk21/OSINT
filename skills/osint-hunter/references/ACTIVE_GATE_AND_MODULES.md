# OSINT Hunter — Collector & Active Gate Reference

## Passive Collectors & Offline Decoders (Law 1 — Instant, 0 Target Packets)
- **Offline Decoders**: ITU E.164 phone + NANPA/carrier hints, ICAO 24-bit hex + military block flag, Maritime IMO checksum + MMSI MID flag state, ISO 3779 17-char VIN WMI/year/check-digit, IEEE OUI MAC + Wi-Fi BSSID bit analysis, JWT header/payload/expiry, local JPEG EXIF GPS + PNG/PDF/DOCX/XLSX/ZIP author carving.
- **Passive Public APIs**: GitHub profile + `.patch` commit email leak + `.keys` SSH + `.gpg` OpenPGP UID carving, GitLab, Keybase cryptographic proofs, Reddit JSON, HackerNews Firebase, npm & PyPI maintainer registries, Gravatar SHA-256, Google DoH (`A`/`AAAA`/`MX`/`TXT`/`NS`/`SOA`/`CAA`) + DMARC/SPF/BIMId, `crt.sh` Certificate Transparency, IANA RDAP, Wayback CDX + sensitive path scan, HackerTarget passive hosts, URLhaus, Shodan InternetDB, RIPEstat BGP/ASN, Nominatim reverse geocode, Mempool.space BTC & Ethereum JSON-RPC.

## 22 Gated Active Modules (Law 2 — Requires Single-Use `ACT-XXXXXXXX` Approval)
1. `active_dns_live_resolver` — **Live DNS & Reverse PTR Resolution** (`domain, url, ip, email`)
2. `active_dns_zone_transfer_axfr` — **Authoritative DNS Zone Transfer (AXFR) & CHAOS Version Audit** (`domain, url`)
3. `active_dns_srv_and_federation` — **Live SRV Service Records & M365/Entra Tenant Federation Probe** (`domain, email`)
4. `active_subdomain_takeover_cname_audit` — **Live CNAME Chain & Dangling Subdomain Takeover Fingerprint Check** (`domain, url`)
5. `active_tls_cert_inspector` — **Live TLS Handshake & X.509 SAN Certificate Inspector** (`domain, url, ip`)
6. `active_tls_protocol_alpn_matrix` — **TLS Protocol Version (1.0–1.3), Cipher Suite, PFS & ALPN Matrix Auditor** (`domain, url, ip`)
7. `active_jarm_tls_fingerprint` — **Active TLS ServerHello Stack & JARM-Style Origin Fingerprinter** (`domain, url, ip`)
8. `active_http_fingerprint_and_headers` — **Live HTTP Redirect, Security Header, CSP & Analytics Tag Fingerprinter** (`domain, url, ip`)
9. `active_http_methods_cors_and_waf` — **Live HTTP OPTIONS Methods, CORS Reflection & WAF/CDN Edge Detector** (`domain, url, ip`)
10. `active_wellknown_and_robots_harvester` — **Live /robots.txt, /.well-known/security.txt & OpenID Tenant Harvester** (`domain, url`)
11. `active_mobile_app_and_fediverse_links` — **Live Android assetlinks, Apple App-Site-Association, Nostr NIP-05 & ATProto Harvester** (`domain, url`)
12. `active_sitemap_and_feed_harvester` — **Live XML Sitemap, Sitemap Index & RSS/Atom Author Harvester** (`domain, url`)
13. `active_api_openapi_and_graphql_discovery` — **Non-Intrusive OpenAPI/Swagger, GraphQL, ai-plugin & llms.txt Spec Discovery** (`domain, url`)
14. `active_exposed_vcs_and_env_check` — **Non-Destructive Exposed /.git/HEAD, /.DS_Store & Cross-Domain Policy Check** (`domain, url`)
15. `active_js_bundle_cloud_and_endpoint_carver` — **Live First-Party JavaScript Bundle API Endpoint & Cloud Bucket Carver** (`domain, url`)
16. `active_favicon_hash_extractor` — **Live /favicon.ico Shodan MurmurHash3 (mmh3) & SHA-256 Calculator** (`domain, url`)
17. `active_url_jsonld_opengraph` — **Live Webpage OpenGraph, JSON-LD sameAs Social Graph & Contact Extractor** (`url, domain`)
18. `active_cloud_bucket_permutation_probe` — **Active AWS S3, Google Cloud Storage & Azure Blob Public Bucket Probe** (`domain, company, username`)
19. `active_tcp_service_banner_probe` — **Expanded 20-Port Non-Intrusive TCP Service & Banner Scanner** (`ip, domain`)
20. `active_ssh_hostkey_and_kex_probe` — **Live SSH-2.0 Banner & RFC 4253 KEXINIT Host-Key/Cipher Fingerprinter** (`ip, domain`)
21. `active_smtp_ehlo_starttls_inspector` — **Live Mail Server SMTP Banner, EHLO Capabilities & STARTTLS Cert Inspector** (`domain, ip, email`)
22. `active_username_live_platform_probe` — **Direct 16-Platform Live HTTP/API Username Existence & Profile Verifier** (`username`)

# OSINT Hunter — Collector & Active Gate Reference

## Passive Collectors & Offline DFIR Decoders (Law 1 — Instant, 0 Target Packets)
- **Offline DFIR & Chronolocation Decoders**: `.eml` hop/SPF/DKIM/DMARC spoofing, `.pcap`/`.pcapng` DNS/SNI/HTTP carver, `.har`, `.mp4`/`.mov` `mvhd`+GPS, PNG/WebP C2PA Content Credentials & ComfyUI/Stable Diffusion AI provenance, Google Search `ei=` timestamp, OpenSSH/PEM fingerprints, TikTok/Snowflake/UUIDv1-v7/ULID/ObjectId UTC, ISO 13616 IBAN (SAMA), ITU E.164 phone + NANPA/GCC/MENA carriers, ICAO 24-bit hex + military block flag, Maritime IMO + MMSI MID, ISO 3779 VIN, IEEE OUI MAC/BSSID, JWT, JPEG EXIF GPS & PDF/OOXML authors.
- **Passive Public APIs + Optional BYOK**: GitHub profile + `.patch` commit email + `.keys` SSH + `.gpg` OpenPGP, GitLab, HuggingFace Hub, Crates.io, Docker Hub, Packagist, npm, PyPI, Bluesky ATProto + `plc.directory` handle-rename audit, Mastodon `rel=me`, Keybase, Reddit, HackerNews, Gravatar, Microsoft Entra ID / M365 tenant, Google DoH + DMARC/SPF/BIMI, `crt.sh` CT SANs, IANA RDAP, Wayback CDX, HackerTarget, URLhaus, Shodan InternetDB, RIPEstat BGP/ASN, Nominatim, Mempool.space BTC & Ethereum RPC, plus optional BYOK (`SHODAN_API_KEY`, `VT_API_KEY`, `URLSCAN_API_KEY`, `HIBP_API_KEY`, `SECURITYTRAILS_API_KEY`, `ABUSEIPDB_API_KEY`, `GITHUB_TOKEN`).

## 22 Gated Active Modules (Law 3 — Requires Single-Use `ACT-XXXXXXXX` Approval)
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

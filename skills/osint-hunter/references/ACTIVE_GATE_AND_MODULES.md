# OSINT Hunter — Collector & Active Gate Reference

## Passive Collectors & Offline Decoders (Law 1 — Instant, 0 Target Packets)
- **Offline Decoders**: ITU E.164 phone + NANPA/carrier hints, ICAO 24-bit hex + military block flag, Maritime IMO checksum + MMSI MID flag state, ISO 3779 17-char VIN WMI/year/check-digit, IEEE OUI MAC + Wi-Fi BSSID bit analysis, JWT header/payload/expiry, local JPEG EXIF GPS + PNG/PDF/DOCX/XLSX/ZIP author carving.
- **Passive Public APIs**: GitHub profile + `.patch` commit email leak + `.keys` SSH + `.gpg` OpenPGP UID carving, GitLab, Keybase cryptographic proofs, Reddit JSON, HackerNews Firebase, npm & PyPI maintainer registries, Gravatar SHA-256, Google DoH (`A`/`AAAA`/`MX`/`TXT`/`NS`/`SOA`/`CAA`) + DMARC/SPF/BIMId, `crt.sh` Certificate Transparency, IANA RDAP, Wayback CDX + sensitive path scan, HackerTarget passive hosts, URLhaus, Shodan InternetDB, RIPEstat BGP/ASN, Nominatim reverse geocode, Mempool.space BTC & Ethereum JSON-RPC.

## Gated Active Modules (Law 2 — Requires Single-Use `ACT-XXXXXXXX` Approval)
1. `active_dns_live_resolver` — Live forward & reverse PTR resolution.
2. `active_tls_cert_inspector` — Direct `:443` TLS handshake, X.509 SANs, issuer, serial, SHA-256 thumbprint.
3. `active_http_fingerprint_and_headers` — Redirect chain, Server/X-Powered-By, HSTS/CSP host extraction, GA4/GTM/AdSense/Meta Pixel IDs.
4. `active_wellknown_and_robots_harvester` — Live `/robots.txt`, `/.well-known/security.txt`, `/.well-known/openid-configuration`, `/humans.txt`.
5. `active_favicon_hash_extractor` — Live `/favicon.ico` Shodan MurmurHash3 (`http.favicon.hash:<mmh3>`) & SHA-256.
6. `active_tcp_service_banner_probe` — Non-intrusive TCP banner read on common ports (`21, 22, 25, 80, 443, 8080, 8443`).
7. `active_url_jsonld_opengraph` — Live HTML OpenGraph, JSON-LD `sameAs` social links, `mailto:` & `tel:` contacts.

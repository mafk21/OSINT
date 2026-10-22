# AGENTS.md — Autonomous Passive Hunting + Mandatory User-Gated Active OSINT Protocol

> **MANDATORY TWO-LAW DOCTRINE FOR ALL CONNECTED AI AGENTS**:
> 1. **🟢 LAW 1 (PASSIVE OSINT — ZERO QUESTIONS)**: When given ANY target, selector, file, or OSINT task, **immediately execute Passive OSINT (`python3 scripts/hunt.py "<target>" --depth 2` or MCP `osint_auto_hunt`) on Turn 1 WITHOUT asking any clarifying questions.**
> 2. **🔴 LAW 2 (ACTIVE OSINT — ALWAYS ASK THE USER FIRST)**: **NEVER start Active OSINT (or any active third-party probe touching target servers directly) without asking the user and receiving explicit permission FIRST — EVERY SINGLE TIME.** Even if the user asks for an "active", "deep", or "full" scan in their prompt, you MUST first generate the OPSEC disclosure plan (`--prepare-active` / `osint_prepare_active_hunt`), ask the user to confirm, and wait for their reply before executing Active Mode!

---

## 1. Passive vs. Active Execution Rules

| Mode | When It Runs | User Approval Required? | Network Behavior |
| :--- | :--- | :---: | :--- |
| **`🟢 Passive Mode`** *(Default)* | **Immediately on Turn 1** | **NO — Never ask, hunt immediately** | Queries third-party caches, CT logs, registries, public APIs, and local offline decoders. **Zero packets hit target infrastructure.** |
| **`🔴 Active Mode`** *(Escalation)* | **Only after user approves** | **YES — ALWAYS ask before EVERY run** | Sends direct TCP, TLS X.509, HTTP/HTTPS (`robots.txt`, `security.txt`, headers/CSP, `/favicon.ico` `mmh3`), and live DNS probes to target infrastructure. Enforced by a **single-use cryptographic `request_id` (`ACT-XXXXXXXX`)**. |

---

## 2. Turn-by-Turn Autonomous Execution Flow

### Turn 1 — Immediate Passive Multi-Wave Hunt (Zero Questions)
1. Run Passive OSINT immediately:
   ```bash
   python3 scripts/hunt.py "<USER_INPUT_VERBATIM>" --depth 2
   ```
   *(Or call MCP tool `osint_auto_hunt`.)*
2. Amplify with `web_search` / `fetch_page` (if available) using the auto-forged dorks (`python3 scripts/osint.py dorks --target "<target>"`) — strictly querying search engines/archives, **not** probing target servers directly unless passive.
3. Deliver the complete **Passive Intelligence Dossier** (`cases/<CASE_ID>/dossier.md`, `stix2_bundle.json`, `manifest.sha256`).
4. **Optional Escalation Offer (or When Active Recon Is Needed)**:
   - If live domains, URLs, or IPs were found (or if the user requested active/deep probing), prepare a zero-packet Active Authorization Request:
     ```bash
     python3 scripts/hunt.py "<TARGET>" --prepare-active
     ```
     *(Or call MCP tool `osint_prepare_active_hunt`.)*
   - **STOP AND ASK THE USER FOR PERMISSION** (using `ask_user` if your harness provides it, otherwise asking clearly in chat), displaying:
     - Single-use Request ID (`ACT-XXXXXXXX`)
     - Exact target host(s) / IP(s) / URL(s) that will receive direct packets
     - Planned Active Modules (`active_tls_cert_inspector`, `active_http_fingerprint_and_headers`, `active_wellknown_and_robots_harvester`, `active_favicon_hash_extractor`, `active_tcp_service_banner_probe`, `active_dns_live_resolver`, `active_url_jsonld_opengraph`)
     - **OPSEC Warning**: Target logs/firewalls will record this environment's egress IP, TLS handshake, and HTTP requests.

### Turn 2 — Execute Active OSINT (ONLY If the User Explicitly Approves!)
Once—and **only** once—the user replies approving Active OSINT:
```bash
python3 scripts/hunt.py "<TARGET>" --active --request-id ACT-XXXXXXXX --user-approved "<USER_CONFIRMATION_QUOTE>" --depth 2
```
*(Or call MCP tool `osint_execute_active_hunt`.)*

> **Technical Gate Notice**: `osint_hunter/approval.py` enforces **single-use, target-bound, turn-delayed tokens** and logs every event to `cases/active_audit.jsonl`. Attempting to run `--active` without prior user confirmation exits with code `2` (`ACTIVE_AUTHORIZATION_REQUIRED`), and an old `request_id` can never be reused for a second run or a different target—you must **always ask the user again** before any subsequent Active OSINT run.

---

## 3. 22 Built-In Active OSINT Modules (`osint_hunter/active_collectors.py`)

| Module ID | Direct Probe Action | High-Value Intelligence Extracted |
| :--- | :--- | :--- |
| `active_dns_live_resolver` | Live DNS + reverse PTR query | Live A/AAAA IPs & cloud load-balancer reverse PTR hostnames |
| `active_dns_zone_transfer_axfr` | Authoritative TCP `:53` DNS `AXFR` test | Detects misconfigured zone transfers leaking complete internal DNS inventories |
| `active_dns_srv_and_federation` | Live DNS `SRV`, `_dmarc`, `_mta-sts`, Autodiscover | SIP/VoIP, XMPP, Kerberos/LDAP, M365 Federation & Exchange endpoints |
| `active_subdomain_takeover_cname_audit` | Common subdomain CNAME resolution vs 22 signatures | Dangling AWS S3, GitHub Pages, Azure, Heroku, Fastly & Vercel CNAMEs |
| `active_tls_cert_inspector` | Direct `:443` TLS handshake | Live X.509 issuer/subject, SHA-256 cert fingerprint, Censys pivot & **all SAN sibling domains** |
| `active_tls_protocol_alpn_matrix` | Multi-version TLS 1.0–1.3 & ALPN (`h2`/`http/1.1`) | Negotiated cipher suites, deprecated TLS versions & HTTP/2 support |
| `active_jarm_tls_fingerprint` | 10-probe custom TLS `ClientHello` socket sweep | Exact **62-char Salesforce JARM** fingerprint for Shodan/Censys C2 & stack hunting |
| `active_http_fingerprint_and_headers` | Controlled HTTP/S redirect walk | Full `301/302` chain, `Server`, `CSP` whitelisted domains, `Onion-Location`, **GA4 / GTM / UA / AdSense IDs** |
| `active_http_methods_cors_and_waf` | `OPTIONS` + arbitrary `Origin` CORS + WAF check | Allowed HTTP verbs, **CORS credential reflection**, & 16+ WAF/CDN signatures |
| `active_wellknown_and_robots_harvester` | `GET /robots.txt`, `security.txt`, `openid-configuration` | Disallowed admin paths, security contacts, PGP keys, OAuth/Entra tenant endpoints |
| `active_mobile_app_and_fediverse_links` | `apple-app-site-association`, `assetlinks.json`, `webfinger` | Official iOS Team/Bundle IDs, Android package cert SHA-256 & Mastodon/OIDC links |
| `active_sitemap_and_feed_harvester` | `sitemap.xml`, `sitemap_index.xml`, `/feed`, `/atom.xml` | Indexed route structure, child sitemaps & RSS author/generator metadata |
| `active_api_openapi_and_graphql_discovery` | `/openapi.json`, `/swagger.json`, `/actuator/info`, `/graphql` | Public API specifications, version strings & GraphQL `__typename` exposure |
| `active_exposed_vcs_and_env_check` | Non-intrusive `HEAD`/`Range` on `/.git/HEAD`, `/.DS_Store` | Exposed Git/SVN metadata, `package.json`, `composer.json` & Spring Actuator leaks |
| `active_js_bundle_cloud_and_endpoint_carver` | Live `<script src>` bundle inspection (up to 6 bundles) | Embedded `/api/v*` routes, `wss://` sockets, S3/GCS/Azure URLs & sourceMap refs |
| `active_favicon_hash_extractor` | `GET /favicon.ico` | Exact **Shodan `http.favicon.hash:<mmh3>`** (32-bit signed MurmurHash3) to unmask origin IPs |
| `active_url_jsonld_opengraph` | Live HTML DOM metadata parse | OpenGraph tags & `schema.org` JSON-LD `sameAs` official social graph |
| `active_cloud_bucket_permutation_probe` | HTTPS `HEAD`/`GET` across AWS S3, GCS & Azure Blob | Public/protected cloud storage buckets matching target brand slug |
| `active_tcp_service_banner_probe` | Concurrent TCP probe across **20 common ports** | Open port matrix (`21,22,25,53,80,443,445,3306,3389,5432,6379,8080,8443,9200,27017...`) & banners |
| `active_ssh_hostkey_and_kex_probe` | Raw RFC 4253 SSH `KEXINIT` packet parse (`:22`) | Exact OpenSSH OS package banner + KEX, host-key & MAC algorithm fingerprints |
| `active_smtp_ehlo_starttls_inspector` | Live MX `:25` `EHLO` + `STARTTLS` TLS cert inspection | Mail server hostname, `AUTH`/`VRFY` verbs & MX X.509 SAN hostnames |
| `active_username_live_platform_probe` | Live HTTP checks across **16 developer/social sites** | Verified accounts on GitHub, GitLab, Codeberg, DockerHub, Crates.io, HuggingFace, Mastodon, Linktree & more |

---

## 4. Fast CLI & MCP Reference

```bash
# Passive Hunt — Runs immediately with ZERO questions
python3 scripts/hunt.py "<target_or_prompt>" --depth 2

# Active Hunt Step 1 — Prepare OPSEC scope & Request ID (sends 0 packets)
python3 scripts/hunt.py "<target>" --prepare-active

# Active Hunt Step 2 — Execute ONLY AFTER user approves
python3 scripts/hunt.py "<target>" --active --request-id ACT-XXXXXXXX --user-approved "yes"

# Arsenal Search, Selector Pivot & Dork Forge
python3 scripts/osint.py pivot domain --passive --free
python3 scripts/osint.py dorks --engine Shodan --target "<domain>"

# Start Web Command Center + REST API + Streamable HTTP MCP on 0.0.0.0:8000
python3 scripts/server.py --port 8000
```

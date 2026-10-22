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

## 3. Active OSINT Modules Reference (`osint_hunter/active_collectors.py`)

| Module ID | Direct Probe Action | High-Value Intelligence Extracted |
| :--- | :--- | :--- |
| `active_dns_live_resolver` | Live DNS + reverse PTR query | Live A/AAAA IPs & cloud load-balancer reverse PTR hostnames |
| `active_tls_cert_inspector` | Direct `:443` TLS handshake | Live X.509 issuer/subject, SHA-256 cert fingerprint, Censys pivot & **all SAN sibling domains** |
| `active_http_fingerprint_and_headers` | Controlled HTTP/S redirect walk | Full `301/302` chain, `Server`, `CSP` whitelisted domains, `Onion-Location`, **GA4 / GTM / UA / AdSense IDs** |
| `active_wellknown_and_robots_harvester` | `GET /robots.txt`, `/.well-known/security.txt`, `openid-configuration`, `/humans.txt` | Disallowed admin paths, security contacts, PGP keys, OAuth/Entra tenant endpoints |
| `active_favicon_hash_extractor` | `GET /favicon.ico` | Exact **Shodan `http.favicon.hash:<mmh3>`** (32-bit signed MurmurHash3) to unmask origin IPs behind CDNs |
| `active_tcp_service_banner_probe` | Brief TCP connect on `21,22,25,80,443,8080,8443` | Open port map & SSH/SMTP/FTP version banners (`OpenSSH_9.x Ubuntu` OS patch fingerprinting) |
| `active_url_jsonld_opengraph` | Live HTML DOM metadata parse | OpenGraph tags & `schema.org` JSON-LD `sameAs` official social graph |

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

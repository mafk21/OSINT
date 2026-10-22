[⬅️ Back to Master Index](../README.md) · [◀ ⛓️ Crypto & Blockchain OSINT](./15-crypto-blockchain-web3.md) · [🛡️ Threat Intel, Malware & IOCs ▶](./17-threat-intel-malware-cti.md)

# 🧅 16. Dark Web, Tor (.onion), I2P & Ransomware / Underground Monitoring (`DARKINT`)

> **Scope**: Clearnet-to-Tor `.onion` search engines, darknet crawlers, AI dark-web triage agents, ransomware extortion group trackers, Tor relay telemetry, and PGP keyserver attribution tools.
>
> **OPSEC Advisory**: Never browse live `.onion` hidden services from a host browser or Tor2Web proxy. Use Tor Browser inside Whonix/Tails or an isolated disposable VM with JavaScript set to Safest.

**Discipline Telemetry**: `22` Verified Tools · `6` S-Tier Flagships · `18` Passive · `18` Free/Open-Source

## Subcategories
- [Tor (.onion) Search Engines](#tor-onion-search-engines) (3)
- [Darknet Crawlers & AI Triage](#darknet-crawlers-ai-triage) (4)
- [Ransomware & Underground Monitors](#ransomware-underground-monitors) (6)
- [Tor Network & Relay Attribution](#tor-network-relay-attribution) (2)
- [PGP & Cryptographic Attribution](#pgp-cryptographic-attribution) (2)
- [Hidden Service OPSEC Auditing](#hidden-service-opsec-auditing) (3)
- [Alternative Darknets](#alternative-darknets) (2)

---

## Tor (.onion) Search Engines

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Ahmia.fi**](https://ahmia.fi/) ([GitHub](https://github.com/ahmia/ahmia-site)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `keyword, onion_url, domain` → `darkweb_mentions, urls` |
| **A** | [**OnionSearch**](https://github.com/megadose/OnionSearch) ([GitHub](https://github.com/megadose/OnionSearch)) | CLI | OSS / Free | 🟢 Passive | ✅ | `keyword` → `darkweb_mentions, urls` |
| **B** | [**darkdump**](https://github.com/josh0xA/darkdump) ([GitHub](https://github.com/josh0xA/darkdump)) | CLI | OSS / Free | 🟢 Passive | ✅ | `keyword` → `darkweb_mentions, urls` |

### [Ahmia.fi](https://ahmia.fi/) `[S-Tier]`
- **ID**: `ahmia` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ahmia/ahmia-site`](https://github.com/ahmia/ahmia-site)
- **Inputs**: `keyword`, `onion_url`, `domain` → **Outputs**: `darkweb_mentions`, `urls`
- **Platforms**: Web · **Tags**: `tor-search`, `onion-v3`, `clearnet-gateway`, `open-source`, `flagship`
- **Overview**: Longest-running reputable clearnet-and-Tor search engine indexing public `.onion` v3 hidden services while strictly filtering illegal abuse material—safe first-pass darknet keyword discovery.
- **Quick-Start / Tradecraft**: `Search brand names, domains, or threat handles safely from clearnet at https://ahmia.fi/ before launching Tor Browser.`

### [OnionSearch](https://github.com/megadose/OnionSearch) `[A-Tier]`
- **ID**: `onionsearch` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`megadose/OnionSearch`](https://github.com/megadose/OnionSearch)
- **Inputs**: `keyword` → **Outputs**: `darkweb_mentions`, `urls`
- **Platforms**: Linux, macOS, Python · **Tags**: `meta-search`, `tor-engines`, `csv-export`, `megadose`
- **Overview**: Python CLI meta-scraper aggregating results across a dozen active `.onion` darknet search engines simultaneously over Tor (`127.0.0.1:9050`) into a clean CSV.
- **Quick-Start / Tradecraft**: `pipx install onionsearch && onionsearch 'target keyword' --proxy 127.0.0.1:9050 --output hits.csv`

### [darkdump](https://github.com/josh0xA/darkdump) `[B-Tier]`
- **ID**: `darkdump` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`josh0xA/darkdump`](https://github.com/josh0xA/darkdump)
- **Inputs**: `keyword` → **Outputs**: `darkweb_mentions`, `urls`
- **Platforms**: Linux, macOS, Python · **Tags**: `darkweb-cli`, `onion-discovery`, `quick-triage`
- **Overview**: Clean Python CLI querying deep/darknet search indexes from the terminal and returning deduplicated `.onion` titles, descriptions, and metadata.
- **Quick-Start / Tradecraft**: `python3 darkdump.py --query 'target_keyword'`

---

## Darknet Crawlers & AI Triage

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**AIL Framework (Analysis Information Leak — CIRCL)**](https://www.ail-project.org/) ([GitHub](https://github.com/ail-project/ail-framework)) | Framework | OSS / Free | 🟢 Passive | ✅ | `onion_url, keyword, domain` → `darkweb_mentions, breach_records, secrets` |
| **S** | [**Robin (AI-Powered Dark Web OSINT)**](https://github.com/apurvsinghgautam/robin) ([GitHub](https://github.com/apurvsinghgautam/robin)) | CLI | OSS / Free | 🟢 Passive | ✅ | `keyword, domain, company` → `darkweb_mentions, urls` |
| **A** | [**darknet-mcp-server**](https://github.com/badchars/darknet-mcp-server) ([GitHub](https://github.com/badchars/darknet-mcp-server)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `company, domain, email` → `darkweb_mentions, breach_records, malware_iocs` |
| **A** | [**TorBot (OWASP)**](https://github.com/DedSecInside/TorBot) ([GitHub](https://github.com/DedSecInside/TorBot)) | CLI | OSS / Free | 🔴 Active | ✅ | `onion_url` → `darkweb_mentions, emails, urls` |

### [AIL Framework (Analysis Information Leak — CIRCL)](https://www.ail-project.org/) `[S-Tier]`
- **ID**: `ail-framework` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ail-project/ail-framework`](https://github.com/ail-project/ail-framework)
- **Inputs**: `onion_url`, `keyword`, `domain`, `email` → **Outputs**: `darkweb_mentions`, `breach_records`, `secrets`, `certificates`
- **Platforms**: Linux, Docker, Python · **Tags**: `circl`, `paste-monitoring`, `onion-indexing`, `modular-cti`, `cert-grade`
- **Overview**: CIRCL's modular open-source framework analyzing unstructured paste feeds, Tor `.onion` hidden services (`Lacunan`), Telegram streams, and leak dumps to detect credential/secret/PGP/crypto exposures.
- **Quick-Start / Tradecraft**: `Deploy AIL via Docker to run an in-house private equivalent of DarkOwl/IntelX over Tor & paste feeds.`

### [Robin (AI-Powered Dark Web OSINT)](https://github.com/apurvsinghgautam/robin) `[S-Tier]`
- **ID**: `robin-darkweb` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`apurvsinghgautam/robin`](https://github.com/apurvsinghgautam/robin)
- **Inputs**: `keyword`, `domain`, `company` → **Outputs**: `darkweb_mentions`, `urls`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `ai-darkweb`, `tor-socks5`, `ollama-support`, `threat-triage`, `flagship`
- **Overview**: Open-source AI-assisted Dark Web OSINT tool querying multiple Tor search engines simultaneously via local Tor SOCKS5 proxy, deduplicating `.onion` hits, and synthesizing threat summaries via local/API LLMs.
- **Quick-Start / Tradecraft**: `Ensure Tor service (`127.0.0.1:9050`) is running in an isolated VM, then run `robin -m llama3.1 -q 'target_domain'`.`

### [darknet-mcp-server](https://github.com/badchars/darknet-mcp-server) `[A-Tier]`
- **ID**: `darknet-mcp-server` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`badchars/darknet-mcp-server`](https://github.com/badchars/darknet-mcp-server)
- **Inputs**: `company`, `domain`, `email`, `crypto_address`, `file_hash` → **Outputs**: `darkweb_mentions`, `breach_records`, `malware_iocs`
- **Platforms**: Linux, macOS, Node.js · **Tags**: `darkweb-mcp`, `ransomware-feeds`, `abuse-ch`, `66-tools`
- **Overview**: 66-tool MCP server exposing ransomware group/victim tracking, HIBP checks, IntelX search, Tor exit-node verification, MalwareBazaar/ThreatFox/URLhaus feeds, and BTC address lookups to AI agents.
- **Quick-Start / Tradecraft**: `npx darknet-mcp-server`

### [TorBot (OWASP)](https://github.com/DedSecInside/TorBot) `[A-Tier]`
- **ID**: `torbot` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`DedSecInside/TorBot`](https://github.com/DedSecInside/TorBot)
- **Inputs**: `onion_url` → **Outputs**: `darkweb_mentions`, `emails`, `urls`, `entity_graph`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `owasp`, `onion-crawler`, `link-tree`, `darknet-osint`
- **Overview**: OWASP open-source Dark Web OSINT crawler traversing `.onion` links over Tor SOCKS5 to extract page titles, embedded emails, clearnet pivot links, JSON link trees, and status codes.
- **Quick-Start / Tradecraft**: `Run strictly inside Whonix/Tails/VM: `python3 main.py -u http://example.onion --depth 2 --visualize tree`.`

---

## Ransomware & Underground Monitors

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**deepdarkCTI (fastfire)**](https://github.com/fastfire/deepdarkCTI) ([GitHub](https://github.com/fastfire/deepdarkCTI)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `onion_url, keyword` → `darkweb_mentions, malware_iocs` |
| **S** | [**Ransomware.live (Julien Mousqueton)**](https://www.ransomware.live/) ([GitHub](https://github.com/JMousqueton/ransomware.live)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `company, domain, keyword` → `darkweb_mentions, breach_records, documents` |
| **A** | [**DarkFeed / Ransomfeed**](https://ransomfeed.it/) ([GitHub](https://github.com/Ransomfeed-it/ransomfeed-cli)) | Web Platform | Freemium | 🟢 Passive | ✅ | `company, keyword` → `darkweb_mentions, breach_records` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | Search Engine | Paid | 🟢 Passive | 🔑 | `email, domain, ip` → `darkweb_mentions, breach_records` |
| **A** | [**Flare Threat Exposure Management**](https://flare.io/) | Web Platform | Paid | 🟢 Passive | 🔑 | `domain, email, company` → `darkweb_mentions, breach_records, secrets` |
| **A** | [**Searchlight Cyber (Cerberus / DarkIQ)**](https://www.slcyber.io/) | Web Platform | Paid | 🟢 Passive | 🔑 | `onion_url, domain, company` → `darkweb_mentions, archived_pages, certificates` |

### [deepdarkCTI (fastfire)](https://github.com/fastfire/deepdarkCTI) `[S-Tier]`
- **ID**: `deepdarkcti` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`fastfire/deepdarkCTI`](https://github.com/fastfire/deepdarkCTI)
- **Inputs**: `onion_url`, `keyword` → **Outputs**: `darkweb_mentions`, `malware_iocs`
- **Platforms**: Web · **Tags**: `darkweb-directory`, `ransomware-onions`, `threat-actor-telegram`, `cti-reference`, `flagship`
- **Overview**: Continuously updated open-source Cyber Threat Intelligence catalog tracking active Telegram threat channels, ransomware `.onion` URLs, cybercrime forums, Discord servers, and stealer marketplaces.
- **Quick-Start / Tradecraft**: `Cross-reference active vs dead ransomware gang `.onion` v3 mirrors in `fastfire/deepdarkCTI` markdown tables.`

### [Ransomware.live (Julien Mousqueton)](https://www.ransomware.live/) `[S-Tier]`
- **ID**: `ransomware-live` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`JMousqueton/ransomware.live`](https://github.com/JMousqueton/ransomware.live)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `darkweb_mentions`, `breach_records`, `documents`
- **Platforms**: Web, Python · **Tags**: `ransomware-live`, `negotiation-chats`, `ransom-notes`, `free-rest-api`, `flagship`
- **Overview**: Widely cited open-source ransomware intelligence portal & free REST API tracking 200+ extortion groups, victim posts, ransom notes, negotiation chats, and darknet `.onion` mirror statuses.
- **Quick-Start / Tradecraft**: `curl -s https://api.ransomware.live/recentvictims | jq '.[0:5]'`

### [DarkFeed / Ransomfeed](https://ransomfeed.it/) `[A-Tier]`
- **ID**: `darkfeed` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Ransomfeed-it/ransomfeed-cli`](https://github.com/Ransomfeed-it/ransomfeed-cli)
- **Inputs**: `company`, `keyword` → **Outputs**: `darkweb_mentions`, `breach_records`
- **Platforms**: Web · **Tags**: `ransomware-tracker`, `double-extortion`, `victim-alerts`, `cti`
- **Overview**: Real-time ransomware extortion monitoring dashboard, statistics tracker, RSS/JSON feed, and Telegram alert service cataloging global double-extortion claims.
- **Quick-Start / Tradecraft**: `Search company names or country codes at https://ransomfeed.it/ without connecting directly to ransomware onion portals.`

### [DarkOwl Vision](https://www.darkowl.com/) `[A-Tier]`
- **ID**: `darkowl` · **Type**: `Search Engine` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `email`, `domain`, `ip`, `company`, `crypto_address`, `keyword` → **Outputs**: `darkweb_mentions`, `breach_records`
- **Platforms**: Web · **Tags**: `enterprise-darknet`, `tor-i2p-zeronet`, `boolean-search`, `safe-clearnet-ui`
- **Overview**: Enterprise darknet data provider indexing Tor, I2P, ZeroNet, authenticated underground forums, and illicit chat platforms into a high-speed clearnet Boolean/regex search engine.
- **Quick-Start / Tradecraft**: `Use clearnet Boolean proximity searches in DarkOwl Vision to avoid direct active interaction with hostile `.onion` servers.`

### [Flare Threat Exposure Management](https://flare.io/) `[A-Tier]`
- **ID**: `flare-io` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain`, `email`, `company`, `keyword` → **Outputs**: `darkweb_mentions`, `breach_records`, `secrets`
- **Platforms**: Web · **Tags**: `underground-forums`, ` illicit-telegram`, `stealer-monitoring`, `enterprise-cti`
- **Overview**: Commercial continuous dark-web, illicit Telegram channel, infostealer log, and cybercrime forum monitoring platform providing automated clearnet search across underground communities.
- **Quick-Start / Tradecraft**: `Configure domain, VIP email, and CIDR watchlists in Flare to surface dark-market and stealer mentions passively.`

### [Searchlight Cyber (Cerberus / DarkIQ)](https://www.slcyber.io/) `[A-Tier]`
- **ID**: `searchlight-cyber` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `onion_url`, `domain`, `company`, `email`, `keyword` → **Outputs**: `darkweb_mentions`, `archived_pages`, `certificates`
- **Platforms**: Web · **Tags**: `historical-onion-snapshots`, `darkweb-wayback`, `threat-actor-attribution`
- **Overview**: Dark-web threat intelligence platform combining multi-decade historical `.onion` crawl snapshots (a 'Wayback Machine for Tor'!) with SSH/certificate darknet infrastructure attribution.
- **Quick-Start / Tradecraft**: `Inspect historical snapshots of seized or vanished `.onion` marketplaces and extortion blogs.`

---

## Tor Network & Relay Attribution

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Tor Metrics — Relay & Bridge Search**](https://metrics.torproject.org/rs.html) ([GitHub](https://github.com/torproject/tor)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `ip, asn, keyword` → `opsec_protection, whois, signal_telemetry` |
| **A** | [**ExoneraTor (Tor Historical Relay Archive)**](https://metrics.torproject.org/exonerator.html) ([GitHub](https://github.com/torproject/exonerator)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `ip` → `opsec_protection, whois` |

### [Tor Metrics — Relay & Bridge Search](https://metrics.torproject.org/rs.html) `[S-Tier]`
- **ID**: `tor-metrics-relay-search` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`torproject/tor`](https://github.com/torproject/tor)
- **Inputs**: `ip`, `asn`, `keyword` → **Outputs**: `opsec_protection`, `whois`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `tor-exit-nodes`, `exonerator`, `relay-families`, `log-triage`, `flagship`
- **Overview**: Official Tor Project directory and ExoneraTor historical lookup confirming whether an IPv4/IPv6 address was operating as a Tor Exit, Guard, or Middle relay on any specific UTC date!
- **Quick-Start / Tradecraft**: `Use ExoneraTor (`metrics.torproject.org/exonerator.html`) to prove whether a suspect IP was a Tor Exit node on a historic date.`

### [ExoneraTor (Tor Historical Relay Archive)](https://metrics.torproject.org/exonerator.html) `[A-Tier]`
- **ID**: `exonerator` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`torproject/exonerator`](https://github.com/torproject/exonerator)
- **Inputs**: `ip` → **Outputs**: `opsec_protection`, `whois`
- **Platforms**: Web · **Tags**: `historical-tor-exits`, `consensus-archive`, `log-forensics`, `tor-project`
- **Overview**: Queries historical Tor network consensus archives back to 2010 to verify definitively whether an IPv4 or IPv6 address was a public Tor relay or exit node on any UTC date.
- **Quick-Start / Tradecraft**: `Enter an incident IP + UTC date on https://metrics.torproject.org/exonerator.html during log attribution.`

---

## PGP & Cryptographic Attribution

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**GnuPG (`gpg`) & pgpdump Packet Inspector**](https://gnupg.org/) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, email, keyword` → `metadata, emails, certificates` |
| **A** | [**keys.openpgp.org & Ubuntu Keyserver**](https://keys.openpgp.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `email, keyword, username` → `emails, person_records, certificates` |

### [GnuPG (`gpg`) & pgpdump Packet Inspector](https://gnupg.org/) `[A-Tier]`
- **ID**: `kleopatra-gnupg` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `document`, `email`, `keyword` → **Outputs**: `metadata`, `emails`, `certificates`, `person_records`
- **Platforms**: Linux, macOS, Windows, Web · **Tags**: `pgp-forensics`, `packet-inspection`, `darknet-attribution`, `photo-uid`
- **Overview**: Command-line OpenPGP packet analyzer (`gpg --list-packets` / `pgpdump`) extracting embedded key creation UTC timestamps, preferred cipher suites, photo IDs, and historical cross-signer key IDs!
- **Quick-Start / Tradecraft**: `gpg --list-packets pubkey.asc  # Inspect exact Unix creation second, client version header, and secondary UIDs!`

### [keys.openpgp.org & Ubuntu Keyserver](https://keys.openpgp.org/) `[A-Tier]`
- **ID**: `keys-openpgp-org` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email`, `keyword`, `username` → **Outputs**: `emails`, `person_records`, `certificates`
- **Platforms**: Web, CLI · **Tags**: `pgp-keys`, `key-fingerprint`, `darknet-vendors`, `uid-emails`, `attribution`
- **Overview**: Public OpenPGP cryptographic keyservers (`keys.openpgp.org` and `keyserver.ubuntu.com`) indexing PGP public keys, creation timestamps, UID email aliases, and web-of-trust cross-signatures.
- **Quick-Start / Tradecraft**: `gpg --keyserver hkps://keyserver.ubuntu.com --search-keys target@example.com  # Ubuntu keyserver retains unverified historical UIDs!`

---

## Hidden Service OPSEC Auditing

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**OnionScan / Onion-Location Deanonymization Checks**](https://github.com/s-rah/onionscan) ([GitHub](https://github.com/s-rah/onionscan)) | CLI | OSS / Free | 🔴 Active | ✅ | `onion_url` → `ip_addresses, certificates, metadata` |
| **B** | [**Daunt.link (Signed Tor Mirror Verification)**](https://daunt.link/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `onion_url, keyword` → `certificates, opsec_protection` |
| **B** | [**Tor.taxi Signed Darknet Directory**](https://tor.taxi/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `onion_url, keyword` → `urls, certificates` |

### [OnionScan / Onion-Location Deanonymization Checks](https://github.com/s-rah/onionscan) `[A-Tier]`
- **ID**: `onionscan` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`s-rah/onionscan`](https://github.com/s-rah/onionscan)
- **Inputs**: `onion_url` → **Outputs**: `ip_addresses`, `certificates`, `metadata`, `open_ports`
- **Platforms**: Linux, Docker, Go · **Tags**: `hidden-service-audit`, `ssh-fingerprint-pivot`, `apache-status`, `deanonymization`
- **Overview**: Classic hidden-service OPSEC auditing tool hunting misconfigurations that deanonymize `.onion` servers—exposed Apache `server-status`, SSH host key reuse against Shodan, EXIF metadata, and open SMTP headers.
- **Quick-Start / Tradecraft**: `Extract a hidden service's SSH/TLS public key fingerprint via Tor and search that exact hash passively in Shodan & Censys!`

### [Daunt.link (Signed Tor Mirror Verification)](https://daunt.link/) `[B-Tier]`
- **ID**: `daunt-link` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `onion_url`, `keyword` → **Outputs**: `certificates`, `opsec_protection`
- **Platforms**: Web · **Tags**: `pgp-verification`, `anti-phishing-mirrors`, `dread-forum`, `onion-authenticity`
- **Overview**: Publishes PGP-verified canonical `.onion` addresses and cryptographic mirror proofs for major darknet forums such as Dread—preventing investigators from landing on MITM phishing clones.
- **Quick-Start / Tradecraft**: `Always verify PGP-signed `mirrors.txt` signatures with `gpg --verify` inside Whonix before viewing any forum onion.`

### [Tor.taxi Signed Darknet Directory](https://tor.taxi/) `[B-Tier]`
- **ID**: `onionshare-metadata-check` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `onion_url`, `keyword` → **Outputs**: `urls`, `certificates`
- **Platforms**: Web · **Tags**: `onion-v3-directory`, `anti-phishing`, `pgp-keys`
- **Overview**: Clearnet/onion gateway directory publishing verified `.onion` v3 addresses and PGP keys for major darknet communication and research services to prevent typoquatting.
- **Quick-Start / Tradecraft**: `Never trust unverified `.onion` links pasted on Reddit/X; always cross-check PGP-signed canonical mirrors.`

---

## Alternative Darknets

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Hyphanet (formerly Freenet) & ZeroNet Archives**](https://www.hyphanet.org/) ([GitHub](https://github.com/hyphanet/fred)) | Framework | OSS / Free | 🔴 Active | ✅ | `keyword` → `darkweb_mentions, archived_pages` |
| **B** | [**I2P (Invisible Internet Project)**](https://geti2p.net/) ([GitHub](https://github.com/PurpleI2P/i2pd)) | Framework | OSS / Free | 🔴 Active | ✅ | `keyword` → `darkweb_mentions, opsec_protection` |

### [Hyphanet (formerly Freenet) & ZeroNet Archives](https://www.hyphanet.org/) `[B-Tier]`
- **ID**: `hyphanet-freenet` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`hyphanet/fred`](https://github.com/hyphanet/fred)
- **Inputs**: `keyword` → **Outputs**: `darkweb_mentions`, `archived_pages`
- **Platforms**: Linux, macOS, Windows · **Tags**: `decentralized-darknet`, `freesites`, `p2p-storage`
- **Overview**: Decentralized censorship-resistant peer-to-peer distributed datastore hosting persistent `USK@`/`CHK@` freesites and message boards outside both DNS and Tor.
- **Quick-Start / Tradecraft**: `Run strictly inside an isolated VM with Opennet mode if investigating legacy Freenet/ZeroNet artifacts.`

### [I2P (Invisible Internet Project)](https://geti2p.net/) `[B-Tier]`
- **ID**: `i2p-network` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`PurpleI2P/i2pd`](https://github.com/PurpleI2P/i2pd)
- **Inputs**: `keyword` → **Outputs**: `darkweb_mentions`, `opsec_protection`
- **Platforms**: Linux, macOS, Windows, Docker · **Tags**: `i2p`, `eepsites`, `garlic-routing`, `i2pd`
- **Overview**: Garlic-routed peer-to-peer anonymous overlay network hosting `.i2p` eepsites, forums, and trackers increasingly favored as fallback infrastructure when Tor hidden services face DDoS.
- **Quick-Start / Tradecraft**: `Run lightweight C++ `i2pd` router inside an isolated disposable VM when investigating `.i2p` fallback mirrors.`

---
[⬅️ Back to Master Index](../README.md) · [◀ ⛓️ Crypto & Blockchain OSINT](./15-crypto-blockchain-web3.md) · [🛡️ Threat Intel, Malware & IOCs ▶](./17-threat-intel-malware-cti.md)

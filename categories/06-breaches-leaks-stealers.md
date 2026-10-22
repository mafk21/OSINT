[⬅️ Back to Master Index](../README.md) · [◀ 🪪 People & Public Records](./05-people-public-records.md) · [🌐 Domains, DNS & ASM ▶](./07-domain-dns-asm.md)

# 🔓 06. Data Breaches, Infostealer Logs, Paste Sites & Leak Archives (`BREACHINT`)

> **Scope**: Historical credential breach indexes, infostealer malware infection telemetry, public whistleblowing document troves, ransomware leak trackers, and paste-site monitors.
>
> **OPSEC Advisory**: Verify legal authorization in your jurisdiction before downloading or querying raw credential dumps. Prefer metadata/exposure verification APIs (HIBP, Hudson Rock Cavalier, IntelX) over unvetted underground bots.

**Discipline Telemetry**: `23` Verified Tools · `6` S-Tier Flagships · `23` Passive · `11` Free/Open-Source

## Subcategories
- [Breach Exposure Indexes](#breach-exposure-indexes) (9)
- [Public-Interest Leak Archives](#public-interest-leak-archives) (3)
- [Infostealer Telemetry](#infostealer-telemetry) (3)
- [Darknet & Leak Search Engines](#darknet-leak-search-engines) (1)
- [Ransomware Extortion Trackers](#ransomware-extortion-trackers) (2)
- [Exposed Databases & Misconfigs](#exposed-databases-misconfigs) (1)
- [Paste & Snippet Archives](#paste-snippet-archives) (1)
- [Official Breach Disclosures](#official-breach-disclosures) (2)
- [Enterprise Identity & Breach Platforms](#enterprise-identity-breach-platforms) (1)

---

## Breach Exposure Indexes

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**DeHashed**](https://dehashed.com/) | Search Engine | Paid | 🟢 Passive | 🔑 | `email, username, ip` → `breach_records, emails, ip_addresses` |
| **S** | [**Have I Been Pwned (HIBP)**](https://haveibeenpwned.com/) ([GitHub](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)) | Web Platform | Freemium | 🟢 Passive | ✅ | `email, domain, file_hash` → `breach_records` |
| **A** | [**LeakCheck**](https://leakcheck.io/) ([GitHub](https://github.com/LeakCheck/leakcheck-api)) | Search Engine | Freemium | 🟢 Passive | 🔑 | `email, username, domain` → `breach_records, emails, usernames` |
| **A** | [**Pwned Passwords k-Anonymity API**](https://haveibeenpwned.com/Passwords) ([GitHub](https://github.com/HaveIBeenPwned/PwnedPasswordsAzureFunction)) | API / Service | OSS / Free | 🟢 Passive | ✅ | `file_hash` → `breach_records` |
| **B** | [**BreachDirectory**](https://breachdirectory.org/) | Search Engine | Freemium | 🟢 Passive | ✅ | `email, username, domain` → `breach_records` |
| **B** | [**Mozilla Monitor**](https://monitor.mozilla.org/) ([GitHub](https://github.com/mozilla/blurts-server)) | Web Platform | Freemium | 🟢 Passive | 🔑 | `email, person_name` → `breach_records, person_records` |
| **B** | [**pwnedOrNot**](https://github.com/thewhiteh4t/pwnedOrNot) ([GitHub](https://github.com/thewhiteh4t/pwnedOrNot)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `email, domain` → `breach_records` |
| **B** | [**Snusbase**](https://snusbase.com/) | Search Engine | Paid | 🟢 Passive | 🔑 | `email, username, ip` → `breach_records, ip_addresses, emails` |
| **B** | [**WhatBreach**](https://github.com/Ekultek/WhatBreach) ([GitHub](https://github.com/Ekultek/WhatBreach)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `email` → `breach_records` |

### [DeHashed](https://dehashed.com/) `[S-Tier]`
- **ID**: `dehashed` · **Type**: `Search Engine` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `email`, `username`, `ip`, `phone`, `domain`, `person_name`, `vin` → **Outputs**: `breach_records`, `emails`, `ip_addresses`, `usernames`
- **Platforms**: Web, CLI · **Tags**: `breach-correlation`, `wildcard-search`, `ip-pivot`, `hash-pivot`
- **Overview**: High-speed breach correlation search engine and REST API for authorized security researchers, supporting regex/wildcard pivoting across emails, usernames, IPs, phones, VINs, and password hashes.
- **Quick-Start / Tradecraft**: `Pivot from a breached email -> registration IP or password hash -> other accounts sharing that exact unique hash.`

### [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/) `[S-Tier]`
- **ID**: `have-i-been-pwned` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`HaveIBeenPwned/PwnedPasswordsDownloader`](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
- **Inputs**: `email`, `domain`, `file_hash` → **Outputs**: `breach_records`
- **Platforms**: Web · **Tags**: `troy-hunt`, `breach-check`, `pwned-passwords`, `k-anonymity`, `flagship`
- **Overview**: Troy Hunt's gold-standard breach exposure service indexing 17.8B+ compromised accounts across 1,000+ breaches, stealer logs, and pastes—without ever exposing raw victim passwords.
- **Quick-Start / Tradecraft**: `Check single emails free on web, verify owned domains for free org monitoring, or query Pwned Passwords via k-Anonymity SHA-1 prefix (`api.pwnedpasswords.com/range/5BAA6`).`

### [LeakCheck](https://leakcheck.io/) `[A-Tier]`
- **ID**: `leakcheck` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`LeakCheck/leakcheck-api`](https://github.com/LeakCheck/leakcheck-api)
- **Inputs**: `email`, `username`, `domain`, `phone`, `keyword` → **Outputs**: `breach_records`, `emails`, `usernames`
- **Platforms**: Web, Python, CLI · **Tags**: `7.5b-records`, `domain-breach-audit`, `stealer-logs`, `api`
- **Overview**: Breach search engine indexing 7.5B+ records across 3,000+ leaked databases and stealer logs, searchable by email, username, corporate domain, phone, or keyword.
- **Quick-Start / Tradecraft**: `pip install leakcheck && leakcheck-cli lookup user@example.com`

### [Pwned Passwords k-Anonymity API](https://haveibeenpwned.com/Passwords) `[A-Tier]`
- **ID**: `hibp-pwned-passwords-cli` · **Type**: `API / Service` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`HaveIBeenPwned/PwnedPasswordsAzureFunction`](https://github.com/HaveIBeenPwned/PwnedPasswordsAzureFunction)
- **Inputs**: `file_hash` → **Outputs**: `breach_records`
- **Platforms**: Web, CLI, Python · **Tags**: `k-anonymity`, `ntlm-sha1`, `zero-leak-opsec`, `cloudflare-worker`
- **Overview**: Keyless, zero-knowledge SHA-1/NTLM hash range API (`api.pwnedpasswords.com/range/<5-hex>`) checking 900M+ real-world leaked passwords without ever transmitting the full hash over the network!
- **Quick-Start / Tradecraft**: `SHA1=$(printf 'password123' | sha1sum | awk '{print toupper($1)}'); curl -s https://api.pwnedpasswords.com/range/${SHA1:0:5} | grep ${SHA1:5}`

### [BreachDirectory](https://breachdirectory.org/) `[B-Tier]`
- **ID**: `breachdirectory` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email`, `username`, `domain` → **Outputs**: `breach_records`
- **Platforms**: Web · **Tags**: `redacted-preview`, `sha1-correlation`, `free-tier`
- **Overview**: Public breach search engine revealing redacted password prefixes and SHA-1 hashes tied to compromised emails and usernames to verify identity continuity across sites.
- **Quick-Start / Tradecraft**: `Compare SHA-1 hash fingerprints across multiple handles to test whether the same person registered both accounts.`

### [Mozilla Monitor](https://monitor.mozilla.org/) `[B-Tier]`
- **ID**: `mozilla-monitor` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`mozilla/blurts-server`](https://github.com/mozilla/blurts-server)
- **Inputs**: `email`, `person_name` → **Outputs**: `breach_records`, `person_records`
- **Platforms**: Web · **Tags**: `self-osint`, `data-broker-removal`, `hibp`, `privacy-audit`
- **Overview**: Open-source personal data-broker and breach exposure checker backed by HIBP and US data-broker scan coverage for defensive self-OSINT audits.
- **Quick-Start / Tradecraft**: `Audit executive/investigator exposure on data-broker sites and breaches at https://monitor.mozilla.org/.`

### [pwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) `[B-Tier]`
- **ID**: `pwnedornot` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`thewhiteh4t/pwnedOrNot`](https://github.com/thewhiteh4t/pwnedOrNot)
- **Inputs**: `email`, `domain` → **Outputs**: `breach_records`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `hibp`, `paste-hunter`, `email-breaches`, `cli`
- **Overview**: Python OSINT CLI checking email breach metadata via HaveIBeenPwned v3 and hunting corresponding public Pastebin dumps.
- **Quick-Start / Tradecraft**: `python3 pwnedornot.py -e target@example.com`

### [Snusbase](https://snusbase.com/) `[B-Tier]`
- **ID**: `snusbase` · **Type**: `Search Engine` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `email`, `username`, `ip`, `person_name`, `domain` → **Outputs**: `breach_records`, `ip_addresses`, `emails`
- **Platforms**: Web · **Tags**: `breach-pivot`, `ip-correlation`, `hash-lookup`
- **Overview**: Indexed breach lookup service allowing investigators to pivot across emails, usernames, real names, registration IPs, and hashed/unhashed credentials.
- **Quick-Start / Tradecraft**: `Integrate API key with h8mail or query JSON endpoints for automated incident-response triage.`

### [WhatBreach](https://github.com/Ekultek/WhatBreach) `[B-Tier]`
- **ID**: `whatbreach` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`Ekultek/WhatBreach`](https://github.com/Ekultek/WhatBreach)
- **Inputs**: `email` → **Outputs**: `breach_records`
- **Platforms**: Linux, macOS, Python · **Tags**: `batch-email-check`, `hibp`, `paste-correlation`
- **Overview**: Python OSINT CLI correlating breached email addresses against HIBP, BreachDirectory/DeHashed metadata, and Pastebin dumps in batch mode.
- **Quick-Start / Tradecraft**: `python3 whatbreach.py -e target@example.com`

---

## Public-Interest Leak Archives

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Distributed Denial of Secrets (DDoSecrets)**](https://ddosecrets.com/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, email` → `corporate_records, emails, archived_pages` |
| **A** | [**WikiLeaks Public Library of US Diplomacy & Leaks**](https://search.wikileaks.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, email` → `corporate_records, emails, archived_pages` |
| **B** | [**Cryptome**](https://cryptome.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `keyword` → `archived_pages` |

### [Distributed Denial of Secrets (DDoSecrets)](https://ddosecrets.com/) `[S-Tier]`
- **ID**: `ddosecrets` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `email`, `keyword` → **Outputs**: `corporate_records`, `emails`, `archived_pages`
- **Platforms**: Web · **Tags**: `journalism`, `whistleblower-archives`, `public-interest-leaks`, `hunter-search`
- **Overview**: Non-profit journalist transparency collective curating and indexing terabytes of public-interest leaked corporate, government, financial, and oligarch document datasets.
- **Quick-Start / Tradecraft**: `Search indexed public-interest datasets via DDoSecrets or OCCRP Aleph cross-listings.`

### [WikiLeaks Public Library of US Diplomacy & Leaks](https://search.wikileaks.org/) `[A-Tier]`
- **ID**: `wikileaks-search` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `email`, `keyword` → **Outputs**: `corporate_records`, `emails`, `archived_pages`
- **Platforms**: Web · **Tags**: `diplomatic-cables`, `historical-leaks`, `geopolitics`, `full-text`
- **Overview**: Full-text diplomatic cable and historical leak search engine spanning PlusD diplomatic cables, Syria/HackingTeam/Sony/Vault7 archives, and defense procurement documents.
- **Quick-Start / Tradecraft**: `Use `search.wikileaks.org/advanced` filtered by dataset and date range for historical corporate/political vetting.`

### [Cryptome](https://cryptome.org/) `[B-Tier]`
- **ID**: `cryptome` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `archived_pages`
- **Platforms**: Web · **Tags**: `foia`, `declassified`, `sigint-history`, `primary-documents`
- **Overview**: Long-running open-source archive of declassified intelligence manuals, court exhibits, FOIA disclosures, satellite imagery guides, and telecommunications filings since 1996.
- **Quick-Start / Tradecraft**: `Search `site:cryptome.org <topic>` via Google or DuckDuckGo for primary government/telecom documents.`

---

## Infostealer Telemetry

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Hudson Rock — Cavalier Free OSINT Tools**](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | Web Platform | Freemium | 🟢 Passive | ✅ | `email, domain, username` → `breach_records, malware_iocs, tech_stack` |
| **A** | [**SOCRadar Free SOC Tools**](https://socradar.io/labs/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, email, ip` → `breach_records, darkweb_mentions, subdomains` |
| **A** | [**SpyCloud Cybercrime Exposure Check**](https://spycloud.com/check-your-exposure/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, email` → `breach_records, malware_iocs` |

### [Hudson Rock — Cavalier Free OSINT Tools](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) `[S-Tier]`
- **ID**: `hudson-rock-cavalier` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email`, `domain`, `username`, `ip` → **Outputs**: `breach_records`, `malware_iocs`, `tech_stack`
- **Platforms**: Web, Python · **Tags**: `infostealers`, `lumma`, `redline`, `compromised-endpoints`, `free-api`, `flagship`
- **Overview**: Global cybercrime intelligence engine fueled by millions of real-world RedLine, Lumma, Vidar, and Raccoon infostealer malware infections—checking compromised domains, emails, usernames, and IPs.
- **Quick-Start / Tradecraft**: `curl -s 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=test@example.com' | jq`

### [SOCRadar Free SOC Tools](https://socradar.io/labs/) `[A-Tier]`
- **ID**: `socradar-labs` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `email`, `ip` → **Outputs**: `breach_records`, `darkweb_mentions`, `subdomains`, `malware_iocs`
- **Platforms**: Web · **Tags**: `dark-web-exposure`, `stealer-check`, `cti-labs`, `free-tools`
- **Overview**: Suite of free external threat intelligence utilities including Dark Web Report, Stealer Log Domain Check, Phishing Radar, and External Attack Surface Mapper.
- **Quick-Start / Tradecraft**: `Run Account Breach & Dark Web Radar on a target corporate domain at https://socradar.io/labs/.`

### [SpyCloud Cybercrime Exposure Check](https://spycloud.com/check-your-exposure/) `[A-Tier]`
- **ID**: `spycloud-free-check` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `email` → **Outputs**: `breach_records`, `malware_iocs`
- **Platforms**: Web · **Tags**: `infostealer-stats`, `enterprise-exposure`, `session-hijacking`
- **Overview**: Enterprise infostealer and recaptured darknet credential intelligence vendor offering free domain-level exposure statistics (infected employees, infected consumers, reused passwords).
- **Quick-Start / Tradecraft**: `Enter any corporate domain on SpyCloud's free exposure checker to gauge recent stealer-log volume.`

---

## Darknet & Leak Search Engines

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) ([GitHub](https://github.com/IntelligenceX/SDK)) | Search Engine | Freemium | 🟢 Passive | ✅ | `email, domain, ip` → `breach_records, darkweb_mentions, emails` |

### [Intelligence X (IntelX)](https://intelx.io/) `[S-Tier]`
- **ID**: `intelligence-x` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`IntelligenceX/SDK`](https://github.com/IntelligenceX/SDK)
- **Inputs**: `email`, `domain`, `ip`, `phone`, `crypto_address`, `url`, `keyword` → **Outputs**: `breach_records`, `darkweb_mentions`, `emails`, `archived_pages`
- **Platforms**: Web, Python, CLI · **Tags**: `intelx`, `200b-records`, `paste-archive`, `tor-search`, `selector-search`, `flagship`
- **Overview**: Massive historical OSINT archive indexing 200B+ records across data leaks, Pastebin/paste sites, I2P/Tor darknets, WHOIS history, public documents, and DNS selectors.
- **Quick-Start / Tradecraft**: `Search emails, domains, BTC addresses, or CIDRs on https://intelx.io/ (50 free metadata/preview searches/day).`

---

## Ransomware Extortion Trackers

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**RansomLook**](https://www.ransomlook.io/) ([GitHub](https://github.com/RansomLook/RansomLook)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `company, domain, keyword` → `darkweb_mentions, breach_records, archived_pages` |
| **A** | [**ransomwatch**](https://ransomwhat.telemetry.ltd/) ([GitHub](https://github.com/joshhighet/ransomwatch)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `company, keyword` → `darkweb_mentions, breach_records` |

### [RansomLook](https://www.ransomlook.io/) `[S-Tier]`
- **ID**: `ransomlook` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`RansomLook/RansomLook`](https://github.com/RansomLook/RansomLook)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `darkweb_mentions`, `breach_records`, `archived_pages`
- **Platforms**: Web, Docker, Python · **Tags**: `ransomware`, `extortion-sites`, `leak-tracker`, `open-source`, `rest-api`
- **Overview**: 100% open-source ransomware intelligence platform scraping, screenshotting, and indexing 100+ ransomware extortion `.onion` leak portals, Telegram channels, and victim posts on the clearnet.
- **Quick-Start / Tradecraft**: `curl -s https://www.ransomlook.io/api/recent | jq  # Query ransomware victims without touching Tor`

### [ransomwatch](https://ransomwhat.telemetry.ltd/) `[A-Tier]`
- **ID**: `ransomwatch` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`joshhighet/ransomwatch`](https://github.com/joshhighet/ransomwatch)
- **Inputs**: `company`, `keyword` → **Outputs**: `darkweb_mentions`, `breach_records`
- **Platforms**: Web, Python · **Tags**: `ransomware-groups`, `json-feed`, `darknet-mirrors`, `cti`
- **Overview**: Open-source tracker monitoring ransomware gang darknet leak sites and publishing machine-readable JSON feeds of active extortion groups, onion mirror uptime, and claimed victims.
- **Quick-Start / Tradecraft**: `curl -s https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json | jq '.[-5:]'`

---

## Exposed Databases & Misconfigs

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**LeakIX**](https://leakix.net/) ([GitHub](https://github.com/LeakIX/l9format)) | Search Engine | Freemium | 🟢 Passive | ✅ | `ip, domain, asn` → `open_ports, secrets, breach_records` |

### [LeakIX](https://leakix.net/) `[A-Tier]`
- **ID**: `leakix` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`LeakIX/l9format`](https://github.com/LeakIX/l9format)
- **Inputs**: `ip`, `domain`, `asn`, `keyword` → **Outputs**: `open_ports`, `secrets`, `breach_records`, `tech_stack`
- **Platforms**: Web, Go, CLI · **Tags**: `exposed-git`, `open-databases`, `misconfigurations`, `easm`
- **Overview**: Continuous internet-wide indexer flagging misconfigured open databases (Elastic, Mongo, CouchDB, Redis), exposed `.git`/`.env` files, and vulnerable web services with responsible disclosure focus.
- **Quick-Start / Tradecraft**: `Search `+domain:"example.com"` or `+plugin:GitConfigHttpPlugin` passively on https://leakix.net/.`

---

## Paste & Snippet Archives

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Psbdmp**](https://psbdmp.ws/) | Search Engine | Free | 🟢 Passive | ✅ | `email, domain, keyword` → `breach_records, archived_pages` |

### [Psbdmp](https://psbdmp.ws/) `[A-Tier]`
- **ID**: `psbdmp` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email`, `domain`, `keyword` → **Outputs**: `breach_records`, `archived_pages`
- **Platforms**: Web · **Tags**: `pastebin-archive`, `deleted-pastes`, `free-api`, `leak-monitoring`
- **Overview**: Searchable archive of millions of scraped Pastebin dumps with a free REST API for hunting leaked emails, domains, configs, and dox pastes that were later deleted from Pastebin.
- **Quick-Start / Tradecraft**: `curl -s 'https://psbdmp.ws/api/v3/search/example.com' | jq`

---

## Official Breach Disclosures

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**SEC Item 1.05 Material Cybersecurity Incident Filings**](https://www.sec.gov/edgar/search/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `breach_records, corporate_records, documents` |
| **A** | [**State AG Official Data Breach Portals (CA / ME / HHS OCR)**](https://oag.ca.gov/privacy/databreach/list) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `breach_records, corporate_records, documents` |

### [SEC Item 1.05 Material Cybersecurity Incident Filings](https://www.sec.gov/edgar/search/) `[A-Tier]`
- **ID**: `sec-8k-item105` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `breach_records`, `corporate_records`, `documents`
- **Platforms**: Web · **Tags**: `sec-8k`, `item-1.05`, `cyber-incident-filings`, `authoritative`
- **Overview**: Public companies traded in the US must disclose material cybersecurity breaches on Form 8-K Item 1.05 within 4 business days—providing authoritative primary-source incident intelligence.
- **Quick-Start / Tradecraft**: `Search `"Item 1.05"` on SEC EDGAR Full-Text Search (`sec.gov/edgar/search/`) filtered to Form `8-K`.`

### [State AG Official Data Breach Portals (CA / ME / HHS OCR)](https://oag.ca.gov/privacy/databreach/list) `[A-Tier]`
- **ID**: `california-ag-breaches` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `breach_records`, `corporate_records`, `documents`
- **Platforms**: Web · **Tags**: `official-breach-notices`, `maine-ag`, `hhs-wall-of-shame`, `incident-dates`
- **Overview**: Mandatory government breach notification registries (California OAG, Maine AG—shows exact victim headcount & attack vector!, and US HHS OCR 'Wall of Shame' healthcare breaches) with official notification letters!
- **Quick-Start / Tradecraft**: `Search Maine AG (`apps.web.maine.gov/online/aeviewer/ME/40/list.shtml`) & CA OAG to get exact incident dates and forensic breach PDFs!`

---

## Enterprise Identity & Breach Platforms

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Constella Intelligence**](https://constella.ai/) | Web Platform | Paid | 🟢 Passive | 🔑 | `email, username, phone` → `breach_records, person_records, entity_graph` |

### [Constella Intelligence](https://constella.ai/) `[B-Tier]`
- **ID**: `constella-intelligence` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `email`, `username`, `phone`, `person_name`, `ip` → **Outputs**: `breach_records`, `person_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `enterprise-breach-lake`, `fraud-attribution`, `executive-protection`
- **Overview**: Enterprise digital-risk and identity-breach lake indexing 100B+ breach attributes for executive protection, fraud attribution, and law-enforcement correlation.
- **Quick-Start / Tradecraft**: `Used by enterprise CTI and financial-crime units for historical selector linking.`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🪪 People & Public Records](./05-people-public-records.md) · [🌐 Domains, DNS & ASM ▶](./07-domain-dns-asm.md)

[⬅️ Back to Master Index](../README.md) · [◀ 🧰 Frameworks & Link Analysis](./01-all-in-one-frameworks.md) · [📧 Email Intelligence ▶](./03-email-intelligence.md)

# 🕵️ 02. Username Enumeration & Digital Footprint Mapping (`USERINT`)

> **Scope**: Cross-platform handle discovery engines, profile metadata extractors, and account correlation datasets spanning 500 to 6,000+ social networks, forums, and developer platforms.
>
> **OPSEC Advisory**: Username scanners generate high-volume HTTP requests from your IP to hundreds of platforms; route scans through a VPN/Tor or residential proxy pool and manually verify hits to rule out handle collisions.

**Discipline Telemetry**: `29` Verified Tools · `4` S-Tier Flagships · `26` Passive · `27` Free/Open-Source

## Subcategories
- [CLI Handle Scanners](#cli-handle-scanners) (8)
- [Dossier Builders & Deep Scanners](#dossier-builders-deep-scanners) (2)
- [Web Scanners & Datasets](#web-scanners-datasets) (6)
- [Cryptographic Identity Pivots](#cryptographic-identity-pivots) (2)
- [Gaming Handle Intelligence](#gaming-handle-intelligence) (4)
- [Regional & Global Scanners](#regional-global-scanners) (1)
- [Profile Metadata Parsers](#profile-metadata-parsers) (1)
- [Search-Engine Handle Discovery](#search-engine-handle-discovery) (1)
- [Multi-Selector Suites](#multi-selector-suites) (1)
- [Developer Handle Profiling](#developer-handle-profiling) (1)
- [Automated Browser Correlation](#automated-browser-correlation) (1)
- [Corporate Handle Permutations](#corporate-handle-permutations) (1)

---

## CLI Handle Scanners

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Blackbird**](https://github.com/p1ngul1n0/blackbird) ([GitHub](https://github.com/p1ngul1n0/blackbird)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username, email` → `social_profiles, metadata` |
| **S** | [**Sherlock**](https://github.com/sherlock-project/sherlock) ([GitHub](https://github.com/sherlock-project/sherlock)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |
| **A** | [**GoSearch**](https://github.com/ibnaleem/gosearch) ([GitHub](https://github.com/ibnaleem/gosearch)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles, breach_records` |
| **A** | [**user-scanner**](https://github.com/kaifcodec/user-scanner) ([GitHub](https://github.com/kaifcodec/user-scanner)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username, email` → `social_profiles, emails` |
| **B** | [**Aliens_eye**](https://github.com/arxhr007/Aliens_eye) ([GitHub](https://github.com/arxhr007/Aliens_eye)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |
| **B** | [**Nexfil**](https://github.com/thewhiteh4t/nexfil) ([GitHub](https://github.com/thewhiteh4t/nexfil)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |
| **B** | [**socialscan**](https://github.com/iojw/socialscan) ([GitHub](https://github.com/iojw/socialscan)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username, email` → `social_profiles` |
| **B** | [**Tookie-OSINT**](https://github.com/Alfredredbird/tookie-osint) ([GitHub](https://github.com/Alfredredbird/tookie-osint)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |

### [Blackbird](https://github.com/p1ngul1n0/blackbird) `[S-Tier]`
- **ID**: `blackbird` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`p1ngul1n0/blackbird`](https://github.com/p1ngul1n0/blackbird)
- **Inputs**: `username`, `email` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `async`, `username-and-email`, `pdf-export`, `web-gui`
- **Overview**: Fast asynchronous OSINT tool searching accounts by both username and email across 600+ sites, featuring WhatsMyName integration, AI profile metadata extraction, web UI, and PDF reporting.
- **Quick-Start / Tradecraft**: `python3 blackbird.py -u target_handle --pdf`

### [Sherlock](https://github.com/sherlock-project/sherlock) `[S-Tier]`
- **ID**: `sherlock` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`sherlock-project/sherlock`](https://github.com/sherlock-project/sherlock)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `username`, `handle-search`, `social-networks`, `tor-support`, `flagship`
- **Overview**: The most widely used open-source Python CLI for hunting down social media and forum accounts by username across 400+ curated websites simultaneously, with Tor/proxy and CSV/JSON export support.
- **Quick-Start / Tradecraft**: `pipx install sherlock-project && sherlock --timeout 10 --csv target_handle`

### [GoSearch](https://github.com/ibnaleem/gosearch) `[A-Tier]`
- **ID**: `gosearch` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ibnaleem/gosearch`](https://github.com/ibnaleem/gosearch)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `breach_records`
- **Platforms**: Linux, macOS, Windows, Go · **Tags**: `golang`, `fast`, `concurrent`, `hudson-rock`, `username`
- **Overview**: Blazingly fast concurrent Go CLI scanner checking 300+ websites for a target's digital footprint alongside optional Hudson Rock cybercrime/infostealer correlation and BreachDirectory checks.
- **Quick-Start / Tradecraft**: `gosearch -u target_handle --no-false-positives`

### [user-scanner](https://github.com/kaifcodec/user-scanner) `[A-Tier]`
- **ID**: `user-scanner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`kaifcodec/user-scanner`](https://github.com/kaifcodec/user-scanner)
- **Inputs**: `username`, `email` → **Outputs**: `social_profiles`, `emails`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `mcp-ready`, `2500-vectors`, `username`, `email-osint`
- **Overview**: 2-in-1 Email and Username OSINT suite with native Model Context Protocol (MCP) support scanning 2,500+ username vectors and 200+ email registration vectors for deep digital footprinting.
- **Quick-Start / Tradecraft**: `pip install user-scanner && user-scanner -u target_handle`

### [Aliens_eye](https://github.com/arxhr007/Aliens_eye) `[B-Tier]`
- **ID**: `aliens-eye` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`arxhr007/Aliens_eye`](https://github.com/arxhr007/Aliens_eye)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Python · **Tags**: `multithreaded`, `800-sites`, `username-scanner`
- **Overview**: Multi-threaded Python username discovery engine scanning 800+ social media and community websites with JSON/HTML report generation.
- **Quick-Start / Tradecraft**: `aliens_eye target_handle`

### [Nexfil](https://github.com/thewhiteh4t/nexfil) `[B-Tier]`
- **ID**: `nexfil` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`thewhiteh4t/nexfil`](https://github.com/thewhiteh4t/nexfil)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `asyncio`, `fast-enum`, `username`, `cli`
- **Overview**: Asynchronous Python CLI tool engineered to hunt user profiles across 350+ URLs in seconds using custom timeout tuning and status/redirect verification.
- **Quick-Start / Tradecraft**: `python3 nexfil.py -u target_handle`

### [socialscan](https://github.com/iojw/socialscan) `[B-Tier]`
- **ID**: `socialscan` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`iojw/socialscan`](https://github.com/iojw/socialscan)
- **Inputs**: `username`, `email` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `library`, `accurate`, `email-and-username`, `bulk-check`
- **Overview**: High-accuracy Python CLI and library checking both username availability and email registration simultaneously across key platforms (GitHub, Instagram, Reddit, Tumblr, Yahoo, GitLab, Last.fm).
- **Quick-Start / Tradecraft**: `pip install socialscan && socialscan target_handle user@example.com`

### [Tookie-OSINT](https://github.com/Alfredredbird/tookie-osint) `[B-Tier]`
- **ID**: `tookie-osint` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Alfredredbird/tookie-osint`](https://github.com/Alfredredbird/tookie-osint)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `username`, `cli`, `proxy-support`, `footprint`
- **Overview**: Python CLI handle enumerator with site-list auto-updates, proxy support, and scraping helpers for uncovering social media footprints.
- **Quick-Start / Tradecraft**: `python3 brib.py -u target_handle`

---

## Dossier Builders & Deep Scanners

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Maigret**](https://github.com/soxoj/maigret) ([GitHub](https://github.com/soxoj/maigret)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles, person_records, metadata` |
| **A** | [**Social Analyzer**](https://github.com/qeeqbox/social-analyzer) ([GitHub](https://github.com/qeeqbox/social-analyzer)) | Framework | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles, metadata, entity_graph` |

### [Maigret](https://github.com/soxoj/maigret) `[S-Tier]`
- **ID**: `maigret` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`soxoj/maigret`](https://github.com/soxoj/maigret)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `person_records`, `metadata`, `entity_graph`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `username-dossier`, `recursive-pivoting`, `html-report`, `xmind`, `3000-sites`
- **Overview**: Advanced username dossier builder checking 3,000+ websites, parsing discovered profile pages to extract real names, bios, avatars, linked handles, and generating self-contained HTML/PDF/XMind reports.
- **Quick-Start / Tradecraft**: `pipx install maigret && maigret target_handle --html --top-sites 500`

### [Social Analyzer](https://github.com/qeeqbox/social-analyzer) `[A-Tier]`
- **ID**: `social-analyzer` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`qeeqbox/social-analyzer`](https://github.com/qeeqbox/social-analyzer)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `metadata`, `entity_graph`
- **Platforms**: Linux, macOS, Windows, Docker, Node.js, Python · **Tags**: `1000-sites`, `confidence-score`, `ocr`, `web-ui`, `cli`
- **Overview**: API, CLI, and Web App detecting and scoring a target's profile presence across 1,000+ social media websites with language detection, OCR, metadata extraction, and confidence scoring.
- **Quick-Start / Tradecraft**: `npx social-analyzer --username "target_handle" --metadata`

---

## Web Scanners & Datasets

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**WhatsMyName**](https://whatsmyname.app/) ([GitHub](https://github.com/WebBreacher/WhatsMyName)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |
| **B** | [**IDCrawl**](https://www.idcrawl.com/username) | Web Platform | Free | 🟢 Passive | ✅ | `username, person_name` → `social_profiles, person_records` |
| **B** | [**Instant Username Search**](https://instantusername.com/) ([GitHub](https://github.com/saleiva/instant-username-search)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |
| **B** | [**KnowEm**](https://knowem.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `username, company` → `social_profiles, corporate_records` |
| **B** | [**Namechk**](https://namechk.com/) | Web Platform | Free | 🟢 Passive | ✅ | `username, domain` → `social_profiles` |
| **B** | [**UserSearch.org**](https://usersearch.org/) | Web Platform | Freemium | 🟢 Passive | ✅ | `username, email, phone` → `social_profiles` |

### [WhatsMyName](https://whatsmyname.app/) `[S-Tier]`
- **ID**: `whatsmyname` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`WebBreacher/WhatsMyName`](https://github.com/WebBreacher/WhatsMyName)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Web, Python · **Tags**: `whatsmyname`, `low-false-positive`, `web-app`, `dataset`, `handle-recon`
- **Overview**: Community-maintained JSON detection standard (`wmn-data.json`) and instant browser web app checking 700+ sites with finely tuned HTTP status/response fingerprints to minimize false positives.
- **Quick-Start / Tradecraft**: `Visit https://whatsmyname.app/ and filter by category (Coding, Gaming, Social, Finance) or consume wmn-data.json.`

### [IDCrawl](https://www.idcrawl.com/username) `[B-Tier]`
- **ID**: `idcrawl` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `person_name` → **Outputs**: `social_profiles`, `person_records`
- **Platforms**: Web · **Tags**: `people-search`, `username-aggregator`, `no-signup`
- **Overview**: Free aggregator searching a username or full person name across major social networks, deep web profiles, and US public directories.
- **Quick-Start / Tradecraft**: `Query https://www.idcrawl.com/username with a handle to cross-check mainstream social profiles.`

### [Instant Username Search](https://instantusername.com/) `[B-Tier]`
- **ID**: `instant-username-search` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`saleiva/instant-username-search`](https://github.com/saleiva/instant-username-search)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Web · **Tags**: `real-time`, `browser-based`, `no-login`, `handle-check`
- **Overview**: Open-source, real-time browser username checker probing 100+ popular social, gaming, creative, and tech platforms as you type.
- **Quick-Start / Tradecraft**: `Search https://instantusername.com/#/target_handle for immediate browser-side checks.`

### [KnowEm](https://knowem.com/) `[B-Tier]`
- **ID**: `knowem` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `company` → **Outputs**: `social_profiles`, `corporate_records`
- **Platforms**: Web · **Tags**: `500-networks`, `brand-handles`, `trademark-check`
- **Overview**: Checks handle and brand name registration across 500+ social networks, blogging platforms, microblogs, and USPTO trademark records.
- **Quick-Start / Tradecraft**: `Run category-grouped handle checks across 500+ platforms on https://knowem.com/.`

### [Namechk](https://namechk.com/) `[B-Tier]`
- **ID**: `namechk` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `domain` → **Outputs**: `social_profiles`
- **Platforms**: Web · **Tags**: `availability-check`, `web-tool`, `quick-triage`, `domains`
- **Overview**: Instant web-based username and domain availability checker scanning dozens of major social networks, developer portals, and TLDs side-by-side.
- **Quick-Start / Tradecraft**: `Enter a target handle on https://namechk.com/—greyed/taken badges indicate potential existing accounts.`

### [UserSearch.org](https://usersearch.org/) `[B-Tier]`
- **ID**: `usersearch-org` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `email`, `phone` → **Outputs**: `social_profiles`
- **Platforms**: Web · **Tags**: `forums`, `dating-sites`, `reverse-username`, `web-portal`
- **Overview**: Web-based reverse username, email, and dating/forum handle search portal covering 600+ social networks, community forums, crypto discussions, and niche sites.
- **Quick-Start / Tradecraft**: `Run a free multi-category handle sweep at https://usersearch.org/.`

---

## Cryptographic Identity Pivots

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Gravatar Hash & Profile Lookup**](https://gravatar.com/) | API / Service | Free | 🟢 Passive | ✅ | `email, username` → `social_profiles, person_records, metadata` |
| **A** | [**Keybase Identity Graph**](https://keybase.io/) | Web Platform | Free | 🟢 Passive | ✅ | `username, domain, crypto_address` → `social_profiles, certificates, entity_graph` |

### [Gravatar Hash & Profile Lookup](https://gravatar.com/) `[A-Tier]`
- **ID**: `gravatar-lookup` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email`, `username` → **Outputs**: `social_profiles`, `person_records`, `metadata`
- **Platforms**: Web · **Tags**: `md5-hash`, `sha256`, `avatar-pivot`, `email-to-handle`
- **Overview**: Global avatar and identity profile service keyed by MD5/SHA-256 of lowercase trimmed email addresses (`gravatar.com/<hash>.json`), frequently exposing display names, handles, photos, and verified accounts.
- **Quick-Start / Tradecraft**: `python3 -c "import hashlib; h=hashlib.md5(b'user@example.com').hexdigest(); print(f'https://gravatar.com/{h}.json')"`

### [Keybase Identity Graph](https://keybase.io/) `[A-Tier]`
- **ID**: `keybase-lookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `domain`, `crypto_address` → **Outputs**: `social_profiles`, `certificates`, `entity_graph`
- **Platforms**: Web, Linux, macOS, Windows · **Tags**: `pgp`, `cryptographic-proofs`, `developer-attribution`, `identity-graph`
- **Overview**: Cryptographically signed public identity directory where developers and security researchers prove ownership of linked X, GitHub, Reddit, HackerNews, domains, PGP keys, and BTC/ZEC wallets.
- **Quick-Start / Tradecraft**: `curl -s 'https://keybase.io/_/api/1.0/user/lookup.json?usernames=target_handle' | jq`

---

## Gaming Handle Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**NameMC**](https://namemc.com/) | Web Platform | Free | 🟢 Passive | ✅ | `username` → `social_profiles, metadata` |
| **A** | [**SteamID.uk / SteamID.io**](https://steamid.io/) | Web Platform | Free | 🟢 Passive | ✅ | `username, url` → `social_profiles, metadata, entity_graph` |
| **B** | [**Tracker.gg**](https://tracker.gg/) | Web Platform | Free | 🟢 Passive | ✅ | `username` → `social_profiles, metadata` |
| **B** | [**XboxGamertag & PSNProfiles**](https://psnprofiles.com/) | Web Platform | Free | 🟢 Passive | ✅ | `username` → `social_profiles, metadata` |

### [NameMC](https://namemc.com/) `[A-Tier]`
- **ID**: `namemc` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `gaming-osint`, `minecraft`, `uuid`, `historical-usernames`
- **Overview**: Tracks Minecraft Java UUIDs and complete historical username changes over time, frequently bridging an anonymous gamer's current online handle back to childhood/real-name handles.
- **Quick-Start / Tradecraft**: `Search a handle on https://namemc.com/ to inspect permanent account UUID and past handle history.`

### [SteamID.uk / SteamID.io](https://steamid.io/) `[A-Tier]`
- **ID**: `steamid-uk` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `url` → **Outputs**: `social_profiles`, `metadata`, `entity_graph`
- **Platforms**: Web · **Tags**: `gaming-osint`, `steam`, `alias-history`, `friend-graph`
- **Overview**: Resolves Steam vanity URLs, SteamID64 identifiers, historical display-name aliases, friend graphs, and account creation dates—invaluable when targets reuse gaming handles.
- **Quick-Start / Tradecraft**: `Paste any Steam profile URL or handle into https://steamid.io/ to get immutable SteamID64 and alias history.`

### [Tracker.gg](https://tracker.gg/) `[B-Tier]`
- **ID**: `tracker-gg` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `gaming-osint`, `activity-timestamps`, `pattern-of-life`, `xbox-psn`
- **Overview**: Cross-platform gaming telemetry aggregator indexing Riot ID, PSN, Xbox Live, Steam, Epic, Battle.net, and match timestamps—useful for establishing target online/sleep timezone patterns.
- **Quick-Start / Tradecraft**: `Look up a handle across Riot/Xbox/PSN/Steam on https://tracker.gg to infer active hours and linked accounts.`

### [XboxGamertag & PSNProfiles](https://psnprofiles.com/) `[B-Tier]`
- **ID**: `xbox-gamertag-lookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `psn-osint`, `trophy-timestamps`, `pattern-of-life`, `gaming-recon`
- **Overview**: Public PlayStation Network (`psnprofiles.com`) and Xbox Live trophy/achievement timelines exposing exact game unlock timestamps (waking/timezone patterns) and cross-linked social handles.
- **Quick-Start / Tradecraft**: `Plot multi-month PSN trophy unlock timestamps in UTC to determine a target's local sleep window and vacation dates!`

---

## Regional & Global Scanners

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Snoop Project**](https://github.com/snooppr/snoop) ([GitHub](https://github.com/snooppr/snoop)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |

### [Snoop Project](https://github.com/snooppr/snoop) `[A-Tier]`
- **ID**: `snoop` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`snooppr/snoop`](https://github.com/snooppr/snoop)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Linux, Windows, Python · **Tags**: `cis-osint`, `regional-forums`, `username`, `high-coverage`
- **Overview**: High-coverage OSINT username tracker indexing thousands of global and CIS/Eastern European forums, marketplaces, and regional social networks missed by Western-only scanners.
- **Quick-Start / Tradecraft**: `snoop_cli -t 9 target_handle`

---

## Profile Metadata Parsers

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**SocID Extractor**](https://github.com/soxoj/socid-extractor) ([GitHub](https://github.com/soxoj/socid-extractor)) | CLI | OSS / Free | 🟢 Passive | ✅ | `url, username` → `social_profiles, metadata, person_records` |

### [SocID Extractor](https://github.com/soxoj/socid-extractor) `[A-Tier]`
- **ID**: `socid-extractor` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`soxoj/socid-extractor`](https://github.com/soxoj/socid-extractor)
- **Inputs**: `url`, `username` → **Outputs**: `social_profiles`, `metadata`, `person_records`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `uid-extraction`, `profile-parser`, `maigret-engine`, `hidden-attributes`
- **Overview**: Profile parsing library and CLI powering Maigret that extracts hidden internal numeric user IDs, creation dates, avatars, and linked accounts from HTML/JSON responses across 150+ platforms.
- **Quick-Start / Tradecraft**: `pip install socid-extractor && socid_extractor --url https://github.com/torvalds`

---

## Search-Engine Handle Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Marple**](https://github.com/soxoj/marple) ([GitHub](https://github.com/soxoj/marple)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `social_profiles` |

### [Marple](https://github.com/soxoj/marple) `[B-Tier]`
- **ID**: `marple` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`soxoj/marple`](https://github.com/soxoj/marple)
- **Inputs**: `username` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Python · **Tags**: `serp-scraping`, `long-tail-sites`, `username`, `soxoj`
- **Overview**: Collects links to user profiles by querying multiple general search engines (DuckDuckGo, Brave, Yahoo, Ask, Bing, Google) for handle mentions rather than relying on static site lists.
- **Quick-Start / Tradecraft**: `pip install marple && marple target_handle`

---

## Multi-Selector Suites

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Mr.Holmes**](https://github.com/Lucksi/Mr.Holmes) ([GitHub](https://github.com/Lucksi/Mr.Holmes)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `username, phone, domain` → `social_profiles, whois, phones` |

### [Mr.Holmes](https://github.com/Lucksi/Mr.Holmes) `[B-Tier]`
- **ID**: `mr-holmes` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`Lucksi/Mr.Holmes`](https://github.com/Lucksi/Mr.Holmes)
- **Inputs**: `username`, `phone`, `domain` → **Outputs**: `social_profiles`, `whois`, `phones`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `multi-tool`, `username`, `phone`, `dorks`
- **Overview**: Multi-purpose OSINT toolkit investigating usernames, phone numbers, and domains with social profile enumeration, WHOIS/DNS checks, dork generation, and optional GUI portal.
- **Quick-Start / Tradecraft**: `python3 MrHolmes.py`

---

## Developer Handle Profiling

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**OctoSuite**](https://github.com/rly0nheart/octosuite) ([GitHub](https://github.com/rly0nheart/octosuite)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `username, company, repo_code` → `social_profiles, emails, metadata` |

### [OctoSuite](https://github.com/rly0nheart/octosuite) `[A-Tier]`
- **ID**: `octosuite` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`rly0nheart/octosuite`](https://github.com/rly0nheart/octosuite)
- **Inputs**: `username`, `company`, `repo_code` → **Outputs**: `social_profiles`, `emails`, `metadata`, `usernames`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `github-osint`, `username`, `developer-recon`, `cli`
- **Overview**: Advanced interactive CLI for live GitHub user, organization, repository, follower, commit-email, and activity reconnaissance.
- **Quick-Start / Tradecraft**: `octosuite`

---

## Automated Browser Correlation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Social Mapper**](https://github.com/Greenwolf/social_mapper) ([GitHub](https://github.com/Greenwolf/social_mapper)) | CLI | OSS / Free | 🔴 Active | 🔑 | `person_name, image, company` → `social_profiles, usernames, person_records` |

### [Social Mapper](https://github.com/Greenwolf/social_mapper) `[A-Tier]`
- **ID**: `social-mapper` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`Greenwolf/social_mapper`](https://github.com/Greenwolf/social_mapper)
- **Inputs**: `person_name`, `image`, `company` → **Outputs**: `social_profiles`, `usernames`, `person_records`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `facial-recognition`, `selenium`, `active-socmint`, `correlation`
- **Overview**: Active browser-automated social media enumeration tool correlating target names and photographs across LinkedIn, X, Facebook, Instagram, and VKontakte via facial recognition.
- **Quick-Start / Tradecraft**: `python3 social_mapper.py -f imagefolder -i ./targets -m fast -fb -tw -ig -li`

---

## Corporate Handle Permutations

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Username Anarchy**](https://github.com/urbanadventurer/username-anarchy) ([GitHub](https://github.com/urbanadventurer/username-anarchy)) | CLI | OSS / Free | 🟢 Passive | ✅ | `person_name, company` → `usernames, emails` |

### [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) `[A-Tier]`
- **ID**: `username-anarchy` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`urbanadventurer/username-anarchy`](https://github.com/urbanadventurer/username-anarchy)
- **Inputs**: `person_name`, `company` → **Outputs**: `usernames`, `emails`
- **Platforms**: CLI, Linux, macOS · **Tags**: `username-generation`, `email-format`, `permutations`
- **Overview**: Corporate username and email format permutation generator building realistic login wordlists from employee full names for downstream verification.
- **Quick-Start / Tradecraft**: `./username-anarchy --input-file names.txt`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🧰 Frameworks & Link Analysis](./01-all-in-one-frameworks.md) · [📧 Email Intelligence ▶](./03-email-intelligence.md)

[⬅️ Back to Master Index](../README.md)

# 🗺️ End-to-End OSINT Investigation Playbooks

20 battle-tested operational workflows chaining multiple disciplines from initial seed selector to verified intelligence dossier. Query any playbook from the terminal via `python3 scripts/osint.py workflows <id>`.

## Playbook Index

1. [**Person & Digital Footprint Attribution**](#person-identity-attribution) — `HUMINT / USERINT / EMAILINT` · Seed: `username / email / person_name` · *Intermediate*
2. [**Passive-First Domain & Infrastructure Attribution**](#domain-attack-surface-recon) — `DNSINT / NETINT` · Seed: `domain` · *Intermediate*
3. [**Photo & Video Geolocation + Chronolocation**](#photo-video-geolocation-chronolocation) — `GEOINT / IMINT` · Seed: `image / video` · *Advanced*
4. [**Corporate Shell Unmasking, UBO & Sanctions Investigation**](#corporate-beneficial-ownership-sanctions) — `FININT / TRANSINT` · Seed: `company / person_name` · *Advanced*
5. [**Cryptocurrency Wallet Attribution & Cross-Chain Tracing**](#crypto-wallet-laundering-trace) — `CRYPTOINT` · Seed: `crypto_address / tx_hash` · *Advanced*
6. [**Maritime Vessel, AIS Spoofing & Shadow Fleet Investigation**](#maritime-shadow-fleet-investigation) — `TRANSINT / GEOINT / FININT` · Seed: `vessel_imo / mmsi` · *Advanced*
7. [**Military, State & VIP Aircraft Tail-Number Investigation**](#aircraft-tail-number-tracking) — `TRANSINT / SIGINT` · Seed: `aircraft_hex / tail_number` · *Intermediate*
8. [**Telegram & Discord Network Mapping**](#telegram-discord-extremist-scam-mapping) — `PHONEINT / SOCMINT` · Seed: `username / keyword / url` · *Intermediate*
9. [**Developer Attribution & Git Repository Forensics**](#github-secret-developer-attribution) — `CODEINT / EMAILINT` · Seed: `username / repo_code / domain` · *Intermediate*
10. [**Phishing & Malware Infrastructure Pivoting**](#threat-actor-phishing-infra-triage) — `CTI / DNSINT / NETINT` · Seed: `url / ip / file_hash` · *Intermediate*
11. [**Dark Web, Ransomware & Infostealer Exposure Triage**](#darkweb-ransomware-exposure-assessment) — `DARKINT / BREACHINT` · Seed: `domain / email / onion_url` · *Intermediate*
12. [**Wireless BSSID, Cell Tower & RF Signal Intelligence**](#wireless-rf-geospatial-triangulation) — `SIGINT / GEOINT` · Seed: `mac_bssid / rf_frequency / coordinates` · *Advanced*
13. [**Instagram / TikTok / Creator Handle Multi-Stage Surface Expansion**](#social-handle-multi-stage-unmasking) — `SOCMINT / USERINT / PHONEINT` · Seed: `username / url` · *Intermediate*
14. [**Unmasking Origin Server IPs Behind Cloudflare & WAFs**](#origin-ip-unmasking-behind-cdn-waf) — `DNSINT / NETINT` · Seed: `domain` · *Advanced*
15. [**Shadow AI, Exposed LLM & Vector-DB Infrastructure Recon**](#shadow-ai-llm-infrastructure-recon) — `AI-OPSEC / NETINT / CODEINT` · Seed: `domain / asn / company` · *Intermediate*
16. [**Ransomware Leak-Site, `.onion` & Threat Actor Attribution**](#ransomware-onion-actor-attribution) — `DARKINT / CTI / CRYPTOINT` · Seed: `onion_url / crypto_address / file_hash` · *Advanced*
17. [**Cross-Border Shell Company, Sanctions & Beneficial Ownership Tracing**](#sanctions-evasion-shell-company-finint) — `FININT / TRANSINT` · Seed: `company / person_name / vessel_imo` · *Advanced*
18. [**Enterprise Cloud, Microsoft Entra ID & Storage Perimeter Recon**](#cloud-entra-m365-tenant-recon) — `CODEINT / EMAILINT / DNSINT` · Seed: `domain / company` · *Intermediate*
19. [**Investigative Media Verification, Chronolocation & Document Forensics**](#document-media-chronolocation-verification) — `IMINT / GEOINT / ARCHINT` · Seed: `image / video / document / url` · *Intermediate*
20. [**Web3 Phishing Kit, Wallet Drainer & Laundering Attribution**](#web3-drainer-scam-cluster-investigation) — `CRYPTOINT / DNSINT / CTI` · Seed: `crypto_address / domain / url` · *Advanced*

---

<a id="person-identity-attribution"></a>
## Person & Digital Footprint Attribution
- **Playbook ID**: `person-identity-attribution` · **Disciplines**: `HUMINT / USERINT / EMAILINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `username / email / person_name`
- **Objective**: Build a verified 360-degree profile of an online persona or individual by chaining handle enumeration, email side-channels, breach metadata, and visual cross-verification.

### Phase 1: Handle & Profile Discovery
Run cross-platform username sweeps and extract structured profile metadata (avatars, bios, user IDs, creation dates).

- **[`S`] [Maigret](https://github.com/soxoj/maigret)** (🟢 Passive, *OSS / Free*) — Advanced username dossier builder checking 3,000+ websites, parsing discovered profile pages to extract real names, bios, avatars, linked handles, and generating self-contained HTML/PDF/XMind reports.
- **[`S`] [Sherlock](https://github.com/sherlock-project/sherlock)** (🟢 Passive, *OSS / Free*) — The most widely used open-source Python CLI for hunting down social media and forum accounts by username across 400+ curated websites simultaneously, with Tor/proxy and CSV/JSON export support.
- **[`S`] [WhatsMyName](https://whatsmyname.app/)** (🟢 Passive, *OSS / Free*) — Community-maintained JSON detection standard (`wmn-data.json`) and instant browser web app checking 700+ sites with finely tuned HTTP status/response fingerprints to minimize false positives.
- **[`S`] [Blackbird](https://github.com/p1ngul1n0/blackbird)** (🟢 Passive, *OSS / Free*) — Fast asynchronous OSINT tool searching accounts by both username and email across 600+ sites, featuring WhatsMyName integration, AI profile metadata extraction, web UI, and PDF reporting.
- **[`A`] [SocID Extractor](https://github.com/soxoj/socid-extractor)** (🟢 Passive, *OSS / Free*) — Profile parsing library and CLI powering Maigret that extracts hidden internal numeric user IDs, creation dates, avatars, and linked accounts from HTML/JSON responses across 150+ platforms.

### Phase 2: Email & Phone Enrichment
Check discovered emails/phones against silent registration side-channels and Google/Gravatar ecosystems without triggering reset alerts.

- **[`S`] [Holehe](https://github.com/megadose/holehe)** (🟢 Passive, *OSS / Free*) — Checks whether an email address is registered across 120+ websites (Spotify, Instagram, X, GitHub, Adobe, Gravatar, Imgur, Office365) via silent registration/login checks without alerting the target.
- **[`S`] [GHunt](https://github.com/mxrch/GHunt)** (🟢 Passive, *OSS / Free*) — Offensive Google OSINT framework extracting GAIA IDs, display names, profile photos, Google Maps reviews/geolocations, Calendar availability, and Drive document owners from any Gmail address or Google Doc URL.
- **[`S`] [Epieos](https://epieos.com/)** (🟢 Passive, *Freemium*) — Zero-alert web reverse-lookup platform uncovering Google GAIA IDs, Maps contributions, Skype handles, Gravatar, Chess.com, Flickr, Strava, and linked social accounts from an email address or phone number.
- **[`S`] [Ignorant](https://github.com/megadose/ignorant)** (🟢 Passive, *OSS / Free*) — From the creator of Holehe: silently checks whether a target phone number (country code + subscriber digits) is registered on Instagram, Snapchat, Amazon, and other major platforms.
- **[`S`] [PhoneInfoga](https://github.com/sundowndev/phoneinfoga)** (🟢 Passive, *OSS / Free*) — Leading open-source Go framework for international phone number reconnaissance—extracting E.164 country/carrier metadata, OVH/Numverify line types, and automated Google dork footprints across social/classified sites.

### Phase 3: Breach & Historical Correlation
Correlate historical usernames, IP clues, or secondary emails across breach indexes and infostealer telemetry.

- **[`S`] [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/)** (🟢 Passive, *Freemium*) — Troy Hunt's gold-standard breach exposure service indexing 17.8B+ compromised accounts across 1,000+ breaches, stealer logs, and pastes—without ever exposing raw victim passwords.
- **[`S`] [Intelligence X (IntelX)](https://intelx.io/)** (🟢 Passive, *Freemium*) — Massive historical OSINT archive indexing 200B+ records across data leaks, Pastebin/paste sites, I2P/Tor darknets, WHOIS history, public documents, and DNS selectors.
- **[`S`] [Hudson Rock — Cavalier Free OSINT Tools](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools)** (🟢 Passive, *Freemium*) — Global cybercrime intelligence engine fueled by millions of real-world RedLine, Lumma, Vidar, and Raccoon infostealer malware infections—checking compromised domains, emails, usernames, and IPs.
- **[`S`] [DeHashed](https://dehashed.com/)** (🟢 Passive, *Paid*) — High-speed breach correlation search engine and REST API for authorized security researchers, supporting regex/wildcard pivoting across emails, usernames, IPs, phones, VINs, and password hashes.
- **[`S`] [h8mail](https://github.com/khast3x/h8mail)** (🟢 Passive, *OSS / Free*) — Email OSINT and password-breach hunting CLI supporting local `.gz`/cleartext breach compilations alongside HIBP, Snusbase, Leak-Lookup, IntelX, DeHashed, Hunter.io, and EmailRep recursive pivoting.

### Phase 4: Avatar & Face Cross-Match
Reverse-search profile photos across face/visual indexes to uncover unlinked accounts using different handles.

- **[`S`] [Yandex Reverse Image Search](https://yandex.com/images/)** (🟢 Passive, *Free*) — Consistently outperforms Western visual search engines on architectural landmarks, background scenery cropping, Cyrillic/Eurasian web sources, and same-person visual similarity matching.
- **[`S`] [PimEyes](https://pimeyes.com/)** (🟢 Passive, *Paid*) — High-recall commercial reverse facial-recognition engine indexing faces across news sites, blogs, company rosters, event galleries, and public web media (excludes major walled social networks).
- **[`A`] [FaceCheck.ID](https://facecheck.id/)** (🟢 Passive, *Paid*) — Investigative facial-recognition search engine indexing social media avatars, mugshots, news videos, podcasts, and scammer warnings.
- **[`S`] [TinEye](https://tineye.com/)** (🟢 Passive, *Freemium*) — Dedicated perceptual-hash reverse image search indexing 70B+ web images with 'Oldest' sort ordering—the gold standard for debunking old stock/conflict photos reposted as breaking news.
- **[`S`] [Search by Image (Browser Extension)](https://github.com/dessant/search-by-image)** (🟢 Passive, *OSS / Free*) — Open-source browser extension launching right-click reverse image lookups simultaneously across 30+ engines (Google Lens, Yandex, Bing, TinEye, Baidu, Sogou, SauceNAO, KarmaDecay, Alamy).

### Phase 5: Evidence Preservation & Link Graph
Hash and archive all confirmed profile pages and plot entity links with confidence ratings.

- **[`S`] [SingleFile](https://github.com/gildas-lormeau/SingleFile)** (🟢 Passive, *OSS / Free*) — Essential open-source browser extension & CLI saving a complete, pixel-faithful rendered webpage (CSS, fonts, canvas, images embedded as data URIs) into a single self-contained `.html` file locally.
- **[`S`] [Hunchly](https://www.hunchly.com/)** (🟢 Passive, *Paid*) — Gold-standard commercial forensic browser capture suite automatically recording, SHA-256 hashing, timestamping, full-text indexing, and selector-tagging every single webpage visited during an investigation.
- **[`S`] [Maltego](https://www.maltego.com/)** (🟡 Hybrid, *Freemium*) — Industry-standard visual link-analysis platform with 100+ data-hub transforms connecting people, companies, domains, netblocks, social accounts, and cryptocurrency entities on interactive node graphs.
- **[`S`] [Flowsint](https://github.com/reconurge/flowsint)** (🟡 Hybrid, *OSS / Free*) — Modern open-source, graph-based OSINT investigation platform offering extensible enrichers, entity relationship mapping, and visual canvas workflows as a self-hosted alternative to commercial link analyzers.

---

<a id="domain-attack-surface-recon"></a>
## Passive-First Domain & Infrastructure Attribution
- **Playbook ID**: `domain-attack-surface-recon` · **Disciplines**: `DNSINT / NETINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `domain`
- **Objective**: Map an organization's external infrastructure, hidden origin IPs behind CDNs, historical ownership, and sister domains without sending a single packet to the target.

### Phase 1: RDAP, Historical WHOIS & Sister Domains
Query current RDAP and historical WHOIS records to find registrant emails, org names, and reverse-WHOIS sister domains.

- **[`A`] [ICANN Lookup (Official RDAP)](https://lookup.icann.org/)** (🟢 Passive, *Free*) — Authoritative Registration Data Access Protocol (RDAP) client querying gTLD registries directly for registrar IANA IDs, registry lock status, creation/expiry timestamps, and nameservers.
- **[`S`] [Whoxy](https://www.whoxy.com/)** (🟢 Passive, *Freemium*) — High-value historical WHOIS and Reverse WHOIS API/search engine indexing pre-GDPR registrant names, emails, company strings, and 20+ years of domain ownership changes.
- **[`S`] [SecurityTrails](https://securitytrails.com/)** (🟢 Passive, *Freemium*) — Premier historical DNS and WHOIS time-machine tracking multi-year A, AAAA, MX, NS, and TXT record changes—essential for unmasking pre-Cloudflare origin server IPs.
- **[`A`] [ViewDNS.info](https://viewdns.info/)** (🟢 Passive, *Freemium*) — Swiss-army web toolkit bundling 20+ domain/IP utilities: Reverse IP Lookup, Reverse WHOIS, IP History,Reverse MX/NS, Chinese Firewall Test, DNSSEC check, and ASN lookup.
- **[`A`] [DomainTools Iris](https://www.domaintools.com/)** (🟢 Passive, *Paid*) — Enterprise domain intelligence standard offering 20+ years of WHOIS snapshots, Passive DNS, domain risk scoring, and multi-hop infrastructure pivot graphs for CTI teams.

### Phase 2: Certificate Transparency & Passive Subdomains
Harvest subdomains and wildcard SANs from Certificate Transparency logs and passive DNS aggregators.

- **[`S`] [crt.sh (Certificate Transparency Search)](https://crt.sh/)** (🟢 Passive, *OSS / Free*) — Sectigo's free, keyless Certificate Transparency log search engine with direct public PostgreSQL SQL access (`crt.sh:5432`)—exposing every publicly trusted SSL/TLS cert and SAN subdomain ever issued.
- **[`S`] [Subfinder](https://github.com/projectdiscovery/subfinder)** (🟢 Passive, *OSS / Free*) — ProjectDiscovery's ultra-fast passive subdomain enumeration Go CLI querying 40+ passive certificate, DNS, archive, and threat-intel sources in seconds without touching target DNS.
- **[`S`] [OWASP Amass](https://github.com/owasp-amass/amass)** (🟡 Hybrid, *OSS / Free*) — Flagship OWASP external attack-surface mapping engine combining 50+ passive DNS/CT/ASN/archive sources, BGP netblock expansion, and Open Asset Model graph storage.
- **[`A`] [Findomain](https://github.com/Findomain/Findomain)** (🟡 Hybrid, *OSS / Free*) — Blazing-fast Rust subdomain recognition engine supporting passive API aggregation, continuous monitoring, headless screenshots, HTTP probing, and Discord/Slack/Telegram new-asset alerts.
- **[`S`] [DNSDumpster](https://dnsdumpster.com/)** (🟢 Passive, *Free*) — HackerTarget's free domain reconnaissance portal mapping MX, NS, TXT, A records, netblock owners, open banners, and auto-generated network topology graphs.

### Phase 3: Origin IP & Banner Pivoting
Uncover real origin servers behind Cloudflare/WAFs using TLS cert serials, favicon mmh3 hashes, and historical DNS A-records.

- **[`S`] [Shodan](https://www.shodan.io/)** (🟢 Passive, *Freemium*) — World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **[`S`] [Censys Search](https://search.censys.io/)** (🟢 Passive, *Freemium*) — Continuous internet-wide scanner indexing billions of services across all 65,535 TCP ports plus the deepest historical X.509 TLS certificate repository—unmatched for C2 and origin-IP hunting.
- **[`S`] [FOFA](https://en.fofa.info/)** (🟢 Passive, *Freemium*) — Massive cyberspace asset search engine indexing global web titles, HTTP headers, body hashes, TLS certificates, icon hashes, and APAC/global infrastructure often missed by Western crawlers.
- **[`A`] [Netlas.io](https://netlas.io/)** (🟢 Passive, *Freemium*) — Attack-surface and internet intelligence search engine unifying IPv4 responses, Passive DNS, WHOIS domains, and Certificate Transparency into one Lucene query interface.
- **[`A`] [ZoomEye](https://www.zoomeye.ai/)** (🟢 Passive, *Freemium*) — Knownsec's global cyberspace search engine cataloging IPv4/IPv6 host banners, web component fingerprints, IoT firmware versions, and historical port exposure.

### Phase 4: Analytics, AdSense & Source Code Pivoting
Extract Google Tag Manager, Analytics (`G-`/`UA-`), AdSense, or custom JS snippets to discover undisclosed domains run by the same operator.

- **[`S`] [BuiltWith](https://builtwith.com/)** (🟢 Passive, *Freemium*) — Profiles 100,000+ web technologies AND tracks shared Google Analytics, Tag Manager, AdSense, Facebook Pixel, and Cloudflare IDs across historical crawls to link covert sister sites.
- **[`S`] [PublicWWW](https://publicwww.com/)** (🟢 Passive, *Freemium*) — Source-code search engine indexing the raw HTML, inline JavaScript, and CSS of 500M+ web pages—the ultimate weapon for pivoting on Google Analytics IDs, AdSense tags, crypto skimmers, or custom widgets.
- **[`S`] [urlscan.io](https://urlscan.io/)** (🟡 Hybrid, *Freemium*) — Headless browser website sandbox recording full DOM HTML, every HTTP XHR request, JS resource SHA-256 hashes, TLS certificates, ASN details, and visual screenshots—ideal for phishing kit hunting.
- **[`B`] [NerdyData](https://www.nerdydata.com/)** (🟢 Passive, *Freemium*) — Searches rendered HTML, JavaScript, meta tags, and embedded tracking snippets across hundreds of millions of homepages to link related web properties and technology footprints.
- **[`S`] [Web-Check](https://github.com/lissy93/web-check)** (🟡 Hybrid, *OSS / Free*) — All-in-one website OSINT analyzer surfacing nearly 30 inspection panels—DNS, TLS chain, HTTP security headers, WHOIS, server location, traceroute, carbon footprint, open ports, and linked pages.

### Phase 5: Historical Archive Mining
Pull forgotten endpoints, leaked config files, and old team pages from historical web crawls.

- **[`S`] [Wayback Machine (Internet Archive)](https://web.archive.org/)** (🟢 Passive, *Free*) — Humanity's digital memory indexing 900+ billion archived web captures since 1996, backed by the powerful CDX Server API for wildcard subdomain discovery, MIME filtering, and deleted-content recovery.
- **[`S`] [waymore](https://github.com/xnl-h4ck3r/waymore)** (🟢 Passive, *OSS / Free*) — Downloads archived URLs AND actual historical HTTP responses for a domain across Wayback Machine, Common Crawl, AlienVault OTX, URLScan, and VirusTotal simultaneously.
- **[`A`] [gau (GetAllUrls)](https://github.com/lc/gau)** (🟢 Passive, *OSS / Free*) — Fetches known historical URLs for any domain from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan without touching the target.
- **[`A`] [Common Crawl Index](https://commoncrawl.org/)** (🟢 Passive, *OSS / Free*) — Open non-profit repository of petabyte-scale monthly raw web crawls (WARC/WAT/WET) and host-level link graphs since 2008—enabling passive inbound backlink and body-text searches.

---

<a id="photo-video-geolocation-chronolocation"></a>
## Photo & Video Geolocation + Chronolocation
- **Playbook ID**: `photo-video-geolocation-chronolocation` · **Disciplines**: `GEOINT / IMINT` · **Difficulty**: `Advanced` · **Seed Selector**: `image / video`
- **Objective**: Determine the exact coordinates (geolocation) and capture timestamp (chronolocation) of an unverified photo or video using visual, architectural, geometric, and solar clues.

### Phase 1: Metadata & Provenance Triage
Inspect container metadata (EXIF/XMP/QuickTime atoms), extract keyframes, and search for the earliest public upload on the web.

- **[`S`] [ExifTool](https://exiftool.org/)** (🟢 Passive, *OSS / Free*) — Phil Harvey's legendary Perl CLI/library reading, writing, and auditing EXIF, GPS, XMP, IPTC, ICC, QuickTime atoms, PDF producer tags, and Office revision metadata across 400+ file formats.
- **[`S`] [InVID / WeVerify Verification Plugin](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/)** (🟢 Passive, *OSS / Free*) — AFP Medialab / vera.ai browser workbench extracting video keyframes, running multi-engine reverse image searches, inspecting optical magnifiers, and running ELA/Ghost/Block forensic splicing filters.
- **[`S`] [Google Lens](https://lens.google.com/)** (🟢 Passive, *Free*) — Multimodal visual recognition engine excelling at Exact Source ('Find image source') discovery, commercial product/clothing/weapon identification, sign OCR translation, and plant/species matching.
- **[`S`] [Yandex Reverse Image Search](https://yandex.com/images/)** (🟢 Passive, *Free*) — Consistently outperforms Western visual search engines on architectural landmarks, background scenery cropping, Cyrillic/Eurasian web sources, and same-person visual similarity matching.
- **[`S`] [Forensically (29a.ch)](https://29a.ch/photo-forensics/)** (🟢 Passive, *Free*) — Client-side HTML5 digital photo forensics laboratory offering Clone Detection (copy-move), Error Level Analysis (ELA), Noise Analysis, PCA, JPEG Ghost detection, and hidden thumbnail extraction.

### Phase 2: Region Narrowing & AI Scene Leads
Identify country/region indicators (license plates, bollards, road markings, utility poles, scripts, bird calls) and generate candidate regions.

- **[`A`] [GeoHints](https://geohints.com/)** (🟢 Passive, *Free*) — Visual reference encyclopedia cataloging country-specific roadside bollards, utility poles, guardrails, road markings, pedestrian signs, mailboxes, and license plates.
- **[`A`] [Plonk It Guide](https://www.plonkit.net/guide)** (🟢 Passive, *Free*) — Deep country-by-country and sub-regional visual recognition manual detailing regional architecture, phone area codes, vegetation, soil color, and camera-generation clues across 130+ countries.
- **[`A`] [Picarta.ai](https://picarta.ai/)** (🟢 Passive, *Freemium*) — Deep-learning visual photo geolocation platform and Python SDK predicting top GPS coordinate candidates worldwide from architecture, flora, soil, and signage when EXIF is stripped.
- **[`S`] [geo-sleuth](https://github.com/Oldcircle/geo-sleuth)** (🟢 Passive, *OSS / Free*) — Open-source autonomous geolocation agent skill combining OpenStreetMap road/building geometry, elevation skyline matching, satellite imagery, and Street View to geolocate photos with explainable evidence.
- **[`A`] [BirdNET Analyzer](https://birdnet.cornell.edu/)** (🟢 Passive, *OSS / Free*) — Cornell Lab of Ornithology neural classifier identifying 6,000+ global bird species from faint background chirps in outdoor videos—narrowing down continent, biome, and migratory season!

### Phase 3: Vector & Spatial Feature Querying
Translate visual constraints (e.g., 'gas station within 80m of railway and mosque') into OpenStreetMap Overpass queries.

- **[`S`] [Overpass Turbo (OpenStreetMap Query Engine)](https://overpass-turbo.eu/)** (🟢 Passive, *OSS / Free*) — The single most powerful deterministic photo-geolocation tool: executes spatial queries against OpenStreetMap's global vector database to find exact geometric arrangements of roads, towers, bridges, and shops.
- **[`S`] [Bellingcat OpenStreetMap Search](https://osm-search.bellingcat.com/)** (🟢 Passive, *OSS / Free*) — Point-and-click visual builder wrapping Overpass QL so investigators can select up to 5 visible features (e.g., power line, mosque, roundabout, river) and distance tolerances without writing code.
- **[`A`] [Overpass Ultra](https://overpass-ultra.us/)** (🟢 Passive, *OSS / Free*) — Modern MapLibre GL vector-rendered successor to Overpass Turbo handling massive multi-thousand-feature spatial queries smoothly in browser WebGL.
- **[`A`] [PeakVisor / PeakFinder](https://www.peakfinder.com/)** (🟢 Passive, *Freemium*) — Generates synthetic 360-degree mountain horizon skylines from global digital elevation models (DEMs) at any coordinate and elevation—allowing investigators to triangulate rural photos from distant ridgelines.

### Phase 4: Satellite & Street-Level Ground Truthing
Confirm exact camera line-of-sight and historical construction changes using 3D terrain, street-level photos, and multispectral satellite time-series.

- **[`S`] [Google Earth Pro](https://www.google.com/earth/about/versions/)** (🟢 Passive, *Free*) — Indispensable desktop 3D globe offering multi-decade Historical Imagery time-sliders, 3D terrain skyline simulation, sun-lighting previews, viewshed analysis, and KML/KMZ case overlays.
- **[`S`] [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/)** (🟢 Passive, *Free*) — Official ESA portal (replacing retired Sentinel Hub EO Browser) providing free global Sentinel-1 SAR (cloud-penetrating radar!) and 10m Sentinel-2 optical/SWIR/NDVI imagery every ~5 days.
- **[`S`] [Mapillary](https://www.mapillary.com/app/)** (🟢 Passive, *OSS / Free*) — Over 2 billion crowdsourced street-level dashcam and walking images worldwide, offering coverage in countries, conflict zones, and rural roads where Google Street View has never driven.
- **[`A`] [KartaView](https://kartaview.org/)** (🟢 Passive, *OSS / Free*) — Open-licensed crowdsourced street-level photo platform (maintained by Grab/OSM community) providing dense ground-level street sequences especially across Southeast Asia, Eastern Europe, and Latin America.
- **[`S`] [Esri World Imagery Wayback](https://livingatlas.arcgis.com/wayback/)** (🟢 Passive, *OSS / Free*) — Digital archive of 150+ historical global high-resolution satellite basemap releases from Maxar/Earthstar since 2014 with swipe comparison and local-change filtering.

### Phase 5: Solar Azimuth & Shadow Chronolocation
Measure object height vs. shadow length and azimuth angle to verify or narrow the exact date and local time of capture.

- **[`S`] [SunCalc](https://www.suncalc.org/)** (🟢 Passive, *Free*) — Computes solar azimuth, altitude angle, shadow length ratios, dawn/dusk twilight phases, and sun trajectory arcs for any coordinate and date/time on Earth.
- **[`S`] [Bellingcat ShadowFinder](https://shadowfinder.bellingcat.com/)** (🟢 Passive, *OSS / Free*) — Inverts SunCalc math: given a known UTC timestamp plus the ratio of an object's height to its shadow length, plots the exact curved band of Earth where that shadow length is physically possible.
- **[`A`] [Shadowmap](https://app.shadowmap.org/)** (🟢 Passive, *Freemium*) — Interactive global 3D building and terrain sunlight/shadow simulator rendering real-world cast shadows across urban canyons and mountains for any date and minute of the year.
- **[`S`] [Wolfram|Alpha Historical Weather & Astronomy](https://www.wolframalpha.com/)** (🟢 Passive, *Freemium*) — Queries historical airport METAR weather stations worldwide for exact temperature, cloud cover, wind speed, precipitation, moon phase, and twilight at any city and historic date/hour!

---

<a id="corporate-beneficial-ownership-sanctions"></a>
## Corporate Shell Unmasking, UBO & Sanctions Investigation
- **Playbook ID**: `corporate-beneficial-ownership-sanctions` · **Disciplines**: `FININT / TRANSINT` · **Difficulty**: `Advanced` · **Seed Selector**: `company / person_name`
- **Objective**: Trace complex cross-border corporate hierarchies, uncover Ultimate Beneficial Owners (UBOs), screen against global sanctions/PEP lists, and map physical supply-chain shipments.

### Phase 1: Global Registry & LEI Resolution
Locate incorporation filings, company numbers, registered agents, and direct/ultimate parent Legal Entity Identifiers.

- **[`S`] [OpenCorporates](https://opencorporates.com/)** (🟢 Passive, *Freemium*) — World's largest open database of legal entities—normalizing 220M+ company registrations and 290M+ officer/director records across 140+ national and state jurisdictions with direct registry provenance.
- **[`S`] [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/)** (🟢 Passive, *Free*) — Global Legal Entity Identifier Foundation database mapping 2.6M+ financial counterparties worldwide—explicitly disclosing 'Level 2' Direct Accounting Parent and Ultimate Parent ownership chains!
- **[`S`] [UK Companies House & Overseas Entities Register](https://find-and-update.company-information.service.gov.uk/)** (🟢 Passive, *Free*) — Gold-standard completely free corporate registry providing full PDF incorporation deeds, annual accounts, officer DOBs/addresses, Persons with Significant Control (PSC), and Overseas Entities owning UK property!
- **[`S`] [SEC EDGAR Full-Text Search](https://www.sec.gov/edgar/searchedgar/companysearch)** (🟢 Passive, *Free*) — US Securities and Exchange Commission full-text search across every 10-K, 10-Q, 8-K, Form 4 insider trade, 13F fund portfolio, and Exhibit 21 subsidiary list filed since 2001.
- **[`A`] [North Data](https://www.northdata.com/)** (🟢 Passive, *Freemium*) — Visual European corporate intelligence engine automatically graphing director networks, gazette filings, UBO changes, and financials across Germany (`Handelsregister`), France, UK, Switzerland, Spain, and EU states.

### Phase 2: Offshore Leaks & Investigative Document Cross-Check
Pivot officers, addresses, and intermediaries across leaked offshore corporate registries, court filings, and journalism archives.

- **[`S`] [OCCRP Aleph](https://aleph.occrp.org/)** (🟢 Passive, *OSS / Free*) — Organized Crime and Corruption Reporting Project's flagship investigative data platform cross-indexing hundreds of millions of leaked emails, land registries, gazettes, procurement files, and corporate filings.
- **[`S`] [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/)** (🟢 Passive, *OSS / Free*) — Interactive graph database from the International Consortium of Investigative Journalists spanning 810,000+ offshore shell companies, trusts, and foundations from Panama, Pandora, Paradise, and Bahamas Papers.
- **[`A`] [Open Ownership Register](https://register.openownership.org/)** (🟢 Passive, *OSS / Free*) — Transnational beneficial-ownership database expressed in the Beneficial Ownership Data Standard (BODS), linking natural-person UBOs across UK, Denmark, Slovakia, Ukraine, and extractive registries.
- **[`A`] [LittleSis](https://littlesis.org/)** (🟢 Passive, *OSS / Free*) — Watchdog 'involuntary social network' database mapping board memberships, lobbying ties, campaign donations, family links, and revolving-door relationships among executives and public officials.
- **[`S`] [CourtListener & RECAP Archive](https://www.courtlistener.com/)** (🟢 Passive, *OSS / Free*) — Free Law Project's open legal archive containing millions of US federal PACER filings, judicial opinions, oral arguments, judge financial disclosures, and real-time docket alerts.

### Phase 3: Sanctions, PEP & Debarment Screening
Screen entities, directors, vessels, and addresses against consolidated OFAC, EU, UN, UK, and PEP watchlists.

- **[`S`] [OpenSanctions](https://www.opensanctions.org/)** (🟢 Passive, *Freemium*) — Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.
- **[`S`] [US Treasury OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/)** (🟢 Passive, *Free*) — Authoritative US Treasury Office of Foreign Assets Control fuzzy-matching lookup covering SDN and Consolidated Non-SDN lists—including sanctioned passport IDs, IMO numbers, tail numbers, and BTC/ETH/USDT addresses.
- **[`A`] [EU Sanctions Map](https://www.sanctionsmap.eu/)** (🟢 Passive, *Free*) — Official European Commission interactive map detailing EU restrictive measures, arms embargoes, asset-freeze lists, and legal Council Regulations regime-by-regime.
- **[`A`] [SAM.gov (System for Award Management)](https://sam.gov/)** (🟢 Passive, *Free*) — Official US portal for federal contractor registrations (CAGE codes, UEIs, physical addresses, points of contact) and Federal Exclusions/Debarments.

### Phase 4: Customs, Trade & Procurement Verification
Map real-world buyers, overseas factories, HS commodity codes, and government contracts via bills of lading and tender databases.

- **[`S`] [ImportYeti](https://www.importyeti.com/)** (🟢 Passive, *Freemium*) — Free search engine over 100M+ US Customs (CBP Automated Manifest System) sea bills of lading—exposing overseas factory suppliers, US buyers, HS codes, container weights, and shipment frequencies.
- **[`A`] [UN Comtrade Database](https://comtradeplus.un.org/)** (🟢 Passive, *Freemium*) — United Nations repository of official bilateral international trade statistics by 6-digit HS commodity code—essential for spotting sanctions-transshipment spikes ('mirror data' discrepancies).
- **[`A`] [USAspending.gov](https://www.usaspending.gov/)** (🟢 Passive, *OSS / Free*) — Official open-data source of US federal government spending—tracking prime contracts, defense awards, sub-awards, grants, recipient UEIs, and agency obligations.
- **[`A`] [TED (Tenders Electronic Daily — EU)](https://ted.europa.eu/)** (🟢 Passive, *Free*) — Official European Union public-procurement journal publishing multi-year tender notices and contract award notices (winning vendors, contract values, buyer ministries) across Europe.

---

<a id="crypto-wallet-laundering-trace"></a>
## Cryptocurrency Wallet Attribution & Cross-Chain Tracing
- **Playbook ID**: `crypto-wallet-laundering-trace` · **Disciplines**: `CRYPTOINT` · **Difficulty**: `Advanced` · **Seed Selector**: `crypto_address / tx_hash`
- **Objective**: Follow stolen, ransom, or illicit funds across UTXO and EVM blockchains, identify peel chains and cross-chain bridges, and link wallets to off-chain identities or KYC exchanges.

### Phase 1: Raw Ledger Inspection & Token Approvals
Inspect first-funding gas source (faucet/CEX hot wallet), transaction timestamps (activity timezone), and token transfers.

- **[`S`] [Etherscan](https://etherscan.io/)** (🟢 Passive, *Freemium*) — Canonical Ethereum explorer providing verified smart-contract Solidity source code, internal EVM call traces, ERC-20/721 transfers, Token Approval checker, public name tags, and comments.
- **[`S`] [mempool.space](https://mempool.space/)** (🟢 Passive, *OSS / Free*) — Open-source Bitcoin & Lightning Network explorer featuring interactive UTXO input/output flow diagrams, fee-rate telemetry, mining pool attribution, and self-hostable Tor `.onion` support.
- **[`A`] [Blockchair](https://blockchair.com/)** (🟢 Passive, *Freemium*) — Privacy-respecting multi-chain SQL-style search engine spanning 40+ blockchains (BTC, ETH, LTC, BCH, DOGE, XMR, ZEC, TON, XRP, ADA, SOL) with PDF transaction receipts and cross-chain address lookup.
- **[`A`] [Solscan](https://solscan.io/)** (🟢 Passive, *Freemium*) — Leading Solana block explorer parsing SPL token transfers, DeFi swaps, program instructions, fee-payer relationships, and meme-coin deployer funding trees.
- **[`S`] [TRONSCAN](https://tronscan.org/)** (🟢 Passive, *Free*) — Official TRON blockchain explorer—indispensable in modern cybercrime, ransomware, pig-butchering, and sanctions OSINT because `TRC-20 USDT` is a dominant underground settlement rail.

### Phase 2: Entity Attribution & Risk Screening
Check 300M+ institutional/community wallet labels, OFAC SDN crypto tags, and scam reports.

- **[`S`] [Arkham Intelligence](https://intel.arkm.com/)** (🟢 Passive, *Freemium*) — Leading public blockchain intelligence platform attributing 300M+ multi-chain wallet addresses to real-world exchanges, funds, hackers, and individuals with an interactive fund-flow Visualizer.
- **[`A`] [MistTrack (SlowMist)](https://misttrack.io/)** (🟢 Passive, *Freemium*) — SlowMist's AML and crypto-hack investigation platform packing 400M+ address labels across 19+ chains, mixer/bridge risk scoring, OFAC sanctions flags, and stolen-fund monitoring.
- **[`S`] [Chainabuse (by TRM Labs)](https://www.chainabuse.com/)** (🟢 Passive, *Free*) — Free community-driven multi-chain cybercrime reporting database (operated by TRM Labs) indexing hundreds of thousands of victim-reported ransomware, sextortion, drainer, and pig-butchering addresses.
- **[`S`] [OpenSanctions](https://www.opensanctions.org/)** (🟢 Passive, *Freemium*) — Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.

### Phase 3: Visual Hop Graphing & Clustering
Build multi-hop fund-flow graphs, apply UTXO co-spend clustering, and trace DEX/bridge hops to cash-out deposit addresses.

- **[`S`] [Breadcrumbs.app](https://www.breadcrumbs.app/)** (🟢 Passive, *Freemium*) — Intuitive visual blockchain investigation workbench mapping multi-hop BTC, ETH, Polygon, Solana, Arbitrum, Base, and TRON fund flows with entity risk tags and shareable case charts.
- **[`S`] [GraphSense](https://graphsense.org/)** (🟢 Passive, *OSS / Free*) — Premier open-source, self-hostable cryptoasset analytics platform (AIT / Iknaio) providing UTXO co-spend clustering, account-model tracing, attribution tags, and full data sovereignty across BTC, ETH, LTC, ZEC, and TRON.
- **[`A`] [MetaSleuth (BlockSec)](https://metasleuth.io/)** (🟢 Passive, *Freemium*) — BlockSec's automated cross-chain fund-tracking canvas visualizing DeFi exploit drains, Tornado/bridge hops, and cash-out paths across 15+ chains.
- **[`B`] [WalletExplorer.com](https://www.walletexplorer.com/)** (🟢 Passive, *Free*) — Classic automatic Bitcoin common-input-ownership (co-spend) heuristic explorer grouping separate BTC addresses controlled by the same underlying wallet cluster.
- **[`A`] [Bubblemaps](https://bubblemaps.io/)** (🟢 Passive, *Freemium*) — Visualizes ERC-20 and SPL token holder concentration as interactive connected bubbles—instantly exposing cabals, wash-trading rings, and insider dev wallets splitting token supply.

### Phase 4: Web3 Handle & Off-Chain OSINT Pivot
Pivot ENS names, Lens/Farcaster handles, NFT mints, and pasted wallet strings across GitHub, X, Telegram, and darknet indexes.

- **[`A`] [DeBank](https://debank.com/)** (🟢 Passive, *Free*) — Multi-EVM portfolio tracker enumerating every DeFi lending position, LP pool, NFT, social Web3 badge, and chronological activity feed across 35+ EVM chains for any `0x` address.
- **[`S`] [grep.app](https://grep.app/)** (🟢 Passive, *Free*) — Sub-second regular-expression code search engine across 500,000+ public GitHub repositories—ideal for finding internal domains, custom SDK headers, wallet addresses, or unique error strings.
- **[`S`] [Intelligence X (IntelX)](https://intelx.io/)** (🟢 Passive, *Freemium*) — Massive historical OSINT archive indexing 200B+ records across data leaks, Pastebin/paste sites, I2P/Tor darknets, WHOIS history, public documents, and DNS selectors.
- **[`S`] [TGStat](https://tgstat.com/)** (🟢 Passive, *Freemium*) — Largest public Telegram analytics and discovery engine indexing 2.8M+ channels and groups by keyword, language, country, citation graph, subscriber history, and cross-channel reposts.

---

<a id="maritime-shadow-fleet-investigation"></a>
## Maritime Vessel, AIS Spoofing & Shadow Fleet Investigation
- **Playbook ID**: `maritime-shadow-fleet-investigation` · **Disciplines**: `TRANSINT / GEOINT / FININT` · **Difficulty**: `Advanced` · **Seed Selector**: `vessel_imo / mmsi`
- **Objective**: Investigate suspect cargo vessels or tankers conducting dark-ship port calls, ship-to-ship (STS) transfers, flag-hopping, or sanctions evasion.

### Phase 1: Permanent IMO Resolution & Ownership History
Resolve MMSI/name to permanent 7-digit IMO number and pull historical flag changes, ISM managers, P&I insurers, and PSC detentions.

- **[`S`] [Equasis](https://www.equasis.org/)** (🟢 Passive, *Free*) — International public-safety maritime database (founded by EC & French Maritime Admin) providing free historical Registered Owner, Commercial Operator, ISM Manager, Flag, Class, P&I Club, and PSC inspection records by IMO!
- **[`S`] [OpenSanctions](https://www.opensanctions.org/)** (🟢 Passive, *Freemium*) — Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.
- **[`B`] [ITU MARS (Maritime Mobile Access & Retrieval System)](https://www.itu.int/en/ITU-R/terrestrial/mars/Pages/MARS.aspx)** (🟢 Passive, *Free*) — Official International Telecommunication Union ship-station radio license database mapping MMSI numbers, radio callsigns, EPIRB hex IDs, and registered ship owners.
- **[`A`] [Paris MoU & Tokyo MoU Port State Control Databases](https://www.parismou.org/inspection-search/inspection-search)** (🟢 Passive, *Free*) — Official European (`parismou.org`) and Asia-Pacific (`apcis.tmou.org`) Port State Control inspection databases exposing vessel safety deficiencies, detentions, certificates, and ISM technical managers!

### Phase 2: AIS Track & Dark-Gap Analysis
Analyze historical AIS tracks, loitering behavior, draught changes (loaded vs. ballast), and transponder gaps.

- **[`S`] [Global Fishing Watch Map](https://globalfishingwatch.org/map)** (🟢 Passive, *OSS / Free*) — Open-access maritime transparency platform fusing commercial satellite AIS, VMS, Sentinel-1 SAR dark-vessel detections, Sentinel-2 optical imagery, loitering events, and ship-to-ship (STS) encounters!
- **[`S`] [MarineTraffic](https://www.marinetraffic.com/)** (🟢 Passive, *Freemium*) — Global coastal and satellite AIS ship-tracking standard displaying live vessel positions, reported draught changes, destination strings, port arrivals, and crowdsourced hull photography.
- **[`A`] [VesselFinder](https://www.vesselfinder.com/)** (🟢 Passive, *Freemium*) — Fast real-time AIS ship position tracker, port call log, and IMO/MMSI vessel specification lookup with clean unauthenticated search.
- **[`A`] [MyShipTracking](https://www.myshiptracking.com/)** (🟢 Passive, *Freemium*) — Generous free real-time AIS ship map offering multi-day historical vessel tracks, port call logs, speed graphs, and fleet groupings without aggressive paywalls.

### Phase 3: Optical & SAR Satellite Verification
Use Sentinel-1 Synthetic Aperture Radar (penetrates clouds/night) and Sentinel-2 optical imagery to spot 'dark' ships during AIS blackouts.

- **[`S`] [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/)** (🟢 Passive, *Free*) — Official ESA portal (replacing retired Sentinel Hub EO Browser) providing free global Sentinel-1 SAR (cloud-penetrating radar!) and 10m Sentinel-2 optical/SWIR/NDVI imagery every ~5 days.
- **[`S`] [NASA Worldview](https://worldview.earthdata.nasa.gov/)** (🟢 Passive, *OSS / Free*) — Interactive browser over 1,200+ daily global NASA satellite imagery layers—many updated within 3 hours of overpass—for smoke plumes, cloud cover verification, floods, and night-lights blackouts.
- **[`S`] [Google Earth Pro](https://www.google.com/earth/about/versions/)** (🟢 Passive, *Free*) — Indispensable desktop 3D globe offering multi-decade Historical Imagery time-sliders, 3D terrain skyline simulation, sun-lighting previews, viewshed analysis, and KML/KMZ case overlays.
- **[`S`] [GPSJAM](https://gpsjam.org/)** (🟢 Passive, *Free*) — Daily global H3 hexagonal map created by John Wiseman deriving real-world GPS/GNSS electronic-warfare jamming and spoofing zones from aircraft ADS-B navigation-accuracy (`NACp`) drops!

---

<a id="aircraft-tail-number-tracking"></a>
## Military, State & VIP Aircraft Tail-Number Investigation
- **Playbook ID**: `aircraft-tail-number-tracking` · **Disciplines**: `TRANSINT / SIGINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `aircraft_hex / tail_number`
- **Objective**: Track LADD/PIA-blocked executive jets, cargo charters, or military aircraft using unfiltered community ADS-B/MLAT receivers, ACARS datalinks, and aircraft registries.

### Phase 1: ICAO 24-bit Hex & Registration Lookup
Map tail number to ICAO 24-bit Mode-S hex code, airframe serial number, operator, and FAA/civil trust owner.

- **[`A`] [FAA Aircraft Registry (N-Number Inquiry)](https://registry.faa.gov/aircraftinquiry/)** (🟢 Passive, *Free*) — Official US Federal Aviation Administration registry mapping `N-` tail numbers to Mode-S 8-digit octal / 6-char hex codes, airframe serials, registered LLC/bank-trust owners, and downloadable CSV master dumps.
- **[`A`] [Planespotters.net](https://www.planespotters.net/)** (🟢 Passive, *Free*) — Global aviation photography and airframe production-list database tracking aircraft MSN serial numbers across every historical airline/government re-registration and paint livery change.
- **[`A`] [The OpenSky Network](https://opensky-network.org/)** (🟢 Passive, *OSS / Free*) — Swiss non-profit academic air-traffic sensor network offering free REST APIs and multi-year Trino/Impala SQL access to raw historical Mode-S, ADS-B, and FLARM transponder frames.
- **[`S`] [OpenSanctions](https://www.opensanctions.org/)** (🟢 Passive, *Freemium*) — Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.

### Phase 2: Uncensored ADS-B & MLAT Flight Tracking
Reconstruct live and historical flight legs on unfiltered networks that ignore FAA LADD block requests.

- **[`S`] [ADS-B Exchange](https://globe.adsbexchange.com/)** (🟢 Passive, *Free*) — World's largest unfiltered public ADS-B and MLAT aircraft tracking map—refusing FAA LADD/PIA censorship blocks so investigators can track military transports, state VIP jets, and private tail numbers.
- **[`S`] [airplanes.live](https://globe.airplanes.live/)** (🟢 Passive, *Free*) — Community-owned, non-commercial, completely uncensored global ADS-B/MLAT flight tracker built by feeder volunteers displaying military, government, LADD, and private jets for free.
- **[`S`] [Flightradar24](https://www.flightradar24.com/)** (🟢 Passive, *Freemium*) — Highest-density global commercial ADS-B, satellite ADS-B, and FLARM flight tracker offering 3D cockpit replay, weather overlays, airport ground movement, and granular fleet histories.
- **[`A`] [FlightAware](https://www.flightaware.com/)** (🟢 Passive, *Freemium*) — Authoritative IFR flight-plan filing, FBO arrival/departure log, and historical route database covering global airlines and North American/European general aviation.

### Phase 3: Airfield Imagery & RF Correlation
Correlate ramp parking via satellite imagery, ATC audio archives, and regional GNSS jamming interference.

- **[`A`] [LiveATC.net](https://www.liveatc.net/)** (🟢 Passive, *Free*) — Streams live VHF air traffic control tower/approach/center frequencies worldwide and stores 30-day downloadable 30-minute MP3 audio archives keyed by ICAO airport code and UTC block.
- **[`S`] [GPSJAM](https://gpsjam.org/)** (🟢 Passive, *Free*) — Daily global H3 hexagonal map created by John Wiseman deriving real-world GPS/GNSS electronic-warfare jamming and spoofing zones from aircraft ADS-B navigation-accuracy (`NACp`) drops!
- **[`S`] [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/)** (🟢 Passive, *Free*) — Official ESA portal (replacing retired Sentinel Hub EO Browser) providing free global Sentinel-1 SAR (cloud-penetrating radar!) and 10m Sentinel-2 optical/SWIR/NDVI imagery every ~5 days.

---

<a id="telegram-discord-extremist-scam-mapping"></a>
## Telegram & Discord Network Mapping
- **Playbook ID**: `telegram-discord-extremist-scam-mapping` · **Disciplines**: `PHONEINT / SOCMINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `username / keyword / url`
- **Objective**: Discover, archive, and map interconnected Telegram channels, bots, and Discord servers used by threat actors, fraud rings, or influence operations.

### Phase 1: Passive Web Mirror & Catalogue Discovery
Search public channel indexes and Google CSE dorks (`site:t.me`) without joining any group or exposing an account.

- **[`S`] [TGStat](https://tgstat.com/)** (🟢 Passive, *Freemium*) — Largest public Telegram analytics and discovery engine indexing 2.8M+ channels and groups by keyword, language, country, citation graph, subscriber history, and cross-channel reposts.
- **[`A`] [Telemetr.io](https://telemetr.io/)** (🟢 Passive, *Freemium*) — Global Telegram channel directory and full-text post search engine tracking audience overlap, channel mentions, country classifications, and historical deleted/edited post analytics.
- **[`A`] [Telegago (Official Google CSE)](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg)** (🟢 Passive, *Free*) — Custom Google Programmable Search Engine tuned specifically for public Telegram channels, `t.me/s/` post previews, and `joinchat` invite links (use this official `cse.google.com` link only!).
- **[`A`] [TelegramDB](https://www.telegramdb.org/)** (🟢 Passive, *Freemium*) — Searchable database of public Telegram groups, supergroups, channels, and numeric user-to-group memberships accessible via web overview and bot commands.

### Phase 2: Forwarding Graph & Bot Token Analysis
Archive channel messages, build Gephi-ready message-forwarding edge lists, and inspect exposed Telegram bot tokens.

- **[`S`] [Telepathy](https://github.com/prose-intelligence-ltd/Telepathy-Community)** (🟢 Passive, *OSS / Free*) — Open-source Python Telegram OSINT CLI archiving full channel histories, media, member lists, top-poster statistics, user IDs, and Gephi-ready message-forwarding edge lists.
- **[`A`] [Telethon](https://github.com/LonamiWebs/Telethon)** (🟢 Passive, *OSS / Free*) — Actively maintained asynchronous Python 3 MTProto client library for the Telegram API—the standard foundation for custom Telegram OSINT scrapers, channel monitors, and ID resolvers.
- **[`S`] [Gephi](https://gephi.org/)** (🟢 Passive, *OSS / Free*) — Leading open-source desktop network analysis and graph visualization suite capable of rendering tens of thousands of nodes/edges for social network mapping, Telegram forward networks, and corporate ownership.

### Phase 3: Discord Snowflake & Invite Pivoting
Decode Discord Snowflake IDs into exact millisecond creation timestamps, inspect invite metadata, and check leaked server archives.

- **[`A`] [DiscordLookup / Discord.id](https://discord.id/)** (🟢 Passive, *Free*) — Decodes 64-bit Discord Snowflake IDs (users, servers, channels, messages) into exact UTC millisecond creation timestamps, avatar/banner CDN hashes, and public badge flags.
- **[`B`] [DiscordLeaks (Unicorn Riot)](https://discordleaks.unicornriot.ninja/)** (🟢 Passive, *Free*) — Journalistic public-interest searchable archive of hundreds of thousands of chat messages from extremist and hate-group Discord servers published by Unicorn Riot.

---

<a id="github-secret-developer-attribution"></a>
## Developer Attribution & Git Repository Forensics
- **Playbook ID**: `github-secret-developer-attribution` · **Disciplines**: `CODEINT / EMAILINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `username / repo_code / domain`
- **Objective**: Uncover developer real-world identities, corporate affiliations, timezone habits, and accidentally committed credentials from Git commit histories and public code.

### Phase 1: Commit Patch Email & SSH/GPG Key Extraction
Append `.patch` to commits or scan commit logs to extract raw author/committer emails, PGP key IDs, and SSH public keys (`github.com/<user>.keys`).

- **[`A`] [GitRecon](https://github.com/GONZOsint/gitrecon)** (🟢 Passive, *OSS / Free*) — Scans GitHub and GitLab user profiles, commit histories, PGP keys, and public event streams to uncover developer email addresses, full names, avatars, and organization memberships.
- **[`S`] [GHunt](https://github.com/mxrch/GHunt)** (🟢 Passive, *OSS / Free*) — Offensive Google OSINT framework extracting GAIA IDs, display names, profile photos, Google Maps reviews/geolocations, Calendar availability, and Drive document owners from any Gmail address or Google Doc URL.
- **[`A`] [keys.openpgp.org & Ubuntu Keyserver](https://keys.openpgp.org/)** (🟢 Passive, *Free*) — Public OpenPGP cryptographic keyservers (`keys.openpgp.org` and `keyserver.ubuntu.com`) indexing PGP public keys, creation timestamps, UID email aliases, and web-of-trust cross-signatures.
- **[`S`] [GitHub Native Code Search & `.patch` Trick](https://github.com/search)** (🟢 Passive, *Free*) — GitHub's Rust-backed Blackbird code search engine supporting regex (`/pattern/`), `org:`, `path:`, and `symbol:`, plus appending `.patch` to any commit URL to reveal raw git author email headers.

### Phase 2: Cross-Repo Code & Secret Scanning
Scan org repos, forks, and dangling commits for leaked secrets, internal hostnames, and unique code patterns.

- **[`S`] [TruffleHog](https://github.com/trufflesecurity/trufflehog)** (🟡 Hybrid, *OSS / Free*) — Industry-leading open-source secret scanner with 800+ credential detectors across Git commit histories, GitHub orgs, S3 buckets, Docker images, Postman workspaces, and HuggingFace models.
- **[`S`] [Gitleaks](https://github.com/gitleaks/gitleaks)** (🟢 Passive, *OSS / Free*) — Ultra-fast Go SAST/OSINT secret scanner parsing full Git reflogs, dangling commits, and directory trees for hardcoded API keys, JWTs, database URIs, and private keys.
- **[`S`] [grep.app](https://grep.app/)** (🟢 Passive, *Free*) — Sub-second regular-expression code search engine across 500,000+ public GitHub repositories—ideal for finding internal domains, custom SDK headers, wallet addresses, or unique error strings.
- **[`A`] [Sourcegraph Code Search](https://sourcegraph.com/search)** (🟢 Passive, *Freemium*) — Universal structural and regex code search across millions of open-source GitHub, GitLab, and package repositories, supporting commit-diff (`type:diff`) and author searches.
- **[`A`] [git-hound](https://github.com/tillson/git-hound)** (🟢 Passive, *OSS / Free*) — Reconnaissance-oriented GitHub secret hunter combining target subdomain lists with custom regexes and Shannon entropy scoring to surface exposed internal credentials.

### Phase 3: Cloud Storage & Package Ecosystem Pivot
Pivot discovered project slugs across npm/PyPI/DockerHub maintainers and AWS/Azure/GCP public buckets.

- **[`S`] [cloud_enum](https://github.com/initstring/cloud_enum)** (🔴 Active, *OSS / Free*) — Multi-cloud OSINT enumeration tool mutating company/brand keywords to discover publicly accessible AWS S3 buckets, Azure Storage Blobs/Apps, and Google Cloud Storage buckets/AppEngine instances.
- **[`A`] [GrayhatWarfare](https://buckets.grayhatwarfare.com/)** (🟢 Passive, *Freemium*) — Pre-indexed search engine over millions of open AWS S3, Azure Blob, Google Cloud Storage, and DigitalOcean Spaces buckets—enabling 100% passive filename and keyword searches.
- **[`A`] [Open Source Insights (deps.dev)](https://deps.dev/)** (🟢 Passive, *Free*) — Google's open-source package intelligence graph mapping dependency trees, maintainer accounts, Advisories, OpenSSF Scorecards, and linked source repos across npm, PyPI, Go, Maven, Cargo, and NuGet.

---

<a id="threat-actor-phishing-infra-triage"></a>
## Phishing & Malware Infrastructure Pivoting
- **Playbook ID**: `threat-actor-phishing-infra-triage` · **Disciplines**: `CTI / DNSINT / NETINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `url / ip / file_hash`
- **Objective**: Triage a suspicious URL, C2 IP, or malware sample and pivot across TLS certificates, JARM fingerprints, DOM hashes, and passive DNS to uncover the actor's entire campaign.

### Phase 1: Passive Reputation & Sandbox Lookup
Query existing hash, URL, and IP telemetry first before submitting anything new that could tip off the adversary.

- **[`S`] [VirusTotal & VT Graph](https://www.virustotal.com/)** (🟢 Passive, *Freemium*) — Global threat-intelligence nexus correlating 70+ AV engines with Passive DNS, communicating files, downloaded payloads, TLS cert history, favicon `main_icon_dhash`, and interactive VT Graph link boards.
- **[`S`] [urlscan.io](https://urlscan.io/)** (🟡 Hybrid, *Freemium*) — Headless browser website sandbox recording full DOM HTML, every HTTP XHR request, JS resource SHA-256 hashes, TLS certificates, ASN details, and visual screenshots—ideal for phishing kit hunting.
- **[`S`] [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/)** (🟢 Passive, *Free*) — Bern University / abuse.ch community malware repository indexing confirmed samples searchable by MD5/SHA-256, imphash, TLSH, ssdeep, YARA rule, malware family (`tag:LummaStealer`), and code-signing cert.
- **[`S`] [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/)** (🟢 Passive, *Free*) — Open-access Indicator of Compromise (IOC) sharing platform cataloging active botnet C2 `ip:port` sockets, malicious domains, URLs, and payload hashes mapped to Malpedia malware families.
- **[`A`] [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/)** (🟢 Passive, *Free*) — Tracks live and historical malware-distribution URLs (droppers, loaders, GootLoader, ClickFix payloads) with ASN/registrar statistics and downloadable hostfile/RPZ feeds.

### Phase 2: DOM, Favicon, TLS & JARM Pivoting
Pivot on HTTP body hashes, favicon MurmurHash3 (`mmh3`), JARM TLS fingerprints, and certificate serial numbers to find sibling C2/phishing nodes.

- **[`S`] [Censys Search](https://search.censys.io/)** (🟢 Passive, *Freemium*) — Continuous internet-wide scanner indexing billions of services across all 65,535 TCP ports plus the deepest historical X.509 TLS certificate repository—unmatched for C2 and origin-IP hunting.
- **[`S`] [Shodan](https://www.shodan.io/)** (🟢 Passive, *Freemium*) — World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **[`S`] [Validin](https://app.validin.com/)** (🟢 Passive, *Freemium*) — High-speed adversary infrastructure hunting platform offering sub-second pivoting across historical Passive DNS, HTTP response headers, HTML body hashes, favicon hashes, JARM, and TLS certificates.
- **[`A`] [Pulsedive](https://pulsedive.com/)** (🟡 Hybrid, *Freemium*) — Analyst-friendly community threat intelligence platform enriching IPs, domains, and URLs with passive DNS, WHOIS, port banners, HTTP screenshots, risk factors, and MITRE threat links.
- **[`A`] [Hunt.io](https://hunt.io/)** (🟢 Passive, *Freemium*) — Adversary infrastructure discovery engine actively fingerprinting C2 listeners (Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel, AsyncRAT), open directories, and attacker staging servers.

### Phase 3: Noise Filtering & Threat Actor Context
Separate mass internet scanners from targeted attacks and map IOCs to known threat groups and MITRE ATT&CK TTPs.

- **[`S`] [GreyNoise Visualizer](https://viz.greynoise.io/)** (🟢 Passive, *Freemium*) — Global passive honeypot sensor grid distinguishing benign mass internet scanners (Shodan, Censys, Googlebot) and opportunistic botnets from targeted human attacks.
- **[`S`] [Malpedia (Fraunhofer FKIE)](https://malpedia.caad.fkie.fraunhofer.de/)** (🟢 Passive, *Free*) — Curated encyclopedia indexing 3,000+ malware families and 700+ threat actor groups with peer-reviewed vendor reports, YARA rules, and synonym alias mappings (e.g., Cozy Bear = APT29 = Midnight Blizzard).
- **[`S`] [MITRE ATT&CK & ATT&CK Navigator](https://attack.mitre.org/)** (🟢 Passive, *OSS / Free*) — Globally authoritative knowledge base of adversary tactics, techniques, software tools, and tracked intrusion groups across Enterprise, Cloud, Mobile, and ICS environments.
- **[`S`] [OpenCTI](https://github.com/OpenCTI-Platform/opencti)** (🟢 Passive, *OSS / Free*) — Enterprise-grade open-source Cyber Threat Intelligence knowledge graph built on STIX 2.1, linking threat actors, campaigns, infrastructure, malware, geopolitical entities, and OSINT reports.
- **[`S`] [IntelOwl](https://github.com/intelowlproject/IntelOwl)** (🟢 Passive, *OSS / Free*) — API-driven threat intelligence and OSINT orchestration platform executing 150+ analyzers (Shodan, Censys, OTX, AbuseIPDB, Epieos, Tor, YARA, ExifTool) in parallel against a single observable.

---

<a id="darkweb-ransomware-exposure-assessment"></a>
## Dark Web, Ransomware & Infostealer Exposure Triage
- **Playbook ID**: `darkweb-ransomware-exposure-assessment` · **Disciplines**: `DARKINT / BREACHINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `domain / email / onion_url`
- **Objective**: Assess whether an organization or executive has compromised employee/customer stealer logs, darknet mentions, or active ransomware extortion listings.

### Phase 1: Ransomware Extortion & Leak-Site Check
Query clearnet ransomware victim trackers and darknet indexers without directly visiting hostile extortion `.onion` portals.

- **[`S`] [RansomLook](https://www.ransomlook.io/)** (🟢 Passive, *OSS / Free*) — 100% open-source ransomware intelligence platform scraping, screenshotting, and indexing 100+ ransomware extortion `.onion` leak portals, Telegram channels, and victim posts on the clearnet.
- **[`A`] [ransomwatch](https://ransomwhat.telemetry.ltd/)** (🟢 Passive, *OSS / Free*) — Open-source tracker monitoring ransomware gang darknet leak sites and publishing machine-readable JSON feeds of active extortion groups, onion mirror uptime, and claimed victims.
- **[`S`] [Ahmia.fi](https://ahmia.fi/)** (🟢 Passive, *OSS / Free*) — Longest-running reputable clearnet-and-Tor search engine indexing public `.onion` v3 hidden services while strictly filtering illegal abuse material—safe first-pass darknet keyword discovery.
- **[`S`] [Intelligence X (IntelX)](https://intelx.io/)** (🟢 Passive, *Freemium*) — Massive historical OSINT archive indexing 200B+ records across data leaks, Pastebin/paste sites, I2P/Tor darknets, WHOIS history, public documents, and DNS selectors.

### Phase 2: Corporate Infostealer Infection Check
Identify infected employee/user devices compromised by RedLine, Lumma, Raccoon, or Vidar infostealers targeting corporate login URLs.

- **[`S`] [Hudson Rock — Cavalier Free OSINT Tools](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools)** (🟢 Passive, *Freemium*) — Global cybercrime intelligence engine fueled by millions of real-world RedLine, Lumma, Vidar, and Raccoon infostealer malware infections—checking compromised domains, emails, usernames, and IPs.
- **[`S`] [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/)** (🟢 Passive, *Freemium*) — Troy Hunt's gold-standard breach exposure service indexing 17.8B+ compromised accounts across 1,000+ breaches, stealer logs, and pastes—without ever exposing raw victim passwords.
- **[`S`] [DeHashed](https://dehashed.com/)** (🟢 Passive, *Paid*) — High-speed breach correlation search engine and REST API for authorized security researchers, supporting regex/wildcard pivoting across emails, usernames, IPs, phones, VINs, and password hashes.
- **[`A`] [LeakIX](https://leakix.net/)** (🟢 Passive, *Freemium*) — Continuous internet-wide indexer flagging misconfigured open databases (Elastic, Mongo, CouchDB, Redis), exposed `.git`/`.env` files, and vulnerable web services with responsible disclosure focus.

### Phase 3: Isolated Darknet Deep Dive
When direct `.onion` inspection is required, execute crawls and triage inside an isolated Tor/Whonix workspace.

- **[`S`] [Whonix](https://www.whonix.org/)** (🟢 Passive, *OSS / Free*) — Two-VM security operating system (Gateway + Workstation) enforcing total Tor network isolation at the hypervisor level—making accidental real-IP DNS or WebRTC leaks structurally impossible even under malware compromise.
- **[`S`] [Tor Browser](https://www.torproject.org/download/)** (🟢 Passive, *OSS / Free*) — Official onion-routed anti-fingerprinting browser from The Tor Project—mandatory for accessing `.onion` services and compartmentalizing anonymity-critical research.
- **[`S`] [Robin (AI-Powered Dark Web OSINT)](https://github.com/apurvsinghgautam/robin)** (🟢 Passive, *OSS / Free*) — Open-source AI-assisted Dark Web OSINT tool querying multiple Tor search engines simultaneously via local Tor SOCKS5 proxy, deduplicating `.onion` hits, and synthesizing threat summaries via local/API LLMs.
- **[`A`] [TorBot (OWASP)](https://github.com/DedSecInside/TorBot)** (🔴 Active, *OSS / Free*) — OWASP open-source Dark Web OSINT crawler traversing `.onion` links over Tor SOCKS5 to extract page titles, embedded emails, clearnet pivot links, JSON link trees, and status codes.

---

<a id="wireless-rf-geospatial-triangulation"></a>
## Wireless BSSID, Cell Tower & RF Signal Intelligence
- **Playbook ID**: `wireless-rf-geospatial-triangulation` · **Disciplines**: `SIGINT / GEOINT` · **Difficulty**: `Advanced` · **Seed Selector**: `mac_bssid / rf_frequency / coordinates`
- **Objective**: Geolocate devices, routers, IoT beacons, or radio transmissions by pivoting MAC/BSSID identifiers, cell-tower LAC/CID tuples, and global SDR monitoring nodes.

### Phase 1: OUI Vendor & BSSID Geolocation
Resolve Wi-Fi BSSID / Bluetooth MAC addresses to hardware manufacturers and historical wardriven GPS coordinates.

- **[`S`] [WiGLE (Wireless Geographic Logging Engine)](https://wigle.net/)** (🟢 Passive, *Freemium*) — World's largest wardriving database indexing 1.4+ billion Wi-Fi networks (SSID/BSSID), Bluetooth beacons, and cell towers mapped to exact GPS coordinates since 2001.
- **[`S`] [Apple WPS BSSID Geolocation (`bssid-geolocator`)](https://github.com/acheong08/apple-corelocation-experiments)** (🟢 Passive, *OSS / Free*) — Queries Apple's public unauthenticated CoreLocation Wi-Fi Positioning System protobuf endpoint (`gs-loc.apple.com`) to resolve any router MAC/BSSID to fresh iPhone-crowdsourced GPS coordinates!
- **[`A`] [Wireshark IEEE MAC OUI Vendor Lookup](https://www.wireshark.org/tools/oui-lookup.html)** (🟢 Passive, *OSS / Free*) — Client-side IEEE Organizationally Unique Identifier lookup mapping the first 24/28/36 bits of any Ethernet, Wi-Fi BSSID, or Bluetooth MAC address to exact hardware manufacturer (e.g., DJI, Hikvision, Starlink, Cisco).

### Phase 2: Cellular Tower & GNSS Interference Mapping
Map MCC/MNC/LAC/CID cell tower identifiers to physical tower coordinates and inspect regional GPS/GNSS spoofing zones.

- **[`S`] [OpenCelliD & Unwired Labs](https://opencellid.org/)** (🟢 Passive, *Free*) — World's largest open database of 40M+ GSM/UMTS/LTE/5G cellular base stations, resolving `MCC + MNC + LAC/TAC + CellID` tuples from telecom logs or field modems to physical tower GPS coordinates.
- **[`A`] [CellMapper](https://www.cellmapper.net/)** (🟢 Passive, *Free*) — Crowdsourced cellular tower sector-polygon, frequency band, PCI, and eNodeB/gNodeB directional azimuth coverage map across global mobile carriers.
- **[`S`] [GPSJAM](https://gpsjam.org/)** (🟢 Passive, *Free*) — Daily global H3 hexagonal map created by John Wiseman deriving real-world GPS/GNSS electronic-warfare jamming and spoofing zones from aircraft ADS-B navigation-accuracy (`NACp`) drops!

### Phase 3: Remote SDR & Orbital Downlink Monitoring
Monitor HF/VHF utility broadcasts via networked Software-Defined Radios and correlate overhead satellite passes.

- **[`S`] [KiwiSDR Global Public Receiver Network](http://kiwisdr.com/public/)** (🟢 Passive, *OSS / Free*) — Global grid of 600+ volunteer-hosted wideband 0–30 MHz HF Software-Defined Radios tunable live in any browser—supporting TDoA (Time Difference of Arrival) direction-finding triangulation of unknown transmitters!
- **[`S`] [WebSDR.org](http://www.websdr.org/)** (🟢 Passive, *Free*) — University of Twente & worldwide directory of browser-accessible multi-user SDR receivers spanning HF, VHF, UHF, amateur bands, marine VHF, and geostationary QO-100 satellite transponders.
- **[`S`] [SatNOGS (Open Source Satellite Ground Station Network)](https://network.satnogs.org/)** (🟢 Passive, *OSS / Free*) — Libre Space Foundation's global network of automated open-source VHF/UHF/L/S-band ground stations recording live satellite waterfall spectrograms, telemetry frames, and transmitter downlink frequencies.
- **[`S`] [CelesTrak](https://celestrak.org/)** (🟢 Passive, *Free*) — Dr. T.S. Kelso's authoritative public astrodynamics portal publishing Two-Line Element (TLE) / GP orbital catalogs, SATCAT metadata, conjunction alerts, and live 3D Cesium orbit visualizations.

---

<a id="social-handle-multi-stage-unmasking"></a>
## Instagram / TikTok / Creator Handle Multi-Stage Surface Expansion
- **Playbook ID**: `social-handle-multi-stage-unmasking` · **Disciplines**: `SOCMINT / USERINT / PHONEINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `username / url`
- **Objective**: Turn a single social handle (e.g. Instagram or TikTok username) into a complete cross-platform identity, business, phone, email, and web infrastructure graph using iterative stage-by-stage expansion.

### Phase 1: Handle Enumeration & Deterministic Alias Mutation
Sweep exact handle and separator/prefix variants (`.` -> `_`, `-`, concatenated, title-stripped) across 600+ social platforms and developer registries.

- **[`S`] [WhatsMyName](https://whatsmyname.app/)** (🟢 Passive, *OSS / Free*) — Community-maintained JSON detection standard (`wmn-data.json`) and instant browser web app checking 700+ sites with finely tuned HTTP status/response fingerprints to minimize false positives.
- **[`S`] [Maigret](https://github.com/soxoj/maigret)** (🟢 Passive, *OSS / Free*) — Advanced username dossier builder checking 3,000+ websites, parsing discovered profile pages to extract real names, bios, avatars, linked handles, and generating self-contained HTML/PDF/XMind reports.
- **[`S`] [Sherlock](https://github.com/sherlock-project/sherlock)** (🟢 Passive, *OSS / Free*) — The most widely used open-source Python CLI for hunting down social media and forum accounts by username across 400+ curated websites simultaneously, with Tor/proxy and CSV/JSON export support.
- **[`S`] [Blackbird](https://github.com/p1ngul1n0/blackbird)** (🟢 Passive, *OSS / Free*) — Fast asynchronous OSINT tool searching accounts by both username and email across 600+ sites, featuring WhatsMyName integration, AI profile metadata extraction, web UI, and PDF reporting.

### Phase 2: Link-in-Bio, WhatsApp & Contact Carving
Harvest indexed bios, Linktree/Beacons hubs, and `wa.me/` links to extract E.164 phone numbers, booking emails, and external clinic/brand domains.

- **[`S`] [Instaloader](https://instaloader.github.io/)** (🟢 Passive, *OSS / Free*) — Gold-standard open-source Python CLI and library downloading public/followed Instagram photos, videos, Reels, Stories, IGTV, captions, comments, timestamps, and geotags cleanly.
- **[`S`] [yt-dlp](https://github.com/yt-dlp/yt-dlp)** (🟢 Passive, *OSS / Free*) — De facto open-source media archiver supporting 1,800+ video/social platforms (YouTube, X, TikTok, Rumble, Telegram,VK, news sites) with `--write-info-json` forensic metadata sidecars.
- **[`S`] [PhoneInfoga](https://github.com/sundowndev/phoneinfoga)** (🟢 Passive, *OSS / Free*) — Leading open-source Go framework for international phone number reconnaissance—extracting E.164 country/carrier metadata, OVH/Numverify line types, and automated Google dork footprints across social/classified sites.
- **[`S`] [Holehe](https://github.com/megadose/holehe)** (🟢 Passive, *OSS / Free*) — Checks whether an email address is registered across 120+ websites (Spotify, Instagram, X, GitHub, Adobe, Gravatar, Imgur, Office365) via silent registration/login checks without alerting the target.

### Phase 3: Domain, TLS SAN & Analytics Network Pivot
Pivot every discovered bio domain through Certificate Transparency, WHOIS/RDAP, and Google Analytics `G-`/`GTM-` IDs to uncover sister properties.

- **[`S`] [crt.sh (Certificate Transparency Search)](https://crt.sh/)** (🟢 Passive, *OSS / Free*) — Sectigo's free, keyless Certificate Transparency log search engine with direct public PostgreSQL SQL access (`crt.sh:5432`)—exposing every publicly trusted SSL/TLS cert and SAN subdomain ever issued.
- **[`S`] [Wayback Google Analytics (Bellingcat)](https://github.com/bellingcat/wayback-google-analytics)** (🟢 Passive, *OSS / Free*) — Bellingcat Python CLI scraping historical Wayback Machine snapshots to extract `UA-`, `G-`, and `GTM-` tracking codes across time to link covert site networks.
- **[`S`] [urlscan.io](https://urlscan.io/)** (🟡 Hybrid, *Freemium*) — Headless browser website sandbox recording full DOM HTML, every HTTP XHR request, JS resource SHA-256 hashes, TLS certificates, ASN details, and visual screenshots—ideal for phishing kit hunting.
- **[`S`] [Wayback Machine (Internet Archive)](https://web.archive.org/)** (🟢 Passive, *Free*) — Humanity's digital memory indexing 900+ billion archived web captures since 1996, backed by the powerful CDX Server API for wildcard subdomain discovery, MIME filtering, and deleted-content recovery.

---

<a id="origin-ip-unmasking-behind-cdn-waf"></a>
## Unmasking Origin Server IPs Behind Cloudflare & WAFs
- **Playbook ID**: `origin-ip-unmasking-behind-cdn-waf` · **Disciplines**: `DNSINT / NETINT` · **Difficulty**: `Advanced` · **Seed Selector**: `domain`
- **Objective**: Identify true backend origin IPv4/IPv6 servers shielded behind Cloudflare, Akamai, or Fastly without triggering WAF rate limits.

### Phase 1: Historical DNS, SPF & Mail Gateway Leaks
Inspect historical `A`/`AAAA` records prior to CDN onboarding, plus `SPF` `ip4:` directives and non-proxied `MX`/`mail.*` subdomains.

- **[`S`] [SecurityTrails](https://securitytrails.com/)** (🟢 Passive, *Freemium*) — Premier historical DNS and WHOIS time-machine tracking multi-year A, AAAA, MX, NS, and TXT record changes—essential for unmasking pre-Cloudflare origin server IPs.
- **[`A`] [ViewDNS.info](https://viewdns.info/)** (🟢 Passive, *Freemium*) — Swiss-army web toolkit bundling 20+ domain/IP utilities: Reverse IP Lookup, Reverse WHOIS, IP History,Reverse MX/NS, Chinese Firewall Test, DNSSEC check, and ASN lookup.
- **[`A`] [haktrails](https://github.com/hakluke/haktrails)** (🟢 Passive, *OSS / Free*) — Go CLI querying SecurityTrails passive DNS, historical WHOIS, and associated domain endpoints in Unix pipelines.
- **[`S`] [checkdmarc](https://github.com/domainaware/checkdmarc)** (🔴 Active, *OSS / Free*) — Python CLI and library that actively queries DNS and connects to live MX servers via SMTP STARTTLS to validate SPF, DMARC, BIMI, MTA-STS, DNSSEC, and TLS certs.

### Phase 2: X.509 Certificate & JARM Stack Correlation
Search global IPv4 TLS scans for non-CDN ASNs presenting valid certificates for `*.target.com` or matching JARM TLS stack fingerprints.

- **[`S`] [Censys Search](https://search.censys.io/)** (🟢 Passive, *Freemium*) — Continuous internet-wide scanner indexing billions of services across all 65,535 TCP ports plus the deepest historical X.509 TLS certificate repository—unmatched for C2 and origin-IP hunting.
- **[`S`] [Shodan](https://www.shodan.io/)** (🟢 Passive, *Freemium*) — World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **[`A`] [tlsx (ProjectDiscovery)](https://github.com/projectdiscovery/tlsx)** (🔴 Active, *OSS / Free*) — Fast TLS connection grabber extracting SAN/CN domain lists, JARM hashes, JA3 fingerprints, certificate serials, and expired/mismatched origin certificates across CIDR blocks.
- **[`S`] [JARM (Salesforce Active TLS Fingerprinter)](https://github.com/salesforce/jarm)** (🔴 Active, *OSS / Free*) — Active TLS server fingerprinting tool sending 10 bespoke TLS ClientHello packets to generate a 62-char hash identifying Cobalt Strike, Mythic, and C2 stacks.

### Phase 3: Shodan MurmurHash3 Favicon & Body Hash Pivot
Compute the 32-bit signed `mmh3` hash of `/favicon.ico` and query cyberspace search engines for direct IPs serving identical brand assets.

- **[`S`] [Shodan](https://www.shodan.io/)** (🟢 Passive, *Freemium*) — World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **[`S`] [FOFA](https://en.fofa.info/)** (🟢 Passive, *Freemium*) — Massive cyberspace asset search engine indexing global web titles, HTTP headers, body hashes, TLS certificates, icon hashes, and APAC/global infrastructure often missed by Western crawlers.
- **[`A`] [ZoomEye](https://www.zoomeye.ai/)** (🟢 Passive, *Freemium*) — Knownsec's global cyberspace search engine cataloging IPv4/IPv6 host banners, web component fingerprints, IoT firmware versions, and historical port exposure.
- **[`S`] [httpx (ProjectDiscovery)](https://github.com/projectdiscovery/httpx)** (🔴 Active, *OSS / Free*) — Fast multi-purpose Go HTTP toolkit probing discovered hosts for status codes, HTML titles, TLS certs, JARM hashes, favicon `mmh3` hashes, tech stacks, ASN info, and CDN detection.

---

<a id="shadow-ai-llm-infrastructure-recon"></a>
## Shadow AI, Exposed LLM & Vector-DB Infrastructure Recon
- **Playbook ID**: `shadow-ai-llm-infrastructure-recon` · **Disciplines**: `AI-OPSEC / NETINT / CODEINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `domain / asn / company`
- **Objective**: Discover unauthenticated Ollama, vLLM, Open WebUI, Gradio, MLflow, Jupyter, and Qdrant/Milvus RAG databases across an organization's cloud perimeter.

### Phase 1: Cyberspace Banner & Port Discovery
Query passive internet scan indexes for AI inference ports (`11434` Ollama, `6333` Qdrant, `19530` Milvus, `8000` vLLM, `7860` Gradio) inside target ASNs/certs.

- **[`S`] [Shodan](https://www.shodan.io/)** (🟢 Passive, *Freemium*) — World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **[`S`] [Censys Search](https://search.censys.io/)** (🟢 Passive, *Freemium*) — Continuous internet-wide scanner indexing billions of services across all 65,535 TCP ports plus the deepest historical X.509 TLS certificate repository—unmatched for C2 and origin-IP hunting.
- **[`S`] [FOFA](https://en.fofa.info/)** (🟢 Passive, *Freemium*) — Massive cyberspace asset search engine indexing global web titles, HTTP headers, body hashes, TLS certificates, icon hashes, and APAC/global infrastructure often missed by Western crawlers.
- **[`A`] [Uncover (ProjectDiscovery)](https://github.com/projectdiscovery/uncover)** (🟢 Passive, *OSS / Free*) — Go CLI wrapper querying Shodan, Censys, FOFA, Quake, Hunter, ZoomEye, Netlas, CriminalIP, and PublicWWW simultaneously and piping deduplicated `ip:port` targets straight into Unix pipelines.

### Phase 2: Code, HuggingFace & MCP Config Leak Hunting
Search public GitHub orgs and HuggingFace spaces for leaked `.env`, `.mcp.json`, fine-tuned weights, and internal dataset references.

- **[`S`] [TruffleHog](https://github.com/trufflesecurity/trufflehog)** (🟡 Hybrid, *OSS / Free*) — Industry-leading open-source secret scanner with 800+ credential detectors across Git commit histories, GitHub orgs, S3 buckets, Docker images, Postman workspaces, and HuggingFace models.
- **[`S`] [Gitleaks](https://github.com/gitleaks/gitleaks)** (🟢 Passive, *OSS / Free*) — Ultra-fast Go SAST/OSINT secret scanner parsing full Git reflogs, dangling commits, and directory trees for hardcoded API keys, JWTs, database URIs, and private keys.
- **[`S`] [detect-secrets (Yelp)](https://github.com/Yelp/detect-secrets)** (🟢 Passive, *OSS / Free*) — Enterprise-grade secret detection suite scanning codebases and git histories using high-entropy heuristics and service-specific regex plugins.
- **[`S`] [KeyHacks](https://github.com/streaak/keyhacks)** (🟡 Hybrid, *OSS / Free*) — Canonical reference catalog of 150+ third-party API key formats and exact commands to verify whether a discovered API token is live.

### Phase 3: Authorized Active Verification
With explicit authorization, verify exposed OpenAPI `/docs`, `/v1/models`, and CORS policies on discovered AI subdomains.

- **[`S`] [httpx (ProjectDiscovery)](https://github.com/projectdiscovery/httpx)** (🔴 Active, *OSS / Free*) — Fast multi-purpose Go HTTP toolkit probing discovered hosts for status codes, HTML titles, TLS certs, JARM hashes, favicon `mmh3` hashes, tech stacks, ASN info, and CDN detection.
- **[`A`] [Nuclei (Exposure & OSINT Templates)](https://github.com/projectdiscovery/nuclei)** (🟡 Hybrid, *OSS / Free*) — YAML template-driven scanner featuring dedicated `osint/`, `exposures/`, `token-spray/`, and `technologies/` template suites ( ONLY run active probes against explicitly authorized targets!).
- **[`S`] [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)** (🔴 Active, *OSS / Free*) — Community-curated library of 10,000+ YAML active detection templates covering exposed panels, cloud misconfigurations, OSINT user checks, and tech fingerprints.
- **[`A`] [Katana](https://github.com/projectdiscovery/katana)** (🔴 Active, *OSS / Free*) — Next-generation Go web crawling and spidering framework supporting both standard HTTP and headless Chromium JS rendering to extract hidden API routes, JS files, and forms.

---

<a id="ransomware-onion-actor-attribution"></a>
## Ransomware Leak-Site, `.onion` & Threat Actor Attribution
- **Playbook ID**: `ransomware-onion-actor-attribution` · **Disciplines**: `DARKINT / CTI / CRYPTOINT` · **Difficulty**: `Advanced` · **Seed Selector**: `onion_url / crypto_address / file_hash`
- **Objective**: Correlate Tor hidden-service technical mistakes, SSH/TLS key reuse, ransom wallet clusters, and malware artifacts to attribute underground operators.

### Phase 1: Passive Dark-Web Indexing & Leak Monitoring
Track actor handles, victim posts, and historical `.onion` mirrors via dark-web threat feeds without touching live C2 infrastructure.

- **[`S`] [RansomLook](https://www.ransomlook.io/)** (🟢 Passive, *OSS / Free*) — 100% open-source ransomware intelligence platform scraping, screenshotting, and indexing 100+ ransomware extortion `.onion` leak portals, Telegram channels, and victim posts on the clearnet.
- **[`S`] [Ahmia.fi](https://ahmia.fi/)** (🟢 Passive, *OSS / Free*) — Longest-running reputable clearnet-and-Tor search engine indexing public `.onion` v3 hidden services while strictly filtering illegal abuse material—safe first-pass darknet keyword discovery.
- **[`A`] [OnionSearch](https://github.com/megadose/OnionSearch)** (🟢 Passive, *OSS / Free*) — Python CLI meta-scraper aggregating results across a dozen active `.onion` darknet search engines simultaneously over Tor (`127.0.0.1:9050`) into a clean CSV.
- **[`S`] [Stem (Tor Controller Python Library)](https://github.com/torproject/stem)** (🟢 Passive, *OSS / Free*) — Official Tor Project Python library inspecting Tor consensus relays, exit-node descriptors, hidden-service v3 descriptors, and circuit rotation.

### Phase 2: SSH Host-Key, Favicon & Certificate De-Anonymization
Match hidden-service SSH host keys, HTTP ETag/favicon hashes, and server headers against clearnet IPv4 scans.

- **[`A`] [OnionScan / Onion-Location Deanonymization Checks](https://github.com/s-rah/onionscan)** (🔴 Active, *OSS / Free*) — Classic hidden-service OPSEC auditing tool hunting misconfigurations that deanonymize `.onion` servers—exposed Apache `server-status`, SSH host key reuse against Shodan, EXIF metadata, and open SMTP headers.
- **[`S`] [Shodan](https://www.shodan.io/)** (🟢 Passive, *Freemium*) — World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **[`S`] [Censys Search](https://search.censys.io/)** (🟢 Passive, *Freemium*) — Continuous internet-wide scanner indexing billions of services across all 65,535 TCP ports plus the deepest historical X.509 TLS certificate repository—unmatched for C2 and origin-IP hunting.
- **[`S`] [ssh-audit](https://github.com/jtesta/ssh-audit)** (🔴 Active, *OSS / Free*) — Zero-dependency Python active SSH server & client fingerprinter grabbing SSH banners, host-key algorithms, KEX/MAC lists, and inferring OS/distro builds.

### Phase 3: Ransomware Wallet Clustering & Malware Pivot
Trace ransom BTC/XMR/TRON flows toward cash-out exchanges and link binary capabilities to known actor toolsets.

- **[`S`] [GraphSense](https://graphsense.org/)** (🟢 Passive, *OSS / Free*) — Premier open-source, self-hostable cryptoasset analytics platform (AIT / Iknaio) providing UTXO co-spend clustering, account-model tracing, attribution tags, and full data sovereignty across BTC, ETH, LTC, ZEC, and TRON.
- **[`S`] [mempool.space](https://mempool.space/)** (🟢 Passive, *OSS / Free*) — Open-source Bitcoin & Lightning Network explorer featuring interactive UTXO input/output flow diagrams, fee-rate telemetry, mining pool attribution, and self-hostable Tor `.onion` support.
- **[`S`] [capa (Mandiant Capability Detector)](https://github.com/mandiant/capa)** (🟢 Passive, *OSS / Free*) — Mandiant static binary analyzer mapping PE/ELF/.NET executables directly to MITRE ATT&CK behaviors, C2 capabilities, and crypto routines.
- **[`A`] [MISP (Open Source Threat Intelligence Platform)](https://www.misp-project.org/)** (🟢 Passive, *OSS / Free*) — Open-source threat intelligence and OSINT sharing standard used by CERTs worldwide to store, correlate, enrich (`misp-modules`), and federate structured IOCs and OSINT dossiers.

---

<a id="sanctions-evasion-shell-company-finint"></a>
## Cross-Border Shell Company, Sanctions & Beneficial Ownership Tracing
- **Playbook ID**: `sanctions-evasion-shell-company-finint` · **Disciplines**: `FININT / TRANSINT` · **Difficulty**: `Advanced` · **Seed Selector**: `company / person_name / vessel_imo`
- **Objective**: Unravel multi-jurisdictional holding structures, nominee directors, sanctioned oligarch proxies, and shadow-fleet maritime tankers.

### Phase 1: Global Corporate Registry & LEI Mapping
Resolve legal entity identifiers, parent-subsidiary trees, officer appointments, and SEC/gazette filings.

- **[`S`] [OpenCorporates](https://opencorporates.com/)** (🟢 Passive, *Freemium*) — World's largest open database of legal entities—normalizing 220M+ company registrations and 290M+ officer/director records across 140+ national and state jurisdictions with direct registry provenance.
- **[`S`] [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/)** (🟢 Passive, *Free*) — Global Legal Entity Identifier Foundation database mapping 2.6M+ financial counterparties worldwide—explicitly disclosing 'Level 2' Direct Accounting Parent and Ultimate Parent ownership chains!
- **[`A`] [Bellingcat EDGAR Search](https://github.com/bellingcat/edgar)** (🟢 Passive, *OSS / Free*) — Investigative toolkit querying SEC EDGAR corporate filings for executive names, subsidiary disclosures, addresses, and insider ownership.
- **[`S`] [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/)** (🟢 Passive, *OSS / Free*) — Interactive graph database from the International Consortium of Investigative Journalists spanning 810,000+ offshore shell companies, trusts, and foundations from Panama, Pandora, Paradise, and Bahamas Papers.

### Phase 2: Sanctions, PEP & Leaked Archive Cross-Matching
Screen entities and directors against OFAC/EU/UN watchlists and cross-border investigative leak archives.

- **[`S`] [OpenSanctions](https://www.opensanctions.org/)** (🟢 Passive, *Freemium*) — Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.
- **[`S`] [Yente (OpenSanctions Self-Hosted API)](https://github.com/opensanctions/yente)** (🟢 Passive, *OSS / Free*) — Self-hosted OpenSanctions entity-resolution search and fuzzy-matching API screening names, companies, vessels, and crypto wallets offline.
- **[`S`] [OCCRP Aleph](https://aleph.occrp.org/)** (🟢 Passive, *OSS / Free*) — Organized Crime and Corruption Reporting Project's flagship investigative data platform cross-indexing hundreds of millions of leaked emails, land registries, gazettes, procurement files, and corporate filings.
- **[`S`] [DocumentCloud & MuckRock](https://www.documentcloud.org/)** (🟢 Passive, *OSS / Free*) — Investigative journalism repository hosting millions of OCR'd primary-source court exhibits, leaked memos, police reports, and FOIA releases contributed by thousands of newsrooms worldwide.

### Phase 3: Physical Asset Verification (Vessels & Aircraft)
Link corporate SPVs to hull IMO numbers, MMSI flag-hopping histories, and executive jet ICAO24 transponders.

- **[`S`] [Equasis](https://www.equasis.org/)** (🟢 Passive, *Free*) — International public-safety maritime database (founded by EC & French Maritime Admin) providing free historical Registered Owner, Commercial Operator, ISM Manager, Flag, Class, P&I Club, and PSC inspection records by IMO!
- **[`S`] [MarineTraffic](https://www.marinetraffic.com/)** (🟢 Passive, *Freemium*) — Global coastal and satellite AIS ship-tracking standard displaying live vessel positions, reported draught changes, destination strings, port arrivals, and crowdsourced hull photography.
- **[`S`] [readsb (1090 MHz ADS-B Decoder)](https://github.com/wiedehopf/readsb)** (🟢 Passive, *OSS / Free*) — Actively maintained Mode-S / ADS-B / TIS-B 1090 MHz SDR receiver and decoder powering modern airplanes.live and ADS-B Exchange feeder stations.
- **[`S`] [tar1090 (ADS-B Historical Track UI)](https://github.com/wiedehopf/tar1090)** (🟢 Passive, *OSS / Free*) — Enhanced ADS-B/Mode-S web interface powering ADS-B Exchange and airplanes.live with replayable altitude/speed trails and military hex filters.

---

<a id="cloud-entra-m365-tenant-recon"></a>
## Enterprise Cloud, Microsoft Entra ID & Storage Perimeter Recon
- **Playbook ID**: `cloud-entra-m365-tenant-recon` · **Disciplines**: `CODEINT / EMAILINT / DNSINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `domain / company`
- **Objective**: Map an enterprise's external cloud identity tenant (Entra ID / Google Workspace), federated domains, public storage buckets, and IaC leaks.

### Phase 1: OIDC Tenant, Mail & Federation Mapping
Query OpenID Connect discovery documents, MX/SPF/DMARC/BIMI records, and federated sibling domains tied to the corporate tenant.

- **[`S`] [ROADtools (Entra ID / Azure AD Recon)](https://github.com/dirkjanm/ROADtools)** (🔴 Active, *OSS / Free*) — Microsoft Entra ID (Azure AD) reconnaissance suite including `roadrecon` for tenant OIDC metadata, federated domains, and directory graphing.
- **[`B`] [o365recon](https://github.com/nyxgeek/o365recon)** (🔴 Active, *OSS / Free*) — Unauthenticated Microsoft 365 and Azure tenant reconnaissance script retrieving federation brand names, tenant IDs, and MDI instances.
- **[`S`] [checkdmarc](https://github.com/domainaware/checkdmarc)** (🔴 Active, *OSS / Free*) — Python CLI and library that actively queries DNS and connects to live MX servers via SMTP STARTTLS to validate SPF, DMARC, BIMI, MTA-STS, DNSSEC, and TLS certs.
- **[`S`] [crt.sh (Certificate Transparency Search)](https://crt.sh/)** (🟢 Passive, *OSS / Free*) — Sectigo's free, keyless Certificate Transparency log search engine with direct public PostgreSQL SQL access (`crt.sh:5432`)—exposing every publicly trusted SSL/TLS cert and SAN subdomain ever issued.

### Phase 2: Public Cloud Bucket & Artifact Enumeration
Identify AWS S3, Google Cloud Storage, and Azure Blob containers matching company brand slugs and JS bundle references.

- **[`A`] [GrayhatWarfare](https://buckets.grayhatwarfare.com/)** (🟢 Passive, *Freemium*) — Pre-indexed search engine over millions of open AWS S3, Azure Blob, Google Cloud Storage, and DigitalOcean Spaces buckets—enabling 100% passive filename and keyword searches.
- **[`S`] [cloud_enum](https://github.com/initstring/cloud_enum)** (🔴 Active, *OSS / Free*) — Multi-cloud OSINT enumeration tool mutating company/brand keywords to discover publicly accessible AWS S3 buckets, Azure Storage Blobs/Apps, and Google Cloud Storage buckets/AppEngine instances.
- **[`B`] [S3Scanner](https://github.com/sa7mon/S3Scanner)** (🔴 Active, *OSS / Free*) — Concurrent Go tool auditing S3-compatible object storage buckets (AWS, GCP, DigitalOcean, Linode) for public READ/WRITE ACL misconfigurations and listing object contents.
- **[`A`] [GCPBucketBrute (Rhino Security Labs)](https://github.com/RhinoSecurityLabs/GCPBucketBrute)** (🔴 Active, *OSS / Free*) — Active Google Cloud Storage enumerator brute-forcing bucket permutations and invoking unauthenticated `testIamPermissions` to detect public exposure.

### Phase 3: Repository IaC, Container & CI/CD Audit
Inspect public GitHub Actions workflows, Terraform files, and container images for leaked AWS Account IDs and secrets.

- **[`S`] [TruffleHog](https://github.com/trufflesecurity/trufflehog)** (🟡 Hybrid, *OSS / Free*) — Industry-leading open-source secret scanner with 800+ credential detectors across Git commit histories, GitHub orgs, S3 buckets, Docker images, Postman workspaces, and HuggingFace models.
- **[`A`] [Checkov](https://github.com/bridgecrewio/checkov)** (🟢 Passive, *OSS / Free*) — Static Infrastructure-as-Code analyzer auditing Terraform, CloudFormation, Helm, and Kubernetes manifests for public buckets and secrets.
- **[`S`] [Trivy (Aqua Security)](https://github.com/aquasecurity/trivy)** (🟡 Hybrid, *OSS / Free*) — All-in-one container image, git repository, filesystem, and Kubernetes scanner extracting SBOM packages, secrets, and CVEs.
- **[`S`] [Prowler](https://github.com/toniblyx/prowler)** (🔴 Active, *OSS / Free*) — Flagship open-source cloud security and asset inventory scanner mapping exposed S3/IAM/VPC/EKS/Azure/GCP/M365 services.

---

<a id="document-media-chronolocation-verification"></a>
## Investigative Media Verification, Chronolocation & Document Forensics
- **Playbook ID**: `document-media-chronolocation-verification` · **Disciplines**: `IMINT / GEOINT / ARCHINT` · **Difficulty**: `Intermediate` · **Seed Selector**: `image / video / document / url`
- **Objective**: Authenticate user-generated conflict or corporate media, extract exact upload timestamps, geolocate terrain landmarks, and preserve court-grade evidence.

### Phase 1: Evidentiary Capture & Cryptographic Hashing
Preserve volatile videos, posts, and webpages into signed WACZ/HTML bundles before takedown.

- **[`S`] [Bellingcat Auto Archiver](https://github.com/bellingcat/auto-archiver)** (🔴 Active, *OSS / Free*) — Bellingcat's evidentiary social media and web preservation pipeline archiving videos, screenshots, WACZ bundles, and SHA-256 hashes before deletion.
- **[`S`] [Monolith](https://github.com/Y2Z/monolith)** (🔴 Active, *OSS / Free*) — Fast Rust CLI fetching a live target webpage and embedding all external CSS, images, frames, and fonts into a single self-contained forensic HTML file.
- **[`S`] [SingleFile](https://github.com/gildas-lormeau/SingleFile)** (🟢 Passive, *OSS / Free*) — Essential open-source browser extension & CLI saving a complete, pixel-faithful rendered webpage (CSS, fonts, canvas, images embedded as data URIs) into a single self-contained `.html` file locally.
- **[`S`] [archive.today (archive.ph / archive.is)](https://archive.ph/)** (🟡 Hybrid, *Free*) — High-fidelity DOM + screenshot web archiver capturing JavaScript-heavy pages, social threads, and news articles that block `archive.org` `robots.txt` rules.

### Phase 2: Container Metadata, Embedded Timestamps & ELA
Extract EXIF/XMP/OLE author trails, decode 64-bit TikTok/Snowflake upload timestamps, and check compression tampering.

- **[`S`] [ExifTool](https://exiftool.org/)** (🟢 Passive, *OSS / Free*) — Phil Harvey's legendary Perl CLI/library reading, writing, and auditing EXIF, GPS, XMP, IPTC, ICC, QuickTime atoms, PDF producer tags, and Office revision metadata across 400+ file formats.
- **[`S`] [oletools (decalage2)](https://github.com/decalage2/oletools)** (🟢 Passive, *OSS / Free*) — Python forensic suite (`olemeta`, `olevba`, `oleid`, `pyxswf`) extracting author metadata, revision timestamps, external URLs, and macros from MS Office files.
- **[`A`] [QPDF](https://github.com/qpdf/qpdf)** (🟢 Passive, *OSS / Free*) — Structural PDF inspection utility decompressing object streams (`--qdf`) to reveal hidden XMP author strings, edit history, and redacted layer remnants.
- **[`S`] [Forensically (29a.ch)](https://29a.ch/photo-forensics/)** (🟢 Passive, *Free*) — Client-side HTML5 digital photo forensics laboratory offering Clone Detection (copy-move), Error Level Analysis (ELA), Noise Analysis, PCA, JPEG Ghost detection, and hidden thumbnail extraction.

### Phase 3: Terrain Triangulation & Shadow Chronolocation
Match skyline geometry, road intersections, and solar azimuth shadow angles against satellite constellations.

- **[`S`] [Bellingcat OpenStreetMap Search](https://osm-search.bellingcat.com/)** (🟢 Passive, *OSS / Free*) — Point-and-click visual builder wrapping Overpass QL so investigators can select up to 5 visible features (e.g., power line, mosque, roundabout, river) and distance tolerances without writing code.
- **[`S`] [SunCalc](https://www.suncalc.org/)** (🟢 Passive, *Free*) — Computes solar azimuth, altitude angle, shadow length ratios, dawn/dusk twilight phases, and sun trajectory arcs for any coordinate and date/time on Earth.
- **[`S`] [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/)** (🟢 Passive, *Free*) — Official ESA portal (replacing retired Sentinel Hub EO Browser) providing free global Sentinel-1 SAR (cloud-penetrating radar!) and 10m Sentinel-2 optical/SWIR/NDVI imagery every ~5 days.
- **[`S`] [Google Earth Pro](https://www.google.com/earth/about/versions/)** (🟢 Passive, *Free*) — Indispensable desktop 3D globe offering multi-decade Historical Imagery time-sliders, 3D terrain skyline simulation, sun-lighting previews, viewshed analysis, and KML/KMZ case overlays.

---

<a id="web3-drainer-scam-cluster-investigation"></a>
## Web3 Phishing Kit, Wallet Drainer & Laundering Attribution
- **Playbook ID**: `web3-drainer-scam-cluster-investigation` · **Disciplines**: `CRYPTOINT / DNSINT / CTI` · **Difficulty**: `Advanced` · **Seed Selector**: `crypto_address / domain / url`
- **Objective**: Pivot from a phishing dApp or victim transaction hash to unmask the drainer operator's smart contracts, sister domains, and cash-out infrastructure.

### Phase 1: Drainer Domain, JS Bundle & Analytics Clustering
Capture the dApp DOM, extract hardcoded receiver/contract addresses from JS bundles, and pivot shared `G-`/Cloudflare patterns.

- **[`S`] [urlscan.io](https://urlscan.io/)** (🟡 Hybrid, *Freemium*) — Headless browser website sandbox recording full DOM HTML, every HTTP XHR request, JS resource SHA-256 hashes, TLS certificates, ASN details, and visual screenshots—ideal for phishing kit hunting.
- **[`A`] [MetaMask Eth-Phishing-Detect](https://github.com/MetaMask/eth-phishing-detect)** (🟢 Passive, *OSS / Free*) — Continuously updated open registry of verified Web3 wallet-drainer domains, typosquatting dApps, and allowlisted crypto infrastructure.
- **[`A`] [ScamSniffer Drainer Database](https://github.com/scamsniffer/scam-database)** (🟢 Passive, *OSS / Free*) — Community threat intelligence feed mapping malicious EVM drainer addresses and phishing domains tied to Pink/Angel/Inferno Drainer kits.
- **[`S`] [PublicWWW](https://publicwww.com/)** (🟢 Passive, *Freemium*) — Source-code search engine indexing the raw HTML, inline JavaScript, and CSS of 500M+ web pages—the ultimate weapon for pivoting on Google Analytics IDs, AdSense tags, crypto skimmers, or custom widgets.

### Phase 2: Smart Contract Bytecode & Approval Tracing
Decompile `Permit2`/approval drainer contracts and export ERC-20/NFT victim transfer traces.

- **[`S`] [Etherscan](https://etherscan.io/)** (🟢 Passive, *Freemium*) — Canonical Ethereum explorer providing verified smart-contract Solidity source code, internal EVM call traces, ERC-20/721 transfers, Token Approval checker, public name tags, and comments.
- **[`S`] [Foundry Cast (`cast`)](https://github.com/foundry-rs/foundry)** (🟡 Hybrid, *OSS / Free*) — Fast Rust EVM command-line Swiss-army knife querying live RPC nodes, reading private storage slots, resolving ENS, decompiling bytecode, and tracing txs.
- **[`S`] [Slither (Trail of Bits)](https://github.com/crytic/slither)** (🟡 Hybrid, *OSS / Free*) — Static analysis framework pulling live verified Solidity/Vyper contracts directly by chain address to map admin privileges, upgrade proxies, and drainers.
- **[`A`] [Ethereum ETL](https://github.com/blockchain-etl/ethereum-etl)** (🟢 Passive, *OSS / Free*) — Python CLI exporting EVM blocks, internal traces, ERC-20/721 transfers, and contract deployments to CSV/JSON/SQL for forensic graph queries.

### Phase 3: Cross-Chain Bridge & Off-Ramp Attribution
Follow consolidated funds across bridges, DEX swaps, and Tron/BTC hops to attributed exchange deposit addresses.

- **[`S`] [Arkham Intelligence](https://intel.arkm.com/)** (🟢 Passive, *Freemium*) — Leading public blockchain intelligence platform attributing 300M+ multi-chain wallet addresses to real-world exchanges, funds, hackers, and individuals with an interactive fund-flow Visualizer.
- **[`S`] [GraphSense](https://graphsense.org/)** (🟢 Passive, *OSS / Free*) — Premier open-source, self-hostable cryptoasset analytics platform (AIT / Iknaio) providing UTXO co-spend clustering, account-model tracing, attribution tags, and full data sovereignty across BTC, ETH, LTC, ZEC, and TRON.
- **[`S`] [Breadcrumbs.app](https://www.breadcrumbs.app/)** (🟢 Passive, *Freemium*) — Intuitive visual blockchain investigation workbench mapping multi-hop BTC, ETH, Polygon, Solana, Arbitrum, Base, and TRON fund flows with entity risk tags and shareable case charts.
- **[`S`] [OpenSanctions](https://www.opensanctions.org/)** (🟢 Passive, *Freemium*) — Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.


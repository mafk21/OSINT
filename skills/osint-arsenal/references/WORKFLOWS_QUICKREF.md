# 20 OSINT Investigation Playbooks

## Person & Digital Footprint Attribution (`person-identity-attribution` — Seed: `username / email / person_name`)
*Build a verified 360-degree profile of an online persona or individual by chaining handle enumeration, email side-channels, breach metadata, and visual cross-verification.*
1. **Handle & Profile Discovery**: Run cross-platform username sweeps and extract structured profile metadata (avatars, bios, user IDs, creation dates). (`maigret, sherlock, whatsmyname, blackbird, socid-extractor`)
2. **Email & Phone Enrichment**: Check discovered emails/phones against silent registration side-channels and Google/Gravatar ecosystems without triggering reset alerts. (`holehe, ghunt, epieos, ignorant, phoneinfoga`)
3. **Breach & Historical Correlation**: Correlate historical usernames, IP clues, or secondary emails across breach indexes and infostealer telemetry. (`have-i-been-pwned, intelligence-x, hudson-rock-cavalier, dehashed, h8mail`)
4. **Avatar & Face Cross-Match**: Reverse-search profile photos across face/visual indexes to uncover unlinked accounts using different handles. (`yandex-images, pimeyes, facecheck-id, tineye, search-by-image`)
5. **Evidence Preservation & Link Graph**: Hash and archive all confirmed profile pages and plot entity links with confidence ratings. (`singlefile, hunchly, maltego, flowsint`)

## Passive-First Domain & Infrastructure Attribution (`domain-attack-surface-recon` — Seed: `domain`)
*Map an organization's external infrastructure, hidden origin IPs behind CDNs, historical ownership, and sister domains without sending a single packet to the target.*
1. **RDAP, Historical WHOIS & Sister Domains**: Query current RDAP and historical WHOIS records to find registrant emails, org names, and reverse-WHOIS sister domains. (`icann-lookup, whoxy, securitytrails, viewdns-info, domaintools`)
2. **Certificate Transparency & Passive Subdomains**: Harvest subdomains and wildcard SANs from Certificate Transparency logs and passive DNS aggregators. (`crt-sh, subfinder, owasp-amass, findomain, dnsdumpster`)
3. **Origin IP & Banner Pivoting**: Uncover real origin servers behind Cloudflare/WAFs using TLS cert serials, favicon mmh3 hashes, and historical DNS A-records. (`shodan, censys, fofa, netlas, zoomeye`)
4. **Analytics, AdSense & Source Code Pivoting**: Extract Google Tag Manager, Analytics (`G-`/`UA-`), AdSense, or custom JS snippets to discover undisclosed domains run by the same operator. (`builtwith, publicwww, urlscan-io, nerdydata, web-check`)
5. **Historical Archive Mining**: Pull forgotten endpoints, leaked config files, and old team pages from historical web crawls. (`wayback-machine, waymore, gau, common-crawl`)

## Photo & Video Geolocation + Chronolocation (`photo-video-geolocation-chronolocation` — Seed: `image / video`)
*Determine the exact coordinates (geolocation) and capture timestamp (chronolocation) of an unverified photo or video using visual, architectural, geometric, and solar clues.*
1. **Metadata & Provenance Triage**: Inspect container metadata (EXIF/XMP/QuickTime atoms), extract keyframes, and search for the earliest public upload on the web. (`exiftool, invid-weverify, google-lens, yandex-images, forensically`)
2. **Region Narrowing & AI Scene Leads**: Identify country/region indicators (license plates, bollards, road markings, utility poles, scripts, bird calls) and generate candidate regions. (`geohints, plonk-it, picarta, geo-sleuth, birdnet`)
3. **Vector & Spatial Feature Querying**: Translate visual constraints (e.g., 'gas station within 80m of railway and mosque') into OpenStreetMap Overpass queries. (`overpass-turbo, bellingcat-osm-search, overpass-ultra, peakvisor`)
4. **Satellite & Street-Level Ground Truthing**: Confirm exact camera line-of-sight and historical construction changes using 3D terrain, street-level photos, and multispectral satellite time-series. (`google-earth-pro, copernicus-browser, mapillary, kartaview, esri-wayback`)
5. **Solar Azimuth & Shadow Chronolocation**: Measure object height vs. shadow length and azimuth angle to verify or narrow the exact date and local time of capture. (`suncalc, bellingcat-shadowfinder, shadowmap, wolfram-alpha`)

## Corporate Shell Unmasking, UBO & Sanctions Investigation (`corporate-beneficial-ownership-sanctions` — Seed: `company / person_name`)
*Trace complex cross-border corporate hierarchies, uncover Ultimate Beneficial Owners (UBOs), screen against global sanctions/PEP lists, and map physical supply-chain shipments.*
1. **Global Registry & LEI Resolution**: Locate incorporation filings, company numbers, registered agents, and direct/ultimate parent Legal Entity Identifiers. (`opencorporates, gleif-lei-search, uk-companies-house, sec-edgar, north-data`)
2. **Offshore Leaks & Investigative Document Cross-Check**: Pivot officers, addresses, and intermediaries across leaked offshore corporate registries, court filings, and journalism archives. (`occrp-aleph, icij-offshore-leaks, openownership, littlesis, courtlistener`)
3. **Sanctions, PEP & Debarment Screening**: Screen entities, directors, vessels, and addresses against consolidated OFAC, EU, UN, UK, and PEP watchlists. (`opensanctions, ofac-sanctions-search, eu-sanctions-map, sam-gov`)
4. **Customs, Trade & Procurement Verification**: Map real-world buyers, overseas factories, HS commodity codes, and government contracts via bills of lading and tender databases. (`importyeti, un-comtrade, usaspending, ted-eu-tenders`)

## Cryptocurrency Wallet Attribution & Cross-Chain Tracing (`crypto-wallet-laundering-trace` — Seed: `crypto_address / tx_hash`)
*Follow stolen, ransom, or illicit funds across UTXO and EVM blockchains, identify peel chains and cross-chain bridges, and link wallets to off-chain identities or KYC exchanges.*
1. **Raw Ledger Inspection & Token Approvals**: Inspect first-funding gas source (faucet/CEX hot wallet), transaction timestamps (activity timezone), and token transfers. (`etherscan, mempool-space, blockchair, solscan, tronscan`)
2. **Entity Attribution & Risk Screening**: Check 300M+ institutional/community wallet labels, OFAC SDN crypto tags, and scam reports. (`arkham-intelligence, misttrack, chainabuse, opensanctions`)
3. **Visual Hop Graphing & Clustering**: Build multi-hop fund-flow graphs, apply UTXO co-spend clustering, and trace DEX/bridge hops to cash-out deposit addresses. (`breadcrumbs, graphsense, metasleuth, walletexplorer, bubblemaps`)
4. **Web3 Handle & Off-Chain OSINT Pivot**: Pivot ENS names, Lens/Farcaster handles, NFT mints, and pasted wallet strings across GitHub, X, Telegram, and darknet indexes. (`debank, grep-app, intelligence-x, tgstat`)

## Maritime Vessel, AIS Spoofing & Shadow Fleet Investigation (`maritime-shadow-fleet-investigation` — Seed: `vessel_imo / mmsi`)
*Investigate suspect cargo vessels or tankers conducting dark-ship port calls, ship-to-ship (STS) transfers, flag-hopping, or sanctions evasion.*
1. **Permanent IMO Resolution & Ownership History**: Resolve MMSI/name to permanent 7-digit IMO number and pull historical flag changes, ISM managers, P&I insurers, and PSC detentions. (`equasis, opensanctions, itu-mars, tokyo-paris-mou`)
2. **AIS Track & Dark-Gap Analysis**: Analyze historical AIS tracks, loitering behavior, draught changes (loaded vs. ballast), and transponder gaps. (`global-fishing-watch, marinetraffic, vesselfinder, myshiptracking`)
3. **Optical & SAR Satellite Verification**: Use Sentinel-1 Synthetic Aperture Radar (penetrates clouds/night) and Sentinel-2 optical imagery to spot 'dark' ships during AIS blackouts. (`copernicus-browser, nasa-worldview, google-earth-pro, gpsjam`)

## Military, State & VIP Aircraft Tail-Number Investigation (`aircraft-tail-number-tracking` — Seed: `aircraft_hex / tail_number`)
*Track LADD/PIA-blocked executive jets, cargo charters, or military aircraft using unfiltered community ADS-B/MLAT receivers, ACARS datalinks, and aircraft registries.*
1. **ICAO 24-bit Hex & Registration Lookup**: Map tail number to ICAO 24-bit Mode-S hex code, airframe serial number, operator, and FAA/civil trust owner. (`faa-n-number-inquiry, planespotters-net, opensky-network, opensanctions`)
2. **Uncensored ADS-B & MLAT Flight Tracking**: Reconstruct live and historical flight legs on unfiltered networks that ignore FAA LADD block requests. (`ads-b-exchange, airplanes-live, flightradar24, flightaware`)
3. **Airfield Imagery & RF Correlation**: Correlate ramp parking via satellite imagery, ATC audio archives, and regional GNSS jamming interference. (`liveatc, gpsjam, copernicus-browser`)

## Telegram & Discord Network Mapping (`telegram-discord-extremist-scam-mapping` — Seed: `username / keyword / url`)
*Discover, archive, and map interconnected Telegram channels, bots, and Discord servers used by threat actors, fraud rings, or influence operations.*
1. **Passive Web Mirror & Catalogue Discovery**: Search public channel indexes and Google CSE dorks (`site:t.me`) without joining any group or exposing an account. (`tgstat, telemetr-io, telegago-cse, telegramdb`)
2. **Forwarding Graph & Bot Token Analysis**: Archive channel messages, build Gephi-ready message-forwarding edge lists, and inspect exposed Telegram bot tokens. (`telepathy, telethon, gephi`)
3. **Discord Snowflake & Invite Pivoting**: Decode Discord Snowflake IDs into exact millisecond creation timestamps, inspect invite metadata, and check leaked server archives. (`discord-lookup, discordleaks`)

## Developer Attribution & Git Repository Forensics (`github-secret-developer-attribution` — Seed: `username / repo_code / domain`)
*Uncover developer real-world identities, corporate affiliations, timezone habits, and accidentally committed credentials from Git commit histories and public code.*
1. **Commit Patch Email & SSH/GPG Key Extraction**: Append `.patch` to commits or scan commit logs to extract raw author/committer emails, PGP key IDs, and SSH public keys (`github.com/<user>.keys`). (`gitrecon, ghunt, keys-openpgp-org, github-code-search`)
2. **Cross-Repo Code & Secret Scanning**: Scan org repos, forks, and dangling commits for leaked secrets, internal hostnames, and unique code patterns. (`trufflehog, gitleaks, grep-app, sourcegraph, git-hound`)
3. **Cloud Storage & Package Ecosystem Pivot**: Pivot discovered project slugs across npm/PyPI/DockerHub maintainers and AWS/Azure/GCP public buckets. (`cloud-enum, grayhatwarfare, deps-dev`)

## Phishing & Malware Infrastructure Pivoting (`threat-actor-phishing-infra-triage` — Seed: `url / ip / file_hash`)
*Triage a suspicious URL, C2 IP, or malware sample and pivot across TLS certificates, JARM fingerprints, DOM hashes, and passive DNS to uncover the actor's entire campaign.*
1. **Passive Reputation & Sandbox Lookup**: Query existing hash, URL, and IP telemetry first before submitting anything new that could tip off the adversary. (`virustotal, urlscan-io, malwarebazaar, threatfox, urlhaus`)
2. **DOM, Favicon, TLS & JARM Pivoting**: Pivot on HTTP body hashes, favicon MurmurHash3 (`mmh3`), JARM TLS fingerprints, and certificate serial numbers to find sibling C2/phishing nodes. (`censys, shodan, validin, pulsedive, hunt-io`)
3. **Noise Filtering & Threat Actor Context**: Separate mass internet scanners from targeted attacks and map IOCs to known threat groups and MITRE ATT&CK TTPs. (`greynoise, malpedia, mitre-attack, opencti, intelowl`)

## Dark Web, Ransomware & Infostealer Exposure Triage (`darkweb-ransomware-exposure-assessment` — Seed: `domain / email / onion_url`)
*Assess whether an organization or executive has compromised employee/customer stealer logs, darknet mentions, or active ransomware extortion listings.*
1. **Ransomware Extortion & Leak-Site Check**: Query clearnet ransomware victim trackers and darknet indexers without directly visiting hostile extortion `.onion` portals. (`ransomlook, ransomwatch, ahmia, intelligence-x`)
2. **Corporate Infostealer Infection Check**: Identify infected employee/user devices compromised by RedLine, Lumma, Raccoon, or Vidar infostealers targeting corporate login URLs. (`hudson-rock-cavalier, have-i-been-pwned, dehashed, leakix`)
3. **Isolated Darknet Deep Dive**: When direct `.onion` inspection is required, execute crawls and triage inside an isolated Tor/Whonix workspace. (`whonix, tor-browser, robin-darkweb, torbot`)

## Wireless BSSID, Cell Tower & RF Signal Intelligence (`wireless-rf-geospatial-triangulation` — Seed: `mac_bssid / rf_frequency / coordinates`)
*Geolocate devices, routers, IoT beacons, or radio transmissions by pivoting MAC/BSSID identifiers, cell-tower LAC/CID tuples, and global SDR monitoring nodes.*
1. **OUI Vendor & BSSID Geolocation**: Resolve Wi-Fi BSSID / Bluetooth MAC addresses to hardware manufacturers and historical wardriven GPS coordinates. (`wigle, apple-bssid-wps, wireshark-oui-lookup`)
2. **Cellular Tower & GNSS Interference Mapping**: Map MCC/MNC/LAC/CID cell tower identifiers to physical tower coordinates and inspect regional GPS/GNSS spoofing zones. (`opencellid, cellmapper, gpsjam`)
3. **Remote SDR & Orbital Downlink Monitoring**: Monitor HF/VHF utility broadcasts via networked Software-Defined Radios and correlate overhead satellite passes. (`kiwisdr, websdr, satnogs, celestrak`)

## Instagram / TikTok / Creator Handle Multi-Stage Surface Expansion (`social-handle-multi-stage-unmasking` — Seed: `username / url`)
*Turn a single social handle (e.g. Instagram or TikTok username) into a complete cross-platform identity, business, phone, email, and web infrastructure graph using iterative stage-by-stage expansion.*
1. **Handle Enumeration & Deterministic Alias Mutation**: Sweep exact handle and separator/prefix variants (`.` -> `_`, `-`, concatenated, title-stripped) across 600+ social platforms and developer registries. (`whatsmyname, maigret, sherlock, blackbird`)
2. **Link-in-Bio, WhatsApp & Contact Carving**: Harvest indexed bios, Linktree/Beacons hubs, and `wa.me/` links to extract E.164 phone numbers, booking emails, and external clinic/brand domains. (`instaloader, yt-dlp, phoneinfoga, holehe`)
3. **Domain, TLS SAN & Analytics Network Pivot**: Pivot every discovered bio domain through Certificate Transparency, WHOIS/RDAP, and Google Analytics `G-`/`GTM-` IDs to uncover sister properties. (`crt-sh, bellingcat-wayback-ga, urlscan-io, wayback-machine`)

## Unmasking Origin Server IPs Behind Cloudflare & WAFs (`origin-ip-unmasking-behind-cdn-waf` — Seed: `domain`)
*Identify true backend origin IPv4/IPv6 servers shielded behind Cloudflare, Akamai, or Fastly without triggering WAF rate limits.*
1. **Historical DNS, SPF & Mail Gateway Leaks**: Inspect historical `A`/`AAAA` records prior to CDN onboarding, plus `SPF` `ip4:` directives and non-proxied `MX`/`mail.*` subdomains. (`securitytrails, viewdns-info, haktrails, checkdmarc`)
2. **X.509 Certificate & JARM Stack Correlation**: Search global IPv4 TLS scans for non-CDN ASNs presenting valid certificates for `*.target.com` or matching JARM TLS stack fingerprints. (`censys, shodan, tlsx, jarm`)
3. **Shodan MurmurHash3 Favicon & Body Hash Pivot**: Compute the 32-bit signed `mmh3` hash of `/favicon.ico` and query cyberspace search engines for direct IPs serving identical brand assets. (`shodan, fofa, zoomeye, httpx`)

## Shadow AI, Exposed LLM & Vector-DB Infrastructure Recon (`shadow-ai-llm-infrastructure-recon` — Seed: `domain / asn / company`)
*Discover unauthenticated Ollama, vLLM, Open WebUI, Gradio, MLflow, Jupyter, and Qdrant/Milvus RAG databases across an organization's cloud perimeter.*
1. **Cyberspace Banner & Port Discovery**: Query passive internet scan indexes for AI inference ports (`11434` Ollama, `6333` Qdrant, `19530` Milvus, `8000` vLLM, `7860` Gradio) inside target ASNs/certs. (`shodan, censys, fofa, uncover`)
2. **Code, HuggingFace & MCP Config Leak Hunting**: Search public GitHub orgs and HuggingFace spaces for leaked `.env`, `.mcp.json`, fine-tuned weights, and internal dataset references. (`trufflehog, gitleaks, detect-secrets, keyhacks`)
3. **Authorized Active Verification**: With explicit authorization, verify exposed OpenAPI `/docs`, `/v1/models`, and CORS policies on discovered AI subdomains. (`httpx, nuclei, nuclei-templates, katana`)

## Ransomware Leak-Site, `.onion` & Threat Actor Attribution (`ransomware-onion-actor-attribution` — Seed: `onion_url / crypto_address / file_hash`)
*Correlate Tor hidden-service technical mistakes, SSH/TLS key reuse, ransom wallet clusters, and malware artifacts to attribute underground operators.*
1. **Passive Dark-Web Indexing & Leak Monitoring**: Track actor handles, victim posts, and historical `.onion` mirrors via dark-web threat feeds without touching live C2 infrastructure. (`ransomlook, ahmia, onionsearch, tor-stem`)
2. **SSH Host-Key, Favicon & Certificate De-Anonymization**: Match hidden-service SSH host keys, HTTP ETag/favicon hashes, and server headers against clearnet IPv4 scans. (`onionscan, shodan, censys, ssh-audit`)
3. **Ransomware Wallet Clustering & Malware Pivot**: Trace ransom BTC/XMR/TRON flows toward cash-out exchanges and link binary capabilities to known actor toolsets. (`graphsense, mempool-space, mandiant-capa, misp`)

## Cross-Border Shell Company, Sanctions & Beneficial Ownership Tracing (`sanctions-evasion-shell-company-finint` — Seed: `company / person_name / vessel_imo`)
*Unravel multi-jurisdictional holding structures, nominee directors, sanctioned oligarch proxies, and shadow-fleet maritime tankers.*
1. **Global Corporate Registry & LEI Mapping**: Resolve legal entity identifiers, parent-subsidiary trees, officer appointments, and SEC/gazette filings. (`opencorporates, gleif-lei-search, bellingcat-edgar, icij-offshore-leaks`)
2. **Sanctions, PEP & Leaked Archive Cross-Matching**: Screen entities and directors against OFAC/EU/UN watchlists and cross-border investigative leak archives. (`opensanctions, opensanctions-yente, occrp-aleph, documentcloud`)
3. **Physical Asset Verification (Vessels & Aircraft)**: Link corporate SPVs to hull IMO numbers, MMSI flag-hopping histories, and executive jet ICAO24 transponders. (`equasis, marinetraffic, readsb, tar1090`)

## Enterprise Cloud, Microsoft Entra ID & Storage Perimeter Recon (`cloud-entra-m365-tenant-recon` — Seed: `domain / company`)
*Map an enterprise's external cloud identity tenant (Entra ID / Google Workspace), federated domains, public storage buckets, and IaC leaks.*
1. **OIDC Tenant, Mail & Federation Mapping**: Query OpenID Connect discovery documents, MX/SPF/DMARC/BIMI records, and federated sibling domains tied to the corporate tenant. (`roadtools, o365recon, checkdmarc, crt-sh`)
2. **Public Cloud Bucket & Artifact Enumeration**: Identify AWS S3, Google Cloud Storage, and Azure Blob containers matching company brand slugs and JS bundle references. (`grayhatwarfare, cloud-enum, s3scanner, gcpbucketbrute`)
3. **Repository IaC, Container & CI/CD Audit**: Inspect public GitHub Actions workflows, Terraform files, and container images for leaked AWS Account IDs and secrets. (`trufflehog, checkov-iac, trivy-scanner, prowler-cloud`)

## Investigative Media Verification, Chronolocation & Document Forensics (`document-media-chronolocation-verification` — Seed: `image / video / document / url`)
*Authenticate user-generated conflict or corporate media, extract exact upload timestamps, geolocate terrain landmarks, and preserve court-grade evidence.*
1. **Evidentiary Capture & Cryptographic Hashing**: Preserve volatile videos, posts, and webpages into signed WACZ/HTML bundles before takedown. (`bellingcat-auto-archiver, monolith, singlefile, archive-today`)
2. **Container Metadata, Embedded Timestamps & ELA**: Extract EXIF/XMP/OLE author trails, decode 64-bit TikTok/Snowflake upload timestamps, and check compression tampering. (`exiftool, oletools, qpdf-forensics, forensically`)
3. **Terrain Triangulation & Shadow Chronolocation**: Match skyline geometry, road intersections, and solar azimuth shadow angles against satellite constellations. (`bellingcat-osm-search, suncalc, copernicus-browser, google-earth-pro`)

## Web3 Phishing Kit, Wallet Drainer & Laundering Attribution (`web3-drainer-scam-cluster-investigation` — Seed: `crypto_address / domain / url`)
*Pivot from a phishing dApp or victim transaction hash to unmask the drainer operator's smart contracts, sister domains, and cash-out infrastructure.*
1. **Drainer Domain, JS Bundle & Analytics Clustering**: Capture the dApp DOM, extract hardcoded receiver/contract addresses from JS bundles, and pivot shared `G-`/Cloudflare patterns. (`urlscan-io, metamask-phishing-db, scamsniffer-db, publicwww`)
2. **Smart Contract Bytecode & Approval Tracing**: Decompile `Permit2`/approval drainer contracts and export ERC-20/NFT victim transfer traces. (`etherscan, foundry-cast, slither-analyzer, ethereum-etl`)
3. **Cross-Chain Bridge & Off-Ramp Attribution**: Follow consolidated funds across bridges, DEX swaps, and Tron/BTC hops to attributed exchange deposit addresses. (`arkham-intelligence, graphsense, breadcrumbs, opensanctions`)


# 12 OSINT Investigation Playbooks

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


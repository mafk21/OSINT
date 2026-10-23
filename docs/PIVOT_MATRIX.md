[⬅️ Back to Master Index](../README.md)

# 🧭 OSINT Selector Pivot Matrix (`Input → Tools → Downstream Pivots`)

Real-world investigations start from a **known selector** (an email, handle, phone number, domain, wallet, photo, IMO number, or BSSID) and pivot toward new selectors. Use this matrix—or run `python3 scripts/osint.py pivot <selector> --passive`—to pick your exact next move.

## Summary Selector Index

| Input Selector | Example Artifact | Total Tools | Passive Tools | Top S-Tier Starting Tools | Primary Downstream Outputs |
| :--- | :--- | :---: | :---: | :--- | :--- |
| [`domain`](#selector-domain) (Domain / Hostname) | `example.com` | **303** | 146 | [BuiltWith](https://builtwith.com/), [crt.sh (Certificate Transparency Search)](https://crt.sh/), [DNSDumpster](https://dnsdumpster.com/), [Subfinder](https://github.com/projectdiscovery/subfinder) | `subdomains`, `urls`, `tech_stack`, `dns_records` |
| [`keyword`](#selector-keyword) (Keyword / Phrase) | Project slug, quote, topic | **232** | 212 | [4CAT: Capture and Analysis Toolkit](https://github.com/digitalmethodsinitiative/4cat), [ADS-B Exchange](https://globe.adsbexchange.com/), [Ahmia.fi](https://ahmia.fi/), [AIL Framework (Analysis Information Leak — CIRCL)](https://www.ail-project.org/) | `geolocation`, `corporate_records`, `urls`, `metadata` |
| [`url`](#selector-url) (Web URL / Post Link) | Webpage, social post, phishing URL | **163** | 84 | [ArchiveWeb.page (Webrecorder)](https://archiveweb.page/), [SingleFile](https://github.com/gildas-lormeau/SingleFile), [Wayback Machine (Internet Archive)](https://web.archive.org/), [Hunchly](https://www.hunchly.com/) | `urls`, `metadata`, `archived_pages`, `tech_stack` |
| [`ip`](#selector-ip) (IPv4 / IPv6 Address) | `198.51.100.42` | **148** | 79 | [GreyNoise Visualizer](https://viz.greynoise.io/), [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [IPinfo.io](https://ipinfo.io/), [RIPEstat](https://stat.ripe.net/) | `open_ports`, `tech_stack`, `malware_iocs`, `dns_records` |
| [`company`](#selector-company) (Company / Organization) | Corporate name, LEI, CAGE | **137** | 112 | [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/), [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/), [OCCRP Aleph](https://aleph.occrp.org/), [OpenCorporates](https://opencorporates.com/) | `corporate_records`, `person_records`, `entity_graph`, `documents` |
| [`username`](#selector-username) (Username / Handle) | `@johndoe`, gaming alias | **99** | 78 | [Blackbird](https://github.com/p1ngul1n0/blackbird), [Maigret](https://github.com/soxoj/maigret), [Sherlock](https://github.com/sherlock-project/sherlock), [WhatsMyName](https://whatsmyname.app/) | `social_profiles`, `metadata`, `entity_graph`, `emails` |
| [`person_name`](#selector-person-name) (Person Full Name) | Individual, executive, official | **97** | 90 | [CourtListener & RECAP Archive](https://www.courtlistener.com/), [Judyrecords](https://www.judyrecords.com/), [Lumen Database (Harvard Berkman Klein Center)](https://lumendatabase.org/), [PACER (US Federal Courts)](https://pacer.uscourts.gov/) | `person_records`, `corporate_records`, `entity_graph`, `emails` |
| [`email`](#selector-email) (Email Address) | `user@company.com` | **86** | 66 | [Epieos](https://epieos.com/), [h8mail](https://github.com/khast3x/h8mail), [Holehe](https://github.com/megadose/holehe), [Proton Mail HKP Key Lookup](https://mail.proton.me/) | `emails`, `breach_records`, `social_profiles`, `entity_graph` |
| [`coordinates`](#selector-coordinates) (GPS Coordinates / AOI) | `lat, lon` bounding box | **80** | 78 | [Bellingcat OpenStreetMap Search](https://osm-search.bellingcat.com/), [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/), [Esri World Imagery Wayback](https://livingatlas.arcgis.com/wayback/), [Google Earth Pro](https://www.google.com/earth/about/versions/) | `geolocation`, `signal_telemetry`, `satellite_imagery`, `flight_tracks` |
| [`asn`](#selector-asn) (ASN / CIDR Netblock) | `AS13335`, `198.51.100.0/24` | **57** | 38 | [GreyNoise Visualizer](https://viz.greynoise.io/), [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [IPinfo.io](https://ipinfo.io/), [RIPEstat](https://stat.ripe.net/) | `open_ports`, `certificates`, `tech_stack`, `ip_addresses` |
| [`crypto_address`](#selector-crypto-address) (Crypto Wallet / Tx) | `0x...`, `bc1...`, `.eth`, `T...` | **47** | 41 | [Chainabuse (by TRM Labs)](https://www.chainabuse.com/), [Etherscan](https://etherscan.io/), [GraphSense](https://graphsense.org/), [mempool.space](https://mempool.space/) | `tx_graph`, `entity_graph`, `metadata`, `social_profiles` |
| [`document`](#selector-document) (Document File) | PDF, DOCX, XLSX, PGP key | **46** | 42 | [Dangerzone (Freedom of the Press Foundation)](https://dangerzone.rocks/), [oletools (decalage2)](https://github.com/decalage2/oletools), [PDFiD & pdf-parser (Didier Stevens Suite)](https://blog.didierstevens.com/programs/pdf-tools/), [QPDF](https://github.com/qpdf/qpdf) | `metadata`, `malware_iocs`, `secrets`, `urls` |
| [`file_hash`](#selector-file-hash) (File / Cert / DOM Hash) | SHA-256, MD5, JARM, mmh3 | **38** | 34 | [AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/), [capa (Mandiant Capability Detector)](https://github.com/mandiant/capa), [Hatching Tria.ge Sandbox](https://tria.ge/), [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) | `malware_iocs`, `dns_records`, `certificates`, `entity_graph` |
| [`phone`](#selector-phone) (Phone Number) | E.164 `+14155552671` | **38** | 29 | [Google libphonenumber Demo](https://libphonenumber.appspot.com/), [Ignorant](https://github.com/megadose/ignorant), [PhoneInfoga](https://github.com/sundowndev/phoneinfoga), [FreeCarrierLookup](https://freecarrierlookup.com/) | `social_profiles`, `phones`, `person_records`, `geolocation` |
| [`image`](#selector-image) (Image / Photograph) | JPEG/PNG, face crop, scenery | **35** | 33 | [Binwalk](https://github.com/ReFirmLabs/binwalk), [ExifTool](https://exiftool.org/), [Forensically (29a.ch)](https://29a.ch/photo-forensics/), [Google Lens](https://lens.google.com/) | `metadata`, `urls`, `geolocation`, `social_profiles` |
| [`repo_code`](#selector-repo-code) (Git Repo / Package) | GitHub org/repo, npm/PyPI pkg | **32** | 24 | [detect-secrets (Yelp)](https://github.com/Yelp/detect-secrets), [GH Archive](https://www.gharchive.org/), [Gitleaks](https://github.com/gitleaks/gitleaks), [grep.app](https://grep.app/) | `secrets`, `urls`, `metadata`, `emails` |
| [`rf_frequency`](#selector-rf-frequency) (RF Frequency (kHz/MHz)) | `8992 kHz` HFGCS, `433.92 MHz` | **21** | 18 | [AIS-catcher](https://github.com/jvde-github/AIS-catcher), [FCC Universal Licensing System (ULS) & FCCID.io](https://fccid.io/), [KiwiSDR Global Public Receiver Network](http://kiwisdr.com/public/), [readsb (1090 MHz ADS-B Decoder)](https://github.com/wiedehopf/readsb) | `signal_telemetry`, `geolocation`, `metadata`, `flight_tracks` |
| [`vessel_imo`](#selector-vessel-imo) (Vessel IMO / MMSI) | 7-digit IMO or 9-digit MMSI | **18** | 18 | [MarineTraffic](https://www.marinetraffic.com/), [Equasis](https://www.equasis.org/), [Global Fishing Watch Map](https://globalfishingwatch.org/map), [MyShipTracking](https://www.myshiptracking.com/) | `vessel_tracks`, `geolocation`, `corporate_records`, `sanctions_hits` |
| [`onion_url`](#selector-onion-url) (Tor `.onion` Address) | v3 hidden service URL | **17** | 12 | [Ahmia.fi](https://ahmia.fi/), [AIL Framework (Analysis Information Leak — CIRCL)](https://www.ail-project.org/), [deepdarkCTI (fastfire)](https://github.com/fastfire/deepdarkCTI), [Stem (Tor Controller Python Library)](https://github.com/torproject/stem) | `darkweb_mentions`, `opsec_protection`, `urls`, `certificates` |
| [`aircraft_hex`](#selector-aircraft-hex) (Aircraft ICAO Hex / Tail) | Mode-S `AE01D5`, `N123AB` | **16** | 16 | [ADS-B Exchange](https://globe.adsbexchange.com/), [airplanes.live](https://globe.airplanes.live/), [Flightradar24](https://www.flightradar24.com/), [tar1090 (ADS-B Historical Track UI)](https://github.com/wiedehopf/tar1090) | `flight_tracks`, `geolocation`, `signal_telemetry`, `corporate_records` |
| [`mac_bssid`](#selector-mac-bssid) (Wi-Fi BSSID / BLE MAC) | `00:11:22:33:44:55` | **11** | 5 | [Apple WPS BSSID Geolocation (`bssid-geolocator`)](https://github.com/acheong08/apple-corelocation-experiments), [WiGLE (Wireless Geographic Logging Engine)](https://wigle.net/), [Wireshark IEEE MAC OUI Vendor Lookup](https://www.wireshark.org/tools/oui-lookup.html), [WireTapper](https://github.com/h9zdev/WireTapper) | `signal_telemetry`, `metadata`, `geolocation`, `ip_addresses` |
| [`video`](#selector-video) (Video Clip) | MP4, livestream, social upload | **9** | 9 | [ExifTool](https://exiftool.org/), [FFmpeg](https://ffmpeg.org/), [InVID / WeVerify Verification Plugin](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [BirdNET Analyzer](https://birdnet.cornell.edu/) | `metadata`, `geolocation`, `person_records`, `urls` |
| [`audio`](#selector-audio) (Audio Recording) | Voice clip, background birds/hum | **8** | 8 | [ExifTool](https://exiftool.org/), [FFmpeg](https://ffmpeg.org/), [BirdNET Analyzer](https://birdnet.cornell.edu/), [Sonic Visualiser / Audacity Spectrogram Forensics](https://www.sonicvisualiser.org/) | `metadata`, `geolocation`, `person_records`, `documents` |
| [`vin`](#selector-vin) (Vehicle 17-Char VIN) | Automotive chassis number | **5** | 5 | [Bidfax / Stat.vin Salvage Auction VIN Archives](https://en.bidfax.info/), [NHTSA vPIC VIN Decoder & API](https://vpic.nhtsa.dot.gov/decoder/), [DeHashed](https://dehashed.com/), [That'sThem](https://thatsthem.com/) | `person_records`, `emails`, `geolocation`, `metadata` |

---

## Selector: domain
**Domain / Hostname** (`example.com`) — `303` tools (`python3 scripts/osint.py pivot domain --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**BBOT (Bighuge BLS OSINT Tool)**](https://github.com/blacklanternsecurity/bbot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `open_ports`, `tech_stack` |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**Google Hacking Database (Exploit-DB GHDB)**](https://www.exploit-db.com/google-hacking-database) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `urls`, `secrets`, `documents` |
| **S** | [**IntelOwl**](https://github.com/intelowlproject/IntelOwl) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `open_ports` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**OpenCTI**](https://github.com/OpenCTI-Platform/opencti) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `darkweb_mentions` |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**SearXNG**](https://docs.searxng.org/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `urls`, `documents` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **S** | [**Web-Check**](https://github.com/lissy93/web-check) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `dns_records`, `certificates`, `whois`, `tech_stack` |
| **A** | [**Brave Search & Custom OSINT Goggles**](https://search.brave.com/) | `all-in-one-frameworks` | 🟢 Passive | Free | `urls` |
| **A** | [**Crucix**](https://github.com/calesthio/Crucix) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `archived_pages`, `signal_telemetry` |
| **A** | [**IntelTechniques Search Tools**](https://inteltechniques.com/tools/index.html) | `all-in-one-frameworks` | 🟢 Passive | Free | `social_profiles`, `person_records`, `whois` |
| **A** | [**IVRE**](https://ivre.rocks/) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `certificates`, `dns_records`, `tech_stack` |
| **A** | [**Osmedeus**](https://github.com/j3ssie/osmedeus) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `open_ports`, `dns_records`, `tech_stack` |
| **A** | [**Photon**](https://github.com/s0md3v/Photon) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `emails`, `social_profiles`, `subdomains`, `secrets` |
| **A** | [**reconFTW**](https://github.com/six2dez/reconftw) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `open_ports`, `tech_stack` |
| **A** | [**reNgine**](https://github.com/yogeshojha/rengine) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `certificates` |
| **A** | [**sn0int**](https://github.com/kpcyrd/sn0int) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses`, `social_profiles`, `breach_records` |
| **A** | [**TheHive Case Management**](https://github.com/StrangeBee/thehive) | `all-in-one-frameworks` | 🟢 Passive | Freemium | `entity_graph`, `malware_iocs` |
| **B** | [**FinalRecon**](https://github.com/thewhiteh4t/FinalRecon) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `whois`, `certificates`, `dns_records`, `subdomains` |
| **B** | [**Harpoon**](https://github.com/Te-k/harpoon) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `dns_records`, `whois`, `open_ports`, `certificates` |
| **B** | [**Lampyre**](https://lampyre.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `geolocation`, `corporate_records`, `social_profiles` |
| **B** | [**Operative Framework**](https://github.com/graniet/operative-framework) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `entity_graph` |
| **A** | [**Keybase Identity Graph**](https://keybase.io/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `certificates`, `entity_graph` |
| **B** | [**Mr.Holmes**](https://github.com/Lucksi/Mr.Holmes) | `username-enumeration` | 🟡 Hybrid | OSS / Free | `social_profiles`, `whois`, `phones` |
| **B** | [**Namechk**](https://namechk.com/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles` |
| **S** | [**h8mail**](https://github.com/khast3x/h8mail) | `email-intelligence` | 🟢 Passive | OSS / Free | `breach_records`, `emails`, `social_profiles` |
| **S** | [**Hunter.io**](https://hunter.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **S** | [**MXToolbox SuperTool**](https://mxtoolbox.com/SuperTool.aspx) | `email-intelligence` | 🟡 Hybrid | Freemium | `dns_records`, `whois`, `tech_stack` |
| **S** | [**theHarvester**](https://github.com/laramies/theHarvester) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `subdomains`, `person_records`, `ip_addresses` |
| **A** | [**CrossLinked**](https://github.com/m8sec/CrossLinked) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `person_records`, `usernames` |
| **A** | [**EasyDMARC SPF / DMARC / BIMI & DKIM Lookup**](https://easydmarc.com/tools) | `email-intelligence` | 🟢 Passive | Free | `dns_records`, `emails`, `tech_stack` |
| **B** | [**AnalyzeID**](https://analyzeid.com/) | `email-intelligence` | 🟢 Passive | Freemium | `whois`, `entity_graph`, `urls` |
| **B** | [**Buster**](https://github.com/sham00n/buster) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `social_profiles`, `breach_records`, `whois` |
| **B** | [**OpenLeads**](https://github.com/openleads-dev/openleads) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `person_records` |
| **B** | [**RocketReach**](https://rocketreach.co/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `phones`, `person_records`, `corporate_records` |
| **B** | [**Skymem**](http://www.skymem.info/) | `email-intelligence` | 🟢 Passive | Freemium | `emails` |
| **B** | [**Snov.io**](https://snov.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **S** | [**Lumen Database (Harvard Berkman Klein Center)**](https://lumendatabase.org/) | `people-public-records` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `urls`, `documents` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **S** | [**Have I Been Pwned (HIBP)**](https://haveibeenpwned.com/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records` |
| **S** | [**Hudson Rock — Cavalier Free OSINT Tools**](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `malware_iocs`, `tech_stack` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **S** | [**RansomLook**](https://www.ransomlook.io/) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `archived_pages` |
| **A** | [**LeakCheck**](https://leakcheck.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `emails`, `usernames` |
| **A** | [**LeakIX**](https://leakix.net/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `open_ports`, `secrets`, `breach_records`, `tech_stack` |
| **A** | [**Psbdmp**](https://psbdmp.ws/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `archived_pages` |
| **A** | [**SOCRadar Free SOC Tools**](https://socradar.io/labs/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `subdomains`, `malware_iocs` |
| **A** | [**SpyCloud Cybercrime Exposure Check**](https://spycloud.com/check-your-exposure/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `malware_iocs` |
| **B** | [**BreachDirectory**](https://breachdirectory.org/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records` |
| **B** | [**pwnedOrNot**](https://github.com/thewhiteh4t/pwnedOrNot) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `breach_records` |
| **B** | [**Snusbase**](https://snusbase.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `ip_addresses`, `emails` |
| **S** | [**BuiltWith**](https://builtwith.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `tech_stack`, `entity_graph` |
| **S** | [**crt.sh (Certificate Transparency Search)**](https://crt.sh/) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `certificates`, `subdomains` |
| **S** | [**DNSDumpster**](https://dnsdumpster.com/) | `domain-dns-asm` | 🟢 Passive | Free | `dns_records`, `subdomains`, `ip_addresses`, `entity_graph` |
| **S** | [**dnstwist**](https://github.com/elceef/dnstwist) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses`, `whois`, `malware_iocs` |
| **S** | [**httpx (ProjectDiscovery)**](https://github.com/projectdiscovery/httpx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `certificates`, `metadata`, `urls` |
| **S** | [**ICANN Centralized Zone Data Service (CZDS)**](https://czds.icann.org/) | `domain-dns-asm` | 🟢 Passive | Free | `dns_records`, `subdomains` |
| **S** | [**OWASP Amass**](https://github.com/owasp-amass/amass) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `ip_addresses`, `whois` |
| **S** | [**SecurityTrails**](https://securitytrails.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `subdomains`, `whois`, `ip_addresses` |
| **S** | [**Subfinder**](https://github.com/projectdiscovery/subfinder) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains` |
| **S** | [**waymore**](https://github.com/xnl-h4ck3r/waymore) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `archived_pages`, `urls`, `secrets` |
| **S** | [**Whoxy**](https://www.whoxy.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `whois`, `subdomains`, `emails` |
| **A** | [**assetfinder**](https://github.com/tomnomnom/assetfinder) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains` |
| **A** | [**Cert Spotter**](https://sslmate.com/certspotter/) | `domain-dns-asm` | 🟢 Passive | Freemium | `certificates`, `subdomains` |
| **A** | [**DNSlytics**](https://dnslytics.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses`, `entity_graph` |
| **A** | [**dnsx (ProjectDiscovery)**](https://github.com/projectdiscovery/dnsx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses`, `subdomains` |
| **A** | [**DomainTools Iris**](https://www.domaintools.com/) | `domain-dns-asm` | 🟢 Passive | Paid | `whois`, `dns_records`, `entity_graph`, `malware_iocs` |
| **A** | [**Findomain**](https://github.com/Findomain/Findomain) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses` |
| **A** | [**gau (GetAllUrls)**](https://github.com/lc/gau) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `urls`, `archived_pages` |
| **A** | [**hakrawler**](https://github.com/hakluke/hakrawler) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains` |
| **A** | [**ICANN Lookup (Official RDAP)**](https://lookup.icann.org/) | `domain-dns-asm` | 🟢 Passive | Free | `whois`, `dns_records` |
| **A** | [**Katana**](https://github.com/projectdiscovery/katana) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `secrets`, `tech_stack` |
| **A** | [**Nuclei (Exposure & OSINT Templates)**](https://github.com/projectdiscovery/nuclei) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `social_profiles`, `tech_stack`, `secrets` |
| **A** | [**OneForAll**](https://github.com/shmilylty/OneForAll) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `ip_addresses` |
| **A** | [**openSquat**](https://github.com/atenreiro/opensquat) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains`, `malware_iocs`, `certificates` |
| **A** | [**ParamSpider**](https://github.com/devanshbatham/ParamSpider) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `urls`, `archived_pages` |
| **A** | [**ProjectDiscovery Chaos Public Bug-Bounty Dataset**](https://chaos.projectdiscovery.io/) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains` |
| **A** | [**RapidDNS**](https://rapiddns.io/) | `domain-dns-asm` | 🟢 Passive | Free | `subdomains`, `dns_records`, `ip_addresses` |
| **A** | [**tlsx (ProjectDiscovery)**](https://github.com/projectdiscovery/tlsx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `certificates`, `subdomains` |
| **A** | [**ViewDNS.info**](https://viewdns.info/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses` |
| **A** | [**Wappalyzer**](https://www.wappalyzer.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `tech_stack` |
| **A** | [**waybackurls**](https://github.com/tomnomnom/waybackurls) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `urls`, `archived_pages` |
| **B** | [**Cariddi**](https://github.com/edoardottt/cariddi) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `secrets` |
| **B** | [**CompleteDNS (Historical Nameserver Changes)**](https://completedns.com/dns-history/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois` |
| **B** | [**digga**](https://github.com/nicholasgasior/digga) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `dns_records`, `whois`, `certificates`, `subdomains` |
| **B** | [**DNSViz**](https://dnsviz.net/) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `entity_graph` |
| **B** | [**DomainBigData**](https://domainbigdata.com/) | `domain-dns-asm` | 🟢 Passive | Free | `whois`, `emails`, `ip_addresses` |
| **B** | [**Robtex**](https://www.robtex.com/) | `domain-dns-asm` | 🟢 Passive | Free | `dns_records`, `ip_addresses`, `entity_graph` |
| **B** | [**WhatWeb**](https://github.com/urbanadventurer/WhatWeb) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **S** | [**Censys Search**](https://search.censys.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `malware_iocs` |
| **S** | [**FOFA**](https://en.fofa.info/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `ip_addresses` |
| **S** | [**Hurricane Electric BGP Toolkit**](https://bgp.he.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `dns_records`, `entity_graph` |
| **S** | [**RIPEstat**](https://stat.ripe.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `whois`, `ip_addresses`, `geolocation`, `signal_telemetry` |
| **S** | [**Shodan**](https://www.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `geolocation` |
| **A** | [**asn (Network Recon CLI)**](https://github.com/nitefood/asn) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `whois`, `geolocation` |
| **A** | [**asnmap (ProjectDiscovery)**](https://github.com/projectdiscovery/asnmap) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `whois` |
| **A** | [**BGP.Tools**](https://bgp.tools/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `entity_graph` |
| **A** | [**Cloudflare Radar & URL Scanner**](https://radar.cloudflare.com/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `dns_records`, `certificates`, `tech_stack` |
| **A** | [**Criminal IP**](https://www.criminalip.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `malware_iocs`, `certificates`, `geolocation` |
| **A** | [**Metabigor**](https://github.com/j3ssie/metabigor) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**Netlas.io**](https://netlas.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `certificates`, `whois` |
| **A** | [**Nmap**](https://nmap.org/) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `certificates`, `tech_stack` |
| **A** | [**OONI Explorer (Open Observatory of Network Interference)**](https://explorer.ooni.org/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `signal_telemetry`, `dns_records` |
| **A** | [**Spamhaus IP & Domain Reputation Checker**](https://check.spamhaus.org/) | `network-ip-iot-search` | 🟢 Passive | Free | `malware_iocs`, `whois` |
| **A** | [**Uncover (ProjectDiscovery)**](https://github.com/projectdiscovery/uncover) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**ZoomEye**](https://www.zoomeye.ai/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `tech_stack`, `certificates`, `geolocation` |
| **B** | [**360 Quake Cyberspace Mapping**](https://quake.360.net/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**BinaryEdge**](https://www.binaryedge.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**Censored Planet Observatory**](https://censoredplanet.org/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `signal_telemetry`, `dns_records` |
| **B** | [**Hunter.how**](https://hunter.how/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**MultiRBL.valli.org**](https://multirbl.valli.org/) | `network-ip-iot-search` | 🟢 Passive | Free | `malware_iocs`, `dns_records` |
| **B** | [**ONYPHE**](https://www.onyphe.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `malware_iocs` |
| **A** | [**ClearSky (Bluesky OSINT)**](https://clearsky.services/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **S** | [**AADInternals / Tenant ID & OpenID Recon**](https://aadinternals.com/osint/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `subdomains`, `corporate_records`, `tech_stack` |
| **S** | [**cloud_enum**](https://github.com/initstring/cloud_enum) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `secrets` |
| **S** | [**GitHub Native Code Search & `.patch` Trick**](https://github.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `secrets`, `urls`, `social_profiles` |
| **S** | [**grep.app**](https://grep.app/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `subdomains` |
| **S** | [**Hugging Face Hub Search (Models, Datasets & Spaces)**](https://huggingface.co/search/full-text) | `code-cloud-dev-osint` | 🟢 Passive | Free | `secrets`, `urls`, `documents` |
| **S** | [**PublicWWW**](https://publicwww.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `tech_stack`, `entity_graph` |
| **A** | [**git-hound**](https://github.com/tillson/git-hound) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `urls` |
| **A** | [**GrayhatWarfare**](https://buckets.grayhatwarfare.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `documents` |
| **A** | [**Postman Public API Network**](https://www.postman.com/explore) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `emails` |
| **A** | [**Sourcegraph Code Search**](https://sourcegraph.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `emails` |
| **B** | [**NerdyData**](https://www.nerdydata.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `tech_stack` |
| **B** | [**pagodo (Passive Google Dork)**](https://github.com/opsdisk/pagodo) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `urls`, `secrets`, `documents` |
| **B** | [**S3Scanner**](https://github.com/sa7mon/S3Scanner) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `secrets` |
| **B** | [**searchcode**](https://searchcode.com/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets` |
| **S** | [**Chainabuse (by TRM Labs)**](https://www.chainabuse.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `malware_iocs`, `breach_records` |
| **S** | [**Web3.bio Identity Graph**](https://web3.bio/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `usernames` |
| **A** | [**ENS Manager (`app.ens.domains`)**](https://app.ens.domains/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `social_profiles`, `emails`, `tx_graph` |
| **S** | [**Ahmia.fi**](https://ahmia.fi/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **S** | [**AIL Framework (Analysis Information Leak — CIRCL)**](https://www.ail-project.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `secrets`, `certificates` |
| **S** | [**Ransomware.live (Julien Mousqueton)**](https://www.ransomware.live/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `documents` |
| **S** | [**Robin (AI-Powered Dark Web OSINT)**](https://github.com/apurvsinghgautam/robin) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **A** | [**darknet-mcp-server**](https://github.com/badchars/darknet-mcp-server) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `malware_iocs` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records` |
| **A** | [**Flare Threat Exposure Management**](https://flare.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records`, `secrets` |
| **A** | [**Searchlight Cyber (Cerberus / DarkIQ)**](https://www.slcyber.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `archived_pages`, `certificates` |
| **S** | [**AlienVault Open Threat Exchange (OTX)**](https://otx.alienvault.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `dns_records`, `urls`, `subdomains` |
| **S** | [**Silent Push Community Edition**](https://www.silentpush.com/community-edition/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `malware_iocs`, `certificates`, `entity_graph` |
| **S** | [**ThreatFox (abuse.ch)**](https://threatfox.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs` |
| **S** | [**urlscan.io**](https://urlscan.io/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `tech_stack`, `certificates`, `urls`, `archived_pages` |
| **S** | [**Validin**](https://app.validin.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `certificates`, `ip_addresses`, `malware_iocs` |
| **S** | [**VirusTotal & VT Graph**](https://www.virustotal.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `certificates`, `entity_graph` |
| **A** | [**ANY.RUN Interactive Malware Sandbox**](https://app.any.run/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `ip_addresses` |
| **A** | [**Cisco Talos Intelligence Center**](https://talosintelligence.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `whois`, `dns_records` |
| **A** | [**Hunt.io**](https://hunt.io/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `certificates`, `entity_graph` |
| **A** | [**Hybrid Analysis**](https://www.hybrid-analysis.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**Joe Sandbox Cloud Basic**](https://www.joesandbox.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**Lookyloo (CIRCL)**](https://lookyloo.circl.lu/) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `urls`, `certificates`, `tech_stack`, `entity_graph` |
| **A** | [**MISP (Open Source Threat Intelligence Platform)**](https://www.misp-project.org/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph` |
| **A** | [**Pulsedive**](https://pulsedive.com/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `malware_iocs`, `dns_records`, `whois`, `open_ports` |
| **A** | [**URLhaus (abuse.ch)**](https://urlhaus.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `urls` |
| **A** | [**YETI (Your Everyday Threat Intelligence)**](https://yeti-platform.io/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `dns_records` |
| **B** | [**OpenPhish & DestroyList**](https://github.com/phishdestroy/destroylist) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **B** | [**ThreatMiner**](https://www.threatminer.org/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `documents`, `dns_records` |
| **S** | [**archive.today (archive.ph / archive.is)**](https://archive.ph/) | `archiving-evidence-docs` | 🟡 Hybrid | Free | `archived_pages` |
| **S** | [**Wayback Machine (Internet Archive)**](https://web.archive.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `archived_pages`, `urls`, `documents` |
| **A** | [**Browsertrix Crawler (Webrecorder)**](https://github.com/webrecorder/browsertrix-crawler) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages` |
| **A** | [**Common Crawl Index**](https://commoncrawl.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `archived_pages`, `urls`, `entity_graph` |
| **A** | [**gowitness**](https://github.com/sensepost/gowitness) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `certificates` |
| **A** | [**Metagoofil / FOCA**](https://github.com/opsdisk/metagoofil) | `archiving-evidence-docs` | 🟡 Hybrid | OSS / Free | `documents`, `metadata`, `usernames`, `emails` |
| **B** | [**EyeWitness**](https://github.com/RedSiege/EyeWitness) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `open_ports` |
| **A** | [**Clearfront (Self-OSINT & MCP)**](https://github.com/scottmartinanderson/clearfront) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records`, `subdomains`, `entity_graph` |
| **A** | [**OSINT Toolbox MCP**](https://github.com/renkagod/osint-toolbox-mcp) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `phones` |
| **A** | [**osint-mcp-server (badchars)**](https://github.com/badchars/osint-mcp-server) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `certificates`, `open_ports` |
| **A** | [**Whoogle Search**](https://github.com/benbusby/whoogle-search) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `urls`, `opsec_protection` |
| **B** | [**Sputnik OSINT Browser Extension**](https://github.com/mitchmoser/sputnik) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **A** | [**Raccoon**](https://github.com/evyatarmeged/Raccoon) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `certificates`, `tech_stack` |
| **B** | [**ReconSpider**](https://github.com/bhavsec/reconspider) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `dns_records`, `emails`, `urls` |
| **A** | [**BlackWidow**](https://github.com/1N3/BlackWidow) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `emails`, `phones` |
| **A** | [**ScopeSentry**](https://github.com/Autumn-27/ScopeSentry) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `urls` |
| **A** | [**ARL-Next (Asset Reconnaissance Lighthouse)**](https://github.com/owl234/ARL-Next) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `certificates` |
| **S** | [**Interactsh**](https://github.com/projectdiscovery/interactsh) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses`, `metadata` |
| **A** | [**Notify (ProjectDiscovery)**](https://github.com/projectdiscovery/notify) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `metadata` |
| **S** | [**UhOh365**](https://github.com/Raikia/UhOh365) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames`, `metadata` |
| **S** | [**checkdmarc**](https://github.com/domainaware/checkdmarc) | `email-intelligence` | 🔴 Active | OSS / Free | `dns_records`, `certificates`, `metadata` |
| **A** | [**smtp-user-enum**](https://github.com/pentestmonkey/smtp-user-enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames` |
| **A** | [**onedrive_user_enum**](https://github.com/nyxgeek/onedrive_user_enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames`, `urls` |
| **S** | [**SIPVicious (svmap / svwar)**](https://github.com/EnableSecurity/sipvicious) | `phone-messaging-osint` | 🔴 Active | OSS / Free | `phones`, `open_ports`, `tech_stack`, `metadata` |
| **S** | [**ffuf (Fuzz Faster U Fool)**](https://github.com/ffuf/ffuf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `tech_stack` |
| **S** | [**Gobuster**](https://github.com/OJ/gobuster) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `urls`, `dns_records` |
| **S** | [**feroxbuster**](https://github.com/epi052/feroxbuster) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `documents`, `tech_stack` |
| **A** | [**dirsearch**](https://github.com/maurosoria/dirsearch) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `documents`, `secrets` |
| **S** | [**MassDNS**](https://github.com/blechschmidt/massdns) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `ip_addresses` |
| **S** | [**puredns**](https://github.com/d3mondev/puredns) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `ip_addresses` |
| **S** | [**shuffledns**](https://github.com/projectdiscovery/shuffledns) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `ip_addresses` |
| **A** | [**AlterX**](https://github.com/projectdiscovery/alterx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains` |
| **S** | [**DNSRecon**](https://github.com/darkoperator/dnsrecon) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains`, `ip_addresses` |
| **A** | [**dnsenum**](https://github.com/fwaeytens/dnsenum) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains`, `ip_addresses`, `whois` |
| **B** | [**SubBrute**](https://github.com/TheRook/subbrute) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records` |
| **A** | [**Sublist3r**](https://github.com/aboul3la/Sublist3r) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `open_ports` |
| **A** | [**Knockpy**](https://github.com/guelfoweb/knock) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `certificates`, `ip_addresses` |
| **S** | [**dnsReaper**](https://github.com/punk-security/dnsReaper) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains`, `metadata` |
| **S** | [**BadDNS (Black Lantern Security)**](https://github.com/blacklanternsecurity/baddns) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains`, `metadata` |
| **A** | [**Subzy**](https://github.com/PentestPad/subzy) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `metadata` |
| **A** | [**Subjack**](https://github.com/haccer/subjack) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records` |
| **A** | [**Subdominator**](https://github.com/Stratus-Security/Subdominator) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `metadata` |
| **A** | [**DNSTake**](https://github.com/pwnesia/dnstake) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains` |
| **A** | [**second-order**](https://github.com/mhmdiaa/second-order) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `secrets` |
| **S** | [**WAFW00F**](https://github.com/EnableSecurity/wafw00f) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**cdncheck (ProjectDiscovery)**](https://github.com/projectdiscovery/cdncheck) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `tech_stack`, `ip_addresses`, `metadata` |
| **A** | [**wappalyzergo**](https://github.com/projectdiscovery/wappalyzergo) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**CMSeeK**](https://github.com/Tuhinshubhra/CMSeeK) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `usernames`, `urls` |
| **S** | [**WPScan**](https://github.com/wpscanteam/wpscan) | `domain-dns-asm` | 🔴 Active | Freemium | `usernames`, `tech_stack`, `urls`, `metadata` |
| **A** | [**Nikto**](https://github.com/sullo/nikto) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `urls`, `certificates`, `metadata` |
| **A** | [**LinkFinder**](https://github.com/GerbenJavado/LinkFinder) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains` |
| **S** | [**xnLinkFinder**](https://github.com/xnl-h4ck3r/xnLinkFinder) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `metadata` |
| **B** | [**getJS**](https://github.com/003random/getJS) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls` |
| **S** | [**GoSpider**](https://github.com/jaeles-project/gospider) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `secrets` |
| **A** | [**httprobe**](https://github.com/tomnomnom/httprobe) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `open_ports` |
| **A** | [**meg (tomnomnom)**](https://github.com/tomnomnom/meg) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata`, `documents` |
| **A** | [**tldfinder (ProjectDiscovery)**](https://github.com/projectdiscovery/tldfinder) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `whois` |
| **S** | [**RustScan**](https://github.com/bee-san/RustScan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack` |
| **S** | [**Naabu (ProjectDiscovery)**](https://github.com/projectdiscovery/naabu) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses` |
| **S** | [**ZGrab 2.0**](https://github.com/zmap/zgrab2) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `certificates`, `tech_stack`, `metadata` |
| **A** | [**ZDNS**](https://github.com/zmap/zdns) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses` |
| **S** | [**fingerprintx (Praetorian)**](https://github.com/praetorian-inc/fingerprintx) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `certificates`, `metadata` |
| **S** | [**testssl.sh**](https://github.com/drwetter/testssl.sh) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `tech_stack`, `metadata` |
| **A** | [**SSLyze**](https://github.com/nabla-c0d3/sslyze) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `subdomains`, `metadata` |
| **S** | [**ssh-audit**](https://github.com/jtesta/ssh-audit) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `tech_stack`, `open_ports`, `metadata` |
| **S** | [**NetExec (nxc)**](https://github.com/Pennyw0rth/NetExec) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `usernames`, `metadata` |
| **A** | [**enum4linux-ng**](https://github.com/cddmp/enum4linux-ng) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `usernames`, `tech_stack`, `metadata` |
| **A** | [**SMBMap**](https://github.com/ShawnDEvans/smbmap) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `documents`, `metadata`, `open_ports` |
| **A** | [**Proxify (ProjectDiscovery)**](https://github.com/projectdiscovery/proxify) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `urls`, `metadata`, `secrets` |
| **A** | [**ATProto SDK & CLI (Bluesky)**](https://github.com/MarshalX/atproto) | `social-media-socmint` | 🟡 Hybrid | OSS / Free | `social_profiles`, `dns_records`, `entity_graph`, `metadata` |
| **S** | [**git-dumper**](https://github.com/arthaud/git-dumper) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `secrets`, `emails`, `usernames`, `documents` |
| **A** | [**GitTools (GitFinder / Dumper / Extractor)**](https://github.com/internetwache/GitTools) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `secrets`, `emails`, `documents` |
| **A** | [**GitGot (Bishop Fox)**](https://github.com/BishopFox/GitGot) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `emails`, `urls` |
| **S** | [**CloudFox (Bishop Fox)**](https://github.com/BishopFox/cloudfox) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `ip_addresses`, `subdomains`, `secrets` |
| **A** | [**Cloudlist (ProjectDiscovery)**](https://github.com/projectdiscovery/cloudlist) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `ip_addresses`, `subdomains`, `dns_records` |
| **A** | [**GCPBucketBrute (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/GCPBucketBrute) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `documents`, `secrets` |
| **S** | [**MicroBurst (NetSPI)**](https://github.com/NetSPI/MicroBurst) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `subdomains`, `urls`, `documents`, `secrets` |
| **B** | [**AWSBucketDump**](https://github.com/jordanpotti/AWSBucketDump) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `documents`, `secrets`, `urls` |
| **B** | [**CloudScraper**](https://github.com/jordanpotti/CloudScraper) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `subdomains` |
| **S** | [**Kiterunner (Assetnote)**](https://github.com/assetnote/kiterunner) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `metadata` |
| **A** | [**sj (swagger-jacker — Bishop Fox)**](https://github.com/BishopFox/sj) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `metadata`, `secrets` |
| **A** | [**graphql-cop**](https://github.com/dolevf/graphql-cop) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `metadata` |
| **A** | [**Graphinder (Escape Technologies)**](https://github.com/Escape-Technologies/graphinder) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `tech_stack` |
| **S** | [**Foundry Cast (`cast`)**](https://github.com/foundry-rs/foundry) | `crypto-blockchain-web3` | 🟡 Hybrid | OSS / Free | `tx_graph`, `metadata`, `secrets` |
| **S** | [**JARM (Salesforce Active TLS Fingerprinter)**](https://github.com/salesforce/jarm) | `threat-intel-malware-cti` | 🔴 Active | OSS / Free | `malware_iocs`, `certificates`, `tech_stack` |
| **S** | [**CertStream**](https://github.com/CaliDog/certstream-python) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `certificates`, `subdomains`, `malware_iocs` |
| **A** | [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `subdomains`, `certificates`, `malware_iocs` |
| **A** | [**Aquatone**](https://github.com/michenriksen/aquatone) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `urls` |
| **S** | [**Scapy**](https://github.com/secdev/scapy) | `sigint-wireless-space-rf` | 🔴 Active | OSS / Free | `open_ports`, `signal_telemetry`, `ip_addresses`, `metadata` |
| **A** | [**pentest-mcp**](https://github.com/DMontgomery40/pentest-mcp) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `open_ports`, `urls`, `tech_stack` |
| **A** | [**nuclei-mcp**](https://github.com/addcontent/nuclei-mcp) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `tech_stack`, `malware_iocs`, `metadata` |
| **A** | [**FofaMap (AI Asset Mapping + Gated Nuclei)**](https://github.com/asaotomo/FofaMap) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `certificates` |
| **B** | [**AutoRedTeam-Orchestrator**](https://github.com/Coff0xc/AutoRedTeam-Orchestrator) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `urls`, `tech_stack` |
| **B** | [**BlitzStrike MCP Toolbelt**](https://github.com/shinthink/blitzstrike) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **B** | [**ExternalAttacker-MCP**](https://github.com/MorDavid/ExternalAttacker-MCP) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `open_ports`, `tech_stack` |
| **S** | [**OWASP Nettacker**](https://github.com/OWASP/Nettacker) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **A** | [**Ruler (SensePost Exchange Recon)**](https://github.com/sensepost/ruler) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `urls`, `tech_stack`, `metadata` |
| **A** | [**Corsy**](https://github.com/s0md3v/Corsy) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata`, `tech_stack` |
| **B** | [**CORScanner**](https://github.com/chenjj/CORScanner) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata` |
| **A** | [**subjs**](https://github.com/lc/subjs) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls` |
| **A** | [**gotator**](https://github.com/Josue87/gotator) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains` |
| **A** | [**AltDNS**](https://github.com/infosec-au/altdns) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records` |
| **A** | [**VHostScan**](https://github.com/codingo/VHostScan) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `urls` |
| **B** | [**fff (Fast Fetching Friend)**](https://github.com/tomnomnom/fff) | `domain-dns-asm` | 🔴 Active | OSS / Free | `archived_pages`, `metadata`, `secrets` |
| **B** | [**WhatWaf**](https://github.com/Ekultek/WhatWaf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **B** | [**identYwaf**](https://github.com/stamparm/identYwaf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**URLFinder (ProjectDiscovery)**](https://github.com/projectdiscovery/urlfinder) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `urls`, `subdomains` |
| **A** | [**nmap-vulners NSE**](https://github.com/vulnersCom/nmap-vulners) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `malware_iocs` |
| **A** | [**Vulscan (Nmap Offline CVE NSE)**](https://github.com/scipag/vulscan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `malware_iocs` |
| **A** | [**windapsearch**](https://github.com/ropnop/windapsearch) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `usernames`, `emails`, `person_records`, `metadata` |
| **S** | [**Impacket Network Protocol Scripts**](https://github.com/fortra/impacket) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `tech_stack`, `usernames`, `metadata`, `open_ports` |
| **B** | [**rmiscout (Bishop Fox)**](https://github.com/BishopFox/rmiscout) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `metadata` |
| **S** | [**Nuclei Templates**](https://github.com/projectdiscovery/nuclei-templates) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `secrets`, `social_profiles`, `metadata` |
| **A** | [**WitnessMe**](https://github.com/byt3bl33d3r/WitnessMe) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `urls` |
| **S** | [**Prowler**](https://github.com/toniblyx/prowler) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `urls`, `secrets`, `metadata` |
| **S** | [**ScoutSuite (NCC Group)**](https://github.com/nccgroup/ScoutSuite) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `open_ports`, `urls`, `entity_graph` |
| **A** | [**Pacu (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/pacu) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `usernames`, `secrets`, `tech_stack` |
| **A** | [**CloudMapper (Duo Labs)**](https://github.com/duo-labs/cloudmapper) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `ip_addresses`, `open_ports`, `entity_graph` |
| **S** | [**Trivy (Aqua Security)**](https://github.com/aquasecurity/trivy) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `tech_stack`, `secrets`, `malware_iocs` |
| **S** | [**ROADtools (Entra ID / Azure AD Recon)**](https://github.com/dirkjanm/ROADtools) | `email-intelligence` | 🔴 Active | OSS / Free | `subdomains`, `emails`, `usernames`, `entity_graph` |
| **A** | [**o365spray**](https://github.com/0xZDH/o365spray) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `tech_stack`, `metadata` |
| **B** | [**o365recon**](https://github.com/nyxgeek/o365recon) | `email-intelligence` | 🔴 Active | OSS / Free | `subdomains`, `corporate_records`, `metadata` |
| **A** | [**GraphRunner**](https://github.com/dafthack/GraphRunner) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `documents`, `usernames` |
| **A** | [**haktrails**](https://github.com/hakluke/haktrails) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `whois` |
| **A** | [**Cero (Go TLS SAN Scraper)**](https://github.com/glebarez/cero) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `certificates` |
| **A** | [**anew**](https://github.com/tomnomnom/anew) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `subdomains`, `urls` |
| **B** | [**OWASP Open Asset Model (OAM)**](https://github.com/owasp-amass/open-asset-model) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **S** | [**BloodHound Community Edition**](https://github.com/SpecterOps/BloodHound) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `entity_graph`, `usernames`, `person_records` |
| **A** | [**Certipy**](https://github.com/ly4k/Certipy) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `tech_stack`, `entity_graph` |
| **A** | [**Malcolm (CISA Network Traffic Suite)**](https://github.com/cisagov/Malcolm) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `entity_graph`, `dns_records`, `ip_addresses`, `malware_iocs` |
| **S** | [**Wayback Google Analytics (Bellingcat)**](https://github.com/bellingcat/wayback-google-analytics) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `entity_graph`, `archived_pages`, `metadata` |
| **S** | [**Cortex (TheHive Observable Analyzer)**](https://github.com/TheHive-Project/Cortex) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `subdomains` |
| **S** | [**Signature-Base (Florian Roth YARA/IOCs)**](https://github.com/Neo23x0/signature-base) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**SigmaHQ Detection Repository**](https://github.com/SigmaHQ/sigma) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `metadata` |
| **S** | [**Velociraptor (Rapid7 / Velocidex)**](https://github.com/Velocidex/velociraptor) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `urls`, `dns_records`, `malware_iocs` |
| **A** | [**Maltrail**](https://github.com/stamparm/maltrail) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**vt-py (Official VirusTotal Python SDK)**](https://github.com/VirusTotal/vt-py) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `subdomains`, `dns_records`, `certificates` |
| **A** | [**MetaMask Eth-Phishing-Detect**](https://github.com/MetaMask/eth-phishing-detect) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**ScamSniffer Drainer Database**](https://github.com/scamsniffer/scam-database) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `malware_iocs`, `sanctions_hits` |
| **A** | [**OpenHands Autonomous Agent**](https://github.com/All-Hands-AI/OpenHands) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |
| **A** | [**CrewAI Multi-Agent Orchestrator**](https://github.com/crewAIInc/crewAI) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |
| **B** | [**SkyArk (Shadow Admin Recon)**](https://github.com/cyberark/SkyArk) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `usernames`, `entity_graph`, `metadata` |
| **B** | [**FIR (Fast Incident Response)**](https://github.com/certsocietegenerale/FIR) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `documents`, `malware_iocs` |

---

## Selector: keyword
**Keyword / Phrase** (Project slug, quote, topic) — `232` tools (`python3 scripts/osint.py pivot keyword --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Bellingcat Online Investigation Toolkit**](https://bellingcat.gitbook.io/toolkit) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `geolocation`, `metadata`, `corporate_records`, `archived_pages` |
| **S** | [**Google Hacking Database (Exploit-DB GHDB)**](https://www.exploit-db.com/google-hacking-database) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `urls`, `secrets`, `documents` |
| **S** | [**OpenCTI**](https://github.com/OpenCTI-Platform/opencti) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `darkweb_mentions` |
| **S** | [**OSINT Framework**](https://osintframework.com/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **S** | [**SearXNG**](https://docs.searxng.org/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `urls`, `documents` |
| **S** | [**The GDELT Project**](https://www.gdeltproject.org/) | `all-in-one-frameworks` | 🟢 Passive | Free | `documents`, `geolocation`, `entity_graph` |
| **S** | [**WorldMonitor**](https://github.com/koala73/worldmonitor) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `geolocation`, `signal_telemetry`, `flight_tracks`, `vessel_tracks` |
| **A** | [**Brave Search & Custom OSINT Goggles**](https://search.brave.com/) | `all-in-one-frameworks` | 🟢 Passive | Free | `urls` |
| **A** | [**Crucix**](https://github.com/calesthio/Crucix) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `archived_pages`, `signal_telemetry` |
| **A** | [**MetaOSINT**](https://metaosint.github.io/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **A** | [**Obsidian (Local-First OSINT Case Vault)**](https://obsidian.md/) | `all-in-one-frameworks` | 🟢 Passive | Free | `entity_graph`, `documents` |
| **B** | [**Mojeek**](https://www.mojeek.com/) | `all-in-one-frameworks` | 🟢 Passive | Free | `urls` |
| **S** | [**TGStat**](https://tgstat.com/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph`, `metadata` |
| **A** | [**DiscordLookup / Discord.id**](https://discord.id/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **A** | [**Telegago (Official Google CSE)**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `urls` |
| **A** | [**TelegramDB**](https://www.telegramdb.org/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph` |
| **A** | [**Telemetr.io**](https://telemetr.io/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `metadata`, `entity_graph` |
| **A** | [**Telethon**](https://github.com/LonamiWebs/Telethon) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles`, `archived_pages`, `metadata` |
| **A** | [**Tosint**](https://github.com/drego85/tosint) | `phone-messaging-osint` | 🔴 Active | OSS / Free | `social_profiles`, `metadata` |
| **B** | [**Awesome Telegram OSINT Toolkit Index**](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**DISBOARD**](https://disboard.org/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles` |
| **B** | [**DiscordLeaks (Unicorn Riot)**](https://discordleaks.unicornriot.ninja/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `archived_pages`, `person_records` |
| **B** | [**Lyzem**](https://lyzem.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `archived_pages` |
| **B** | [**TGScope**](https://tgscope.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **S** | [**CourtListener & RECAP Archive**](https://www.courtlistener.com/) | `people-public-records` | 🟢 Passive | OSS / Free | `person_records`, `corporate_records`, `archived_pages` |
| **S** | [**Judyrecords**](https://www.judyrecords.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **S** | [**PACER (US Federal Courts)**](https://pacer.uscourts.gov/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `corporate_records` |
| **S** | [**Worldwide OSINT Tools Map (cipher387)**](https://cipher387.github.io/osintmap/) | `people-public-records` | 🟢 Passive | OSS / Free | `person_records`, `corporate_records`, `geolocation` |
| **A** | [**BAILII (British & Irish Legal Information Institute)**](https://www.bailii.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **A** | [**DOJ FARA eFile Search**](https://efile.fara.gov/) | `people-public-records` | 🟢 Passive | Free | `corporate_records`, `person_records`, `archived_pages` |
| **A** | [**FamilySearch**](https://www.familysearch.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation` |
| **A** | [**FastPeopleSearch**](https://www.fastpeoplesearch.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `phones`, `emails`, `geolocation` |
| **A** | [**Newspapers.com & Chronicling America (LOC)**](https://chroniclingamerica.loc.gov/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `archived_pages` |
| **A** | [**OSINT-for-Countries Directory**](https://github.com/wddadk/OSINT-for-countries) | `people-public-records` | 🟢 Passive | OSS / Free | `person_records`, `corporate_records` |
| **A** | [**TruePeopleSearch**](https://www.truepeoplesearch.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `phones`, `emails`, `geolocation` |
| **B** | [**ClustrMaps**](https://clustrmaps.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation`, `corporate_records` |
| **B** | [**FBI Wanted & Kidnappings API**](https://www.fbi.gov/wanted) | `people-public-records` | 🟢 Passive | Free | `person_records`, `sanctions_hits` |
| **B** | [**UK National Archives — Find Case Law**](https://caselaw.nationalarchives.gov.uk/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **S** | [**Distributed Denial of Secrets (DDoSecrets)**](https://ddosecrets.com/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **S** | [**RansomLook**](https://www.ransomlook.io/) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `archived_pages` |
| **A** | [**LeakCheck**](https://leakcheck.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `emails`, `usernames` |
| **A** | [**LeakIX**](https://leakix.net/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `open_ports`, `secrets`, `breach_records`, `tech_stack` |
| **A** | [**Psbdmp**](https://psbdmp.ws/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `archived_pages` |
| **A** | [**ransomwatch**](https://ransomwhat.telemetry.ltd/) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records` |
| **A** | [**SEC Item 1.05 Material Cybersecurity Incident Filings**](https://www.sec.gov/edgar/search/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `corporate_records`, `documents` |
| **A** | [**State AG Official Data Breach Portals (CA / ME / HHS OCR)**](https://oag.ca.gov/privacy/databreach/list) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `corporate_records`, `documents` |
| **A** | [**WikiLeaks Public Library of US Diplomacy & Leaks**](https://search.wikileaks.org/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **B** | [**Cryptome**](https://cryptome.org/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `archived_pages` |
| **S** | [**BuiltWith**](https://builtwith.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `tech_stack`, `entity_graph` |
| **S** | [**ICANN Centralized Zone Data Service (CZDS)**](https://czds.icann.org/) | `domain-dns-asm` | 🟢 Passive | Free | `dns_records`, `subdomains` |
| **A** | [**DNSlytics**](https://dnslytics.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses`, `entity_graph` |
| **A** | [**openSquat**](https://github.com/atenreiro/opensquat) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains`, `malware_iocs`, `certificates` |
| **S** | [**Censys Search**](https://search.censys.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `malware_iocs` |
| **S** | [**FOFA**](https://en.fofa.info/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `ip_addresses` |
| **S** | [**GreyNoise Visualizer**](https://viz.greynoise.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `geolocation` |
| **S** | [**Shodan**](https://www.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `geolocation` |
| **A** | [**Cloudflare Radar & URL Scanner**](https://radar.cloudflare.com/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `dns_records`, `certificates`, `tech_stack` |
| **A** | [**Criminal IP**](https://www.criminalip.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `malware_iocs`, `certificates`, `geolocation` |
| **A** | [**IODA (Internet Outage Detection and Analysis)**](https://ioda.inetintel.cc.gatech.edu/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **A** | [**Uncover (ProjectDiscovery)**](https://github.com/projectdiscovery/uncover) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**ZoomEye**](https://www.zoomeye.ai/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `tech_stack`, `certificates`, `geolocation` |
| **B** | [**360 Quake Cyberspace Mapping**](https://quake.360.net/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**Censored Planet Observatory**](https://censoredplanet.org/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `signal_telemetry`, `dns_records` |
| **B** | [**Hunter.how**](https://hunter.how/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **S** | [**4CAT: Capture and Analysis Toolkit**](https://github.com/digitalmethodsinitiative/4cat) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `archived_pages` |
| **S** | [**Filmot (YouTube Subtitle & Transcript Search)**](https://filmot.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `urls`, `metadata`, `archived_pages` |
| **S** | [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **S** | [**PullPush Reddit Archive**](https://search.pullpush.io/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `archived_pages` |
| **S** | [**Who Posted What?**](https://whopostedwhat.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `urls`, `archived_pages` |
| **S** | [**X (Twitter) Native Advanced Search & Geocode**](https://x.com/search-advanced) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `urls` |
| **S** | [**YouTube Metadata & Geofind (MattW)**](https://mattw.io/youtube-metadata/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `social_profiles` |
| **A** | [**Arctic Shift (Reddit Archive & Dumps)**](https://arctic-shift.photon-reddit.com/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `archived_pages` |
| **A** | [**TikTok Timestamp & Snowflake Decoder**](https://dfir.blog/tinkering-with-tiktok-timestamps/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `metadata`, `social_profiles` |
| **A** | [**VK.watch & FindClone / VK OSINT Operators**](https://vk.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `person_records` |
| **A** | [**Xquik**](https://github.com/Xquik-dev/x-twitter-scraper) | `social-media-socmint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph`, `archived_pages` |
| **B** | [**4plebs Archive**](https://archive.4plebs.org/) | `social-media-socmint` | 🟢 Passive | Free | `archived_pages`, `urls` |
| **B** | [**Social Searcher**](https://www.social-searcher.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `social_profiles`, `urls` |
| **S** | [**cloud_enum**](https://github.com/initstring/cloud_enum) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `secrets` |
| **S** | [**GitHub Native Code Search & `.patch` Trick**](https://github.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `secrets`, `urls`, `social_profiles` |
| **S** | [**grep.app**](https://grep.app/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `subdomains` |
| **S** | [**Hugging Face Hub Search (Models, Datasets & Spaces)**](https://huggingface.co/search/full-text) | `code-cloud-dev-osint` | 🟢 Passive | Free | `secrets`, `urls`, `documents` |
| **S** | [**PublicWWW**](https://publicwww.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `tech_stack`, `entity_graph` |
| **A** | [**git-hound**](https://github.com/tillson/git-hound) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `urls` |
| **A** | [**GrayhatWarfare**](https://buckets.grayhatwarfare.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `documents` |
| **A** | [**Open Source Insights (deps.dev)**](https://deps.dev/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `entity_graph`, `social_profiles`, `tech_stack` |
| **A** | [**Postman Public API Network**](https://www.postman.com/explore) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `emails` |
| **A** | [**PyPI & npm Registry Metadata API**](https://pypi.org/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `person_records`, `metadata` |
| **A** | [**Sourcegraph Code Search**](https://sourcegraph.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `emails` |
| **B** | [**NerdyData**](https://www.nerdydata.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `tech_stack` |
| **B** | [**S3Scanner**](https://github.com/sa7mon/S3Scanner) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `secrets` |
| **B** | [**searchcode**](https://searchcode.com/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets` |
| **S** | [**ACLED (Armed Conflict Location & Event Data)**](https://acleddata.com/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **S** | [**Bellingcat OpenStreetMap Search**](https://osm-search.bellingcat.com/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**Bellingcat ShadowFinder**](https://shadowfinder.bellingcat.com/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**Google Earth Pro**](https://www.google.com/earth/about/versions/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation` |
| **S** | [**Overpass Turbo (OpenStreetMap Query Engine)**](https://overpass-turbo.eu/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `entity_graph` |
| **S** | [**Wolfram\|Alpha Historical Weather & Astronomy**](https://www.wolframalpha.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `metadata`, `geolocation` |
| **S** | [**Yandex Maps & Street Panoramas**](https://yandex.com/maps/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation`, `satellite_imagery` |
| **A** | [**Baidu Maps & Total View**](https://map.baidu.com/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **A** | [**GeoHints**](https://geohints.com/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **A** | [**Liveuamap**](https://liveuamap.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `geolocation`, `urls` |
| **A** | [**Maxar Open Data Program**](https://www.maxar.com/open-data) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery` |
| **A** | [**Overpass Ultra**](https://overpass-ultra.us/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**Plonk It Guide**](https://www.plonkit.net/guide) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **A** | [**Wikimapia**](https://wikimapia.org/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **B** | [**Sightline (OSM Infrastructure Search)**](https://github.com/ni5arga/sightline) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**Open Source Munitions Portal & ARES**](https://munitionsportal.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **S** | [**ADS-B Exchange**](https://globe.adsbexchange.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `geolocation` |
| **S** | [**Flightradar24**](https://www.flightradar24.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `flight_tracks`, `geolocation` |
| **S** | [**ImportYeti**](https://www.importyeti.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `corporate_records`, `entity_graph`, `vessel_tracks` |
| **S** | [**MarineTraffic**](https://www.marinetraffic.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation`, `metadata` |
| **A** | [**Airframes.io (ACARS / VDL2 Datalink)**](https://app.airframes.io/) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `signal_telemetry`, `flight_tracks` |
| **A** | [**BIC Container Prefix & Check-Digit Registry**](https://www.bic-code.org/bic-codes/) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records` |
| **A** | [**FlightAware**](https://www.flightaware.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `flight_tracks`, `corporate_records` |
| **A** | [**LiveATC.net**](https://www.liveatc.net/) | `aviation-maritime-transport` | 🟢 Passive | Free | `signal_telemetry`, `archived_pages` |
| **A** | [**MyShipTracking**](https://www.myshiptracking.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation` |
| **A** | [**Planespotters.net**](https://www.planespotters.net/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `corporate_records`, `metadata` |
| **A** | [**S&P Panjiva & ImportGenius**](https://panjiva.com/) | `aviation-maritime-transport` | 🟢 Passive | Paid | `corporate_records`, `vessel_tracks`, `entity_graph` |
| **A** | [**Track-Trace (Multi-Carrier Container & Air Waybill)**](https://www.track-trace.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `vessel_tracks`, `flight_tracks` |
| **A** | [**VesselFinder**](https://www.vesselfinder.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation` |
| **B** | [**CruiseMapper & Port Webcams**](https://www.cruisemapper.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `vessel_tracks`, `geolocation` |
| **B** | [**ITU MARS (Maritime Mobile Access & Retrieval System)**](https://www.itu.int/en/ITU-R/terrestrial/mars/Pages/MARS.aspx) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `signal_telemetry` |
| **S** | [**GLEIF Legal Entity Identifier (LEI) Search**](https://search.gleif.org/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `entity_graph` |
| **S** | [**ICIJ Offshore Leaks Database**](https://offshoreleaks.icij.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**OpenCorporates**](https://opencorporates.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**Pappers.fr (French Corporate & UBO Intelligence)**](https://www.pappers.fr/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**ProPublica Nonprofit Explorer**](https://projects.propublica.org/nonprofits/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**SEC EDGAR Full-Text Search**](https://www.sec.gov/edgar/searchedgar/companysearch) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**UK Companies House & Overseas Entities Register**](https://find-and-update.company-information.service.gov.uk/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**Violation Tracker & Subsidy Tracker (Good Jobs First)**](https://violationtrackerglobal.goodjobsfirst.org/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `sanctions_hits` |
| **A** | [**EU e-Justice Business & Insolvency Registers Portal**](https://e-justice.europa.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records` |
| **A** | [**EU Sanctions Map**](https://www.sanctionsmap.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **A** | [**Google Patents**](https://patents.google.com/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **A** | [**Handelsregister.de (Official German Commercial Register)**](https://www.handelsregister.de/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **A** | [**SAM.gov (System for Award Management)**](https://sam.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `sanctions_hits`, `emails`, `phones` |
| **A** | [**TED (Tenders Electronic Daily — EU)**](https://ted.europa.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `documents` |
| **A** | [**UN Comtrade Database**](https://comtradeplus.un.org/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records` |
| **A** | [**USAspending.gov**](https://www.usaspending.gov/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `documents` |
| **A** | [**WIPO Global Brand & PatentScope Databases**](https://branddb.wipo.int/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **B** | [**OpenInsider (SEC Form 4 Insider Trading Screener)**](http://openinsider.com/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **S** | [**Etherscan**](https://etherscan.io/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `metadata` |
| **S** | [**mempool.space**](https://mempool.space/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph`, `metadata` |
| **A** | [**Blockchair**](https://blockchair.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `metadata` |
| **A** | [**DEX Screener**](https://dexscreener.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `tx_graph`, `metadata` |
| **A** | [**Dune**](https://dune.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph` |
| **A** | [**On-Chain Investigations Tools List (OfficerCIA)**](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph` |
| **S** | [**Ahmia.fi**](https://ahmia.fi/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **S** | [**AIL Framework (Analysis Information Leak — CIRCL)**](https://www.ail-project.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `secrets`, `certificates` |
| **S** | [**deepdarkCTI (fastfire)**](https://github.com/fastfire/deepdarkCTI) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `malware_iocs` |
| **S** | [**Ransomware.live (Julien Mousqueton)**](https://www.ransomware.live/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `documents` |
| **S** | [**Robin (AI-Powered Dark Web OSINT)**](https://github.com/apurvsinghgautam/robin) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **S** | [**Tor Metrics — Relay & Bridge Search**](https://metrics.torproject.org/rs.html) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `opsec_protection`, `whois`, `signal_telemetry` |
| **A** | [**DarkFeed / Ransomfeed**](https://ransomfeed.it/) | `darkweb-tor-underground` | 🟢 Passive | Freemium | `darkweb_mentions`, `breach_records` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records` |
| **A** | [**Flare Threat Exposure Management**](https://flare.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records`, `secrets` |
| **A** | [**GnuPG (`gpg`) & pgpdump Packet Inspector**](https://gnupg.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `metadata`, `emails`, `certificates`, `person_records` |
| **A** | [**keys.openpgp.org & Ubuntu Keyserver**](https://keys.openpgp.org/) | `darkweb-tor-underground` | 🟢 Passive | Free | `emails`, `person_records`, `certificates` |
| **A** | [**OnionSearch**](https://github.com/megadose/OnionSearch) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **A** | [**Searchlight Cyber (Cerberus / DarkIQ)**](https://www.slcyber.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `archived_pages`, `certificates` |
| **B** | [**darkdump**](https://github.com/josh0xA/darkdump) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **B** | [**Daunt.link (Signed Tor Mirror Verification)**](https://daunt.link/) | `darkweb-tor-underground` | 🟢 Passive | Free | `certificates`, `opsec_protection` |
| **B** | [**Hyphanet (formerly Freenet) & ZeroNet Archives**](https://www.hyphanet.org/) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `archived_pages` |
| **B** | [**I2P (Invisible Internet Project)**](https://geti2p.net/) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `opsec_protection` |
| **B** | [**Tor.taxi Signed Darknet Directory**](https://tor.taxi/) | `darkweb-tor-underground` | 🟢 Passive | Free | `urls`, `certificates` |
| **S** | [**AlienVault Open Threat Exchange (OTX)**](https://otx.alienvault.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `dns_records`, `urls`, `subdomains` |
| **S** | [**Hatching Tria.ge Sandbox**](https://tria.ge/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `secrets`, `ip_addresses` |
| **S** | [**Malpedia (Fraunhofer FKIE)**](https://malpedia.caad.fkie.fraunhofer.de/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `documents` |
| **S** | [**MalwareBazaar (abuse.ch)**](https://bazaar.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `certificates` |
| **S** | [**MITRE ATT&CK & ATT&CK Navigator**](https://attack.mitre.org/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph` |
| **S** | [**ThreatFox (abuse.ch)**](https://threatfox.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs` |
| **S** | [**Validin**](https://app.validin.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `certificates`, `ip_addresses`, `malware_iocs` |
| **A** | [**ANY.RUN Interactive Malware Sandbox**](https://app.any.run/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `ip_addresses` |
| **A** | [**CISA Known Exploited Vulnerabilities (KEV) & EPSS**](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs` |
| **B** | [**ThreatMiner**](https://www.threatminer.org/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `documents`, `dns_records` |
| **S** | [**DocumentCloud & MuckRock**](https://www.documentcloud.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `person_records`, `corporate_records` |
| **S** | [**Hunchly**](https://www.hunchly.com/) | `archiving-evidence-docs` | 🟢 Passive | Paid | `archived_pages`, `metadata`, `entity_graph` |
| **S** | [**OpenAlex**](https://openalex.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `person_records`, `entity_graph` |
| **S** | [**Wayback Machine (Internet Archive)**](https://web.archive.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `archived_pages`, `urls`, `documents` |
| **A** | [**Common Crawl Index**](https://commoncrawl.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `archived_pages`, `urls`, `entity_graph` |
| **A** | [**Semantic Scholar & arXiv**](https://www.semanticscholar.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `documents`, `person_records`, `entity_graph` |
| **B** | [**CORE (Open Access Research Aggregator)**](https://core.ac.uk/) | `archiving-evidence-docs` | 🟢 Passive | Freemium | `documents`, `person_records` |
| **B** | [**FOIA.gov (Official US Federal FOIA Portal)**](https://www.foia.gov/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents` |
| **B** | [**WhatDoTheyKnow & AskTheEU**](https://www.whatdotheyknow.com/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `corporate_records` |
| **S** | [**CelesTrak**](https://celestrak.org/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **S** | [**FCC Universal Licensing System (ULS) & FCCID.io**](https://fccid.io/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `corporate_records`, `documents`, `geolocation` |
| **S** | [**OpenCelliD & Unwired Labs**](https://opencellid.org/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **S** | [**SatNOGS (Open Source Satellite Ground Station Network)**](https://network.satnogs.org/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |
| **S** | [**TeleGeography Submarine Cable Map**](https://www.submarinecablemap.com/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `geolocation`, `corporate_records` |
| **S** | [**WiGLE (Wireless Geographic Logging Engine)**](https://wigle.net/) | `sigint-wireless-space-rf` | 🟢 Passive | Freemium | `geolocation`, `signal_telemetry` |
| **A** | [**CellMapper**](https://www.cellmapper.net/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **A** | [**N2YO Real-Time Satellite Tracking**](https://www.n2yo.com/) | `sigint-wireless-space-rf` | 🟢 Passive | Freemium | `signal_telemetry`, `geolocation` |
| **A** | [**OpenMHz & Broadcastify**](https://openmhz.com/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `archived_pages` |
| **A** | [**Wireshark IEEE MAC OUI Vendor Lookup**](https://www.wireshark.org/tools/oui-lookup.html) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `metadata`, `corporate_records` |
| **B** | [**aprs.fi (Live Amateur Radio & Weather Telemetry)**](https://aprs.fi/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **B** | [**Data Center Map & PeeringDB Facilities**](https://www.datacentermap.com/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `corporate_records` |
| **B** | [**PSKReporter & WSPRnet**](https://pskreporter.info/pskmap.html) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **S** | [**CyberChef (GCHQ)**](https://gchq.github.io/CyberChef/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `metadata`, `urls`, `emails`, `ip_addresses` |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `open_ports` |
| **A** | [**Privacy.com / Virtual Burner Cards**](https://privacy.com/) | `ai-agents-mcp-opsec` | 🟢 Passive | Freemium | `opsec_protection` |
| **A** | [**satellite-mcp**](https://github.com/badchars/satellite-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation`, `flight_tracks`, `vessel_tracks` |
| **A** | [**Vortimo OSINT-tool**](https://www.vortimo.com/) | `ai-agents-mcp-opsec` | 🟢 Passive | Freemium | `entity_graph`, `archived_pages`, `emails`, `phones` |
| **A** | [**Whoogle Search**](https://github.com/benbusby/whoogle-search) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `urls`, `opsec_protection` |
| **A** | [**world-intel-mcp**](https://github.com/marc-shade/world-intel-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `geolocation`, `sanctions_hits`, `flight_tracks`, `signal_telemetry` |
| **B** | [**CSI Linux**](https://csilinux.com/) | `ai-agents-mcp-opsec` | 🟢 Passive | Free | `opsec_protection` |
| **B** | [**Tsurugi Linux**](https://tsurugi-linux.org/) | `ai-agents-mcp-opsec` | 🟢 Passive | Free | `opsec_protection` |
| **S** | [**PDTM (ProjectDiscovery Tool Manager)**](https://github.com/projectdiscovery/pdtm) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `opsec_protection`, `tech_stack` |
| **A** | [**Notify (ProjectDiscovery)**](https://github.com/projectdiscovery/notify) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `metadata` |
| **A** | [**tldfinder (ProjectDiscovery)**](https://github.com/projectdiscovery/tldfinder) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `whois` |
| **A** | [**vulnx (ProjectDiscovery)**](https://github.com/projectdiscovery/vulnx) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `malware_iocs`, `tech_stack`, `metadata` |
| **A** | [**twscrape**](https://github.com/vladkens/twscrape) | `social-media-socmint` | 🔴 Active | OSS / Free | `social_profiles`, `usernames`, `urls`, `metadata` |
| **A** | [**ATProto SDK & CLI (Bluesky)**](https://github.com/MarshalX/atproto) | `social-media-socmint` | 🟡 Hybrid | OSS / Free | `social_profiles`, `dns_records`, `entity_graph`, `metadata` |
| **A** | [**GitGot (Bishop Fox)**](https://github.com/BishopFox/GitGot) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `emails`, `urls` |
| **A** | [**GCPBucketBrute (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/GCPBucketBrute) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `documents`, `secrets` |
| **S** | [**MicroBurst (NetSPI)**](https://github.com/NetSPI/MicroBurst) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `subdomains`, `urls`, `documents`, `secrets` |
| **B** | [**AWSBucketDump**](https://github.com/jordanpotti/AWSBucketDump) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `documents`, `secrets`, `urls` |
| **S** | [**CertStream**](https://github.com/CaliDog/certstream-python) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `certificates`, `subdomains`, `malware_iocs` |
| **A** | [**FofaMap (AI Asset Mapping + Gated Nuclei)**](https://github.com/asaotomo/FofaMap) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `certificates` |
| **A** | [**cvemap (ProjectDiscovery)**](https://github.com/projectdiscovery/cvemap) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `tech_stack`, `metadata` |
| **S** | [**KeyHacks**](https://github.com/streaak/keyhacks) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `secrets`, `metadata` |
| **A** | [**Bellingcat EDGAR Search**](https://github.com/bellingcat/edgar) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `documents`, `person_records` |
| **A** | [**Civilian Harm TimeMap (Bellingcat)**](https://github.com/bellingcat/ukraine-timemap) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `archived_pages`, `metadata` |
| **A** | [**RSSHub**](https://github.com/DIYgod/RSSHub) | `social-media-socmint` | 🟡 Hybrid | OSS / Free | `social_profiles`, `urls`, `metadata` |
| **S** | [**Signature-Base (Florian Roth YARA/IOCs)**](https://github.com/Neo23x0/signature-base) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**SigmaHQ Detection Repository**](https://github.com/SigmaHQ/sigma) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `metadata` |
| **A** | [**Chainsaw (WithSecure Labs)**](https://github.com/WithSecureLabs/chainsaw) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `ip_addresses`, `usernames`, `urls`, `malware_iocs` |
| **S** | [**Nominatim (OpenStreetMap Geocoder)**](https://github.com/osm-search/Nominatim) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `metadata` |
| **S** | [**Model Context Protocol Reference Servers**](https://github.com/modelcontextprotocol/servers) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `urls`, `documents`, `metadata` |
| **A** | [**OpenHands Autonomous Agent**](https://github.com/All-Hands-AI/OpenHands) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |
| **A** | [**CrewAI Multi-Agent Orchestrator**](https://github.com/crewAIInc/crewAI) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |
| **A** | [**LiteLLM Unified Model Gateway**](https://github.com/BerriAI/litellm) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection`, `metadata` |

---

## Selector: url
**Web URL / Post Link** (Webpage, social post, phishing URL) — `163` tools (`python3 scripts/osint.py pivot url --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**BBOT (Bighuge BLS OSINT Tool)**](https://github.com/blacklanternsecurity/bbot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `open_ports`, `tech_stack` |
| **S** | [**IntelOwl**](https://github.com/intelowlproject/IntelOwl) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `open_ports` |
| **S** | [**Web-Check**](https://github.com/lissy93/web-check) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `dns_records`, `certificates`, `whois`, `tech_stack` |
| **A** | [**Crucix**](https://github.com/calesthio/Crucix) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `archived_pages`, `signal_telemetry` |
| **A** | [**Photon**](https://github.com/s0md3v/Photon) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `emails`, `social_profiles`, `subdomains`, `secrets` |
| **A** | [**TheHive Case Management**](https://github.com/StrangeBee/thehive) | `all-in-one-frameworks` | 🟢 Passive | Freemium | `entity_graph`, `malware_iocs` |
| **B** | [**FinalRecon**](https://github.com/thewhiteh4t/FinalRecon) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `whois`, `certificates`, `dns_records`, `subdomains` |
| **A** | [**SocID Extractor**](https://github.com/soxoj/socid-extractor) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata`, `person_records` |
| **A** | [**SteamID.uk / SteamID.io**](https://steamid.io/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **S** | [**GHunt**](https://github.com/mxrch/GHunt) | `email-intelligence` | 🟢 Passive | OSS / Free | `person_records`, `social_profiles`, `geolocation`, `metadata` |
| **B** | [**ContactOut**](https://contactout.com/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `phones`, `person_records` |
| **S** | [**Telegram Native Public Preview (`t.me/s/`)**](https://telegram.org/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `archived_pages`, `metadata` |
| **S** | [**Telepathy**](https://github.com/prose-intelligence-ltd/Telepathy-Community) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `archived_pages`, `metadata` |
| **S** | [**TGStat**](https://tgstat.com/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph`, `metadata` |
| **B** | [**TGScope**](https://tgscope.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **S** | [**Lumen Database (Harvard Berkman Klein Center)**](https://lumendatabase.org/) | `people-public-records` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `urls`, `documents` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **S** | [**BuiltWith**](https://builtwith.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `tech_stack`, `entity_graph` |
| **S** | [**httpx (ProjectDiscovery)**](https://github.com/projectdiscovery/httpx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `certificates`, `metadata`, `urls` |
| **S** | [**waymore**](https://github.com/xnl-h4ck3r/waymore) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `archived_pages`, `urls`, `secrets` |
| **A** | [**hakrawler**](https://github.com/hakluke/hakrawler) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains` |
| **A** | [**Katana**](https://github.com/projectdiscovery/katana) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `secrets`, `tech_stack` |
| **A** | [**Nuclei (Exposure & OSINT Templates)**](https://github.com/projectdiscovery/nuclei) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `social_profiles`, `tech_stack`, `secrets` |
| **A** | [**Wappalyzer**](https://www.wappalyzer.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `tech_stack` |
| **B** | [**Cariddi**](https://github.com/edoardottt/cariddi) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `secrets` |
| **B** | [**WhatWeb**](https://github.com/urbanadventurer/WhatWeb) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**Cloudflare Radar & URL Scanner**](https://radar.cloudflare.com/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `dns_records`, `certificates`, `tech_stack` |
| **A** | [**OONI Explorer (Open Observatory of Network Interference)**](https://explorer.ooni.org/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `signal_telemetry`, `dns_records` |
| **S** | [**4CAT: Capture and Analysis Toolkit**](https://github.com/digitalmethodsinitiative/4cat) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `archived_pages` |
| **S** | [**Instaloader**](https://instaloader.github.io/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata`, `geolocation`, `archived_pages` |
| **S** | [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **S** | [**PullPush Reddit Archive**](https://search.pullpush.io/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `archived_pages` |
| **S** | [**X (Twitter) Native Advanced Search & Geocode**](https://x.com/search-advanced) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `urls` |
| **S** | [**YouTube Metadata & Geofind (MattW)**](https://mattw.io/youtube-metadata/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `social_profiles` |
| **A** | [**LinkdTime (LinkedIn Post Timestamp Extractor)**](https://ollie-boyd.github.io/LinkdTime/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `metadata` |
| **A** | [**TikTok Timestamp & Snowflake Decoder**](https://dfir.blog/tinkering-with-tiktok-timestamps/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `metadata`, `social_profiles` |
| **A** | [**Yark (YouTube Archiving Made Simple)**](https://github.com/Owez/yark) | `social-media-socmint` | 🟢 Passive | OSS / Free | `archived_pages`, `metadata` |
| **B** | [**Fediverse / Mastodon WebFinger & API Lookup**](https://instances.social/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **B** | [**YouTube DataViewer (Amnesty International)**](https://citizenevidence.amnestyusa.org/) | `social-media-socmint` | 🟢 Passive | Free | `metadata`, `urls` |
| **S** | [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `secrets`, `emails`, `urls` |
| **S** | [**Map Switcher (Browser Extension)**](https://chromewebstore.google.com/detail/map-switcher/fanpjcbgemkfjgpkefdbcdbeebbibhbp) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**Google Lens**](https://lens.google.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `geolocation`, `metadata` |
| **S** | [**InVID / WeVerify Verification Plugin**](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `urls` |
| **S** | [**Search by Image (Browser Extension)**](https://github.com/dessant/search-by-image) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `urls` |
| **S** | [**TinEye**](https://tineye.com/) | `image-video-media-forensics` | 🟢 Passive | Freemium | `urls`, `archived_pages` |
| **S** | [**Yandex Reverse Image Search**](https://yandex.com/images/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `geolocation`, `social_profiles` |
| **S** | [**yt-dlp**](https://github.com/yt-dlp/yt-dlp) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `archived_pages`, `metadata` |
| **A** | [**Baidu Image Search (`image.baidu.com`)**](https://image.baidu.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `corporate_records` |
| **A** | [**Bing Visual Search**](https://www.bing.com/visualsearch) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `geolocation` |
| **A** | [**SauceNAO**](https://saucenao.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `social_profiles` |
| **A** | [**TrueMedia.org Deepfake Detector**](https://www.truemedia.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**FotoForensics**](https://fotoforensics.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**Hiya AI Voice & Audio Deepfake Detector**](https://www.hiya.com/products/deepfake-voice-detector) | `image-video-media-forensics` | 🟢 Passive | Freemium | `metadata` |
| **S** | [**Chainabuse (by TRM Labs)**](https://www.chainabuse.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `malware_iocs`, `breach_records` |
| **B** | [**GoPlus Security & RugCheck.xyz**](https://gopluslabs.io/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `malware_iocs`, `tx_graph` |
| **S** | [**AlienVault Open Threat Exchange (OTX)**](https://otx.alienvault.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `dns_records`, `urls`, `subdomains` |
| **S** | [**Hatching Tria.ge Sandbox**](https://tria.ge/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `secrets`, `ip_addresses` |
| **S** | [**ThreatFox (abuse.ch)**](https://threatfox.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs` |
| **S** | [**urlscan.io**](https://urlscan.io/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `tech_stack`, `certificates`, `urls`, `archived_pages` |
| **S** | [**VirusTotal & VT Graph**](https://www.virustotal.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `certificates`, `entity_graph` |
| **A** | [**ANY.RUN Interactive Malware Sandbox**](https://app.any.run/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `ip_addresses` |
| **A** | [**Hybrid Analysis**](https://www.hybrid-analysis.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**Joe Sandbox Cloud Basic**](https://www.joesandbox.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**Lookyloo (CIRCL)**](https://lookyloo.circl.lu/) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `urls`, `certificates`, `tech_stack`, `entity_graph` |
| **A** | [**MISP (Open Source Threat Intelligence Platform)**](https://www.misp-project.org/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph` |
| **A** | [**Pulsedive**](https://pulsedive.com/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `malware_iocs`, `dns_records`, `whois`, `open_ports` |
| **A** | [**URLhaus (abuse.ch)**](https://urlhaus.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `urls` |
| **A** | [**YETI (Your Everyday Threat Intelligence)**](https://yeti-platform.io/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `dns_records` |
| **B** | [**OpenPhish & DestroyList**](https://github.com/phishdestroy/destroylist) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **S** | [**archive.today (archive.ph / archive.is)**](https://archive.ph/) | `archiving-evidence-docs` | 🟡 Hybrid | Free | `archived_pages` |
| **S** | [**ArchiveWeb.page (Webrecorder)**](https://archiveweb.page/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `archived_pages` |
| **S** | [**Hunchly**](https://www.hunchly.com/) | `archiving-evidence-docs` | 🟢 Passive | Paid | `archived_pages`, `metadata`, `entity_graph` |
| **S** | [**SingleFile**](https://github.com/gildas-lormeau/SingleFile) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `archived_pages` |
| **S** | [**Wayback Machine (Internet Archive)**](https://web.archive.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `archived_pages`, `urls`, `documents` |
| **A** | [**ArchiveBox**](https://archivebox.io/) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `documents` |
| **A** | [**Browsertrix Crawler (Webrecorder)**](https://github.com/webrecorder/browsertrix-crawler) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages` |
| **A** | [**Common Crawl Index**](https://commoncrawl.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `archived_pages`, `urls`, `entity_graph` |
| **A** | [**Forensic OSINT**](https://www.forensicosint.com/) | `archiving-evidence-docs` | 🟢 Passive | Paid | `archived_pages`, `metadata` |
| **A** | [**Ghostarchive**](https://ghostarchive.org/) | `archiving-evidence-docs` | 🟡 Hybrid | Free | `archived_pages` |
| **A** | [**gowitness**](https://github.com/sensepost/gowitness) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `certificates` |
| **A** | [**Memento TimeTravel**](http://timetravel.mementoweb.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `archived_pages` |
| **A** | [**Perma.cc (Harvard Library Innovation Lab)**](https://perma.cc/) | `archiving-evidence-docs` | 🔴 Active | Freemium | `archived_pages` |
| **B** | [**EyeWitness**](https://github.com/RedSiege/EyeWitness) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack` |
| **S** | [**Kasm Workspaces**](https://www.kasmweb.com/) | `ai-agents-mcp-opsec` | 🟢 Passive | Freemium | `opsec_protection` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **S** | [**Mullvad Browser**](https://mullvad.net/en/browser) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Qubes OS**](https://www.qubes-os.org/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Tails OS**](https://tails.net/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Tor Browser**](https://www.torproject.org/download/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**uBlock Origin**](https://github.com/gorhill/uBlock) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Whonix**](https://www.whonix.org/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **A** | [**BrowserLeaks & EFF Cover Your Tracks**](https://browserleaks.com/) | `ai-agents-mcp-opsec` | 🟢 Passive | Free | `opsec_protection`, `metadata` |
| **A** | [**Firefox Multi-Account Containers**](https://github.com/mozilla/multi-account-containers) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **A** | [**osint-mcp-server (badchars)**](https://github.com/badchars/osint-mcp-server) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `certificates`, `open_ports` |
| **A** | [**Vortimo OSINT-tool**](https://www.vortimo.com/) | `ai-agents-mcp-opsec` | 🟢 Passive | Freemium | `entity_graph`, `archived_pages`, `emails`, `phones` |
| **B** | [**Sputnik OSINT Browser Extension**](https://github.com/mitchmoser/sputnik) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **A** | [**Raccoon**](https://github.com/evyatarmeged/Raccoon) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `certificates`, `tech_stack` |
| **B** | [**ReconSpider**](https://github.com/bhavsec/reconspider) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `dns_records`, `emails`, `urls` |
| **A** | [**BlackWidow**](https://github.com/1N3/BlackWidow) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `emails`, `phones` |
| **S** | [**Interactsh**](https://github.com/projectdiscovery/interactsh) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses`, `metadata` |
| **S** | [**ffuf (Fuzz Faster U Fool)**](https://github.com/ffuf/ffuf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `tech_stack` |
| **S** | [**Gobuster**](https://github.com/OJ/gobuster) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `urls`, `dns_records` |
| **S** | [**feroxbuster**](https://github.com/epi052/feroxbuster) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `documents`, `tech_stack` |
| **A** | [**dirsearch**](https://github.com/maurosoria/dirsearch) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `documents`, `secrets` |
| **A** | [**Subzy**](https://github.com/PentestPad/subzy) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `metadata` |
| **A** | [**second-order**](https://github.com/mhmdiaa/second-order) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `secrets` |
| **S** | [**WAFW00F**](https://github.com/EnableSecurity/wafw00f) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**wappalyzergo**](https://github.com/projectdiscovery/wappalyzergo) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**CMSeeK**](https://github.com/Tuhinshubhra/CMSeeK) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `usernames`, `urls` |
| **S** | [**WPScan**](https://github.com/wpscanteam/wpscan) | `domain-dns-asm` | 🔴 Active | Freemium | `usernames`, `tech_stack`, `urls`, `metadata` |
| **A** | [**Nikto**](https://github.com/sullo/nikto) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `urls`, `certificates`, `metadata` |
| **S** | [**Arjun**](https://github.com/s0md3v/Arjun) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata` |
| **S** | [**jsluice (Bishop Fox)**](https://github.com/BishopFox/jsluice) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `urls`, `secrets`, `subdomains` |
| **A** | [**LinkFinder**](https://github.com/GerbenJavado/LinkFinder) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains` |
| **S** | [**xnLinkFinder**](https://github.com/xnl-h4ck3r/xnLinkFinder) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `metadata` |
| **B** | [**getJS**](https://github.com/003random/getJS) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls` |
| **S** | [**GoSpider**](https://github.com/jaeles-project/gospider) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `secrets` |
| **A** | [**meg (tomnomnom)**](https://github.com/tomnomnom/meg) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata`, `documents` |
| **S** | [**testssl.sh**](https://github.com/drwetter/testssl.sh) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `tech_stack`, `metadata` |
| **A** | [**Proxify (ProjectDiscovery)**](https://github.com/projectdiscovery/proxify) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `urls`, `metadata`, `secrets` |
| **S** | [**gallery-dl**](https://github.com/mikf/gallery-dl) | `social-media-socmint` | 🔴 Active | OSS / Free | `archived_pages`, `metadata`, `urls` |
| **A** | [**twscrape**](https://github.com/vladkens/twscrape) | `social-media-socmint` | 🔴 Active | OSS / Free | `social_profiles`, `usernames`, `urls`, `metadata` |
| **S** | [**git-dumper**](https://github.com/arthaud/git-dumper) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `secrets`, `emails`, `usernames`, `documents` |
| **A** | [**GitTools (GitFinder / Dumper / Extractor)**](https://github.com/internetwache/GitTools) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `secrets`, `emails`, `documents` |
| **B** | [**AWSBucketDump**](https://github.com/jordanpotti/AWSBucketDump) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `documents`, `secrets`, `urls` |
| **B** | [**CloudScraper**](https://github.com/jordanpotti/CloudScraper) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `subdomains` |
| **S** | [**Kiterunner (Assetnote)**](https://github.com/assetnote/kiterunner) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `metadata` |
| **A** | [**sj (swagger-jacker — Bishop Fox)**](https://github.com/BishopFox/sj) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `metadata`, `secrets` |
| **A** | [**graphql-cop**](https://github.com/dolevf/graphql-cop) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `metadata` |
| **A** | [**Graphinder (Escape Technologies)**](https://github.com/Escape-Technologies/graphinder) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `tech_stack` |
| **A** | [**Clairvoyance**](https://github.com/nikitastupin/clairvoyance) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `metadata`, `urls` |
| **A** | [**TorCrawl.py**](https://github.com/MikeMeliz/TorCrawl.py) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `archived_pages`, `urls` |
| **S** | [**CAPEv2 Malware Sandbox**](https://github.com/kevoreilly/CAPEv2) | `threat-intel-malware-cti` | 🔴 Active | OSS / Free | `malware_iocs`, `ip_addresses`, `urls`, `secrets` |
| **A** | [**Aquatone**](https://github.com/michenriksen/aquatone) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `urls` |
| **S** | [**Monolith**](https://github.com/Y2Z/monolith) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `documents` |
| **A** | [**pentest-mcp**](https://github.com/DMontgomery40/pentest-mcp) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `open_ports`, `urls`, `tech_stack` |
| **A** | [**nuclei-mcp**](https://github.com/addcontent/nuclei-mcp) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `tech_stack`, `malware_iocs`, `metadata` |
| **B** | [**AutoRedTeam-Orchestrator**](https://github.com/Coff0xc/AutoRedTeam-Orchestrator) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `urls`, `tech_stack` |
| **B** | [**BlitzStrike MCP Toolbelt**](https://github.com/shinthink/blitzstrike) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **S** | [**OWASP Nettacker**](https://github.com/OWASP/Nettacker) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **A** | [**Corsy**](https://github.com/s0md3v/Corsy) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata`, `tech_stack` |
| **B** | [**CORScanner**](https://github.com/chenjj/CORScanner) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata` |
| **A** | [**subjs**](https://github.com/lc/subjs) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls` |
| **B** | [**hakcheckurl**](https://github.com/hakluke/hakcheckurl) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `metadata` |
| **B** | [**fff (Fast Fetching Friend)**](https://github.com/tomnomnom/fff) | `domain-dns-asm` | 🔴 Active | OSS / Free | `archived_pages`, `metadata`, `secrets` |
| **B** | [**WhatWaf**](https://github.com/Ekultek/WhatWaf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **B** | [**identYwaf**](https://github.com/stamparm/identYwaf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **S** | [**Nuclei Templates**](https://github.com/projectdiscovery/nuclei-templates) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `secrets`, `social_profiles`, `metadata` |
| **A** | [**WitnessMe**](https://github.com/byt3bl33d3r/WitnessMe) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `urls` |
| **S** | [**Trivy (Aqua Security)**](https://github.com/aquasecurity/trivy) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `tech_stack`, `secrets`, `malware_iocs` |
| **S** | [**gf (Grep-Friend Pattern Wrapper)**](https://github.com/tomnomnom/gf) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `secrets`, `urls`, `subdomains` |
| **S** | [**unfurl**](https://github.com/tomnomnom/unfurl) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains`, `urls`, `metadata` |
| **A** | [**anew**](https://github.com/tomnomnom/anew) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `subdomains`, `urls` |
| **S** | [**Bellingcat Auto Archiver**](https://github.com/bellingcat/auto-archiver) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `metadata`, `documents` |
| **S** | [**Wayback Google Analytics (Bellingcat)**](https://github.com/bellingcat/wayback-google-analytics) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `entity_graph`, `archived_pages`, `metadata` |
| **A** | [**RSSHub**](https://github.com/DIYgod/RSSHub) | `social-media-socmint` | 🟡 Hybrid | OSS / Free | `social_profiles`, `urls`, `metadata` |
| **S** | [**Cortex (TheHive Observable Analyzer)**](https://github.com/TheHive-Project/Cortex) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `subdomains` |
| **A** | [**Maltrail**](https://github.com/stamparm/maltrail) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**vt-py (Official VirusTotal Python SDK)**](https://github.com/VirusTotal/vt-py) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `subdomains`, `dns_records`, `certificates` |
| **A** | [**MetaMask Eth-Phishing-Detect**](https://github.com/MetaMask/eth-phishing-detect) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **S** | [**Model Context Protocol Reference Servers**](https://github.com/modelcontextprotocol/servers) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `urls`, `documents`, `metadata` |
| **S** | [**Fabric (Daniel Miessler AI Patterns)**](https://github.com/danielmiessler/fabric) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph`, `metadata` |
| **B** | [**qsreplace**](https://github.com/tomnomnom/qsreplace) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `urls` |

---

## Selector: ip
**IPv4 / IPv6 Address** (`198.51.100.42`) — `148` tools (`python3 scripts/osint.py pivot ip --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**BBOT (Bighuge BLS OSINT Tool)**](https://github.com/blacklanternsecurity/bbot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `open_ports`, `tech_stack` |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**IntelOwl**](https://github.com/intelowlproject/IntelOwl) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `open_ports` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**OpenCTI**](https://github.com/OpenCTI-Platform/opencti) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `darkweb_mentions` |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **A** | [**IVRE**](https://ivre.rocks/) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `certificates`, `dns_records`, `tech_stack` |
| **A** | [**Osmedeus**](https://github.com/j3ssie/osmedeus) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `open_ports`, `dns_records`, `tech_stack` |
| **A** | [**reNgine**](https://github.com/yogeshojha/rengine) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `certificates` |
| **A** | [**sn0int**](https://github.com/kpcyrd/sn0int) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses`, `social_profiles`, `breach_records` |
| **A** | [**TheHive Case Management**](https://github.com/StrangeBee/thehive) | `all-in-one-frameworks` | 🟢 Passive | Freemium | `entity_graph`, `malware_iocs` |
| **B** | [**Harpoon**](https://github.com/Te-k/harpoon) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `dns_records`, `whois`, `open_ports`, `certificates` |
| **B** | [**Lampyre**](https://lampyre.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `geolocation`, `corporate_records`, `social_profiles` |
| **S** | [**MXToolbox SuperTool**](https://mxtoolbox.com/SuperTool.aspx) | `email-intelligence` | 🟡 Hybrid | Freemium | `dns_records`, `whois`, `tech_stack` |
| **B** | [**That'sThem**](https://thatsthem.com/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `phones`, `emails`, `geolocation` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **S** | [**Hudson Rock — Cavalier Free OSINT Tools**](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `malware_iocs`, `tech_stack` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **A** | [**LeakIX**](https://leakix.net/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `open_ports`, `secrets`, `breach_records`, `tech_stack` |
| **A** | [**SOCRadar Free SOC Tools**](https://socradar.io/labs/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `subdomains`, `malware_iocs` |
| **B** | [**Constella Intelligence**](https://constella.ai/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `person_records`, `entity_graph` |
| **B** | [**Snusbase**](https://snusbase.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `ip_addresses`, `emails` |
| **S** | [**httpx (ProjectDiscovery)**](https://github.com/projectdiscovery/httpx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `certificates`, `metadata`, `urls` |
| **S** | [**OWASP Amass**](https://github.com/owasp-amass/amass) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `ip_addresses`, `whois` |
| **S** | [**SecurityTrails**](https://securitytrails.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `subdomains`, `whois`, `ip_addresses` |
| **A** | [**DNSlytics**](https://dnslytics.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses`, `entity_graph` |
| **A** | [**dnsx (ProjectDiscovery)**](https://github.com/projectdiscovery/dnsx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses`, `subdomains` |
| **A** | [**DomainTools Iris**](https://www.domaintools.com/) | `domain-dns-asm` | 🟢 Passive | Paid | `whois`, `dns_records`, `entity_graph`, `malware_iocs` |
| **A** | [**RapidDNS**](https://rapiddns.io/) | `domain-dns-asm` | 🟢 Passive | Free | `subdomains`, `dns_records`, `ip_addresses` |
| **A** | [**tlsx (ProjectDiscovery)**](https://github.com/projectdiscovery/tlsx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `certificates`, `subdomains` |
| **A** | [**ViewDNS.info**](https://viewdns.info/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses` |
| **B** | [**Robtex**](https://www.robtex.com/) | `domain-dns-asm` | 🟢 Passive | Free | `dns_records`, `ip_addresses`, `entity_graph` |
| **B** | [**WhatWeb**](https://github.com/urbanadventurer/WhatWeb) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `metadata` |
| **S** | [**Censys Search**](https://search.censys.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `malware_iocs` |
| **S** | [**FOFA**](https://en.fofa.info/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `ip_addresses` |
| **S** | [**GreyNoise Visualizer**](https://viz.greynoise.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `geolocation` |
| **S** | [**Hurricane Electric BGP Toolkit**](https://bgp.he.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `dns_records`, `entity_graph` |
| **S** | [**IPinfo.io**](https://ipinfo.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `geolocation`, `whois`, `corporate_records` |
| **S** | [**RIPEstat**](https://stat.ripe.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `whois`, `ip_addresses`, `geolocation`, `signal_telemetry` |
| **S** | [**Shodan**](https://www.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `geolocation` |
| **S** | [**Shodan InternetDB**](https://internetdb.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Free | `open_ports`, `tech_stack`, `dns_records` |
| **S** | [**Spur.us Context**](https://spur.us/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `geolocation`, `malware_iocs`, `opsec_protection` |
| **A** | [**AbuseIPDB**](https://www.abuseipdb.com/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `malware_iocs`, `whois`, `geolocation` |
| **A** | [**asn (Network Recon CLI)**](https://github.com/nitefood/asn) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `whois`, `geolocation` |
| **A** | [**asnmap (ProjectDiscovery)**](https://github.com/projectdiscovery/asnmap) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `whois` |
| **A** | [**BGP.Tools**](https://bgp.tools/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `entity_graph` |
| **A** | [**Criminal IP**](https://www.criminalip.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `malware_iocs`, `certificates`, `geolocation` |
| **A** | [**Metabigor**](https://github.com/j3ssie/metabigor) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**Netlas.io**](https://netlas.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `certificates`, `whois` |
| **A** | [**Nmap**](https://nmap.org/) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `certificates`, `tech_stack` |
| **A** | [**Spamhaus IP & Domain Reputation Checker**](https://check.spamhaus.org/) | `network-ip-iot-search` | 🟢 Passive | Free | `malware_iocs`, `whois` |
| **A** | [**Uncover (ProjectDiscovery)**](https://github.com/projectdiscovery/uncover) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**ZoomEye**](https://www.zoomeye.ai/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `tech_stack`, `certificates`, `geolocation` |
| **B** | [**360 Quake Cyberspace Mapping**](https://quake.360.net/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**BinaryEdge**](https://www.binaryedge.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**Hunter.how**](https://hunter.how/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**MultiRBL.valli.org**](https://multirbl.valli.org/) | `network-ip-iot-search` | 🟢 Passive | Free | `malware_iocs`, `dns_records` |
| **B** | [**ONYPHE**](https://www.onyphe.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `malware_iocs` |
| **S** | [**Tor Metrics — Relay & Bridge Search**](https://metrics.torproject.org/rs.html) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `opsec_protection`, `whois`, `signal_telemetry` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records` |
| **A** | [**ExoneraTor (Tor Historical Relay Archive)**](https://metrics.torproject.org/exonerator.html) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `opsec_protection`, `whois` |
| **S** | [**AlienVault Open Threat Exchange (OTX)**](https://otx.alienvault.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `dns_records`, `urls`, `subdomains` |
| **S** | [**Silent Push Community Edition**](https://www.silentpush.com/community-edition/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `malware_iocs`, `certificates`, `entity_graph` |
| **S** | [**ThreatFox (abuse.ch)**](https://threatfox.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs` |
| **S** | [**urlscan.io**](https://urlscan.io/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `tech_stack`, `certificates`, `urls`, `archived_pages` |
| **S** | [**Validin**](https://app.validin.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `certificates`, `ip_addresses`, `malware_iocs` |
| **S** | [**VirusTotal & VT Graph**](https://www.virustotal.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `certificates`, `entity_graph` |
| **A** | [**ANY.RUN Interactive Malware Sandbox**](https://app.any.run/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `ip_addresses` |
| **A** | [**Cisco Talos Intelligence Center**](https://talosintelligence.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `whois`, `dns_records` |
| **A** | [**Feodo Tracker (abuse.ch)**](https://feodotracker.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `open_ports` |
| **A** | [**Hunt.io**](https://hunt.io/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `certificates`, `entity_graph` |
| **A** | [**Hybrid Analysis**](https://www.hybrid-analysis.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**Joe Sandbox Cloud Basic**](https://www.joesandbox.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**MISP (Open Source Threat Intelligence Platform)**](https://www.misp-project.org/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph` |
| **A** | [**Pulsedive**](https://pulsedive.com/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `malware_iocs`, `dns_records`, `whois`, `open_ports` |
| **A** | [**SSLBL (abuse.ch Malicious SSL & JA3 Blacklist)**](https://sslbl.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `certificates`, `malware_iocs` |
| **A** | [**URLhaus (abuse.ch)**](https://urlhaus.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `urls` |
| **A** | [**YETI (Your Everyday Threat Intelligence)**](https://yeti-platform.io/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `dns_records` |
| **B** | [**ThreatMiner**](https://www.threatminer.org/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `documents`, `dns_records` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `open_ports` |
| **A** | [**osint-mcp-server (badchars)**](https://github.com/badchars/osint-mcp-server) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `certificates`, `open_ports` |
| **B** | [**Sputnik OSINT Browser Extension**](https://github.com/mitchmoser/sputnik) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **A** | [**Raccoon**](https://github.com/evyatarmeged/Raccoon) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `certificates`, `tech_stack` |
| **B** | [**ReconSpider**](https://github.com/bhavsec/reconspider) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `dns_records`, `emails`, `urls` |
| **A** | [**ScopeSentry**](https://github.com/Autumn-27/ScopeSentry) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `urls` |
| **A** | [**ARL-Next (Asset Reconnaissance Lighthouse)**](https://github.com/owl234/ARL-Next) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `certificates` |
| **A** | [**smtp-user-enum**](https://github.com/pentestmonkey/smtp-user-enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames` |
| **S** | [**SIPVicious (svmap / svwar)**](https://github.com/EnableSecurity/sipvicious) | `phone-messaging-osint` | 🔴 Active | OSS / Free | `phones`, `open_ports`, `tech_stack`, `metadata` |
| **S** | [**ffuf (Fuzz Faster U Fool)**](https://github.com/ffuf/ffuf) | `domain-dns-asm` | 🔴 Active | OSS / Free | `urls`, `subdomains`, `tech_stack` |
| **S** | [**DNSRecon**](https://github.com/darkoperator/dnsrecon) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains`, `ip_addresses` |
| **A** | [**cdncheck (ProjectDiscovery)**](https://github.com/projectdiscovery/cdncheck) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `tech_stack`, `ip_addresses`, `metadata` |
| **A** | [**Nikto**](https://github.com/sullo/nikto) | `domain-dns-asm` | 🔴 Active | OSS / Free | `tech_stack`, `urls`, `certificates`, `metadata` |
| **S** | [**Masscan**](https://github.com/robertdavidgraham/masscan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses`, `certificates`, `tech_stack` |
| **S** | [**RustScan**](https://github.com/bee-san/RustScan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack` |
| **S** | [**Naabu (ProjectDiscovery)**](https://github.com/projectdiscovery/naabu) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses` |
| **A** | [**mapcidr**](https://github.com/projectdiscovery/mapcidr) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses` |
| **S** | [**ZMap**](https://github.com/zmap/zmap) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses` |
| **S** | [**ZGrab 2.0**](https://github.com/zmap/zgrab2) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `certificates`, `tech_stack`, `metadata` |
| **A** | [**ZDNS**](https://github.com/zmap/zdns) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `dns_records`, `ip_addresses` |
| **S** | [**fingerprintx (Praetorian)**](https://github.com/praetorian-inc/fingerprintx) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `certificates`, `metadata` |
| **S** | [**testssl.sh**](https://github.com/drwetter/testssl.sh) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `tech_stack`, `metadata` |
| **A** | [**SSLyze**](https://github.com/nabla-c0d3/sslyze) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `subdomains`, `metadata` |
| **S** | [**ssh-audit**](https://github.com/jtesta/ssh-audit) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `tech_stack`, `open_ports`, `metadata` |
| **A** | [**arp-scan**](https://github.com/royhills/arp-scan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `ip_addresses`, `metadata`, `tech_stack` |
| **S** | [**NetExec (nxc)**](https://github.com/Pennyw0rth/NetExec) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `usernames`, `metadata` |
| **A** | [**enum4linux-ng**](https://github.com/cddmp/enum4linux-ng) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `usernames`, `tech_stack`, `metadata` |
| **A** | [**SMBMap**](https://github.com/ShawnDEvans/smbmap) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `documents`, `metadata`, `open_ports` |
| **A** | [**onesixtyone**](https://github.com/trailofbits/onesixtyone) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `tech_stack`, `open_ports`, `metadata` |
| **S** | [**JARM (Salesforce Active TLS Fingerprinter)**](https://github.com/salesforce/jarm) | `threat-intel-malware-cti` | 🔴 Active | OSS / Free | `malware_iocs`, `certificates`, `tech_stack` |
| **A** | [**Aquatone**](https://github.com/michenriksen/aquatone) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `urls` |
| **S** | [**bettercap**](https://github.com/bettercap/bettercap) | `sigint-wireless-space-rf` | 🔴 Active | OSS / Free | `signal_telemetry`, `ip_addresses`, `metadata` |
| **S** | [**Scapy**](https://github.com/secdev/scapy) | `sigint-wireless-space-rf` | 🔴 Active | OSS / Free | `open_ports`, `signal_telemetry`, `ip_addresses`, `metadata` |
| **A** | [**pentest-mcp**](https://github.com/DMontgomery40/pentest-mcp) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `open_ports`, `urls`, `tech_stack` |
| **A** | [**nuclei-mcp**](https://github.com/addcontent/nuclei-mcp) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `tech_stack`, `malware_iocs`, `metadata` |
| **A** | [**FofaMap (AI Asset Mapping + Gated Nuclei)**](https://github.com/asaotomo/FofaMap) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `certificates` |
| **B** | [**AutoRedTeam-Orchestrator**](https://github.com/Coff0xc/AutoRedTeam-Orchestrator) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `urls`, `tech_stack` |
| **B** | [**BlitzStrike MCP Toolbelt**](https://github.com/shinthink/blitzstrike) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **B** | [**ExternalAttacker-MCP**](https://github.com/MorDavid/ExternalAttacker-MCP) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `open_ports`, `tech_stack` |
| **S** | [**OWASP Nettacker**](https://github.com/OWASP/Nettacker) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **A** | [**hakrevdns**](https://github.com/hakluke/hakrevdns) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records` |
| **A** | [**hakip2host**](https://github.com/hakluke/hakip2host) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `certificates`, `dns_records` |
| **A** | [**VHostScan**](https://github.com/codingo/VHostScan) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `urls` |
| **A** | [**nmap-vulners NSE**](https://github.com/vulnersCom/nmap-vulners) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `malware_iocs` |
| **A** | [**Vulscan (Nmap Offline CVE NSE)**](https://github.com/scipag/vulscan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `malware_iocs` |
| **A** | [**windapsearch**](https://github.com/ropnop/windapsearch) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `usernames`, `emails`, `person_records`, `metadata` |
| **S** | [**Impacket Network Protocol Scripts**](https://github.com/fortra/impacket) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `tech_stack`, `usernames`, `metadata`, `open_ports` |
| **B** | [**rmiscout (Bishop Fox)**](https://github.com/BishopFox/rmiscout) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `tech_stack`, `metadata` |
| **S** | [**Nuclei Templates**](https://github.com/projectdiscovery/nuclei-templates) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `secrets`, `social_profiles`, `metadata` |
| **A** | [**WitnessMe**](https://github.com/byt3bl33d3r/WitnessMe) | `archiving-evidence-docs` | 🔴 Active | OSS / Free | `archived_pages`, `tech_stack`, `urls` |
| **A** | [**haktrails**](https://github.com/hakluke/haktrails) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `whois` |
| **A** | [**Cero (Go TLS SAN Scraper)**](https://github.com/glebarez/cero) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `certificates` |
| **A** | [**anew**](https://github.com/tomnomnom/anew) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `subdomains`, `urls` |
| **B** | [**OWASP Open Asset Model (OAM)**](https://github.com/owasp-amass/open-asset-model) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **A** | [**Certipy**](https://github.com/ly4k/Certipy) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `certificates`, `tech_stack`, `entity_graph` |
| **A** | [**Responder**](https://github.com/lgandx/Responder) | `network-ip-iot-search` | 🟡 Hybrid | OSS / Free | `usernames`, `tech_stack`, `ip_addresses` |
| **S** | [**Wireshark / tshark**](https://github.com/wireshark/wireshark) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `dns_records`, `certificates`, `metadata` |
| **S** | [**Zeek Network Security Monitor**](https://github.com/zeek/zeek) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `dns_records`, `certificates`, `urls`, `malware_iocs` |
| **S** | [**Suricata**](https://github.com/OISF/suricata) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `malware_iocs`, `dns_records`, `certificates` |
| **A** | [**Malcolm (CISA Network Traffic Suite)**](https://github.com/cisagov/Malcolm) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `entity_graph`, `dns_records`, `ip_addresses`, `malware_iocs` |
| **B** | [**nDPI (Deep Packet Inspection)**](https://github.com/ntop/nDPI) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `tech_stack`, `metadata`, `ip_addresses` |
| **S** | [**Cortex (TheHive Observable Analyzer)**](https://github.com/TheHive-Project/Cortex) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `subdomains` |
| **A** | [**Maltrail**](https://github.com/stamparm/maltrail) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**FireHOL Blocklist IPsets**](https://github.com/firehol/blocklist-ipsets) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `ip_addresses` |
| **A** | [**vt-py (Official VirusTotal Python SDK)**](https://github.com/VirusTotal/vt-py) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `subdomains`, `dns_records`, `certificates` |
| **S** | [**Stem (Tor Controller Python Library)**](https://github.com/torproject/stem) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `ip_addresses`, `darkweb_mentions`, `opsec_protection` |
| **B** | [**FIR (Fast Incident Response)**](https://github.com/certsocietegenerale/FIR) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `documents`, `malware_iocs` |

---

## Selector: company
**Company / Organization** (Corporate name, LEI, CAGE) — `137` tools (`python3 scripts/osint.py pivot company --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**OpenCTI**](https://github.com/OpenCTI-Platform/opencti) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `darkweb_mentions` |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**The GDELT Project**](https://www.gdeltproject.org/) | `all-in-one-frameworks` | 🟢 Passive | Free | `documents`, `geolocation`, `entity_graph` |
| **A** | [**OSIRIS**](https://github.com/simplifaisoul/osiris) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `sanctions_hits`, `tx_graph`, `flight_tracks`, `vessel_tracks` |
| **B** | [**Lampyre**](https://lampyre.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `geolocation`, `corporate_records`, `social_profiles` |
| **B** | [**Social Links**](https://sociallinks.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `social_profiles`, `darkweb_mentions`, `corporate_records` |
| **B** | [**KnowEm**](https://knowem.com/) | `username-enumeration` | 🟢 Passive | Freemium | `social_profiles`, `corporate_records` |
| **S** | [**Hunter.io**](https://hunter.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **S** | [**theHarvester**](https://github.com/laramies/theHarvester) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `subdomains`, `person_records`, `ip_addresses` |
| **A** | [**CrossLinked**](https://github.com/m8sec/CrossLinked) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `person_records`, `usernames` |
| **B** | [**ContactOut**](https://contactout.com/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `phones`, `person_records` |
| **B** | [**linkedin2username**](https://github.com/initstring/linkedin2username) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `person_records` |
| **B** | [**OpenLeads**](https://github.com/openleads-dev/openleads) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `person_records` |
| **B** | [**RocketReach**](https://rocketreach.co/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `phones`, `person_records`, `corporate_records` |
| **B** | [**Skymem**](http://www.skymem.info/) | `email-intelligence` | 🟢 Passive | Freemium | `emails` |
| **B** | [**Snov.io**](https://snov.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **S** | [**CourtListener & RECAP Archive**](https://www.courtlistener.com/) | `people-public-records` | 🟢 Passive | OSS / Free | `person_records`, `corporate_records`, `archived_pages` |
| **S** | [**Judyrecords**](https://www.judyrecords.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **S** | [**Lumen Database (Harvard Berkman Klein Center)**](https://lumendatabase.org/) | `people-public-records` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `urls`, `documents` |
| **S** | [**PACER (US Federal Courts)**](https://pacer.uscourts.gov/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `corporate_records` |
| **A** | [**BAILII (British & Irish Legal Information Institute)**](https://www.bailii.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **A** | [**DOJ FARA eFile Search**](https://efile.fara.gov/) | `people-public-records` | 🟢 Passive | Free | `corporate_records`, `person_records`, `archived_pages` |
| **A** | [**FEC Individual Contributions Search**](https://www.fec.gov/data/receipts/individual-contributions/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation` |
| **A** | [**FINRA BrokerCheck & SEC IAPD**](https://brokercheck.finra.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records`, `sanctions_hits` |
| **A** | [**Justia Dockets & Filings**](https://dockets.justia.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **A** | [**LittleSis**](https://littlesis.org/) | `people-public-records` | 🟢 Passive | OSS / Free | `entity_graph`, `person_records`, `corporate_records` |
| **A** | [**Newspapers.com & Chronicling America (LOC)**](https://chroniclingamerica.loc.gov/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `archived_pages` |
| **A** | [**OpenSecrets**](https://www.opensecrets.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **B** | [**UK National Archives — Find Case Law**](https://caselaw.nationalarchives.gov.uk/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **B** | [**US NPPES NPI Registry (Healthcare Providers)**](https://npiregistry.cms.hhs.gov/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records`, `phones`, `geolocation` |
| **S** | [**Distributed Denial of Secrets (DDoSecrets)**](https://ddosecrets.com/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **S** | [**RansomLook**](https://www.ransomlook.io/) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `archived_pages` |
| **A** | [**ransomwatch**](https://ransomwhat.telemetry.ltd/) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records` |
| **A** | [**SEC Item 1.05 Material Cybersecurity Incident Filings**](https://www.sec.gov/edgar/search/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `corporate_records`, `documents` |
| **A** | [**State AG Official Data Breach Portals (CA / ME / HHS OCR)**](https://oag.ca.gov/privacy/databreach/list) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `corporate_records`, `documents` |
| **A** | [**WikiLeaks Public Library of US Diplomacy & Leaks**](https://search.wikileaks.org/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **S** | [**crt.sh (Certificate Transparency Search)**](https://crt.sh/) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `certificates`, `subdomains` |
| **S** | [**OWASP Amass**](https://github.com/owasp-amass/amass) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `ip_addresses`, `whois` |
| **S** | [**Whoxy**](https://www.whoxy.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `whois`, `subdomains`, `emails` |
| **A** | [**ProjectDiscovery Chaos Public Bug-Bounty Dataset**](https://chaos.projectdiscovery.io/) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains` |
| **S** | [**Censys Search**](https://search.censys.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `malware_iocs` |
| **S** | [**Hurricane Electric BGP Toolkit**](https://bgp.he.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `dns_records`, `entity_graph` |
| **S** | [**Shodan**](https://www.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `geolocation` |
| **A** | [**asn (Network Recon CLI)**](https://github.com/nitefood/asn) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `whois`, `geolocation` |
| **A** | [**asnmap (ProjectDiscovery)**](https://github.com/projectdiscovery/asnmap) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `whois` |
| **A** | [**BGP.Tools**](https://bgp.tools/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `entity_graph` |
| **A** | [**Metabigor**](https://github.com/j3ssie/metabigor) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**Netlas.io**](https://netlas.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `certificates`, `whois` |
| **A** | [**PeeringDB**](https://www.peeringdb.com/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `corporate_records`, `geolocation`, `emails` |
| **A** | [**Uncover (ProjectDiscovery)**](https://github.com/projectdiscovery/uncover) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **S** | [**Filmot (YouTube Subtitle & Transcript Search)**](https://filmot.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `urls`, `metadata`, `archived_pages` |
| **S** | [**cloud_enum**](https://github.com/initstring/cloud_enum) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `tech_stack`, `secrets` |
| **S** | [**Hugging Face Hub Search (Models, Datasets & Spaces)**](https://huggingface.co/search/full-text) | `code-cloud-dev-osint` | 🟢 Passive | Free | `secrets`, `urls`, `documents` |
| **S** | [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `secrets`, `emails`, `urls` |
| **A** | [**Docker Hub & Layer Inspector (`dive`)**](https://hub.docker.com/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack` |
| **A** | [**GrayhatWarfare**](https://buckets.grayhatwarfare.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `documents` |
| **A** | [**Postman Public API Network**](https://www.postman.com/explore) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `emails` |
| **B** | [**Gitrob / Shhgit**](https://github.com/eth0izzle/shhgit) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `urls` |
| **S** | [**Equasis**](https://www.equasis.org/) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `vessel_tracks`, `sanctions_hits` |
| **S** | [**Global Fishing Watch Map**](https://globalfishingwatch.org/map) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `vessel_tracks`, `satellite_imagery`, `geolocation` |
| **S** | [**ImportYeti**](https://www.importyeti.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `corporate_records`, `entity_graph`, `vessel_tracks` |
| **A** | [**FAA Aircraft Registry (N-Number Inquiry)**](https://registry.faa.gov/aircraftinquiry/) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `person_records`, `flight_tracks` |
| **A** | [**Paris MoU & Tokyo MoU Port State Control Databases**](https://www.parismou.org/inspection-search/inspection-search) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `vessel_tracks`, `documents` |
| **A** | [**S&P Panjiva & ImportGenius**](https://panjiva.com/) | `aviation-maritime-transport` | 🟢 Passive | Paid | `corporate_records`, `vessel_tracks`, `entity_graph` |
| **S** | [**GLEIF Legal Entity Identifier (LEI) Search**](https://search.gleif.org/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `entity_graph` |
| **S** | [**ICIJ Offshore Leaks Database**](https://offshoreleaks.icij.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**OpenCorporates**](https://opencorporates.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**OpenSanctions**](https://www.opensanctions.org/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `sanctions_hits`, `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**Pappers.fr (French Corporate & UBO Intelligence)**](https://www.pappers.fr/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**ProPublica Nonprofit Explorer**](https://projects.propublica.org/nonprofits/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**SEC EDGAR Full-Text Search**](https://www.sec.gov/edgar/searchedgar/companysearch) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**UK Companies House & Overseas Entities Register**](https://find-and-update.company-information.service.gov.uk/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**US Treasury OFAC Sanctions List Search**](https://sanctionssearch.ofac.treas.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **S** | [**Violation Tracker & Subsidy Tracker (Good Jobs First)**](https://violationtrackerglobal.goodjobsfirst.org/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `sanctions_hits` |
| **A** | [**EU e-Justice Business & Insolvency Registers Portal**](https://e-justice.europa.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records` |
| **A** | [**EU Sanctions Map**](https://www.sanctionsmap.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **A** | [**Google Patents**](https://patents.google.com/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **A** | [**Handelsregister.de (Official German Commercial Register)**](https://www.handelsregister.de/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **A** | [**North Data**](https://www.northdata.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **A** | [**Open Ownership Register**](https://register.openownership.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `entity_graph` |
| **A** | [**SAM.gov (System for Award Management)**](https://sam.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `sanctions_hits`, `emails`, `phones` |
| **A** | [**TED (Tenders Electronic Daily — EU)**](https://ted.europa.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `documents` |
| **A** | [**USAspending.gov**](https://www.usaspending.gov/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `documents` |
| **A** | [**WIPO Global Brand & PatentScope Databases**](https://branddb.wipo.int/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **A** | [**World Bank Listing of Ineligible (Debarred) Firms & Individuals**](https://www.worldbank.org/en/projects-operations/procurement/debarred-firms) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits`, `corporate_records` |
| **B** | [**Crunchbase**](https://www.crunchbase.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **B** | [**OpenInsider (SEC Form 4 Insider Trading Screener)**](http://openinsider.com/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **S** | [**Arkham Intelligence**](https://intel.arkm.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph`, `person_records` |
| **S** | [**Ransomware.live (Julien Mousqueton)**](https://www.ransomware.live/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `documents` |
| **S** | [**Robin (AI-Powered Dark Web OSINT)**](https://github.com/apurvsinghgautam/robin) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **A** | [**DarkFeed / Ransomfeed**](https://ransomfeed.it/) | `darkweb-tor-underground` | 🟢 Passive | Freemium | `darkweb_mentions`, `breach_records` |
| **A** | [**darknet-mcp-server**](https://github.com/badchars/darknet-mcp-server) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `malware_iocs` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records` |
| **A** | [**Flare Threat Exposure Management**](https://flare.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records`, `secrets` |
| **A** | [**Searchlight Cyber (Cerberus / DarkIQ)**](https://www.slcyber.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `archived_pages`, `certificates` |
| **S** | [**DocumentCloud & MuckRock**](https://www.documentcloud.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `person_records`, `corporate_records` |
| **S** | [**OpenAlex**](https://openalex.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `person_records`, `entity_graph` |
| **A** | [**Semantic Scholar & arXiv**](https://www.semanticscholar.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `documents`, `person_records`, `entity_graph` |
| **B** | [**CORE (Open Access Research Aggregator)**](https://core.ac.uk/) | `archiving-evidence-docs` | 🟢 Passive | Freemium | `documents`, `person_records` |
| **B** | [**FOIA.gov (Official US Federal FOIA Portal)**](https://www.foia.gov/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents` |
| **B** | [**WhatDoTheyKnow & AskTheEU**](https://www.whatdotheyknow.com/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `corporate_records` |
| **S** | [**FCC Universal Licensing System (ULS) & FCCID.io**](https://fccid.io/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `corporate_records`, `documents`, `geolocation` |
| **S** | [**TeleGeography Submarine Cable Map**](https://www.submarinecablemap.com/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `geolocation`, `corporate_records` |
| **B** | [**Data Center Map & PeeringDB Facilities**](https://www.datacentermap.com/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `corporate_records` |
| **A** | [**Sanctions Screening MCP Server**](https://github.com/cyanheads/sanctions-screening-mcp-server) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `sanctions_hits`, `corporate_records` |
| **A** | [**Sift (Corporate & Financial Cross-Reference MCP)**](https://github.com/mefos-lab/sift) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `corporate_records`, `sanctions_hits`, `entity_graph` |
| **A** | [**world-intel-mcp**](https://github.com/marc-shade/world-intel-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `geolocation`, `sanctions_hits`, `flight_tracks`, `signal_telemetry` |
| **A** | [**ScopeSentry**](https://github.com/Autumn-27/ScopeSentry) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `urls` |
| **A** | [**ARL-Next (Asset Reconnaissance Lighthouse)**](https://github.com/owl234/ARL-Next) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `certificates` |
| **A** | [**OctoSuite**](https://github.com/rly0nheart/octosuite) | `username-enumeration` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `metadata`, `usernames` |
| **A** | [**Social Mapper**](https://github.com/Greenwolf/social_mapper) | `username-enumeration` | 🔴 Active | OSS / Free | `social_profiles`, `usernames`, `person_records` |
| **A** | [**onedrive_user_enum**](https://github.com/nyxgeek/onedrive_user_enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames`, `urls` |
| **A** | [**tldfinder (ProjectDiscovery)**](https://github.com/projectdiscovery/tldfinder) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `whois` |
| **A** | [**GitGot (Bishop Fox)**](https://github.com/BishopFox/GitGot) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `emails`, `urls` |
| **S** | [**CloudFox (Bishop Fox)**](https://github.com/BishopFox/cloudfox) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `ip_addresses`, `subdomains`, `secrets` |
| **A** | [**Cloudlist (ProjectDiscovery)**](https://github.com/projectdiscovery/cloudlist) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `ip_addresses`, `subdomains`, `dns_records` |
| **A** | [**GCPBucketBrute (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/GCPBucketBrute) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `urls`, `documents`, `secrets` |
| **S** | [**MicroBurst (NetSPI)**](https://github.com/NetSPI/MicroBurst) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `subdomains`, `urls`, `documents`, `secrets` |
| **S** | [**CertStream**](https://github.com/CaliDog/certstream-python) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `certificates`, `subdomains`, `malware_iocs` |
| **A** | [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `subdomains`, `certificates`, `malware_iocs` |
| **A** | [**FofaMap (AI Asset Mapping + Gated Nuclei)**](https://github.com/asaotomo/FofaMap) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `certificates` |
| **B** | [**ExternalAttacker-MCP**](https://github.com/MorDavid/ExternalAttacker-MCP) | `ai-agents-mcp-opsec` | 🔴 Active | OSS / Free | `subdomains`, `dns_records`, `open_ports`, `tech_stack` |
| **A** | [**Username Anarchy**](https://github.com/urbanadventurer/username-anarchy) | `username-enumeration` | 🟢 Passive | OSS / Free | `usernames`, `emails` |
| **S** | [**Prowler**](https://github.com/toniblyx/prowler) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `urls`, `secrets`, `metadata` |
| **S** | [**ScoutSuite (NCC Group)**](https://github.com/nccgroup/ScoutSuite) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `open_ports`, `urls`, `entity_graph` |
| **A** | [**Pacu (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/pacu) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `usernames`, `secrets`, `tech_stack` |
| **A** | [**CloudMapper (Duo Labs)**](https://github.com/duo-labs/cloudmapper) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `ip_addresses`, `open_ports`, `entity_graph` |
| **A** | [**haktrails**](https://github.com/hakluke/haktrails) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `whois` |
| **B** | [**OWASP Open Asset Model (OAM)**](https://github.com/owasp-amass/open-asset-model) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **S** | [**BloodHound Community Edition**](https://github.com/SpecterOps/BloodHound) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `entity_graph`, `usernames`, `person_records` |
| **A** | [**Bellingcat EDGAR Search**](https://github.com/bellingcat/edgar) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `documents`, `person_records` |
| **S** | [**Yente (OpenSanctions Self-Hosted API)**](https://github.com/opensanctions/yente) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `sanctions_hits`, `corporate_records`, `entity_graph` |
| **A** | [**CrewAI Multi-Agent Orchestrator**](https://github.com/crewAIInc/crewAI) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |
| **B** | [**SkyArk (Shadow Admin Recon)**](https://github.com/cyberark/SkyArk) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `usernames`, `entity_graph`, `metadata` |

---

## Selector: username
**Username / Handle** (`@johndoe`, gaming alias) — `99` tools (`python3 scripts/osint.py pivot username --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **A** | [**IntelTechniques Search Tools**](https://inteltechniques.com/tools/index.html) | `all-in-one-frameworks` | 🟢 Passive | Free | `social_profiles`, `person_records`, `whois` |
| **A** | [**OSINT Industries**](https://www.osint.industries/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `social_profiles`, `person_records`, `geolocation`, `entity_graph` |
| **A** | [**sn0int**](https://github.com/kpcyrd/sn0int) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses`, `social_profiles`, `breach_records` |
| **B** | [**Harpoon**](https://github.com/Te-k/harpoon) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `dns_records`, `whois`, `open_ports`, `certificates` |
| **B** | [**Operative Framework**](https://github.com/graniet/operative-framework) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `entity_graph` |
| **B** | [**Social Links**](https://sociallinks.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `social_profiles`, `darkweb_mentions`, `corporate_records` |
| **S** | [**Blackbird**](https://github.com/p1ngul1n0/blackbird) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata` |
| **S** | [**Maigret**](https://github.com/soxoj/maigret) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `person_records`, `metadata`, `entity_graph` |
| **S** | [**Sherlock**](https://github.com/sherlock-project/sherlock) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **S** | [**WhatsMyName**](https://whatsmyname.app/) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **A** | [**GoSearch**](https://github.com/ibnaleem/gosearch) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records` |
| **A** | [**Gravatar Hash & Profile Lookup**](https://gravatar.com/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `person_records`, `metadata` |
| **A** | [**Keybase Identity Graph**](https://keybase.io/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `certificates`, `entity_graph` |
| **A** | [**NameMC**](https://namemc.com/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **A** | [**Snoop Project**](https://github.com/snooppr/snoop) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **A** | [**Social Analyzer**](https://github.com/qeeqbox/social-analyzer) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata`, `entity_graph` |
| **A** | [**SocID Extractor**](https://github.com/soxoj/socid-extractor) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata`, `person_records` |
| **A** | [**SteamID.uk / SteamID.io**](https://steamid.io/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **A** | [**user-scanner**](https://github.com/kaifcodec/user-scanner) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `emails` |
| **B** | [**Aliens_eye**](https://github.com/arxhr007/Aliens_eye) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**IDCrawl**](https://www.idcrawl.com/username) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `person_records` |
| **B** | [**Instant Username Search**](https://instantusername.com/) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**KnowEm**](https://knowem.com/) | `username-enumeration` | 🟢 Passive | Freemium | `social_profiles`, `corporate_records` |
| **B** | [**Marple**](https://github.com/soxoj/marple) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**Mr.Holmes**](https://github.com/Lucksi/Mr.Holmes) | `username-enumeration` | 🟡 Hybrid | OSS / Free | `social_profiles`, `whois`, `phones` |
| **B** | [**Namechk**](https://namechk.com/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles` |
| **B** | [**Nexfil**](https://github.com/thewhiteh4t/nexfil) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**socialscan**](https://github.com/iojw/socialscan) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**Tookie-OSINT**](https://github.com/Alfredredbird/tookie-osint) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**Tracker.gg**](https://tracker.gg/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **B** | [**UserSearch.org**](https://usersearch.org/) | `username-enumeration` | 🟢 Passive | Freemium | `social_profiles` |
| **B** | [**XboxGamertag & PSNProfiles**](https://psnprofiles.com/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **S** | [**h8mail**](https://github.com/khast3x/h8mail) | `email-intelligence` | 🟢 Passive | OSS / Free | `breach_records`, `emails`, `social_profiles` |
| **A** | [**GitRecon**](https://github.com/GONZOsint/gitrecon) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `person_records`, `social_profiles` |
| **S** | [**Telegram Native Public Preview (`t.me/s/`)**](https://telegram.org/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `archived_pages`, `metadata` |
| **S** | [**Telepathy**](https://github.com/prose-intelligence-ltd/Telepathy-Community) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `archived_pages`, `metadata` |
| **S** | [**TGStat**](https://tgstat.com/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph`, `metadata` |
| **A** | [**DiscordLookup / Discord.id**](https://discord.id/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **A** | [**Telegago (Official Google CSE)**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `urls` |
| **A** | [**TelegramDB**](https://www.telegramdb.org/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph` |
| **A** | [**Telemetr.io**](https://telemetr.io/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `social_profiles`, `metadata`, `entity_graph` |
| **A** | [**Telethon**](https://github.com/LonamiWebs/Telethon) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles`, `archived_pages`, `metadata` |
| **A** | [**Tosint**](https://github.com/drego85/tosint) | `phone-messaging-osint` | 🔴 Active | OSS / Free | `social_profiles`, `metadata` |
| **B** | [**Awesome Telegram OSINT Toolkit Index**](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**DiscordLeaks (Unicorn Riot)**](https://discordleaks.unicornriot.ninja/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `archived_pages`, `person_records` |
| **B** | [**TGScope**](https://tgscope.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **A** | [**Pipl**](https://pipl.com/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `emails`, `phones`, `social_profiles` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **S** | [**Hudson Rock — Cavalier Free OSINT Tools**](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `malware_iocs`, `tech_stack` |
| **A** | [**LeakCheck**](https://leakcheck.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `emails`, `usernames` |
| **B** | [**BreachDirectory**](https://breachdirectory.org/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records` |
| **B** | [**Constella Intelligence**](https://constella.ai/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `person_records`, `entity_graph` |
| **B** | [**Snusbase**](https://snusbase.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `ip_addresses`, `emails` |
| **A** | [**Nuclei (Exposure & OSINT Templates)**](https://github.com/projectdiscovery/nuclei) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `social_profiles`, `tech_stack`, `secrets` |
| **S** | [**4CAT: Capture and Analysis Toolkit**](https://github.com/digitalmethodsinitiative/4cat) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `archived_pages` |
| **S** | [**Instaloader**](https://instaloader.github.io/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata`, `geolocation`, `archived_pages` |
| **S** | [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **S** | [**PullPush Reddit Archive**](https://search.pullpush.io/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `archived_pages` |
| **S** | [**X (Twitter) Native Advanced Search & Geocode**](https://x.com/search-advanced) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `urls` |
| **A** | [**Arctic Shift (Reddit Archive & Dumps)**](https://arctic-shift.photon-reddit.com/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `archived_pages` |
| **A** | [**ClearSky (Bluesky OSINT)**](https://clearsky.services/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata`, `entity_graph` |
| **A** | [**RedditMetis**](https://redditmetis.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `person_records`, `metadata` |
| **A** | [**Toutatis**](https://github.com/megadose/toutatis) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `emails`, `phones`, `metadata` |
| **A** | [**VK.watch & FindClone / VK OSINT Operators**](https://vk.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `person_records` |
| **A** | [**Xquik**](https://github.com/Xquik-dev/x-twitter-scraper) | `social-media-socmint` | 🟢 Passive | Freemium | `social_profiles`, `entity_graph`, `archived_pages` |
| **A** | [**Yark (YouTube Archiving Made Simple)**](https://github.com/Owez/yark) | `social-media-socmint` | 🟢 Passive | OSS / Free | `archived_pages`, `metadata` |
| **B** | [**Fediverse / Mastodon WebFinger & API Lookup**](https://instances.social/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **B** | [**Osintgram**](https://github.com/Datalux/Osintgram) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `emails`, `geolocation`, `entity_graph` |
| **B** | [**Redective (Reddit Account Detective)**](https://www.redective.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **B** | [**Social Blade**](https://socialblade.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `social_profiles`, `metadata` |
| **B** | [**Social Searcher**](https://www.social-searcher.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `social_profiles`, `urls` |
| **B** | [**Sterra (Instagram Follower Graph Exporter)**](https://github.com/novitae/sterraxcyl) | `social-media-socmint` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph` |
| **S** | [**GH Archive**](https://www.gharchive.org/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `emails`, `archived_pages`, `social_profiles` |
| **S** | [**GitHub Native Code Search & `.patch` Trick**](https://github.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `secrets`, `urls`, `social_profiles` |
| **S** | [**Hugging Face Hub Search (Models, Datasets & Spaces)**](https://huggingface.co/search/full-text) | `code-cloud-dev-osint` | 🟢 Passive | Free | `secrets`, `urls`, `documents` |
| **S** | [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `secrets`, `emails`, `urls` |
| **A** | [**Docker Hub & Layer Inspector (`dive`)**](https://hub.docker.com/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack` |
| **A** | [**PyPI & npm Registry Metadata API**](https://pypi.org/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `person_records`, `metadata` |
| **S** | [**Arkham Intelligence**](https://intel.arkm.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph`, `person_records` |
| **S** | [**Web3.bio Identity Graph**](https://web3.bio/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `usernames` |
| **A** | [**ENS Manager (`app.ens.domains`)**](https://app.ens.domains/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `social_profiles`, `emails`, `tx_graph` |
| **A** | [**keys.openpgp.org & Ubuntu Keyserver**](https://keys.openpgp.org/) | `darkweb-tor-underground` | 🟢 Passive | Free | `emails`, `person_records`, `certificates` |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `open_ports` |
| **A** | [**Clearfront (Self-OSINT & MCP)**](https://github.com/scottmartinanderson/clearfront) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records`, `subdomains`, `entity_graph` |
| **A** | [**OSINT Toolbox MCP**](https://github.com/renkagod/osint-toolbox-mcp) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `phones` |
| **A** | [**Trace Labs OSINT VM**](https://www.tracelabs.org/initiatives/osint-vm) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection`, `person_records` |
| **A** | [**OctoSuite**](https://github.com/rly0nheart/octosuite) | `username-enumeration` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `metadata`, `usernames` |
| **A** | [**smtp-user-enum**](https://github.com/pentestmonkey/smtp-user-enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames` |
| **A** | [**onedrive_user_enum**](https://github.com/nyxgeek/onedrive_user_enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames`, `urls` |
| **S** | [**gallery-dl**](https://github.com/mikf/gallery-dl) | `social-media-socmint` | 🔴 Active | OSS / Free | `archived_pages`, `metadata`, `urls` |
| **A** | [**twscrape**](https://github.com/vladkens/twscrape) | `social-media-socmint` | 🔴 Active | OSS / Free | `social_profiles`, `usernames`, `urls`, `metadata` |
| **A** | [**ATProto SDK & CLI (Bluesky)**](https://github.com/MarshalX/atproto) | `social-media-socmint` | 🟡 Hybrid | OSS / Free | `social_profiles`, `dns_records`, `entity_graph`, `metadata` |
| **S** | [**Nuclei Templates**](https://github.com/projectdiscovery/nuclei-templates) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `tech_stack`, `secrets`, `social_profiles`, `metadata` |
| **A** | [**Pacu (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/pacu) | `code-cloud-dev-osint` | 🔴 Active | OSS / Free | `usernames`, `secrets`, `tech_stack` |
| **A** | [**RSSHub**](https://github.com/DIYgod/RSSHub) | `social-media-socmint` | 🟡 Hybrid | OSS / Free | `social_profiles`, `urls`, `metadata` |

---

## Selector: person_name
**Person Full Name** (Individual, executive, official) — `97` tools (`python3 scripts/osint.py pivot person_name --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**OpenCTI**](https://github.com/OpenCTI-Platform/opencti) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `darkweb_mentions` |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**SearXNG**](https://docs.searxng.org/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `urls`, `documents` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **S** | [**The GDELT Project**](https://www.gdeltproject.org/) | `all-in-one-frameworks` | 🟢 Passive | Free | `documents`, `geolocation`, `entity_graph` |
| **A** | [**Brave Search & Custom OSINT Goggles**](https://search.brave.com/) | `all-in-one-frameworks` | 🟢 Passive | Free | `urls` |
| **A** | [**IntelTechniques Search Tools**](https://inteltechniques.com/tools/index.html) | `all-in-one-frameworks` | 🟢 Passive | Free | `social_profiles`, `person_records`, `whois` |
| **A** | [**OSINT Industries**](https://www.osint.industries/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `social_profiles`, `person_records`, `geolocation`, `entity_graph` |
| **A** | [**OSIRIS**](https://github.com/simplifaisoul/osiris) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `sanctions_hits`, `tx_graph`, `flight_tracks`, `vessel_tracks` |
| **B** | [**Lampyre**](https://lampyre.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `geolocation`, `corporate_records`, `social_profiles` |
| **B** | [**Mojeek**](https://www.mojeek.com/) | `all-in-one-frameworks` | 🟢 Passive | Free | `urls` |
| **B** | [**Operative Framework**](https://github.com/graniet/operative-framework) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `entity_graph` |
| **B** | [**Social Links**](https://sociallinks.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `social_profiles`, `darkweb_mentions`, `corporate_records` |
| **B** | [**IDCrawl**](https://www.idcrawl.com/username) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `person_records` |
| **S** | [**Hunter.io**](https://hunter.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **B** | [**Buster**](https://github.com/sham00n/buster) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `social_profiles`, `breach_records`, `whois` |
| **B** | [**ContactOut**](https://contactout.com/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `phones`, `person_records` |
| **B** | [**RocketReach**](https://rocketreach.co/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `phones`, `person_records`, `corporate_records` |
| **B** | [**Snov.io**](https://snov.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **B** | [**SpyDialer**](https://www.spydialer.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `person_records`, `phones` |
| **S** | [**CourtListener & RECAP Archive**](https://www.courtlistener.com/) | `people-public-records` | 🟢 Passive | OSS / Free | `person_records`, `corporate_records`, `archived_pages` |
| **S** | [**Judyrecords**](https://www.judyrecords.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **S** | [**Lumen Database (Harvard Berkman Klein Center)**](https://lumendatabase.org/) | `people-public-records` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `urls`, `documents` |
| **S** | [**PACER (US Federal Courts)**](https://pacer.uscourts.gov/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `corporate_records` |
| **A** | [**BAILII (British & Irish Legal Information Institute)**](https://www.bailii.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **A** | [**DOJ FARA eFile Search**](https://efile.fara.gov/) | `people-public-records` | 🟢 Passive | Free | `corporate_records`, `person_records`, `archived_pages` |
| **A** | [**FamilySearch**](https://www.familysearch.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation` |
| **A** | [**FastPeopleSearch**](https://www.fastpeoplesearch.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `phones`, `emails`, `geolocation` |
| **A** | [**FEC Individual Contributions Search**](https://www.fec.gov/data/receipts/individual-contributions/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation` |
| **A** | [**FINRA BrokerCheck & SEC IAPD**](https://brokercheck.finra.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records`, `sanctions_hits` |
| **A** | [**INTERPOL Red & Yellow Notices**](https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices) | `people-public-records` | 🟢 Passive | Free | `person_records`, `sanctions_hits` |
| **A** | [**Justia Dockets & Filings**](https://dockets.justia.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **A** | [**LittleSis**](https://littlesis.org/) | `people-public-records` | 🟢 Passive | OSS / Free | `entity_graph`, `person_records`, `corporate_records` |
| **A** | [**Newspapers.com & Chronicling America (LOC)**](https://chroniclingamerica.loc.gov/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `archived_pages` |
| **A** | [**OpenSecrets**](https://www.opensecrets.org/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **A** | [**Pipl**](https://pipl.com/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `emails`, `phones`, `social_profiles` |
| **A** | [**TruePeopleSearch**](https://www.truepeoplesearch.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `phones`, `emails`, `geolocation` |
| **B** | [**Ancestry**](https://www.ancestry.com/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `geolocation` |
| **B** | [**ClustrMaps**](https://clustrmaps.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation`, `corporate_records` |
| **B** | [**Europe's Most Wanted (Europol / ENFAST)**](https://eumostwanted.eu/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `sanctions_hits` |
| **B** | [**FBI Wanted & Kidnappings API**](https://www.fbi.gov/wanted) | `people-public-records` | 🟢 Passive | Free | `person_records`, `sanctions_hits` |
| **B** | [**Find a Grave**](https://www.findagrave.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `geolocation` |
| **B** | [**That'sThem**](https://thatsthem.com/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `phones`, `emails`, `geolocation` |
| **B** | [**UK National Archives — Find Case Law**](https://caselaw.nationalarchives.gov.uk/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records` |
| **B** | [**US Federal Bureau of Prisons (BOP) Locator**](https://www.bop.gov/inmateloc/) | `people-public-records` | 🟢 Passive | Free | `person_records` |
| **B** | [**US NPPES NPI Registry (Healthcare Providers)**](https://npiregistry.cms.hhs.gov/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records`, `phones`, `geolocation` |
| **B** | [**VINELink**](https://vinelink.vineapps.com/) | `people-public-records` | 🟢 Passive | Free | `person_records` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **S** | [**Distributed Denial of Secrets (DDoSecrets)**](https://ddosecrets.com/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **A** | [**WikiLeaks Public Library of US Diplomacy & Leaks**](https://search.wikileaks.org/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **B** | [**Constella Intelligence**](https://constella.ai/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `person_records`, `entity_graph` |
| **B** | [**Mozilla Monitor**](https://monitor.mozilla.org/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `person_records` |
| **B** | [**Snusbase**](https://snusbase.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `ip_addresses`, `emails` |
| **S** | [**Whoxy**](https://www.whoxy.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `whois`, `subdomains`, `emails` |
| **A** | [**ViewDNS.info**](https://viewdns.info/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses` |
| **B** | [**DomainBigData**](https://domainbigdata.com/) | `domain-dns-asm` | 🟢 Passive | Free | `whois`, `emails`, `ip_addresses` |
| **S** | [**Filmot (YouTube Subtitle & Transcript Search)**](https://filmot.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `urls`, `metadata`, `archived_pages` |
| **S** | [**Who Posted What?**](https://whopostedwhat.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `urls`, `archived_pages` |
| **A** | [**VK.watch & FindClone / VK OSINT Operators**](https://vk.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `person_records` |
| **B** | [**Social Searcher**](https://www.social-searcher.com/) | `social-media-socmint` | 🟢 Passive | Freemium | `social_profiles`, `urls` |
| **A** | [**FAA Aircraft Registry (N-Number Inquiry)**](https://registry.faa.gov/aircraftinquiry/) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `person_records`, `flight_tracks` |
| **S** | [**ICIJ Offshore Leaks Database**](https://offshoreleaks.icij.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**OpenCorporates**](https://opencorporates.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**OpenSanctions**](https://www.opensanctions.org/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `sanctions_hits`, `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**Pappers.fr (French Corporate & UBO Intelligence)**](https://www.pappers.fr/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**ProPublica Nonprofit Explorer**](https://projects.propublica.org/nonprofits/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**SEC EDGAR Full-Text Search**](https://www.sec.gov/edgar/searchedgar/companysearch) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**UK Companies House & Overseas Entities Register**](https://find-and-update.company-information.service.gov.uk/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **S** | [**US Treasury OFAC Sanctions List Search**](https://sanctionssearch.ofac.treas.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **A** | [**EU Sanctions Map**](https://www.sanctionsmap.eu/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **A** | [**Google Patents**](https://patents.google.com/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records`, `documents` |
| **A** | [**North Data**](https://www.northdata.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **A** | [**Open Ownership Register**](https://register.openownership.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `entity_graph` |
| **A** | [**SAM.gov (System for Award Management)**](https://sam.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `sanctions_hits`, `emails`, `phones` |
| **A** | [**WIPO Global Brand & PatentScope Databases**](https://branddb.wipo.int/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **A** | [**World Bank Listing of Ineligible (Debarred) Firms & Individuals**](https://www.worldbank.org/en/projects-operations/procurement/debarred-firms) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits`, `corporate_records` |
| **B** | [**Crunchbase**](https://www.crunchbase.com/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `corporate_records`, `person_records`, `entity_graph` |
| **B** | [**OpenInsider (SEC Form 4 Insider Trading Screener)**](http://openinsider.com/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **S** | [**Arkham Intelligence**](https://intel.arkm.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph`, `person_records` |
| **S** | [**DocumentCloud & MuckRock**](https://www.documentcloud.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `person_records`, `corporate_records` |
| **S** | [**OpenAlex**](https://openalex.org/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `person_records`, `entity_graph` |
| **A** | [**Semantic Scholar & arXiv**](https://www.semanticscholar.org/) | `archiving-evidence-docs` | 🟢 Passive | Free | `documents`, `person_records`, `entity_graph` |
| **B** | [**CORE (Open Access Research Aggregator)**](https://core.ac.uk/) | `archiving-evidence-docs` | 🟢 Passive | Freemium | `documents`, `person_records` |
| **B** | [**FOIA.gov (Official US Federal FOIA Portal)**](https://www.foia.gov/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents` |
| **B** | [**WhatDoTheyKnow & AskTheEU**](https://www.whatdotheyknow.com/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `documents`, `corporate_records` |
| **A** | [**Sanctions Screening MCP Server**](https://github.com/cyanheads/sanctions-screening-mcp-server) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `sanctions_hits`, `corporate_records` |
| **A** | [**Sift (Corporate & Financial Cross-Reference MCP)**](https://github.com/mefos-lab/sift) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `corporate_records`, `sanctions_hits`, `entity_graph` |
| **A** | [**Trace Labs OSINT VM**](https://www.tracelabs.org/initiatives/osint-vm) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection`, `person_records` |
| **A** | [**world-intel-mcp**](https://github.com/marc-shade/world-intel-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `geolocation`, `sanctions_hits`, `flight_tracks`, `signal_telemetry` |
| **A** | [**Social Mapper**](https://github.com/Greenwolf/social_mapper) | `username-enumeration` | 🔴 Active | OSS / Free | `social_profiles`, `usernames`, `person_records` |
| **A** | [**Username Anarchy**](https://github.com/urbanadventurer/username-anarchy) | `username-enumeration` | 🟢 Passive | OSS / Free | `usernames`, `emails` |
| **A** | [**Bellingcat EDGAR Search**](https://github.com/bellingcat/edgar) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `documents`, `person_records` |
| **S** | [**Yente (OpenSanctions Self-Hosted API)**](https://github.com/opensanctions/yente) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `sanctions_hits`, `corporate_records`, `entity_graph` |
| **A** | [**CrewAI Multi-Agent Orchestrator**](https://github.com/crewAIInc/crewAI) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |

---

## Selector: email
**Email Address** (`user@company.com`) — `86` tools (`python3 scripts/osint.py pivot email --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**BBOT (Bighuge BLS OSINT Tool)**](https://github.com/blacklanternsecurity/bbot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `open_ports`, `tech_stack` |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**IntelOwl**](https://github.com/intelowlproject/IntelOwl) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `open_ports` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **A** | [**IntelTechniques Search Tools**](https://inteltechniques.com/tools/index.html) | `all-in-one-frameworks` | 🟢 Passive | Free | `social_profiles`, `person_records`, `whois` |
| **A** | [**OSINT Industries**](https://www.osint.industries/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `social_profiles`, `person_records`, `geolocation`, `entity_graph` |
| **A** | [**sn0int**](https://github.com/kpcyrd/sn0int) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses`, `social_profiles`, `breach_records` |
| **A** | [**TheHive Case Management**](https://github.com/StrangeBee/thehive) | `all-in-one-frameworks` | 🟢 Passive | Freemium | `entity_graph`, `malware_iocs` |
| **B** | [**Harpoon**](https://github.com/Te-k/harpoon) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `dns_records`, `whois`, `open_ports`, `certificates` |
| **B** | [**Lampyre**](https://lampyre.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `geolocation`, `corporate_records`, `social_profiles` |
| **B** | [**Operative Framework**](https://github.com/graniet/operative-framework) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `entity_graph` |
| **B** | [**Social Links**](https://sociallinks.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `social_profiles`, `darkweb_mentions`, `corporate_records` |
| **S** | [**Blackbird**](https://github.com/p1ngul1n0/blackbird) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata` |
| **A** | [**Gravatar Hash & Profile Lookup**](https://gravatar.com/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `person_records`, `metadata` |
| **A** | [**user-scanner**](https://github.com/kaifcodec/user-scanner) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles`, `emails` |
| **B** | [**socialscan**](https://github.com/iojw/socialscan) | `username-enumeration` | 🟢 Passive | OSS / Free | `social_profiles` |
| **B** | [**UserSearch.org**](https://usersearch.org/) | `username-enumeration` | 🟢 Passive | Freemium | `social_profiles` |
| **S** | [**Epieos**](https://epieos.com/) | `email-intelligence` | 🟢 Passive | Freemium | `social_profiles`, `person_records`, `geolocation` |
| **S** | [**GHunt**](https://github.com/mxrch/GHunt) | `email-intelligence` | 🟢 Passive | OSS / Free | `person_records`, `social_profiles`, `geolocation`, `metadata` |
| **S** | [**h8mail**](https://github.com/khast3x/h8mail) | `email-intelligence` | 🟢 Passive | OSS / Free | `breach_records`, `emails`, `social_profiles` |
| **S** | [**Holehe**](https://github.com/megadose/holehe) | `email-intelligence` | 🟢 Passive | OSS / Free | `social_profiles`, `metadata` |
| **S** | [**Hunter.io**](https://hunter.io/) | `email-intelligence` | 🟢 Passive | Freemium | `emails`, `person_records` |
| **S** | [**Proton Mail HKP Key Lookup**](https://mail.proton.me/) | `email-intelligence` | 🟢 Passive | Free | `metadata`, `certificates` |
| **A** | [**EmailRep.io**](https://emailrep.io/) | `email-intelligence` | 🟢 Passive | Freemium | `social_profiles`, `breach_records`, `malware_iocs` |
| **A** | [**MailAccess**](https://github.com/KatrielMoses/MailAccess) | `email-intelligence` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records`, `entity_graph` |
| **A** | [**MOSINT**](https://github.com/alpkeskin/mosint) | `email-intelligence` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `emails` |
| **A** | [**Reacher**](https://github.com/reacherhq/check-if-email-exists) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `dns_records` |
| **B** | [**AnalyzeID**](https://analyzeid.com/) | `email-intelligence` | 🟢 Passive | Freemium | `whois`, `entity_graph`, `urls` |
| **B** | [**Buster**](https://github.com/sham00n/buster) | `email-intelligence` | 🟢 Passive | OSS / Free | `emails`, `social_profiles`, `breach_records`, `whois` |
| **B** | [**email2phonenumber**](https://github.com/martinvigo/email2phonenumber) | `email-intelligence` | 🔴 Active | OSS / Free | `phones` |
| **B** | [**Verifalia Email Verifier**](https://verifalia.com/validate-email) | `email-intelligence` | 🔴 Active | Freemium | `emails`, `dns_records` |
| **B** | [**SpyDialer**](https://www.spydialer.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `person_records`, `phones` |
| **A** | [**Pipl**](https://pipl.com/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `emails`, `phones`, `social_profiles` |
| **B** | [**That'sThem**](https://thatsthem.com/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `phones`, `emails`, `geolocation` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **S** | [**Distributed Denial of Secrets (DDoSecrets)**](https://ddosecrets.com/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **S** | [**Have I Been Pwned (HIBP)**](https://haveibeenpwned.com/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records` |
| **S** | [**Hudson Rock — Cavalier Free OSINT Tools**](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `malware_iocs`, `tech_stack` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **A** | [**LeakCheck**](https://leakcheck.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `emails`, `usernames` |
| **A** | [**Psbdmp**](https://psbdmp.ws/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `breach_records`, `archived_pages` |
| **A** | [**SOCRadar Free SOC Tools**](https://socradar.io/labs/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `subdomains`, `malware_iocs` |
| **A** | [**SpyCloud Cybercrime Exposure Check**](https://spycloud.com/check-your-exposure/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `malware_iocs` |
| **A** | [**WikiLeaks Public Library of US Diplomacy & Leaks**](https://search.wikileaks.org/) | `breaches-leaks-stealers` | 🟢 Passive | Free | `corporate_records`, `emails`, `archived_pages` |
| **B** | [**BreachDirectory**](https://breachdirectory.org/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records` |
| **B** | [**Constella Intelligence**](https://constella.ai/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `person_records`, `entity_graph` |
| **B** | [**Mozilla Monitor**](https://monitor.mozilla.org/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `person_records` |
| **B** | [**pwnedOrNot**](https://github.com/thewhiteh4t/pwnedOrNot) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `breach_records` |
| **B** | [**Snusbase**](https://snusbase.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `ip_addresses`, `emails` |
| **B** | [**WhatBreach**](https://github.com/Ekultek/WhatBreach) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `breach_records` |
| **S** | [**SecurityTrails**](https://securitytrails.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `subdomains`, `whois`, `ip_addresses` |
| **S** | [**Whoxy**](https://www.whoxy.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `whois`, `subdomains`, `emails` |
| **A** | [**DomainTools Iris**](https://www.domaintools.com/) | `domain-dns-asm` | 🟢 Passive | Paid | `whois`, `dns_records`, `entity_graph`, `malware_iocs` |
| **A** | [**ViewDNS.info**](https://viewdns.info/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses` |
| **B** | [**DomainBigData**](https://domainbigdata.com/) | `domain-dns-asm` | 🟢 Passive | Free | `whois`, `emails`, `ip_addresses` |
| **A** | [**Netlas.io**](https://netlas.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `certificates`, `whois` |
| **B** | [**Fediverse / Mastodon WebFinger & API Lookup**](https://instances.social/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `metadata` |
| **S** | [**AADInternals / Tenant ID & OpenID Recon**](https://aadinternals.com/osint/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `subdomains`, `corporate_records`, `tech_stack` |
| **S** | [**GH Archive**](https://www.gharchive.org/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `emails`, `archived_pages`, `social_profiles` |
| **A** | [**Sourcegraph Code Search**](https://sourcegraph.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `emails` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**AIL Framework (Analysis Information Leak — CIRCL)**](https://www.ail-project.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `secrets`, `certificates` |
| **A** | [**darknet-mcp-server**](https://github.com/badchars/darknet-mcp-server) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `malware_iocs` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records` |
| **A** | [**Flare Threat Exposure Management**](https://flare.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records`, `secrets` |
| **A** | [**GnuPG (`gpg`) & pgpdump Packet Inspector**](https://gnupg.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `metadata`, `emails`, `certificates`, `person_records` |
| **A** | [**keys.openpgp.org & Ubuntu Keyserver**](https://keys.openpgp.org/) | `darkweb-tor-underground` | 🟢 Passive | Free | `emails`, `person_records`, `certificates` |
| **A** | [**Searchlight Cyber (Cerberus / DarkIQ)**](https://www.slcyber.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `archived_pages`, `certificates` |
| **A** | [**MISP (Open Source Threat Intelligence Platform)**](https://www.misp-project.org/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `open_ports` |
| **A** | [**Clearfront (Self-OSINT & MCP)**](https://github.com/scottmartinanderson/clearfront) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records`, `subdomains`, `entity_graph` |
| **A** | [**OSINT Toolbox MCP**](https://github.com/renkagod/osint-toolbox-mcp) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `phones` |
| **A** | [**SimpleLogin / Proton Pass Email Aliases**](https://simplelogin.io/) | `ai-agents-mcp-opsec` | 🟢 Passive | Freemium | `opsec_protection` |
| **A** | [**Trace Labs OSINT VM**](https://www.tracelabs.org/initiatives/osint-vm) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection`, `person_records` |
| **B** | [**ReconSpider**](https://github.com/bhavsec/reconspider) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `dns_records`, `emails`, `urls` |
| **S** | [**UhOh365**](https://github.com/Raikia/UhOh365) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames`, `metadata` |
| **A** | [**smtp-user-enum**](https://github.com/pentestmonkey/smtp-user-enum) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `usernames` |
| **A** | [**Ruler (SensePost Exchange Recon)**](https://github.com/sensepost/ruler) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `urls`, `tech_stack`, `metadata` |
| **S** | [**ROADtools (Entra ID / Azure AD Recon)**](https://github.com/dirkjanm/ROADtools) | `email-intelligence` | 🔴 Active | OSS / Free | `subdomains`, `emails`, `usernames`, `entity_graph` |
| **A** | [**o365spray**](https://github.com/0xZDH/o365spray) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `tech_stack`, `metadata` |
| **A** | [**GraphRunner**](https://github.com/dafthack/GraphRunner) | `email-intelligence` | 🔴 Active | OSS / Free | `emails`, `documents`, `usernames` |
| **S** | [**Cortex (TheHive Observable Analyzer)**](https://github.com/TheHive-Project/Cortex) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `subdomains` |
| **B** | [**FIR (Fast Incident Response)**](https://github.com/certsocietegenerale/FIR) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `documents`, `malware_iocs` |

---

## Selector: coordinates
**GPS Coordinates / AOI** (`lat, lon` bounding box) — `80` tools (`python3 scripts/osint.py pivot coordinates --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `person_records`, `whois` |
| **S** | [**The GDELT Project**](https://www.gdeltproject.org/) | `all-in-one-frameworks` | 🟢 Passive | Free | `documents`, `geolocation`, `entity_graph` |
| **S** | [**WorldMonitor**](https://github.com/koala73/worldmonitor) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `geolocation`, `signal_telemetry`, `flight_tracks`, `vessel_tracks` |
| **A** | [**ShadowBroker**](https://github.com/BigBodyCobain/Shadowbroker) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `flight_tracks`, `vessel_tracks`, `signal_telemetry`, `geolocation` |
| **S** | [**Worldwide OSINT Tools Map (cipher387)**](https://cipher387.github.io/osintmap/) | `people-public-records` | 🟢 Passive | OSS / Free | `person_records`, `corporate_records`, `geolocation` |
| **S** | [**Shodan**](https://www.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `geolocation` |
| **A** | [**IODA (Internet Outage Detection and Analysis)**](https://ioda.inetintel.cc.gatech.edu/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **S** | [**Snapchat Snap Map**](https://map.snapchat.com/) | `social-media-socmint` | 🟢 Passive | Free | `geolocation`, `urls` |
| **S** | [**Strava Global Heatmap**](https://www.strava.com/maps/global-heatmap) | `social-media-socmint` | 🟢 Passive | Freemium | `geolocation` |
| **S** | [**Who Posted What?**](https://whopostedwhat.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `urls`, `archived_pages` |
| **S** | [**X (Twitter) Native Advanced Search & Geocode**](https://x.com/search-advanced) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `urls` |
| **S** | [**YouTube Metadata & Geofind (MattW)**](https://mattw.io/youtube-metadata/) | `social-media-socmint` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `social_profiles` |
| **A** | [**Bellingcat Instagram Location Search**](https://github.com/bellingcat/instagram-location-search) | `social-media-socmint` | 🟢 Passive | OSS / Free | `geolocation`, `urls` |
| **A** | [**VK.watch & FindClone / VK OSINT Operators**](https://vk.com/) | `social-media-socmint` | 🟢 Passive | Free | `social_profiles`, `geolocation`, `person_records` |
| **S** | [**ACLED (Armed Conflict Location & Event Data)**](https://acleddata.com/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **S** | [**Bellingcat OpenStreetMap Search**](https://osm-search.bellingcat.com/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**Copernicus Data Space Browser**](https://browser.dataspace.copernicus.eu/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation` |
| **S** | [**Esri World Imagery Wayback**](https://livingatlas.arcgis.com/wayback/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation` |
| **S** | [**Google Earth Pro**](https://www.google.com/earth/about/versions/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation` |
| **S** | [**Map Switcher (Browser Extension)**](https://chromewebstore.google.com/detail/map-switcher/fanpjcbgemkfjgpkefdbcdbeebbibhbp) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**Mapillary**](https://www.mapillary.com/app/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**NASA FIRMS (Fire Information for Resource Management System)**](https://firms.modaps.eosdis.nasa.gov/map/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation`, `signal_telemetry` |
| **S** | [**NASA Worldview**](https://worldview.earthdata.nasa.gov/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation` |
| **S** | [**Overpass Turbo (OpenStreetMap Query Engine)**](https://overpass-turbo.eu/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `entity_graph` |
| **S** | [**QGIS**](https://qgis.org/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `satellite_imagery` |
| **S** | [**SunCalc**](https://www.suncalc.org/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation`, `metadata` |
| **S** | [**Wolfram\|Alpha Historical Weather & Astronomy**](https://www.wolframalpha.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `metadata`, `geolocation` |
| **S** | [**Yandex Maps & Street Panoramas**](https://yandex.com/maps/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation`, `satellite_imagery` |
| **A** | [**Baidu Maps & Total View**](https://map.baidu.com/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **A** | [**DeepStateMAP**](https://deepstatemap.live/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation`, `satellite_imagery` |
| **A** | [**earth.nullschool.net (Global Wind, Ocean & Smoke)**](https://earth.nullschool.net/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `signal_telemetry` |
| **A** | [**Global Forest Watch**](https://www.globalforestwatch.org/map/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation` |
| **A** | [**God's Eye View**](https://github.com/bilawalsidhu/gods-eye-view) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `flight_tracks`, `signal_telemetry` |
| **A** | [**KartaView**](https://kartaview.org/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**Liveuamap**](https://liveuamap.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `geolocation`, `urls` |
| **A** | [**MapChecking (Crowd Size Estimator)**](https://www.mapchecking.com/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `metadata` |
| **A** | [**Maxar Open Data Program**](https://www.maxar.com/open-data) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery` |
| **A** | [**OpenAerialMap**](https://map.openaerialmap.org/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation` |
| **A** | [**Overpass Ultra**](https://overpass-ultra.us/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**PeakVisor / PeakFinder**](https://www.peakfinder.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `geolocation` |
| **A** | [**Satellites.pro**](https://satellites.pro/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation` |
| **A** | [**Shadowmap**](https://app.shadowmap.org/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `geolocation` |
| **A** | [**SkyFi**](https://www.skyfi.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `satellite_imagery` |
| **A** | [**USGS EarthExplorer**](https://earthexplorer.usgs.gov/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation` |
| **A** | [**Wikimapia**](https://wikimapia.org/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **A** | [**Zoom Earth**](https://zoom.earth/) | `geoint-maps-satellites` | 🟢 Passive | Free | `satellite_imagery`, `geolocation` |
| **B** | [**Sightline (OSM Infrastructure Search)**](https://github.com/ni5arga/sightline) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**ADS-B Exchange**](https://globe.adsbexchange.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `geolocation` |
| **S** | [**airplanes.live**](https://globe.airplanes.live/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `geolocation` |
| **S** | [**Flightradar24**](https://www.flightradar24.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `flight_tracks`, `geolocation` |
| **S** | [**Global Fishing Watch Map**](https://globalfishingwatch.org/map) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `vessel_tracks`, `satellite_imagery`, `geolocation` |
| **S** | [**GPSJAM**](https://gpsjam.org/) | `aviation-maritime-transport` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **S** | [**MarineTraffic**](https://www.marinetraffic.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation`, `metadata` |
| **A** | [**LiveATC.net**](https://www.liveatc.net/) | `aviation-maritime-transport` | 🟢 Passive | Free | `signal_telemetry`, `archived_pages` |
| **A** | [**MyShipTracking**](https://www.myshiptracking.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation` |
| **A** | [**OpenRailwayMap**](https://www.openrailwaymap.org/) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**The OpenSky Network**](https://opensky-network.org/) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `flight_tracks`, `signal_telemetry` |
| **A** | [**VesselFinder**](https://www.vesselfinder.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation` |
| **B** | [**CruiseMapper & Port Webcams**](https://www.cruisemapper.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `vessel_tracks`, `geolocation` |
| **S** | [**CelesTrak**](https://celestrak.org/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **S** | [**FCC Universal Licensing System (ULS) & FCCID.io**](https://fccid.io/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `corporate_records`, `documents`, `geolocation` |
| **S** | [**KiwiSDR Global Public Receiver Network**](http://kiwisdr.com/public/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |
| **S** | [**OpenCelliD & Unwired Labs**](https://opencellid.org/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **S** | [**TeleGeography Submarine Cable Map**](https://www.submarinecablemap.com/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `geolocation`, `corporate_records` |
| **S** | [**WiGLE (Wireless Geographic Logging Engine)**](https://wigle.net/) | `sigint-wireless-space-rf` | 🟢 Passive | Freemium | `geolocation`, `signal_telemetry` |
| **A** | [**CellMapper**](https://www.cellmapper.net/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **A** | [**Ground Station**](https://github.com/sgoudelis/ground-station) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |
| **A** | [**N2YO Real-Time Satellite Tracking**](https://www.n2yo.com/) | `sigint-wireless-space-rf` | 🟢 Passive | Freemium | `signal_telemetry`, `geolocation` |
| **A** | [**OpenMHz & Broadcastify**](https://openmhz.com/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `archived_pages` |
| **B** | [**aprs.fi (Live Amateur Radio & Weather Telemetry)**](https://aprs.fi/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `signal_telemetry` |
| **B** | [**Data Center Map & PeeringDB Facilities**](https://www.datacentermap.com/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `geolocation`, `corporate_records` |
| **B** | [**PSKReporter & WSPRnet**](https://pskreporter.info/pskmap.html) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **A** | [**satellite-mcp**](https://github.com/badchars/satellite-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation`, `flight_tracks`, `vessel_tracks` |
| **A** | [**world-intel-mcp**](https://github.com/marc-shade/world-intel-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `geolocation`, `sanctions_hits`, `flight_tracks`, `signal_telemetry` |
| **S** | [**Kismet Wireless**](https://github.com/kismetwireless/kismet) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `geolocation`, `metadata` |
| **A** | [**Civilian Harm TimeMap (Bellingcat)**](https://github.com/bellingcat/ukraine-timemap) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `archived_pages`, `metadata` |
| **S** | [**Nominatim (OpenStreetMap Geocoder)**](https://github.com/osm-search/Nominatim) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `metadata` |
| **A** | [**Protomaps PMTiles**](https://github.com/protomaps/PMTiles) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `opsec_protection` |
| **A** | [**CesiumJS 3D Geospatial Engine**](https://github.com/CesiumGS/cesium) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `flight_tracks` |
| **S** | [**tar1090 (ADS-B Historical Track UI)**](https://github.com/wiedehopf/tar1090) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `flight_tracks`, `geolocation`, `signal_telemetry` |

---

## Selector: asn
**ASN / CIDR Netblock** (`AS13335`, `198.51.100.0/24`) — `57` tools (`python3 scripts/osint.py pivot asn --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**BBOT (Bighuge BLS OSINT Tool)**](https://github.com/blacklanternsecurity/bbot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `emails`, `open_ports`, `tech_stack` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **A** | [**IVRE**](https://ivre.rocks/) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `certificates`, `dns_records`, `tech_stack` |
| **A** | [**Osmedeus**](https://github.com/j3ssie/osmedeus) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `open_ports`, `dns_records`, `tech_stack` |
| **B** | [**Harpoon**](https://github.com/Te-k/harpoon) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `dns_records`, `whois`, `open_ports`, `certificates` |
| **A** | [**LeakIX**](https://leakix.net/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `open_ports`, `secrets`, `breach_records`, `tech_stack` |
| **S** | [**OWASP Amass**](https://github.com/owasp-amass/amass) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `subdomains`, `dns_records`, `ip_addresses`, `whois` |
| **A** | [**DNSlytics**](https://dnslytics.com/) | `domain-dns-asm` | 🟢 Passive | Freemium | `dns_records`, `whois`, `ip_addresses`, `entity_graph` |
| **A** | [**tlsx (ProjectDiscovery)**](https://github.com/projectdiscovery/tlsx) | `domain-dns-asm` | 🔴 Active | OSS / Free | `certificates`, `subdomains` |
| **B** | [**Robtex**](https://www.robtex.com/) | `domain-dns-asm` | 🟢 Passive | Free | `dns_records`, `ip_addresses`, `entity_graph` |
| **S** | [**Censys Search**](https://search.censys.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `malware_iocs` |
| **S** | [**FOFA**](https://en.fofa.info/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `ip_addresses` |
| **S** | [**GreyNoise Visualizer**](https://viz.greynoise.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `geolocation` |
| **S** | [**Hurricane Electric BGP Toolkit**](https://bgp.he.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `dns_records`, `entity_graph` |
| **S** | [**IPinfo.io**](https://ipinfo.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `geolocation`, `whois`, `corporate_records` |
| **S** | [**RIPEstat**](https://stat.ripe.net/) | `network-ip-iot-search` | 🟢 Passive | Free | `whois`, `ip_addresses`, `geolocation`, `signal_telemetry` |
| **S** | [**Shodan**](https://www.shodan.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack`, `geolocation` |
| **A** | [**AbuseIPDB**](https://www.abuseipdb.com/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `malware_iocs`, `whois`, `geolocation` |
| **A** | [**asn (Network Recon CLI)**](https://github.com/nitefood/asn) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `whois`, `geolocation` |
| **A** | [**asnmap (ProjectDiscovery)**](https://github.com/projectdiscovery/asnmap) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `whois` |
| **A** | [**BGP.Tools**](https://bgp.tools/) | `network-ip-iot-search` | 🟢 Passive | Free | `ip_addresses`, `whois`, `entity_graph` |
| **A** | [**Cloudflare Radar & URL Scanner**](https://radar.cloudflare.com/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `dns_records`, `certificates`, `tech_stack` |
| **A** | [**IODA (Internet Outage Detection and Analysis)**](https://ioda.inetintel.cc.gatech.edu/) | `network-ip-iot-search` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **A** | [**Metabigor**](https://github.com/j3ssie/metabigor) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**Netlas.io**](https://netlas.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `certificates`, `whois` |
| **A** | [**OONI Explorer (Open Observatory of Network Interference)**](https://explorer.ooni.org/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `signal_telemetry`, `dns_records` |
| **A** | [**PeeringDB**](https://www.peeringdb.com/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `corporate_records`, `geolocation`, `emails` |
| **A** | [**Spamhaus IP & Domain Reputation Checker**](https://check.spamhaus.org/) | `network-ip-iot-search` | 🟢 Passive | Free | `malware_iocs`, `whois` |
| **A** | [**Uncover (ProjectDiscovery)**](https://github.com/projectdiscovery/uncover) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `subdomains` |
| **A** | [**ZoomEye**](https://www.zoomeye.ai/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `tech_stack`, `certificates`, `geolocation` |
| **B** | [**360 Quake Cyberspace Mapping**](https://quake.360.net/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**BinaryEdge**](https://www.binaryedge.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**Censored Planet Observatory**](https://censoredplanet.org/) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `signal_telemetry`, `dns_records` |
| **B** | [**Hunter.how**](https://hunter.how/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `certificates`, `tech_stack` |
| **B** | [**ONYPHE**](https://www.onyphe.io/) | `network-ip-iot-search` | 🟢 Passive | Freemium | `open_ports`, `dns_records`, `malware_iocs` |
| **S** | [**Tor Metrics — Relay & Bridge Search**](https://metrics.torproject.org/rs.html) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `opsec_protection`, `whois`, `signal_telemetry` |
| **S** | [**Silent Push Community Edition**](https://www.silentpush.com/community-edition/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `malware_iocs`, `certificates`, `entity_graph` |
| **S** | [**urlscan.io**](https://urlscan.io/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `tech_stack`, `certificates`, `urls`, `archived_pages` |
| **A** | [**Feodo Tracker (abuse.ch)**](https://feodotracker.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `open_ports` |
| **A** | [**Hunt.io**](https://hunt.io/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `certificates`, `entity_graph` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **A** | [**osint-mcp-server (badchars)**](https://github.com/badchars/osint-mcp-server) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `subdomains`, `dns_records`, `certificates`, `open_ports` |
| **A** | [**ScopeSentry**](https://github.com/Autumn-27/ScopeSentry) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `urls` |
| **A** | [**ARL-Next (Asset Reconnaissance Lighthouse)**](https://github.com/owl234/ARL-Next) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `subdomains`, `open_ports`, `tech_stack`, `certificates` |
| **S** | [**SIPVicious (svmap / svwar)**](https://github.com/EnableSecurity/sipvicious) | `phone-messaging-osint` | 🔴 Active | OSS / Free | `phones`, `open_ports`, `tech_stack`, `metadata` |
| **S** | [**DNSRecon**](https://github.com/darkoperator/dnsrecon) | `domain-dns-asm` | 🔴 Active | OSS / Free | `dns_records`, `subdomains`, `ip_addresses` |
| **S** | [**Masscan**](https://github.com/robertdavidgraham/masscan) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses`, `certificates`, `tech_stack` |
| **S** | [**Naabu (ProjectDiscovery)**](https://github.com/projectdiscovery/naabu) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses` |
| **A** | [**mapcidr**](https://github.com/projectdiscovery/mapcidr) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses` |
| **S** | [**ZMap**](https://github.com/zmap/zmap) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `open_ports`, `ip_addresses` |
| **A** | [**onesixtyone**](https://github.com/trailofbits/onesixtyone) | `network-ip-iot-search` | 🔴 Active | OSS / Free | `tech_stack`, `open_ports`, `metadata` |
| **S** | [**OWASP Nettacker**](https://github.com/OWASP/Nettacker) | `all-in-one-frameworks` | 🔴 Active | OSS / Free | `open_ports`, `subdomains`, `tech_stack`, `urls` |
| **A** | [**hakrevdns**](https://github.com/hakluke/hakrevdns) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `dns_records` |
| **A** | [**hakip2host**](https://github.com/hakluke/hakip2host) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `certificates`, `dns_records` |
| **A** | [**Cero (Go TLS SAN Scraper)**](https://github.com/glebarez/cero) | `domain-dns-asm` | 🔴 Active | OSS / Free | `subdomains`, `certificates` |
| **B** | [**OWASP Open Asset Model (OAM)**](https://github.com/owasp-amass/open-asset-model) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **A** | [**FireHOL Blocklist IPsets**](https://github.com/firehol/blocklist-ipsets) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `ip_addresses` |

---

## Selector: crypto_address
**Crypto Wallet / Tx** (`0x...`, `bc1...`, `.eth`, `T...`) — `47` tools (`python3 scripts/osint.py pivot crypto_address --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Flowsint**](https://github.com/reconurge/flowsint) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `social_profiles`, `whois` |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **A** | [**OSINT Industries**](https://www.osint.industries/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `social_profiles`, `person_records`, `geolocation`, `entity_graph` |
| **A** | [**OSIRIS**](https://github.com/simplifaisoul/osiris) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `sanctions_hits`, `tx_graph`, `flight_tracks`, `vessel_tracks` |
| **A** | [**sn0int**](https://github.com/kpcyrd/sn0int) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses`, `social_profiles`, `breach_records` |
| **B** | [**Social Links**](https://sociallinks.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `social_profiles`, `darkweb_mentions`, `corporate_records` |
| **A** | [**Keybase Identity Graph**](https://keybase.io/) | `username-enumeration` | 🟢 Passive | Free | `social_profiles`, `certificates`, `entity_graph` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **S** | [**grep.app**](https://grep.app/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `subdomains` |
| **S** | [**PublicWWW**](https://publicwww.com/) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `tech_stack`, `entity_graph` |
| **S** | [**OpenSanctions**](https://www.opensanctions.org/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `sanctions_hits`, `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**US Treasury OFAC Sanctions List Search**](https://sanctionssearch.ofac.treas.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **S** | [**Arkham Intelligence**](https://intel.arkm.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph`, `person_records` |
| **S** | [**Breadcrumbs.app**](https://www.breadcrumbs.app/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph` |
| **S** | [**Chainabuse (by TRM Labs)**](https://www.chainabuse.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `malware_iocs`, `breach_records` |
| **S** | [**Etherscan**](https://etherscan.io/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `metadata` |
| **S** | [**GraphSense**](https://graphsense.org/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph`, `entity_graph` |
| **S** | [**mempool.space**](https://mempool.space/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph`, `metadata` |
| **S** | [**TRONSCAN**](https://tronscan.org/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `tx_graph`, `sanctions_hits` |
| **S** | [**Web3.bio Identity Graph**](https://web3.bio/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `social_profiles`, `entity_graph`, `usernames` |
| **A** | [**Blockchair**](https://blockchair.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `metadata` |
| **A** | [**Blockscout**](https://www.blockscout.com/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph`, `metadata` |
| **A** | [**Bubblemaps**](https://bubblemaps.io/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `entity_graph`, `tx_graph` |
| **A** | [**Chainalysis Free Sanctions Screening Oracle**](https://public.chainalysis.com/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `sanctions_hits` |
| **A** | [**DeBank**](https://debank.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `tx_graph`, `social_profiles` |
| **A** | [**DEX Screener**](https://dexscreener.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `tx_graph`, `metadata` |
| **A** | [**Dune**](https://dune.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph` |
| **A** | [**ENS Manager (`app.ens.domains`)**](https://app.ens.domains/) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `social_profiles`, `emails`, `tx_graph` |
| **A** | [**MetaSleuth (BlockSec)**](https://metasleuth.io/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `entity_graph` |
| **A** | [**MistTrack (SlowMist)**](https://misttrack.io/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `sanctions_hits`, `malware_iocs` |
| **A** | [**On-Chain Investigations Tools List (OfficerCIA)**](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph` |
| **A** | [**Solscan**](https://solscan.io/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `metadata` |
| **B** | [**BitcoinAbuse / BitcoinWho'sWho**](https://www.bitcoinwhoswho.com/) | `crypto-blockchain-web3` | 🟢 Passive | Freemium | `tx_graph`, `urls` |
| **B** | [**BitInfoCharts**](https://bitinfocharts.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `tx_graph` |
| **B** | [**GoPlus Security & RugCheck.xyz**](https://gopluslabs.io/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `malware_iocs`, `tx_graph` |
| **B** | [**WalletExplorer.com**](https://www.walletexplorer.com/) | `crypto-blockchain-web3` | 🟢 Passive | Free | `tx_graph`, `entity_graph` |
| **A** | [**darknet-mcp-server**](https://github.com/badchars/darknet-mcp-server) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `malware_iocs` |
| **A** | [**DarkOwl Vision**](https://www.darkowl.com/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `breach_records` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **S** | [**Foundry Cast (`cast`)**](https://github.com/foundry-rs/foundry) | `crypto-blockchain-web3` | 🟡 Hybrid | OSS / Free | `tx_graph`, `metadata`, `secrets` |
| **S** | [**Slither (Trail of Bits)**](https://github.com/crytic/slither) | `crypto-blockchain-web3` | 🟡 Hybrid | OSS / Free | `metadata`, `entity_graph`, `malware_iocs` |
| **A** | [**Cryo (Paradigm)**](https://github.com/paradigmxyz/cryo) | `crypto-blockchain-web3` | 🔴 Active | OSS / Free | `tx_graph`, `metadata` |
| **S** | [**Yente (OpenSanctions Self-Hosted API)**](https://github.com/opensanctions/yente) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `sanctions_hits`, `corporate_records`, `entity_graph` |
| **A** | [**Ethereum ETL**](https://github.com/blockchain-etl/ethereum-etl) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph`, `metadata` |
| **B** | [**Rotki**](https://github.com/rotki/rotki) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `tx_graph`, `metadata` |
| **A** | [**ScamSniffer Drainer Database**](https://github.com/scamsniffer/scam-database) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `malware_iocs`, `sanctions_hits` |
| **A** | [**Echidna (Trail of Bits EVM Analyzer)**](https://github.com/crytic/echidna) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `metadata`, `malware_iocs` |

---

## Selector: document
**Document File** (PDF, DOCX, XLSX, PGP key) — `46` tools (`python3 scripts/osint.py pivot document --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Gephi**](https://gephi.org/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **S** | [**IntelOwl**](https://github.com/intelowlproject/IntelOwl) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `open_ports` |
| **A** | [**Obsidian (Local-First OSINT Case Vault)**](https://obsidian.md/) | `all-in-one-frameworks` | 🟢 Passive | Free | `entity_graph`, `documents` |
| **B** | [**Cytoscape**](https://cytoscape.org/) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph` |
| **S** | [**GHunt**](https://github.com/mxrch/GHunt) | `email-intelligence` | 🟢 Passive | OSS / Free | `person_records`, `social_profiles`, `geolocation`, `metadata` |
| **S** | [**MXToolbox SuperTool**](https://mxtoolbox.com/SuperTool.aspx) | `email-intelligence` | 🟡 Hybrid | Freemium | `dns_records`, `whois`, `tech_stack` |
| **A** | [**Nosey Parker**](https://github.com/praetorian-inc/noseyparker) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `emails` |
| **S** | [**QGIS**](https://qgis.org/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `satellite_imagery` |
| **S** | [**ExifTool**](https://exiftool.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `person_records` |
| **A** | [**GnuPG (`gpg`) & pgpdump Packet Inspector**](https://gnupg.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `metadata`, `emails`, `certificates`, `person_records` |
| **S** | [**Dangerzone (Freedom of the Press Foundation)**](https://dangerzone.rocks/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `opsec_protection`, `documents` |
| **A** | [**PDFiD & pdf-parser (Didier Stevens Suite)**](https://blog.didierstevens.com/programs/pdf-tools/) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `metadata`, `malware_iocs` |
| **S** | [**CyberChef (GCHQ)**](https://gchq.github.io/CyberChef/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `metadata`, `urls`, `emails`, `ip_addresses` |
| **S** | [**Qubes OS**](https://www.qubes-os.org/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**YARA-X (VirusTotal)**](https://github.com/VirusTotal/yara-x) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `secrets`, `metadata` |
| **S** | [**CAPEv2 Malware Sandbox**](https://github.com/kevoreilly/CAPEv2) | `threat-intel-malware-cti` | 🔴 Active | OSS / Free | `malware_iocs`, `ip_addresses`, `urls`, `secrets` |
| **A** | [**Strelka (Target)**](https://github.com/target/strelka) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `metadata`, `certificates`, `urls` |
| **S** | [**detect-secrets (Yelp)**](https://github.com/Yelp/detect-secrets) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `metadata` |
| **B** | [**Credential Detector**](https://github.com/ynori7/credential-detector) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets` |
| **B** | [**Cloudsplaining (Salesforce)**](https://github.com/salesforce/cloudsplaining) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `metadata` |
| **A** | [**Syft (Anchore SBOM Extractor)**](https://github.com/anchore/syft) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**Grype**](https://github.com/anchore/grype) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `malware_iocs`, `tech_stack` |
| **A** | [**Checkov**](https://github.com/bridgecrewio/checkov) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack`, `urls` |
| **S** | [**gf (Grep-Friend Pattern Wrapper)**](https://github.com/tomnomnom/gf) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `secrets`, `urls`, `subdomains` |
| **S** | [**Wireshark / tshark**](https://github.com/wireshark/wireshark) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `dns_records`, `certificates`, `metadata` |
| **S** | [**Zeek Network Security Monitor**](https://github.com/zeek/zeek) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `dns_records`, `certificates`, `urls`, `malware_iocs` |
| **S** | [**Suricata**](https://github.com/OISF/suricata) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `malware_iocs`, `dns_records`, `certificates` |
| **A** | [**Malcolm (CISA Network Traffic Suite)**](https://github.com/cisagov/Malcolm) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `entity_graph`, `dns_records`, `ip_addresses`, `malware_iocs` |
| **B** | [**nDPI (Deep Packet Inspection)**](https://github.com/ntop/nDPI) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `tech_stack`, `metadata`, `ip_addresses` |
| **S** | [**Binwalk**](https://github.com/ReFirmLabs/binwalk) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `secrets`, `documents` |
| **S** | [**oletools (decalage2)**](https://github.com/decalage2/oletools) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `metadata`, `urls`, `person_records`, `malware_iocs` |
| **A** | [**QPDF**](https://github.com/qpdf/qpdf) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `metadata`, `documents` |
| **S** | [**capa (Mandiant Capability Detector)**](https://github.com/mandiant/capa) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `metadata` |
| **S** | [**FLOSS (Mandiant Deobfuscated Strings)**](https://github.com/mandiant/flare-floss) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `urls`, `ip_addresses`, `secrets`, `malware_iocs` |
| **A** | [**Loki IOC & YARA Scanner**](https://github.com/Neo23x0/Loki) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **A** | [**yarGen**](https://github.com/Neo23x0/yarGen) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `metadata` |
| **A** | [**Hayabusa (Yamato Security)**](https://github.com/Yamato-Security/hayabusa) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `ip_addresses`, `usernames`, `malware_iocs` |
| **A** | [**Chainsaw (WithSecure Labs)**](https://github.com/WithSecureLabs/chainsaw) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `ip_addresses`, `usernames`, `urls`, `malware_iocs` |
| **S** | [**Volatility 3**](https://github.com/volatilityfoundation/volatility3) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `ip_addresses`, `open_ports`, `secrets`, `malware_iocs` |
| **S** | [**Velociraptor (Rapid7 / Velocidex)**](https://github.com/Velocidex/velociraptor) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `urls`, `dns_records`, `malware_iocs` |
| **A** | [**OnionShare**](https://github.com/onionshare/onionshare) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `opsec_protection`, `documents` |
| **S** | [**Model Context Protocol Reference Servers**](https://github.com/modelcontextprotocol/servers) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `urls`, `documents`, `metadata` |
| **S** | [**Fabric (Daniel Miessler AI Patterns)**](https://github.com/danielmiessler/fabric) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph`, `metadata` |
| **A** | [**LiteLLM Unified Model Gateway**](https://github.com/BerriAI/litellm) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection`, `metadata` |
| **B** | [**Terrascan**](https://github.com/tenable/terrascan) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `tech_stack`, `secrets`, `open_ports` |
| **A** | [**tfsec**](https://github.com/aquasecurity/tfsec) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack` |

---

## Selector: file_hash
**File / Cert / DOM Hash** (SHA-256, MD5, JARM, mmh3) — `38` tools (`python3 scripts/osint.py pivot file_hash --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**IntelOwl**](https://github.com/intelowlproject/IntelOwl) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `open_ports` |
| **S** | [**OpenCTI**](https://github.com/OpenCTI-Platform/opencti) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `darkweb_mentions` |
| **A** | [**TheHive Case Management**](https://github.com/StrangeBee/thehive) | `all-in-one-frameworks` | 🟢 Passive | Freemium | `entity_graph`, `malware_iocs` |
| **B** | [**Harpoon**](https://github.com/Te-k/harpoon) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `dns_records`, `whois`, `open_ports`, `certificates` |
| **S** | [**Have I Been Pwned (HIBP)**](https://haveibeenpwned.com/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records` |
| **A** | [**Pwned Passwords k-Anonymity API**](https://haveibeenpwned.com/Passwords) | `breaches-leaks-stealers` | 🟢 Passive | OSS / Free | `breach_records` |
| **B** | [**4plebs Archive**](https://archive.4plebs.org/) | `social-media-socmint` | 🟢 Passive | Free | `archived_pages`, `urls` |
| **A** | [**darknet-mcp-server**](https://github.com/badchars/darknet-mcp-server) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `malware_iocs` |
| **S** | [**AlienVault Open Threat Exchange (OTX)**](https://otx.alienvault.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `dns_records`, `urls`, `subdomains` |
| **S** | [**Hatching Tria.ge Sandbox**](https://tria.ge/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `secrets`, `ip_addresses` |
| **S** | [**MalwareBazaar (abuse.ch)**](https://bazaar.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `certificates` |
| **S** | [**Silent Push Community Edition**](https://www.silentpush.com/community-edition/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `malware_iocs`, `certificates`, `entity_graph` |
| **S** | [**ThreatFox (abuse.ch)**](https://threatfox.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs` |
| **S** | [**urlscan.io**](https://urlscan.io/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `tech_stack`, `certificates`, `urls`, `archived_pages` |
| **S** | [**Validin**](https://app.validin.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `dns_records`, `certificates`, `ip_addresses`, `malware_iocs` |
| **S** | [**VirusTotal & VT Graph**](https://www.virustotal.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `certificates`, `entity_graph` |
| **A** | [**ANY.RUN Interactive Malware Sandbox**](https://app.any.run/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records`, `ip_addresses` |
| **A** | [**CIRCL hashlookup (NSRL Known-Good Filter)**](https://hashlookup.circl.lu/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `metadata` |
| **A** | [**Cisco Talos Intelligence Center**](https://talosintelligence.com/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `whois`, `dns_records` |
| **A** | [**Hunt.io**](https://hunt.io/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `open_ports`, `certificates`, `entity_graph` |
| **A** | [**Hybrid Analysis**](https://www.hybrid-analysis.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**Joe Sandbox Cloud Basic**](https://www.joesandbox.com/) | `threat-intel-malware-cti` | 🟢 Passive | Freemium | `malware_iocs`, `dns_records` |
| **A** | [**MISP (Open Source Threat Intelligence Platform)**](https://www.misp-project.org/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph` |
| **A** | [**Pulsedive**](https://pulsedive.com/) | `threat-intel-malware-cti` | 🟡 Hybrid | Freemium | `malware_iocs`, `dns_records`, `whois`, `open_ports` |
| **A** | [**SSLBL (abuse.ch Malicious SSL & JA3 Blacklist)**](https://sslbl.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `certificates`, `malware_iocs` |
| **A** | [**URLhaus (abuse.ch)**](https://urlhaus.abuse.ch/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `urls` |
| **A** | [**YETI (Your Everyday Threat Intelligence)**](https://yeti-platform.io/) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `entity_graph`, `malware_iocs`, `dns_records` |
| **B** | [**ThreatMiner**](https://www.threatminer.org/) | `threat-intel-malware-cti` | 🟢 Passive | Free | `malware_iocs`, `documents`, `dns_records` |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **B** | [**Sputnik OSINT Browser Extension**](https://github.com/mitchmoser/sputnik) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `whois`, `open_ports` |
| **S** | [**YARA-X (VirusTotal)**](https://github.com/VirusTotal/yara-x) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `secrets`, `metadata` |
| **S** | [**Cortex (TheHive Observable Analyzer)**](https://github.com/TheHive-Project/Cortex) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `malware_iocs`, `whois`, `dns_records`, `subdomains` |
| **S** | [**capa (Mandiant Capability Detector)**](https://github.com/mandiant/capa) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `metadata` |
| **A** | [**Loki IOC & YARA Scanner**](https://github.com/Neo23x0/Loki) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **S** | [**Signature-Base (Florian Roth YARA/IOCs)**](https://github.com/Neo23x0/signature-base) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs` |
| **S** | [**Velociraptor (Rapid7 / Velocidex)**](https://github.com/Velocidex/velociraptor) | `threat-intel-malware-cti` | 🟡 Hybrid | OSS / Free | `urls`, `dns_records`, `malware_iocs` |
| **A** | [**vt-py (Official VirusTotal Python SDK)**](https://github.com/VirusTotal/vt-py) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `malware_iocs`, `subdomains`, `dns_records`, `certificates` |
| **B** | [**FIR (Fast Incident Response)**](https://github.com/certsocietegenerale/FIR) | `threat-intel-malware-cti` | 🟢 Passive | OSS / Free | `documents`, `malware_iocs` |

---

## Selector: phone
**Phone Number** (E.164 `+14155552671`) — `38` tools (`python3 scripts/osint.py pivot phone --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Maltego**](https://www.maltego.com/) | `all-in-one-frameworks` | 🟡 Hybrid | Freemium | `entity_graph`, `social_profiles`, `dns_records`, `whois` |
| **S** | [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `entity_graph`, `subdomains`, `emails`, `breach_records` |
| **A** | [**IntelTechniques Search Tools**](https://inteltechniques.com/tools/index.html) | `all-in-one-frameworks` | 🟢 Passive | Free | `social_profiles`, `person_records`, `whois` |
| **A** | [**OSINT Industries**](https://www.osint.industries/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `social_profiles`, `person_records`, `geolocation`, `entity_graph` |
| **A** | [**sn0int**](https://github.com/kpcyrd/sn0int) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `subdomains`, `ip_addresses`, `social_profiles`, `breach_records` |
| **B** | [**Lampyre**](https://lampyre.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `geolocation`, `corporate_records`, `social_profiles` |
| **B** | [**Operative Framework**](https://github.com/graniet/operative-framework) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `entity_graph` |
| **B** | [**Social Links**](https://sociallinks.io/) | `all-in-one-frameworks` | 🟢 Passive | Paid | `entity_graph`, `social_profiles`, `darkweb_mentions`, `corporate_records` |
| **B** | [**Mr.Holmes**](https://github.com/Lucksi/Mr.Holmes) | `username-enumeration` | 🟡 Hybrid | OSS / Free | `social_profiles`, `whois`, `phones` |
| **B** | [**UserSearch.org**](https://usersearch.org/) | `username-enumeration` | 🟢 Passive | Freemium | `social_profiles` |
| **S** | [**Epieos**](https://epieos.com/) | `email-intelligence` | 🟢 Passive | Freemium | `social_profiles`, `person_records`, `geolocation` |
| **S** | [**Google libphonenumber Demo**](https://libphonenumber.appspot.com/) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `phones`, `geolocation` |
| **S** | [**Ignorant**](https://github.com/megadose/ignorant) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles` |
| **S** | [**PhoneInfoga**](https://github.com/sundowndev/phoneinfoga) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `phones`, `geolocation`, `social_profiles` |
| **A** | [**FreeCarrierLookup**](https://freecarrierlookup.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `phones` |
| **A** | [**Telethon**](https://github.com/LonamiWebs/Telethon) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `social_profiles`, `archived_pages`, `metadata` |
| **A** | [**Truecaller Web Lookup**](https://www.truecaller.com/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `person_records`, `phones` |
| **A** | [**Twilio Lookup v2**](https://www.twilio.com/docs/lookup/v2-api) | `phone-messaging-osint` | 🟢 Passive | Paid | `phones`, `person_records` |
| **B** | [**ITU National Numbering Plans**](https://www.itu.int/oth/T0202.aspx?parent=T0202) | `phone-messaging-osint` | 🟢 Passive | Free | `phones`, `geolocation` |
| **B** | [**Numverify API**](https://numverify.com/) | `phone-messaging-osint` | 🟢 Passive | Freemium | `phones`, `geolocation` |
| **B** | [**SearchPhone**](https://github.com/HackUnderway/SearchPhone) | `phone-messaging-osint` | 🟢 Passive | OSS / Free | `phones`, `breach_records`, `social_profiles` |
| **B** | [**SpyDialer**](https://www.spydialer.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `person_records`, `phones` |
| **B** | [**WhatsApp Direct & Business Metadata (`wa.me`)**](https://faq.whatsapp.com/) | `phone-messaging-osint` | 🟢 Passive | Free | `social_profiles`, `metadata`, `geolocation` |
| **A** | [**FastPeopleSearch**](https://www.fastpeoplesearch.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `phones`, `emails`, `geolocation` |
| **A** | [**Pipl**](https://pipl.com/) | `people-public-records` | 🟢 Passive | Paid | `person_records`, `emails`, `phones`, `social_profiles` |
| **A** | [**TruePeopleSearch**](https://www.truepeoplesearch.com/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `phones`, `emails`, `geolocation` |
| **B** | [**That'sThem**](https://thatsthem.com/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `phones`, `emails`, `geolocation` |
| **B** | [**US NPPES NPI Registry (Healthcare Providers)**](https://npiregistry.cms.hhs.gov/) | `people-public-records` | 🟢 Passive | Free | `person_records`, `corporate_records`, `phones`, `geolocation` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **S** | [**Intelligence X (IntelX)**](https://intelx.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `darkweb_mentions`, `emails`, `archived_pages` |
| **A** | [**LeakCheck**](https://leakcheck.io/) | `breaches-leaks-stealers` | 🟢 Passive | Freemium | `breach_records`, `emails`, `usernames` |
| **B** | [**Constella Intelligence**](https://constella.ai/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `person_records`, `entity_graph` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `breach_records`, `dns_records`, `open_ports` |
| **A** | [**OSINT Toolbox MCP**](https://github.com/renkagod/osint-toolbox-mcp) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `phones` |
| **A** | [**Trace Labs OSINT VM**](https://www.tracelabs.org/initiatives/osint-vm) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection`, `person_records` |
| **B** | [**ReconSpider**](https://github.com/bhavsec/reconspider) | `all-in-one-frameworks` | 🟡 Hybrid | OSS / Free | `open_ports`, `dns_records`, `emails`, `urls` |
| **S** | [**SIPVicious (svmap / svwar)**](https://github.com/EnableSecurity/sipvicious) | `phone-messaging-osint` | 🔴 Active | OSS / Free | `phones`, `open_ports`, `tech_stack`, `metadata` |

---

## Selector: image
**Image / Photograph** (JPEG/PNG, face crop, scenery) — `35` tools (`python3 scripts/osint.py pivot image --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **B** | [**4plebs Archive**](https://archive.4plebs.org/) | `social-media-socmint` | 🟢 Passive | Free | `archived_pages`, `urls` |
| **S** | [**Bellingcat ShadowFinder**](https://shadowfinder.bellingcat.com/) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**geo-sleuth**](https://github.com/Oldcircle/geo-sleuth) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `satellite_imagery` |
| **A** | [**GeoHints**](https://geohints.com/) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **A** | [**PeakVisor / PeakFinder**](https://www.peakfinder.com/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `geolocation` |
| **A** | [**Picarta.ai**](https://picarta.ai/) | `geoint-maps-satellites` | 🟢 Passive | Freemium | `geolocation` |
| **A** | [**Plonk It Guide**](https://www.plonkit.net/guide) | `geoint-maps-satellites` | 🟢 Passive | Free | `geolocation` |
| **S** | [**ExifTool**](https://exiftool.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `person_records` |
| **S** | [**Forensically (29a.ch)**](https://29a.ch/photo-forensics/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **S** | [**Google Lens**](https://lens.google.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `geolocation`, `metadata` |
| **S** | [**InVID / WeVerify Verification Plugin**](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `urls` |
| **S** | [**PimEyes**](https://pimeyes.com/) | `image-video-media-forensics` | 🟢 Passive | Paid | `urls`, `person_records` |
| **S** | [**Search by Image (Browser Extension)**](https://github.com/dessant/search-by-image) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `urls` |
| **S** | [**TinEye**](https://tineye.com/) | `image-video-media-forensics` | 🟢 Passive | Freemium | `urls`, `archived_pages` |
| **S** | [**Yandex Reverse Image Search**](https://yandex.com/images/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `geolocation`, `social_profiles` |
| **A** | [**Baidu Image Search (`image.baidu.com`)**](https://image.baidu.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `corporate_records` |
| **A** | [**Bing Visual Search**](https://www.bing.com/visualsearch) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `geolocation` |
| **A** | [**FaceCheck.ID**](https://facecheck.id/) | `image-video-media-forensics` | 🟢 Passive | Paid | `social_profiles`, `urls`, `person_records` |
| **A** | [**Hugin Panorama Stitcher**](https://hugin.sourceforge.io/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**Open Source Munitions Portal & ARES**](https://munitionsportal.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **A** | [**SauceNAO**](https://saucenao.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `urls`, `social_profiles` |
| **A** | [**Search4Faces**](https://search4faces.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `social_profiles`, `person_records` |
| **A** | [**TrueMedia.org Deepfake Detector**](https://www.truemedia.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**Aperi'Solve**](https://www.aperisolve.com/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `secrets` |
| **B** | [**FotoForensics**](https://fotoforensics.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**Jimpl Online EXIF & GPS Viewer**](https://jimpl.com/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata`, `geolocation` |
| **A** | [**Planespotters.net**](https://www.planespotters.net/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `corporate_records`, `metadata` |
| **A** | [**WIPO Global Brand & PatentScope Databases**](https://branddb.wipo.int/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `corporate_records`, `person_records` |
| **S** | [**CyberChef (GCHQ)**](https://gchq.github.io/CyberChef/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `metadata`, `urls`, `emails`, `ip_addresses` |
| **A** | [**Clearfront (Self-OSINT & MCP)**](https://github.com/scottmartinanderson/clearfront) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `social_profiles`, `breach_records`, `subdomains`, `entity_graph` |
| **A** | [**OSINT Toolbox MCP**](https://github.com/renkagod/osint-toolbox-mcp) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `subdomains`, `phones` |
| **A** | [**Social Mapper**](https://github.com/Greenwolf/social_mapper) | `username-enumeration` | 🔴 Active | OSS / Free | `social_profiles`, `usernames`, `person_records` |
| **A** | [**Unredacter (Bishop Fox)**](https://github.com/BishopFox/unredacter) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `secrets` |
| **A** | [**Eyeballer (Bishop Fox)**](https://github.com/BishopFox/eyeballer) | `archiving-evidence-docs` | 🟢 Passive | OSS / Free | `metadata`, `urls` |
| **S** | [**Binwalk**](https://github.com/ReFirmLabs/binwalk) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `secrets`, `documents` |

---

## Selector: repo_code
**Git Repo / Package** (GitHub org/repo, npm/PyPI pkg) — `32` tools (`python3 scripts/osint.py pivot repo_code --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**GH Archive**](https://www.gharchive.org/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `emails`, `archived_pages`, `social_profiles` |
| **S** | [**GitHub Native Code Search & `.patch` Trick**](https://github.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `secrets`, `urls`, `social_profiles` |
| **S** | [**Gitleaks**](https://github.com/gitleaks/gitleaks) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `emails` |
| **S** | [**grep.app**](https://grep.app/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets`, `subdomains` |
| **S** | [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `secrets`, `emails`, `urls` |
| **A** | [**Docker Hub & Layer Inspector (`dive`)**](https://hub.docker.com/) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack` |
| **A** | [**git-hound**](https://github.com/tillson/git-hound) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `urls` |
| **A** | [**Nosey Parker**](https://github.com/praetorian-inc/noseyparker) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `emails` |
| **A** | [**Open Source Insights (deps.dev)**](https://deps.dev/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `entity_graph`, `social_profiles`, `tech_stack` |
| **A** | [**PyPI & npm Registry Metadata API**](https://pypi.org/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `emails`, `person_records`, `metadata` |
| **A** | [**Sourcegraph Code Search**](https://sourcegraph.com/search) | `code-cloud-dev-osint` | 🟢 Passive | Freemium | `urls`, `secrets`, `emails` |
| **B** | [**Gitrob / Shhgit**](https://github.com/eth0izzle/shhgit) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `urls` |
| **B** | [**searchcode**](https://searchcode.com/) | `code-cloud-dev-osint` | 🟢 Passive | Free | `urls`, `secrets` |
| **A** | [**OctoSuite**](https://github.com/rly0nheart/octosuite) | `username-enumeration` | 🟡 Hybrid | OSS / Free | `social_profiles`, `emails`, `metadata`, `usernames` |
| **S** | [**jsluice (Bishop Fox)**](https://github.com/BishopFox/jsluice) | `domain-dns-asm` | 🟡 Hybrid | OSS / Free | `urls`, `secrets`, `subdomains` |
| **S** | [**Slither (Trail of Bits)**](https://github.com/crytic/slither) | `crypto-blockchain-web3` | 🟡 Hybrid | OSS / Free | `metadata`, `entity_graph`, `malware_iocs` |
| **S** | [**detect-secrets (Yelp)**](https://github.com/Yelp/detect-secrets) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `metadata` |
| **A** | [**git-secrets (AWS Labs)**](https://github.com/awslabs/git-secrets) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets` |
| **A** | [**Talisman (Thoughtworks)**](https://github.com/thoughtworks/talisman) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `certificates` |
| **S** | [**KeyHacks**](https://github.com/streaak/keyhacks) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `secrets`, `metadata` |
| **B** | [**Credential Detector**](https://github.com/ynori7/credential-detector) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets` |
| **B** | [**Cloudsplaining (Salesforce)**](https://github.com/salesforce/cloudsplaining) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `metadata` |
| **S** | [**Trivy (Aqua Security)**](https://github.com/aquasecurity/trivy) | `code-cloud-dev-osint` | 🟡 Hybrid | OSS / Free | `tech_stack`, `secrets`, `malware_iocs` |
| **A** | [**Syft (Anchore SBOM Extractor)**](https://github.com/anchore/syft) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `tech_stack`, `metadata` |
| **A** | [**Grype**](https://github.com/anchore/grype) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `malware_iocs`, `tech_stack` |
| **A** | [**Checkov**](https://github.com/bridgecrewio/checkov) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack`, `urls` |
| **S** | [**gf (Grep-Friend Pattern Wrapper)**](https://github.com/tomnomnom/gf) | `domain-dns-asm` | 🟢 Passive | OSS / Free | `secrets`, `urls`, `subdomains` |
| **S** | [**Model Context Protocol Reference Servers**](https://github.com/modelcontextprotocol/servers) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `urls`, `documents`, `metadata` |
| **A** | [**OpenHands Autonomous Agent**](https://github.com/All-Hands-AI/OpenHands) | `ai-agents-mcp-opsec` | 🟡 Hybrid | OSS / Free | `documents`, `entity_graph` |
| **B** | [**Terrascan**](https://github.com/tenable/terrascan) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `tech_stack`, `secrets`, `open_ports` |
| **A** | [**tfsec**](https://github.com/aquasecurity/tfsec) | `code-cloud-dev-osint` | 🟢 Passive | OSS / Free | `secrets`, `tech_stack` |
| **A** | [**Echidna (Trail of Bits EVM Analyzer)**](https://github.com/crytic/echidna) | `crypto-blockchain-web3` | 🟢 Passive | OSS / Free | `metadata`, `malware_iocs` |

---

## Selector: rf_frequency
**RF Frequency (kHz/MHz)** (`8992 kHz` HFGCS, `433.92 MHz`) — `21` tools (`python3 scripts/osint.py pivot rf_frequency --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **A** | [**ShadowBroker**](https://github.com/BigBodyCobain/Shadowbroker) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `flight_tracks`, `vessel_tracks`, `signal_telemetry`, `geolocation` |
| **S** | [**FCC Universal Licensing System (ULS) & FCCID.io**](https://fccid.io/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `corporate_records`, `documents`, `geolocation` |
| **S** | [**KiwiSDR Global Public Receiver Network**](http://kiwisdr.com/public/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |
| **S** | [**SatNOGS (Open Source Satellite Ground Station Network)**](https://network.satnogs.org/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |
| **S** | [**WebSDR.org**](http://www.websdr.org/) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry` |
| **A** | [**Ground Station**](https://github.com/sgoudelis/ground-station) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |
| **A** | [**iNTERCEPT**](https://github.com/smittix/intercept) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `flight_tracks`, `vessel_tracks` |
| **A** | [**rtl_433 (ISM Band Telemetry Decoder)**](https://github.com/merbanan/rtl_433) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |
| **A** | [**SatDump**](https://www.satdump.org/) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `satellite_imagery`, `signal_telemetry` |
| **B** | [**PSKReporter & WSPRnet**](https://pskreporter.info/pskmap.html) | `sigint-wireless-space-rf` | 🟢 Passive | Free | `signal_telemetry`, `geolocation` |
| **B** | [**WireTapper**](https://github.com/h9zdev/WireTapper) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |
| **S** | [**Kismet Wireless**](https://github.com/kismetwireless/kismet) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `geolocation`, `metadata` |
| **S** | [**readsb (1090 MHz ADS-B Decoder)**](https://github.com/wiedehopf/readsb) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `flight_tracks`, `signal_telemetry`, `geolocation` |
| **S** | [**AIS-catcher**](https://github.com/jvde-github/AIS-catcher) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `vessel_tracks`, `signal_telemetry`, `geolocation` |
| **A** | [**Project Ubertooth**](https://github.com/greatscottgadgets/ubertooth) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `metadata` |
| **A** | [**Gqrx SDR**](https://github.com/gqrx-sdr/gqrx) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |
| **A** | [**SigDigger**](https://github.com/BatchDrake/SigDigger) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `metadata` |
| **A** | [**HackRF Suite (Great Scott Gadgets)**](https://github.com/greatscottgadgets/hackrf) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |
| **B** | [**SoapySDR**](https://github.com/pothosware/SoapySDR) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |
| **A** | [**Flipper Zero Official Firmware**](https://github.com/flipperdevices/flipperzero-firmware) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `metadata` |
| **B** | [**bladeRF SDR Suite (Nuand)**](https://github.com/Nuand/bladeRF) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry` |

---

## Selector: vessel_imo
**Vessel IMO / MMSI** (7-digit IMO or 9-digit MMSI) — `18` tools (`python3 scripts/osint.py pivot vessel_imo --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **A** | [**OSIRIS**](https://github.com/simplifaisoul/osiris) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `sanctions_hits`, `tx_graph`, `flight_tracks`, `vessel_tracks` |
| **A** | [**ShadowBroker**](https://github.com/BigBodyCobain/Shadowbroker) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `flight_tracks`, `vessel_tracks`, `signal_telemetry`, `geolocation` |
| **S** | [**Equasis**](https://www.equasis.org/) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `vessel_tracks`, `sanctions_hits` |
| **S** | [**Global Fishing Watch Map**](https://globalfishingwatch.org/map) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `vessel_tracks`, `satellite_imagery`, `geolocation` |
| **S** | [**MarineTraffic**](https://www.marinetraffic.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation`, `metadata` |
| **A** | [**MyShipTracking**](https://www.myshiptracking.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation` |
| **A** | [**Paris MoU & Tokyo MoU Port State Control Databases**](https://www.parismou.org/inspection-search/inspection-search) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `vessel_tracks`, `documents` |
| **A** | [**S&P Panjiva & ImportGenius**](https://panjiva.com/) | `aviation-maritime-transport` | 🟢 Passive | Paid | `corporate_records`, `vessel_tracks`, `entity_graph` |
| **A** | [**VesselFinder**](https://www.vesselfinder.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `vessel_tracks`, `geolocation` |
| **B** | [**ArcNautical Vessel Sanctions Screen**](https://arcnautical.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `sanctions_hits`, `vessel_tracks` |
| **B** | [**CruiseMapper & Port Webcams**](https://www.cruisemapper.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `vessel_tracks`, `geolocation` |
| **B** | [**ITU MARS (Maritime Mobile Access & Retrieval System)**](https://www.itu.int/en/ITU-R/terrestrial/mars/Pages/MARS.aspx) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `signal_telemetry` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `corporate_records`, `person_records`, `documents`, `entity_graph` |
| **S** | [**OpenSanctions**](https://www.opensanctions.org/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `sanctions_hits`, `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**US Treasury OFAC Sanctions List Search**](https://sanctionssearch.ofac.treas.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **A** | [**satellite-mcp**](https://github.com/badchars/satellite-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation`, `flight_tracks`, `vessel_tracks` |
| **S** | [**AIS-catcher**](https://github.com/jvde-github/AIS-catcher) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `vessel_tracks`, `signal_telemetry`, `geolocation` |
| **S** | [**Yente (OpenSanctions Self-Hosted API)**](https://github.com/opensanctions/yente) | `corporate-financial-sanctions` | 🟢 Passive | OSS / Free | `sanctions_hits`, `corporate_records`, `entity_graph` |

---

## Selector: onion_url
**Tor `.onion` Address** (v3 hidden service URL) — `17` tools (`python3 scripts/osint.py pivot onion_url --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Ahmia.fi**](https://ahmia.fi/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `urls` |
| **S** | [**AIL Framework (Analysis Information Leak — CIRCL)**](https://www.ail-project.org/) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `breach_records`, `secrets`, `certificates` |
| **S** | [**deepdarkCTI (fastfire)**](https://github.com/fastfire/deepdarkCTI) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `darkweb_mentions`, `malware_iocs` |
| **A** | [**OnionScan / Onion-Location Deanonymization Checks**](https://github.com/s-rah/onionscan) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `ip_addresses`, `certificates`, `metadata`, `open_ports` |
| **A** | [**Searchlight Cyber (Cerberus / DarkIQ)**](https://www.slcyber.io/) | `darkweb-tor-underground` | 🟢 Passive | Paid | `darkweb_mentions`, `archived_pages`, `certificates` |
| **A** | [**TorBot (OWASP)**](https://github.com/DedSecInside/TorBot) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `emails`, `urls`, `entity_graph` |
| **B** | [**Daunt.link (Signed Tor Mirror Verification)**](https://daunt.link/) | `darkweb-tor-underground` | 🟢 Passive | Free | `certificates`, `opsec_protection` |
| **B** | [**Tor.taxi Signed Darknet Directory**](https://tor.taxi/) | `darkweb-tor-underground` | 🟢 Passive | Free | `urls`, `certificates` |
| **S** | [**Qubes OS**](https://www.qubes-os.org/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Tails OS**](https://tails.net/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Tor Browser**](https://www.torproject.org/download/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **S** | [**Whonix**](https://www.whonix.org/) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `opsec_protection` |
| **A** | [**Onioff**](https://github.com/k4m4/onioff) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `urls`, `metadata` |
| **A** | [**TorCrawl.py**](https://github.com/MikeMeliz/TorCrawl.py) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `archived_pages`, `urls` |
| **A** | [**Ahmia Crawler**](https://github.com/ahmia/ahmia-crawler) | `darkweb-tor-underground` | 🔴 Active | OSS / Free | `darkweb_mentions`, `urls`, `archived_pages` |
| **S** | [**Stem (Tor Controller Python Library)**](https://github.com/torproject/stem) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `ip_addresses`, `darkweb_mentions`, `opsec_protection` |
| **A** | [**OnionShare**](https://github.com/onionshare/onionshare) | `darkweb-tor-underground` | 🟢 Passive | OSS / Free | `opsec_protection`, `documents` |

---

## Selector: aircraft_hex
**Aircraft ICAO Hex / Tail** (Mode-S `AE01D5`, `N123AB`) — `16` tools (`python3 scripts/osint.py pivot aircraft_hex --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **A** | [**OSIRIS**](https://github.com/simplifaisoul/osiris) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `sanctions_hits`, `tx_graph`, `flight_tracks`, `vessel_tracks` |
| **A** | [**ShadowBroker**](https://github.com/BigBodyCobain/Shadowbroker) | `all-in-one-frameworks` | 🟢 Passive | OSS / Free | `flight_tracks`, `vessel_tracks`, `signal_telemetry`, `geolocation` |
| **S** | [**ADS-B Exchange**](https://globe.adsbexchange.com/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `geolocation` |
| **S** | [**airplanes.live**](https://globe.airplanes.live/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `geolocation` |
| **S** | [**Flightradar24**](https://www.flightradar24.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `flight_tracks`, `geolocation` |
| **A** | [**Airframes.io (ACARS / VDL2 Datalink)**](https://app.airframes.io/) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `signal_telemetry`, `flight_tracks` |
| **A** | [**FAA Aircraft Registry (N-Number Inquiry)**](https://registry.faa.gov/aircraftinquiry/) | `aviation-maritime-transport` | 🟢 Passive | Free | `corporate_records`, `person_records`, `flight_tracks` |
| **A** | [**FlightAware**](https://www.flightaware.com/) | `aviation-maritime-transport` | 🟢 Passive | Freemium | `flight_tracks`, `corporate_records` |
| **A** | [**Planespotters.net**](https://www.planespotters.net/) | `aviation-maritime-transport` | 🟢 Passive | Free | `flight_tracks`, `corporate_records`, `metadata` |
| **A** | [**The OpenSky Network**](https://opensky-network.org/) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `flight_tracks`, `signal_telemetry` |
| **S** | [**OpenSanctions**](https://www.opensanctions.org/) | `corporate-financial-sanctions` | 🟢 Passive | Freemium | `sanctions_hits`, `corporate_records`, `person_records`, `entity_graph` |
| **S** | [**US Treasury OFAC Sanctions List Search**](https://sanctionssearch.ofac.treas.gov/) | `corporate-financial-sanctions` | 🟢 Passive | Free | `sanctions_hits` |
| **A** | [**satellite-mcp**](https://github.com/badchars/satellite-mcp) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `satellite_imagery`, `geolocation`, `flight_tracks`, `vessel_tracks` |
| **S** | [**readsb (1090 MHz ADS-B Decoder)**](https://github.com/wiedehopf/readsb) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `flight_tracks`, `signal_telemetry`, `geolocation` |
| **A** | [**CesiumJS 3D Geospatial Engine**](https://github.com/CesiumGS/cesium) | `geoint-maps-satellites` | 🟢 Passive | OSS / Free | `geolocation`, `flight_tracks` |
| **S** | [**tar1090 (ADS-B Historical Track UI)**](https://github.com/wiedehopf/tar1090) | `aviation-maritime-transport` | 🟢 Passive | OSS / Free | `flight_tracks`, `geolocation`, `signal_telemetry` |

---

## Selector: mac_bssid
**Wi-Fi BSSID / BLE MAC** (`00:11:22:33:44:55`) — `11` tools (`python3 scripts/osint.py pivot mac_bssid --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Apple WPS BSSID Geolocation (`bssid-geolocator`)**](https://github.com/acheong08/apple-corelocation-experiments) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**WiGLE (Wireless Geographic Logging Engine)**](https://wigle.net/) | `sigint-wireless-space-rf` | 🟢 Passive | Freemium | `geolocation`, `signal_telemetry` |
| **A** | [**Wireshark IEEE MAC OUI Vendor Lookup**](https://www.wireshark.org/tools/oui-lookup.html) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `metadata`, `corporate_records` |
| **B** | [**WireTapper**](https://github.com/h9zdev/WireTapper) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |
| **S** | [**Kismet Wireless**](https://github.com/kismetwireless/kismet) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `geolocation`, `metadata` |
| **S** | [**bettercap**](https://github.com/bettercap/bettercap) | `sigint-wireless-space-rf` | 🔴 Active | OSS / Free | `signal_telemetry`, `ip_addresses`, `metadata` |
| **S** | [**Aircrack-ng Suite (airodump-ng)**](https://github.com/aircrack-ng/aircrack-ng) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `geolocation`, `metadata` |
| **S** | [**Scapy**](https://github.com/secdev/scapy) | `sigint-wireless-space-rf` | 🔴 Active | OSS / Free | `open_ports`, `signal_telemetry`, `ip_addresses`, `metadata` |
| **A** | [**Project Ubertooth**](https://github.com/greatscottgadgets/ubertooth) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `metadata` |
| **S** | [**Wireshark / tshark**](https://github.com/wireshark/wireshark) | `network-ip-iot-search` | 🟢 Passive | OSS / Free | `ip_addresses`, `dns_records`, `certificates`, `metadata` |
| **A** | [**Flipper Zero Official Firmware**](https://github.com/flipperdevices/flipperzero-firmware) | `sigint-wireless-space-rf` | 🟡 Hybrid | OSS / Free | `signal_telemetry`, `metadata` |

---

## Selector: video
**Video Clip** (MP4, livestream, social upload) — `9` tools (`python3 scripts/osint.py pivot video --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**ExifTool**](https://exiftool.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `person_records` |
| **S** | [**FFmpeg**](https://ffmpeg.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata` |
| **S** | [**InVID / WeVerify Verification Plugin**](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `urls` |
| **A** | [**BirdNET Analyzer**](https://birdnet.cornell.edu/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `geolocation`, `metadata` |
| **A** | [**Hugin Panorama Stitcher**](https://hugin.sourceforge.io/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `geolocation` |
| **A** | [**TrueMedia.org Deepfake Detector**](https://www.truemedia.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**Hiya AI Voice & Audio Deepfake Detector**](https://www.hiya.com/products/deepfake-voice-detector) | `image-video-media-forensics` | 🟢 Passive | Freemium | `metadata` |
| **S** | [**OpenAI Whisper (Local Speech-to-Text)**](https://github.com/openai/whisper) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `documents`, `metadata` |
| **S** | [**Fabric (Daniel Miessler AI Patterns)**](https://github.com/danielmiessler/fabric) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `malware_iocs`, `entity_graph`, `metadata` |

---

## Selector: audio
**Audio Recording** (Voice clip, background birds/hum) — `8` tools (`python3 scripts/osint.py pivot audio --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**ExifTool**](https://exiftool.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `person_records` |
| **S** | [**FFmpeg**](https://ffmpeg.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata` |
| **A** | [**BirdNET Analyzer**](https://birdnet.cornell.edu/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `geolocation`, `metadata` |
| **A** | [**Sonic Visualiser / Audacity Spectrogram Forensics**](https://www.sonicvisualiser.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation` |
| **A** | [**TrueMedia.org Deepfake Detector**](https://www.truemedia.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**Hiya AI Voice & Audio Deepfake Detector**](https://www.hiya.com/products/deepfake-voice-detector) | `image-video-media-forensics` | 🟢 Passive | Freemium | `metadata` |
| **S** | [**OpenAI Whisper (Local Speech-to-Text)**](https://github.com/openai/whisper) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `documents`, `metadata` |
| **A** | [**SigDigger**](https://github.com/BatchDrake/SigDigger) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `metadata` |

---

## Selector: vin
**Vehicle 17-Char VIN** (Automotive chassis number) — `5` tools (`python3 scripts/osint.py pivot vin --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **A** | [**IntelTechniques Search Tools**](https://inteltechniques.com/tools/index.html) | `all-in-one-frameworks` | 🟢 Passive | Free | `social_profiles`, `person_records`, `whois` |
| **B** | [**That'sThem**](https://thatsthem.com/) | `people-public-records` | 🟢 Passive | Freemium | `person_records`, `phones`, `emails`, `geolocation` |
| **S** | [**DeHashed**](https://dehashed.com/) | `breaches-leaks-stealers` | 🟢 Passive | Paid | `breach_records`, `emails`, `ip_addresses`, `usernames` |
| **A** | [**Bidfax / Stat.vin Salvage Auction VIN Archives**](https://en.bidfax.info/) | `aviation-maritime-transport` | 🟢 Passive | Free | `metadata`, `geolocation`, `urls` |
| **A** | [**NHTSA vPIC VIN Decoder & API**](https://vpic.nhtsa.dot.gov/decoder/) | `aviation-maritime-transport` | 🟢 Passive | Free | `metadata`, `corporate_records` |


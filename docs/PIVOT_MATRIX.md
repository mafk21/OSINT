[⬅️ Back to Master Index](../README.md)

# 🧭 OSINT Selector Pivot Matrix (`Input → Tools → Downstream Pivots`)

Real-world investigations start from a **known selector** (an email, handle, phone number, domain, wallet, photo, IMO number, or BSSID) and pivot toward new selectors. Use this matrix—or run `python3 scripts/osint.py pivot <selector> --passive`—to pick your exact next move.

## Summary Selector Index

| Input Selector | Example Artifact | Total Tools | Passive Tools | Top S-Tier Starting Tools | Primary Downstream Outputs |
| :--- | :--- | :---: | :---: | :--- | :--- |
| [`keyword`](#selector-keyword) (Keyword / Phrase) | Project slug, quote, topic | **207** | 201 | [4CAT: Capture and Analysis Toolkit](https://github.com/digitalmethodsinitiative/4cat), [ADS-B Exchange](https://globe.adsbexchange.com/), [Ahmia.fi](https://ahmia.fi/), [AIL Framework (Analysis Information Leak — CIRCL)](https://www.ail-project.org/) | `geolocation`, `corporate_records`, `person_records`, `urls` |
| [`domain`](#selector-domain) (Domain / Hostname) | `example.com` | **172** | 129 | [BuiltWith](https://builtwith.com/), [crt.sh (Certificate Transparency Search)](https://crt.sh/), [DNSDumpster](https://dnsdumpster.com/), [Subfinder](https://github.com/projectdiscovery/subfinder) | `dns_records`, `subdomains`, `malware_iocs`, `whois` |
| [`company`](#selector-company) (Company / Organization) | Corporate name, LEI, CAGE | **110** | 104 | [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/), [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/), [OCCRP Aleph](https://aleph.occrp.org/), [OpenCorporates](https://opencorporates.com/) | `corporate_records`, `person_records`, `entity_graph`, `documents` |
| [`url`](#selector-url) (Web URL / Post Link) | Webpage, social post, phishing URL | **96** | 75 | [ArchiveWeb.page (Webrecorder)](https://archiveweb.page/), [SingleFile](https://github.com/gildas-lormeau/SingleFile), [Wayback Machine (Internet Archive)](https://web.archive.org/), [Hunchly](https://www.hunchly.com/) | `archived_pages`, `metadata`, `urls`, `malware_iocs` |
| [`person_name`](#selector-person-name) (Person Full Name) | Individual, executive, official | **92** | 87 | [CourtListener & RECAP Archive](https://www.courtlistener.com/), [Judyrecords](https://www.judyrecords.com/), [Lumen Database (Harvard Berkman Klein Center)](https://lumendatabase.org/), [PACER (US Federal Courts)](https://pacer.uscourts.gov/) | `person_records`, `corporate_records`, `entity_graph`, `emails` |
| [`username`](#selector-username) (Username / Handle) | `@johndoe`, gaming alias | **90** | 78 | [Blackbird](https://github.com/p1ngul1n0/blackbird), [Maigret](https://github.com/soxoj/maigret), [Sherlock](https://github.com/sherlock-project/sherlock), [WhatsMyName](https://whatsmyname.app/) | `social_profiles`, `metadata`, `entity_graph`, `emails` |
| [`ip`](#selector-ip) (IPv4 / IPv6 Address) | `198.51.100.42` | **84** | 65 | [GreyNoise Visualizer](https://viz.greynoise.io/), [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [IPinfo.io](https://ipinfo.io/), [RIPEstat](https://stat.ripe.net/) | `malware_iocs`, `dns_records`, `open_ports`, `whois` |
| [`email`](#selector-email) (Email Address) | `user@company.com` | **77** | 65 | [Epieos](https://epieos.com/), [h8mail](https://github.com/khast3x/h8mail), [Holehe](https://github.com/megadose/holehe), [Proton Mail HKP Key Lookup](https://mail.proton.me/) | `breach_records`, `social_profiles`, `emails`, `entity_graph` |
| [`coordinates`](#selector-coordinates) (GPS Coordinates / AOI) | `lat, lon` bounding box | **74** | 73 | [Bellingcat OpenStreetMap Search](https://osm-search.bellingcat.com/), [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/), [Esri World Imagery Wayback](https://livingatlas.arcgis.com/wayback/), [Google Earth Pro](https://www.google.com/earth/about/versions/) | `geolocation`, `signal_telemetry`, `satellite_imagery`, `flight_tracks` |
| [`asn`](#selector-asn) (ASN / CIDR Netblock) | `AS13335`, `198.51.100.0/24` | **42** | 35 | [GreyNoise Visualizer](https://viz.greynoise.io/), [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [IPinfo.io](https://ipinfo.io/), [RIPEstat](https://stat.ripe.net/) | `open_ports`, `certificates`, `dns_records`, `whois` |
| [`crypto_address`](#selector-crypto-address) (Crypto Wallet / Tx) | `0x...`, `bc1...`, `.eth`, `T...` | **39** | 36 | [Chainabuse (by TRM Labs)](https://www.chainabuse.com/), [Etherscan](https://etherscan.io/), [GraphSense](https://graphsense.org/), [mempool.space](https://mempool.space/) | `tx_graph`, `entity_graph`, `social_profiles`, `sanctions_hits` |
| [`phone`](#selector-phone) (Phone Number) | E.164 `+14155552671` | **36** | 29 | [Google libphonenumber Demo](https://libphonenumber.appspot.com/), [Ignorant](https://github.com/megadose/ignorant), [PhoneInfoga](https://github.com/sundowndev/phoneinfoga), [FreeCarrierLookup](https://freecarrierlookup.com/) | `social_profiles`, `phones`, `person_records`, `geolocation` |
| [`image`](#selector-image) (Image / Photograph) | JPEG/PNG, face crop, scenery | **31** | 30 | [ExifTool](https://exiftool.org/), [Forensically (29a.ch)](https://29a.ch/photo-forensics/), [Google Lens](https://lens.google.com/), [InVID / WeVerify Verification Plugin](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) | `urls`, `geolocation`, `metadata`, `social_profiles` |
| [`file_hash`](#selector-file-hash) (File / Cert / DOM Hash) | SHA-256, MD5, JARM, mmh3 | **30** | 28 | [AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/), [Hatching Tria.ge Sandbox](https://tria.ge/), [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/), [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | `malware_iocs`, `dns_records`, `entity_graph`, `certificates` |
| [`vessel_imo`](#selector-vessel-imo) (Vessel IMO / MMSI) | 7-digit IMO or 9-digit MMSI | **16** | 16 | [MarineTraffic](https://www.marinetraffic.com/), [Equasis](https://www.equasis.org/), [Global Fishing Watch Map](https://globalfishingwatch.org/map), [MyShipTracking](https://www.myshiptracking.com/) | `vessel_tracks`, `geolocation`, `corporate_records`, `sanctions_hits` |
| [`document`](#selector-document) (Document File) | PDF, DOCX, XLSX, PGP key | **14** | 13 | [Dangerzone (Freedom of the Press Foundation)](https://dangerzone.rocks/), [PDFiD & pdf-parser (Didier Stevens Suite)](https://blog.didierstevens.com/programs/pdf-tools/), [CyberChef (GCHQ)](https://gchq.github.io/CyberChef/), [ExifTool](https://exiftool.org/) | `metadata`, `entity_graph`, `person_records`, `geolocation` |
| [`aircraft_hex`](#selector-aircraft-hex) (Aircraft ICAO Hex / Tail) | Mode-S `AE01D5`, `N123AB` | **13** | 13 | [ADS-B Exchange](https://globe.adsbexchange.com/), [airplanes.live](https://globe.airplanes.live/), [Flightradar24](https://www.flightradar24.com/), [Airframes.io (ACARS / VDL2 Datalink)](https://app.airframes.io/) | `flight_tracks`, `geolocation`, `corporate_records`, `sanctions_hits` |
| [`repo_code`](#selector-repo-code) (Git Repo / Package) | GitHub org/repo, npm/PyPI pkg | **13** | 12 | [GH Archive](https://www.gharchive.org/), [Gitleaks](https://github.com/gitleaks/gitleaks), [grep.app](https://grep.app/), [GitHub Native Code Search & `.patch` Trick](https://github.com/search) | `secrets`, `emails`, `urls`, `social_profiles` |
| [`onion_url`](#selector-onion-url) (Tor `.onion` Address) | v3 hidden service URL | **12** | 10 | [Ahmia.fi](https://ahmia.fi/), [AIL Framework (Analysis Information Leak — CIRCL)](https://www.ail-project.org/), [deepdarkCTI (fastfire)](https://github.com/fastfire/deepdarkCTI), [Searchlight Cyber (Cerberus / DarkIQ)](https://www.slcyber.io/) | `darkweb_mentions`, `certificates`, `opsec_protection`, `urls` |
| [`rf_frequency`](#selector-rf-frequency) (RF Frequency (kHz/MHz)) | `8992 kHz` HFGCS, `433.92 MHz` | **11** | 11 | [FCC Universal Licensing System (ULS) & FCCID.io](https://fccid.io/), [KiwiSDR Global Public Receiver Network](http://kiwisdr.com/public/), [SatNOGS (Open Source Satellite Ground Station Network)](https://network.satnogs.org/), [WebSDR.org](http://www.websdr.org/) | `signal_telemetry`, `geolocation`, `flight_tracks`, `vessel_tracks` |
| [`video`](#selector-video) (Video Clip) | MP4, livestream, social upload | **8** | 8 | [ExifTool](https://exiftool.org/), [FFmpeg](https://ffmpeg.org/), [InVID / WeVerify Verification Plugin](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [BirdNET Analyzer](https://birdnet.cornell.edu/) | `metadata`, `geolocation`, `person_records`, `urls` |
| [`audio`](#selector-audio) (Audio Recording) | Voice clip, background birds/hum | **7** | 7 | [ExifTool](https://exiftool.org/), [FFmpeg](https://ffmpeg.org/), [BirdNET Analyzer](https://birdnet.cornell.edu/), [Sonic Visualiser / Audacity Spectrogram Forensics](https://www.sonicvisualiser.org/) | `metadata`, `geolocation`, `person_records`, `documents` |
| [`vin`](#selector-vin) (Vehicle 17-Char VIN) | Automotive chassis number | **5** | 5 | [Bidfax / Stat.vin Salvage Auction VIN Archives](https://en.bidfax.info/), [NHTSA vPIC VIN Decoder & API](https://vpic.nhtsa.dot.gov/decoder/), [DeHashed](https://dehashed.com/), [That'sThem](https://thatsthem.com/) | `person_records`, `emails`, `geolocation`, `metadata` |
| [`mac_bssid`](#selector-mac-bssid) (Wi-Fi BSSID / BLE MAC) | `00:11:22:33:44:55` | **4** | 4 | [Apple WPS BSSID Geolocation (`bssid-geolocator`)](https://github.com/acheong08/apple-corelocation-experiments), [WiGLE (Wireless Geographic Logging Engine)](https://wigle.net/), [Wireshark IEEE MAC OUI Vendor Lookup](https://www.wireshark.org/tools/oui-lookup.html), [WireTapper](https://github.com/h9zdev/WireTapper) | `geolocation`, `signal_telemetry`, `metadata`, `corporate_records` |

---

## Selector: keyword
**Keyword / Phrase** (Project slug, quote, topic) — `207` tools (`python3 scripts/osint.py pivot keyword --passive`)

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

---

## Selector: domain
**Domain / Hostname** (`example.com`) — `172` tools (`python3 scripts/osint.py pivot domain --passive`)

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

---

## Selector: company
**Company / Organization** (Corporate name, LEI, CAGE) — `110` tools (`python3 scripts/osint.py pivot company --passive`)

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

---

## Selector: url
**Web URL / Post Link** (Webpage, social post, phishing URL) — `96` tools (`python3 scripts/osint.py pivot url --passive`)

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

---

## Selector: person_name
**Person Full Name** (Individual, executive, official) — `92` tools (`python3 scripts/osint.py pivot person_name --passive`)

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

---

## Selector: username
**Username / Handle** (`@johndoe`, gaming alias) — `90` tools (`python3 scripts/osint.py pivot username --passive`)

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

---

## Selector: ip
**IPv4 / IPv6 Address** (`198.51.100.42`) — `84` tools (`python3 scripts/osint.py pivot ip --passive`)

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

---

## Selector: email
**Email Address** (`user@company.com`) — `77` tools (`python3 scripts/osint.py pivot email --passive`)

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

---

## Selector: coordinates
**GPS Coordinates / AOI** (`lat, lon` bounding box) — `74` tools (`python3 scripts/osint.py pivot coordinates --passive`)

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

---

## Selector: asn
**ASN / CIDR Netblock** (`AS13335`, `198.51.100.0/24`) — `42` tools (`python3 scripts/osint.py pivot asn --passive`)

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

---

## Selector: crypto_address
**Crypto Wallet / Tx** (`0x...`, `bc1...`, `.eth`, `T...`) — `39` tools (`python3 scripts/osint.py pivot crypto_address --passive`)

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

---

## Selector: phone
**Phone Number** (E.164 `+14155552671`) — `36` tools (`python3 scripts/osint.py pivot phone --passive`)

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

---

## Selector: image
**Image / Photograph** (JPEG/PNG, face crop, scenery) — `31` tools (`python3 scripts/osint.py pivot image --passive`)

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

---

## Selector: file_hash
**File / Cert / DOM Hash** (SHA-256, MD5, JARM, mmh3) — `30` tools (`python3 scripts/osint.py pivot file_hash --passive`)

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

---

## Selector: vessel_imo
**Vessel IMO / MMSI** (7-digit IMO or 9-digit MMSI) — `16` tools (`python3 scripts/osint.py pivot vessel_imo --passive`)

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

---

## Selector: document
**Document File** (PDF, DOCX, XLSX, PGP key) — `14` tools (`python3 scripts/osint.py pivot document --passive`)

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

---

## Selector: aircraft_hex
**Aircraft ICAO Hex / Tail** (Mode-S `AE01D5`, `N123AB`) — `13` tools (`python3 scripts/osint.py pivot aircraft_hex --passive`)

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

---

## Selector: repo_code
**Git Repo / Package** (GitHub org/repo, npm/PyPI pkg) — `13` tools (`python3 scripts/osint.py pivot repo_code --passive`)

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

---

## Selector: onion_url
**Tor `.onion` Address** (v3 hidden service URL) — `12` tools (`python3 scripts/osint.py pivot onion_url --passive`)

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

---

## Selector: rf_frequency
**RF Frequency (kHz/MHz)** (`8992 kHz` HFGCS, `433.92 MHz`) — `11` tools (`python3 scripts/osint.py pivot rf_frequency --passive`)

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

---

## Selector: video
**Video Clip** (MP4, livestream, social upload) — `8` tools (`python3 scripts/osint.py pivot video --passive`)

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

---

## Selector: audio
**Audio Recording** (Voice clip, background birds/hum) — `7` tools (`python3 scripts/osint.py pivot audio --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**ExifTool**](https://exiftool.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation`, `person_records` |
| **S** | [**FFmpeg**](https://ffmpeg.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata` |
| **A** | [**BirdNET Analyzer**](https://birdnet.cornell.edu/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `geolocation`, `metadata` |
| **A** | [**Sonic Visualiser / Audacity Spectrogram Forensics**](https://www.sonicvisualiser.org/) | `image-video-media-forensics` | 🟢 Passive | OSS / Free | `metadata`, `geolocation` |
| **A** | [**TrueMedia.org Deepfake Detector**](https://www.truemedia.org/) | `image-video-media-forensics` | 🟢 Passive | Free | `metadata` |
| **B** | [**Hiya AI Voice & Audio Deepfake Detector**](https://www.hiya.com/products/deepfake-voice-detector) | `image-video-media-forensics` | 🟢 Passive | Freemium | `metadata` |
| **S** | [**OpenAI Whisper (Local Speech-to-Text)**](https://github.com/openai/whisper) | `ai-agents-mcp-opsec` | 🟢 Passive | OSS / Free | `documents`, `metadata` |

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

---

## Selector: mac_bssid
**Wi-Fi BSSID / BLE MAC** (`00:11:22:33:44:55`) — `4` tools (`python3 scripts/osint.py pivot mac_bssid --passive`)

| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **S** | [**Apple WPS BSSID Geolocation (`bssid-geolocator`)**](https://github.com/acheong08/apple-corelocation-experiments) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `geolocation` |
| **S** | [**WiGLE (Wireless Geographic Logging Engine)**](https://wigle.net/) | `sigint-wireless-space-rf` | 🟢 Passive | Freemium | `geolocation`, `signal_telemetry` |
| **A** | [**Wireshark IEEE MAC OUI Vendor Lookup**](https://www.wireshark.org/tools/oui-lookup.html) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `metadata`, `corporate_records` |
| **B** | [**WireTapper**](https://github.com/h9zdev/WireTapper) | `sigint-wireless-space-rf` | 🟢 Passive | OSS / Free | `signal_telemetry`, `geolocation` |


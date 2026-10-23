<div align="center">

# 🛰️ OSINT MONSTER DATABASE

**Autonomous OSINT Hunting Engine · 760-Tool Intelligence Arsenal · 22 Gated Active Probes · Native MCP & Skills**

![Verified Tools](https://img.shields.io/badge/Verified_Tools-760-00e5ff?style=for-the-badge) ![Passive Safe](https://img.shields.io/badge/Passive_Safe-559-00e676?style=for-the-badge) ![Active & Hybrid](https://img.shields.io/badge/Active_&_Hybrid-201-ff5252?style=for-the-badge) ![Open Source](https://img.shields.io/badge/GitHub_Repos-475-ffab00?style=for-the-badge) ![Disciplines](https://img.shields.io/badge/Disciplines-20-7c4dff?style=for-the-badge)

[**🤖 Agent Protocol**](./AGENTS.md) · [**🧩 Skills Setup**](./docs/SKILLS_SETUP.md) · [**🗂️ Full 760-Tool Index**](./docs/FULL_INDEX.md) · [**🧭 Pivot Matrix**](./docs/PIVOT_MATRIX.md) · [**🗺️ 20 Playbooks**](./docs/WORKFLOWS.md) · [**🎯 105 Dorks**](./docs/DORKS_ARSENAL.md) · [**🪦 2026 Graveyard**](./docs/GRAVEYARD_2026.md) · [**🛡️ OPSEC Guide**](./docs/OPSEC_TRADECRAFT.md)

</div>

---

## ⚡ What's Inside

Unlike flat bookmark lists filled with dead links, **OSINT Monster Database** combines a **strictly validated 760-tool multi-format catalog** (646 keyless/no-auth ready) with a **zero-dependency Python execution engine** (`osint_hunter/`) that AI agents, MCP hosts, and human analysts can run out of the box.

| Capability | Entrypoint | Highlights |
| :--- | :--- | :--- |
| **🧩 Portable Agent Skills** | [`skills/`](./skills/) · [`docs/SKILLS_SETUP.md`](./docs/SKILLS_SETUP.md) | Self-contained `osint-hunter` & `osint-arsenal` skills for **Claude Code, Codex, Claude.ai, Cursor & 75+ agents** (no repo clone needed) |
| **🤖 Multi-Stage Hunter** | [`scripts/hunt.py`](./scripts/hunt.py) · [`osint_hunter/`](./osint_hunter/) | Exhaustive multi-stage surface expansion (`--depth 4..6`), 35+ passive collectors + **22 user-gated active probes**, Exposure Score (`0–100`), standalone **`report.html`**, **`entities.csv`**, Mermaid & **STIX 2.1** |
| **🧬 Forensic Decoders** | [`osint_hunter/offline_intel.py`](./osint_hunter/offline_intel.py) | **Zero-network** chronolocation & checksum decoding: **TikTok video/post UTC**, Discord/X Snowflakes, **UUIDv1/v6/v7**, ULID, MongoDB ObjectId, **IBAN (ISO 13616 + SAMA)**, E.164 (US/UK/GCC/MENA), VIN, ICAO24, IMO/MMSI, MAC/BSSID, JWT & EXIF |
| **🔌 Native MCP Server** | [`.mcp.json`](./.mcp.json) · [`scripts/mcp_server.py`](./scripts/mcp_server.py) | 10 MCP tools (`osint_auto_hunt`, `osint_ingest_and_expand_case`, `osint_forensic_decode`, `osint_compare_cases`, Active Gate) + [`openai_tools.json`](./data/openai_tools.json) |
| **🖥️ Web Command Center** | [`scripts/server.py`](./scripts/server.py) · [`web/`](./web/) | Live Multi-Stage Hunt UI, **Forensic Decoder tab**, Executive Synthesis & Exposure Score, Case Expansion bar, SVG graph, Active Auth Modal & Live Dork Forge |
| **🗃️ Multi-Format Data** | [`data/`](./data/) · [`scripts/osint.py`](./scripts/osint.py) | `tools.json`, **SQLite FTS5** (`osint.sqlite`), `tools.csv`, `tools.jsonl`, `osint.py decode/doctor`, & `pip install -e .` (`pyproject.toml`) |

---

## 🧩 Install as Agent Skills (Claude, Codex, Cursor & 75+ Agents)

Both [**`osint-hunter`**](./skills/osint-hunter/SKILL.md) (autonomous Passive + 22-probe User-Gated Active recon engine) and [**`osint-arsenal`**](./skills/osint-arsenal/SKILL.md) (760-tool pivot, playbook & dork advisor) are **100% self-contained** — install them globally and investigate targets from **any directory** without cloning this repo:

```bash
# Universal Skills CLI (Claude Code, OpenAI Codex, Cursor, OpenCode, Windsurf, Copilot & 75+ agents)
npx skills add mafk21/OSINT -g

# Claude Code Native Plugin Marketplace (run inside Claude Code)
/plugin marketplace add mafk21/OSINT
/plugin install osint-monster@osint-monster

# OpenAI Codex Native $skill-installer (run inside Codex)
$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-hunter
$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-arsenal

# Zero-Node Pure-Python Local Installer (from a local checkout)
python3 scripts/install_skills.py --all
```

- **Claude.ai Web & Claude Desktop Upload**: Download [**`releases/osint-hunter-skill.zip`**](./releases/osint-hunter-skill.zip) and [**`releases/osint-arsenal-skill.zip`**](./releases/osint-arsenal-skill.zip) and upload in **Settings → Capabilities → Skills**. Full guide in [**`docs/SKILLS_SETUP.md`**](./docs/SKILLS_SETUP.md).

---

## 🚀 60-Second Quick Start

*Requires only Python 3.9+ standard library — zero `pip install` needed.*

```bash
# 1. Instant Exhaustive Multi-Stage Passive Hunt (Zero questions · Zero target packets)
python3 scripts/hunt.py "@torvalds, +966501234567, aircraft AE01D5, MMSI 613123456, VIN 5YJ3E1EA7KF317000" --depth 4

# 2. Resume & Expand an Investigation Stage with External Bios/Search Findings + Cross-Case Link Analysis
python3 scripts/hunt.py --resume-case CASE-XXXX --ingest-file stage1_findings.txt
python3 scripts/hunt.py --compare-cases CASE-AAAA CASE-BBBB

# 3. Zero-Network Forensic & Chronolocation Decoder (TikTok UTC, Snowflake, UUIDv1/v7, IBAN, Phone, VIN, MAC)
python3 scripts/osint.py decode "https://www.tiktok.com/@bellingcat/video/7345123456789012485"
python3 scripts/osint.py decode "SA0380000000608010167519"

# 4. Active OSINT Mode (ALWAYS asks permission first via single-use ACT-XXXXXXXX gate)
python3 scripts/hunt.py --prepare-active --from-case CASE-XXXX
python3 scripts/hunt.py "github.com" --active --request-id ACT-XXXXXXXX --user-approved "yes"

# 5. Launch Web Command Center + REST API + Search the Arsenal / Run Environment Doctor
python3 scripts/server.py --port 8000
python3 scripts/osint.py doctor
python3 scripts/osint.py pivot domain --opsec Active --free
python3 scripts/osint.py dorks --engine Shodan --target example.com
```

---

## 🤖 AI Agent Integration: The Three-Law Doctrine

Whether installed via [**`skills/`**](./skills/) or opened directly in this repo ([`AGENTS.md`](./AGENTS.md), [`CLAUDE.md`](./CLAUDE.md), [`.cursorrules`](./.cursorrules), [`.codex-plugin/`](./.codex-plugin/plugin.json), [`.claude-plugin/`](./.claude-plugin/marketplace.json)), connected agents obey three strict laws:

| Law | Agent Behavior | Enforcement & Scope |
| :--- | :--- | :--- |
| **`1. 🟢 Turn-1 Passive Start`** | **Starts hunting immediately on Turn 1 with zero clarifying questions** | Queries 35+ passive APIs & zero-network decoders (GitHub commit/SSH/PGP packet carving, npm/PyPI, DoH, `crt.sh`, RDAP, Wayback, InternetDB, RIPEstat, TikTok/Snowflake/UUIDv1/v7, IBAN, E.164, ICAO24, MMSI/IMO, VIN, OUI, EXIF). **Zero packets hit target servers.** |
| **`2. 🔄 Exhaustive Multi-Stage Convergence`** | **Collects EVERY clue per stage, analyzes ALL findings, and hunts ALL new leads in the next stage** | Powered by [`stage_analyzer.py`](./osint_hunter/stage_analyzer.py) & [`correlator.py`](./osint_hunter/correlator.py): carves handle variants, phones, `wa.me` links, emails, names, orgs & domains across stages until `0` new leads remain (`converged: true`). |
| **`3. 🔴 Hard-Gated Active Mode`** | **ALWAYS asks your permission before every single active run** | Enforced in [`approval.py`](./osint_hunter/approval.py) via **single-use, target-bound `ACT-XXXXXXXX` tokens**. Unlocks **22 built-in live probes** (DNS AXFR, SRV/M365, CNAME takeover, TLS 1.0–1.3, JARM, CORS/WAF, OpenAPI/GraphQL, `.git/HEAD`, JS carver, cloud buckets, 20-port TCP, SSH/SMTP, 16-site handle check) + **201 Active/Hybrid tools**. |

Every hunt writes a gitignored forensic bundle under `cases/<UTC_TIMESTAMP>_<SLUG>/` containing **`dossier.md`** (with Mermaid graph), **`report.html`** (standalone dark-mode executive report + inline SVG), **`report.json`**, **`entities.csv`**, **`graph.json`**, **`graph.mermaid`**, **`stix2_bundle.json`**, and **`manifest.sha256`**.

---

## 📚 20 Intelligence Disciplines

Browse individual manuals below (with CLI `quick_start` commands and `Input → Output` tags) or open the [**Single-Page 760-Tool Directory (`docs/FULL_INDEX.md`)**](./docs/FULL_INDEX.md).

| # | Discipline | Tools | Flagship S-Tier Tools |
| :---: | :--- | :---: | :--- |
| **01** | [🧰 **Frameworks & Link Analysis**](./categories/01-all-in-one-frameworks.md) (`ALL-SOURCE`) | **48** | [BBOT (Bighuge BLS OSINT Tool)](https://github.com/blacklanternsecurity/bbot), [Bellingcat Online Investigation Toolkit](https://bellingcat.gitbook.io/toolkit), [Flowsint](https://github.com/reconurge/flowsint), [Gephi](https://gephi.org/) |
| **02** | [🕵️ **Username & Handle Recon**](./categories/02-username-enumeration.md) (`USERINT`) | **29** | [Blackbird](https://github.com/p1ngul1n0/blackbird), [Maigret](https://github.com/soxoj/maigret), [Sherlock](https://github.com/sherlock-project/sherlock), [WhatsMyName](https://whatsmyname.app/) |
| **03** | [📧 **Email Intelligence**](./categories/03-email-intelligence.md) (`EMAILINT`) | **34** | [Epieos](https://epieos.com/), [GHunt](https://github.com/mxrch/GHunt), [h8mail](https://github.com/khast3x/h8mail), [Holehe](https://github.com/megadose/holehe) |
| **04** | [📱 **Phone & Messaging OSINT**](./categories/04-phone-messaging-osint.md) (`PHONEINT`) | **26** | [Google libphonenumber Demo](https://libphonenumber.appspot.com/), [Ignorant](https://github.com/megadose/ignorant), [PhoneInfoga](https://github.com/sundowndev/phoneinfoga), [Telegram Native Public Preview (`t.me/s/`)](https://telegram.org/) |
| **05** | [🪪 **People & Public Records**](./categories/05-people-public-records.md) (`HUMINT`) | **29** | [CourtListener & RECAP Archive](https://www.courtlistener.com/), [Judyrecords](https://www.judyrecords.com/), [Lumen Database (Harvard Berkman Klein Center)](https://lumendatabase.org/), [PACER (US Federal Courts)](https://pacer.uscourts.gov/) |
| **06** | [🔓 **Breaches & Infostealers**](./categories/06-breaches-leaks-stealers.md) (`BREACHINT`) | **23** | [DeHashed](https://dehashed.com/), [Distributed Denial of Secrets (DDoSecrets)](https://ddosecrets.com/), [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/), [Hudson Rock — Cavalier Free OSINT Tools](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) |
| **07** | [🌐 **Domains, DNS & ASM**](./categories/07-domain-dns-asm.md) (`DNSINT`) | **92** | [BuiltWith](https://builtwith.com/), [crt.sh (Certificate Transparency Search)](https://crt.sh/), [DNSDumpster](https://dnsdumpster.com/), [dnstwist](https://github.com/elceef/dnstwist) |
| **08** | [📡 **Cyberspace & Network Search**](./categories/08-network-ip-iot-search.md) (`NETINT`) | **61** | [Censys Search](https://search.censys.io/), [FOFA](https://en.fofa.info/), [GreyNoise Visualizer](https://viz.greynoise.io/), [Hurricane Electric BGP Toolkit](https://bgp.he.net/) |
| **09** | [💬 **Social Media (SOCMINT)**](./categories/09-social-media-socmint.md) (`SOCMINT`) | **32** | [4CAT: Capture and Analysis Toolkit](https://github.com/digitalmethodsinitiative/4cat), [Filmot (YouTube Subtitle & Transcript Search)](https://filmot.com/), [Instaloader](https://instaloader.github.io/), [Meta Content Library](https://transparency.meta.com/researchtools/meta-content-library) |
| **10** | [💻 **Code, Secrets & Cloud OSINT**](./categories/10-code-cloud-dev-osint.md) (`CODEINT`) | **54** | [AADInternals / Tenant ID & OpenID Recon](https://aadinternals.com/osint/), [cloud_enum](https://github.com/initstring/cloud_enum), [GH Archive](https://www.gharchive.org/), [GitHub Native Code Search & `.patch` Trick](https://github.com/search) |
| **11** | [🛰️ **GEOINT, Maps & Satellites**](./categories/11-geoint-maps-satellites.md) (`GEOINT`) | **42** | [ACLED (Armed Conflict Location & Event Data)](https://acleddata.com/), [Bellingcat OpenStreetMap Search](https://osm-search.bellingcat.com/), [Bellingcat ShadowFinder](https://shadowfinder.bellingcat.com/), [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/) |
| **12** | [🔬 **Image, Video & Media Forensics**](./categories/12-image-video-media-forensics.md) (`IMINT`) | **26** | [ExifTool](https://exiftool.org/), [FFmpeg](https://ffmpeg.org/), [Forensically (29a.ch)](https://29a.ch/photo-forensics/), [Google Lens](https://lens.google.com/) |
| **13** | [✈️ **Aviation, Maritime & Transport**](./categories/13-aviation-maritime-transport.md) (`TRANSINT`) | **27** | [ADS-B Exchange](https://globe.adsbexchange.com/), [airplanes.live](https://globe.airplanes.live/), [Equasis](https://www.equasis.org/), [Flightradar24](https://www.flightradar24.com/) |
| **14** | [🏛️ **Corporate, Finance & Sanctions**](./categories/14-corporate-financial-sanctions.md) (`FININT`) | **27** | [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/), [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/), [OCCRP Aleph](https://aleph.occrp.org/), [OpenCorporates](https://opencorporates.com/) |
| **15** | [⛓️ **Crypto & Blockchain OSINT**](./categories/15-crypto-blockchain-web3.md) (`CRYPTOINT`) | **32** | [Arkham Intelligence](https://intel.arkm.com/), [Breadcrumbs.app](https://www.breadcrumbs.app/), [Chainabuse (by TRM Labs)](https://www.chainabuse.com/), [Etherscan](https://etherscan.io/) |
| **16** | [🧅 **Dark Web & Underground**](./categories/16-darkweb-tor-underground.md) (`DARKINT`) | **27** | [Ahmia.fi](https://ahmia.fi/), [AIL Framework (Analysis Information Leak — CIRCL)](https://www.ail-project.org/), [deepdarkCTI (fastfire)](https://github.com/fastfire/deepdarkCTI), [Ransomware.live (Julien Mousqueton)](https://www.ransomware.live/) |
| **17** | [🛡️ **Threat Intel, Malware & IOCs**](./categories/17-threat-intel-malware-cti.md) (`CTI`) | **48** | [AlienVault Open Threat Exchange (OTX)](https://otx.alienvault.com/), [Hatching Tria.ge Sandbox](https://tria.ge/), [Malpedia (Fraunhofer FKIE)](https://malpedia.caad.fkie.fraunhofer.de/), [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) |
| **18** | [🗄️ **Archiving, Evidence & Docs**](./categories/18-archiving-evidence-docs.md) (`ARCHINT`) | **30** | [archive.today (archive.ph / archive.is)](https://archive.ph/), [ArchiveWeb.page (Webrecorder)](https://archiveweb.page/), [Dangerzone (Freedom of the Press Foundation)](https://dangerzone.rocks/), [DocumentCloud & MuckRock](https://www.documentcloud.org/) |
| **19** | [📻 **SIGINT, Wireless, SDR & Space**](./categories/19-sigint-wireless-space-rf.md) (`SIGINT`) | **34** | [Apple WPS BSSID Geolocation (`bssid-geolocator`)](https://github.com/acheong08/apple-corelocation-experiments), [CelesTrak](https://celestrak.org/), [FCC Universal Licensing System (ULS) & FCCID.io](https://fccid.io/), [KiwiSDR Global Public Receiver Network](http://kiwisdr.com/public/) |
| **20** | [🤖 **AI Agents, MCP & OPSEC**](./categories/20-ai-agents-mcp-opsec.md) (`AI-OPSEC`) | **39** | [CyberChef (GCHQ)](https://gchq.github.io/CyberChef/), [Kasm Workspaces](https://www.kasmweb.com/), [Mitaka](https://github.com/ninoseki/mitaka), [Mullvad Browser](https://mullvad.net/en/browser) |

---

## 🧭 Quick Pivot Cheat Sheet — *"I Have X, Where Do I Start?"*

See all 24 input selectors in [**`docs/PIVOT_MATRIX.md`**](./docs/PIVOT_MATRIX.md) or run `python3 scripts/osint.py pivot <selector> --passive`.

| Starting Selector | Tools | Top Passive Starting Stack | Primary Outputs |
| :--- | :---: | :--- | :--- |
| [**Username / Handle**](./docs/PIVOT_MATRIX.md#selector-username) (`username`) | `99` | [Blackbird](https://github.com/p1ngul1n0/blackbird), [Maigret](https://github.com/soxoj/maigret), [Sherlock](https://github.com/sherlock-project/sherlock) | `social_profiles`, `metadata`, `entity_graph` |
| [**Email Address**](./docs/PIVOT_MATRIX.md#selector-email) (`email`) | `86` | [Epieos](https://epieos.com/), [h8mail](https://github.com/khast3x/h8mail), [Holehe](https://github.com/megadose/holehe) | `emails`, `breach_records`, `social_profiles` |
| [**Phone Number**](./docs/PIVOT_MATRIX.md#selector-phone) (`phone`) | `38` | [Google libphonenumber Demo](https://libphonenumber.appspot.com/), [Ignorant](https://github.com/megadose/ignorant), [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | `social_profiles`, `phones`, `person_records` |
| [**Person Full Name**](./docs/PIVOT_MATRIX.md#selector-person-name) (`person_name`) | `97` | [CourtListener & RECAP Archive](https://www.courtlistener.com/), [Judyrecords](https://www.judyrecords.com/), [Lumen Database (Harvard Berkman Klein Center)](https://lumendatabase.org/) | `person_records`, `corporate_records`, `entity_graph` |
| [**Domain / Hostname**](./docs/PIVOT_MATRIX.md#selector-domain) (`domain`) | `303` | [BuiltWith](https://builtwith.com/), [crt.sh (Certificate Transparency Search)](https://crt.sh/), [DNSDumpster](https://dnsdumpster.com/) | `subdomains`, `urls`, `tech_stack` |
| [**IPv4 / IPv6 Address**](./docs/PIVOT_MATRIX.md#selector-ip) (`ip`) | `148` | [GreyNoise Visualizer](https://viz.greynoise.io/), [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [IPinfo.io](https://ipinfo.io/) | `open_ports`, `tech_stack`, `malware_iocs` |
| [**Image / Photograph**](./docs/PIVOT_MATRIX.md#selector-image) (`image`) | `35` | [Binwalk](https://github.com/ReFirmLabs/binwalk), [ExifTool](https://exiftool.org/), [Forensically (29a.ch)](https://29a.ch/photo-forensics/) | `metadata`, `urls`, `geolocation` |
| [**Company / Organization**](./docs/PIVOT_MATRIX.md#selector-company) (`company`) | `137` | [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/), [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/), [OCCRP Aleph](https://aleph.occrp.org/) | `corporate_records`, `person_records`, `entity_graph` |
| [**Crypto Wallet / Tx**](./docs/PIVOT_MATRIX.md#selector-crypto-address) (`crypto_address`) | `47` | [Chainabuse (by TRM Labs)](https://www.chainabuse.com/), [Etherscan](https://etherscan.io/), [GraphSense](https://graphsense.org/) | `tx_graph`, `entity_graph`, `metadata` |
| [**Vessel IMO / MMSI**](./docs/PIVOT_MATRIX.md#selector-vessel-imo) (`vessel_imo`) | `18` | [MarineTraffic](https://www.marinetraffic.com/), [Equasis](https://www.equasis.org/), [Global Fishing Watch Map](https://globalfishingwatch.org/map) | `vessel_tracks`, `geolocation`, `corporate_records` |
| [**Aircraft ICAO Hex / Tail**](./docs/PIVOT_MATRIX.md#selector-aircraft-hex) (`aircraft_hex`) | `16` | [ADS-B Exchange](https://globe.adsbexchange.com/), [airplanes.live](https://globe.airplanes.live/), [Flightradar24](https://www.flightradar24.com/) | `flight_tracks`, `geolocation`, `signal_telemetry` |
| [**Vehicle 17-Char VIN**](./docs/PIVOT_MATRIX.md#selector-vin) (`vin`) | `5` | [Bidfax / Stat.vin Salvage Auction VIN Archives](https://en.bidfax.info/), [NHTSA vPIC VIN Decoder & API](https://vpic.nhtsa.dot.gov/decoder/), [DeHashed](https://dehashed.com/) | `person_records`, `emails`, `geolocation` |

---

## 🗂️ Repository Layout

```text
OSINT/
├── skills/osint-hunter & skills/osint-arsenal     # Self-contained Agent Skills (Claude, Codex, Cursor & 75+)
├── .claude-plugin/ & .codex-plugin/ & .agents/    # Native Claude Code & OpenAI Codex plugin marketplaces
├── releases/*-skill.zip                           # Drag-and-drop skill zips for Claude.ai & Claude Desktop
├── AGENTS.md / CLAUDE.md / .mcp.json              # Zero-question Passive + User-Gated Active repo manifests
├── osint_hunter/                                  # Autonomous classifier, passive/active collectors & STIX engine
├── scripts/                                       # hunt.py, osint.py, install_skills.py, mcp_server.py, server.py
├── categories/01-*.md .. 20-*.md                  # 20 deep-dive manuals with CLI quick-starts & OPSEC notes
├── docs/                                          # SKILLS_SETUP, FULL_INDEX, PIVOT_MATRIX, WORKFLOWS, DORKS
├── data/                                          # tools.json, schema.json, osint.sqlite (FTS5), tools.csv
└── web/                                           # Zero-build Interactive OSINT Command Center UI
```

---

## 🪦 Critical 2026 Retired / Hijacked Tool Warnings

- ⚠️ **`telegago.com` is hijacked** — use ONLY the [**Official Google CSE Link**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) & [**TGStat**](https://tgstat.com/).
- **Sentinel Hub EO Browser** *(Retired Mar 2026)* → [**Copernicus Data Space Browser**](https://browser.dataspace.copernicus.eu/)
- **GeoSpy (`geospy.ai`)** *(Public web closed Apr 2026)* → [**Picarta**](https://picarta.ai/), [**geo-sleuth**](https://github.com/Oldcircle/geo-sleuth), & [**Bellingcat OSM Search**](https://osm-search.bellingcat.com/)
- **CrowdTangle** / **Pushshift** → [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library), [**Who Posted What?**](https://whopostedwhat.com/), & [**PullPush**](https://search.pullpush.io/) — full list in [**`docs/GRAVEYARD_2026.md`**](./docs/GRAVEYARD_2026.md).

---

## ⚖️ Legal & Ethical Use

Curated strictly for **authorized security assessments, cyber threat intelligence, journalistic verification, academic research, compliance due diligence, and lawful open-source investigations**. Review [**`docs/OPSEC_TRADECRAFT.md`**](./docs/OPSEC_TRADECRAFT.md) before active probing · [**MIT License**](./LICENSE) · [**Contributing**](./CONTRIBUTING.md).

[⬅️ Back to Master Index](../README.md) · [◀ 📻 SIGINT, Wireless, SDR & Space](./19-sigint-wireless-space-rf.md)

# 🤖 20. AI-Powered OSINT Agents, MCP Servers, Browser Extensions & Investigator OPSEC (`AI-OPSEC`)

> **Scope**: Model Context Protocol (MCP) OSINT servers for AI agents, autonomous geolocation & recon skills, context-menu IOC browser extensions, OSINT Linux distributions, and hardened OPSEC/sock-puppet infrastructure.
>
> **OPSEC Advisory**: When connecting LLM agents to MCP OSINT servers, review whether active/noisy tools are disabled by default (e.g. `OpenOSINT` passive mode) and avoid sending sensitive PII to cloud LLM providers without zero-data-retention.

**Discipline Telemetry**: `28` Verified Tools · `11` S-Tier Flagships · `26` Passive · `24` Free/Open-Source

## Subcategories
- [Analyst Decoders & Swiss-Army Knives](#analyst-decoders-swiss-army-knives) (1)
- [Browser Isolation & OSINT Distros](#browser-isolation-osint-distros) (8)
- [OSINT Browser Extensions](#osint-browser-extensions) (3)
- [OPSEC & Fingerprint Hygiene](#opsec-fingerprint-hygiene) (5)
- [AI Audio & Translation Tools](#ai-audio-translation-tools) (1)
- [OSINT MCP Servers & AI Agents](#osint-mcp-servers-ai-agents) (8)
- [Sock Puppet & Identity Compartmentalization](#sock-puppet-identity-compartmentalization) (2)

---

## Analyst Decoders & Swiss-Army Knives

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**CyberChef (GCHQ)**](https://gchq.github.io/CyberChef/) ([GitHub](https://github.com/gchq/CyberChef)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `keyword, document, image` → `metadata, urls, emails` |

### [CyberChef (GCHQ)](https://gchq.github.io/CyberChef/) `[S-Tier]`
- **ID**: `cyberchef` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`gchq/CyberChef`](https://github.com/gchq/CyberChef)
- **Inputs**: `keyword`, `document`, `image` → **Outputs**: `metadata`, `urls`, `emails`, `ip_addresses`
- **Platforms**: Web, Docker · **Tags**: `gchq`, `client-side`, `decoder`, `regex-extractor`, `unix-timestamps`, `flagship`
- **Overview**: GCHQ's client-side 'Cyber Swiss Army Knife' executing 300+ chained operations in browser RAM—Base64/Hex/Protobuf decoding, AES/XOR decryption, regex IP/URL/email extraction, defanging, EXIF parsing, and timestamps.
- **Quick-Start / Tradecraft**: `Download the standalone release zip from `gchq/CyberChef` to run 100% offline with zero network egress!`

---

## Browser Isolation & OSINT Distros

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Kasm Workspaces**](https://www.kasmweb.com/) ([GitHub](https://github.com/kasmtech/workspaces_images)) | Framework | Freemium | 🟢 Passive | ✅ | `url` → `opsec_protection` |
| **S** | [**Qubes OS**](https://www.qubes-os.org/) ([GitHub](https://github.com/QubesOS/qubes-secpack)) | OS / Distro | OSS / Free | 🟢 Passive | ✅ | `document, onion_url, url` → `opsec_protection` |
| **S** | [**Tails OS**](https://tails.net/) | OS / Distro | OSS / Free | 🟢 Passive | ✅ | `onion_url, url` → `opsec_protection` |
| **S** | [**Tor Browser**](https://www.torproject.org/download/) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `onion_url, url` → `opsec_protection` |
| **S** | [**Whonix**](https://www.whonix.org/) ([GitHub](https://github.com/Whonix/Whonix)) | OS / Distro | OSS / Free | 🟢 Passive | ✅ | `onion_url, url` → `opsec_protection` |
| **A** | [**Trace Labs OSINT VM**](https://www.tracelabs.org/initiatives/osint-vm) ([GitHub](https://github.com/tracelabs/tlosint-vm)) | OS / Distro | OSS / Free | 🟢 Passive | ✅ | `person_name, username, email` → `opsec_protection, person_records` |
| **B** | [**CSI Linux**](https://csilinux.com/) | OS / Distro | Free | 🟢 Passive | ✅ | `keyword` → `opsec_protection` |
| **B** | [**Tsurugi Linux**](https://tsurugi-linux.org/) | OS / Distro | Free | 🟢 Passive | ✅ | `keyword` → `opsec_protection` |

### [Kasm Workspaces](https://www.kasmweb.com/) `[S-Tier]`
- **ID**: `kasm-workspaces` · **Type**: `Framework` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`kasmtech/workspaces_images`](https://github.com/kasmtech/workspaces_images)
- **Inputs**: `url` → **Outputs**: `opsec_protection`
- **Platforms**: Docker, Linux, Web · **Tags**: `browser-isolation`, `disposable-containers`, `burn-after-reading`, `opsec`, `flagship`
- **Overview**: Containerized streaming browser and Linux desktop isolation platform—spin up disposable, ephemeral Tor Browser, Mullvad, Maltego, or Trace Labs containers inside your browser and nuke them after every case!
- **Quick-Start / Tradecraft**: `Self-host Kasm Community Edition on a remote VPS so target servers only ever see disposable container fingerprints & VPN exit IPs.`

### [Qubes OS](https://www.qubes-os.org/) `[S-Tier]`
- **ID**: `qubes-os` · **Type**: `OS / Distro` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`QubesOS/qubes-secpack`](https://github.com/QubesOS/qubes-secpack)
- **Inputs**: `document`, `onion_url`, `url` → **Outputs**: `opsec_protection`
- **Platforms**: Linux · **Tags**: `xen-hypervisor`, `disposable-vms`, `compartmentalization`, `gold-standard-opsec`
- **Overview**: Xen-hypervisor 'security through compartmentalization' desktop OS running separate hardware-isolated AppVMs and single-use DisposableVMs (`dispXXXX`) for untrusted files, sock puppets, and Whonix Tor routing.
- **Quick-Start / Tradecraft**: `Open every suspect attachment or hostile webpage inside an ephemeral `whonix-ws-17-dvm` Disposable Qube!`

### [Tails OS](https://tails.net/) `[S-Tier]`
- **ID**: `tails-os` · **Type**: `OS / Distro` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `onion_url`, `url` → **Outputs**: `opsec_protection`
- **Platforms**: Linux · **Tags**: `amnesic-os`, `live-usb`, `tor-project`, `journalist-opsec`
- **Overview**: Amnesic live USB operating system routing all connections through Tor and wiping RAM clean on shutdown, leaving zero forensic trace on the host computer.
- **Quick-Start / Tradecraft**: `Boot from USB in field environments; store case encryption keys only inside an optional LUKS-encrypted Persistent Storage volume.`

### [Tor Browser](https://www.torproject.org/download/) `[S-Tier]`
- **ID**: `tor-browser` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `onion_url`, `url` → **Outputs**: `opsec_protection`
- **Platforms**: Windows, macOS, Linux · **Tags**: `tor-project`, `onion-routing`, `safest-mode-no-js`, `anonymity`, `flagship`
- **Overview**: Official onion-routed anti-fingerprinting browser from The Tor Project—mandatory for accessing `.onion` services and compartmentalizing anonymity-critical research.
- **Quick-Start / Tradecraft**: `Switch Security Level to 'Safest' (disables JavaScript & WebAssembly) BEFORE opening any untrusted `.onion` URL!`

### [Whonix](https://www.whonix.org/) `[S-Tier]`
- **ID**: `whonix` · **Type**: `OS / Distro` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Whonix/Whonix`](https://github.com/Whonix/Whonix)
- **Inputs**: `onion_url`, `url` → **Outputs**: `opsec_protection`
- **Platforms**: Linux, Windows, macOS · **Tags**: `tor-isolation`, `zero-ip-leak`, `two-vm-architecture`, `darkweb-opsec`, `flagship`
- **Overview**: Two-VM security operating system (Gateway + Workstation) enforcing total Tor network isolation at the hypervisor level—making accidental real-IP DNS or WebRTC leaks structurally impossible even under malware compromise.
- **Quick-Start / Tradecraft**: `Run Whonix inside VirtualBox, KVM, or Qubes OS (`anon-whonix`) for all high-risk darknet and adversary infrastructure research.`

### [Trace Labs OSINT VM](https://www.tracelabs.org/initiatives/osint-vm) `[A-Tier]`
- **ID**: `trace-labs-osint-vm` · **Type**: `OS / Distro` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tracelabs/tlosint-vm`](https://github.com/tracelabs/tlosint-vm)
- **Inputs**: `person_name`, `username`, `email`, `phone` → **Outputs**: `opsec_protection`, `person_records`
- **Platforms**: Linux · **Tags**: `trace-labs`, `missing-persons-osint`, `kali-vm`, `preconfigured-lab`
- **Overview**: Kali Linux-based virtual machine curated by non-profit missing-persons organization Trace Labs—preloaded with Maigret, Sherlock, Holehe, SpiderFoot, GHunt, ExifTool, and hardened Firefox bookmarks.
- **Quick-Start / Tradecraft**: `Import the official `.ova` appliance into VirtualBox/VMware for an instant ready-to-run OSINT workstation.`

### [CSI Linux](https://csilinux.com/) `[B-Tier]`
- **ID**: `csi-linux` · **Type**: `OS / Distro` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `opsec_protection`
- **Platforms**: Linux · **Tags**: `cyber-investigation-os`, `case-management`, `whonix-routing`, `dfir`
- **Overview**: Purpose-built Ubuntu-based cyber-investigation distribution integrating Case Management, Tor/Whonix gateway routing, social/darkweb OSINT tools, and computer forensics utilities.
- **Quick-Start / Tradecraft**: `Deploy CSI Linux VM appliance when requiring integrated case-folder hashing and Tor gateway toggles.`

### [Tsurugi Linux](https://tsurugi-linux.org/) `[B-Tier]`
- **ID**: `tsurugi-linux` · **Type**: `OS / Distro` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `opsec_protection`
- **Platforms**: Linux · **Tags**: `dfir-osint-distro`, `profile-switcher`, `computer-forensics`
- **Overview**: Dedicated DFIR and OSINT Linux distribution featuring a built-in OSINT Profile Switcher that isolates SOCMINT, GEOINT, and Malware investigation toolbars and workspaces.
- **Quick-Start / Tradecraft**: `Boot Tsurugi Linux ISO in a VM when combining disk/memory forensics with open-source intelligence.`

---

## OSINT Browser Extensions

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Mitaka**](https://github.com/ninoseki/mitaka) ([GitHub](https://github.com/ninoseki/mitaka)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `ip, domain, url` → `malware_iocs, whois, open_ports` |
| **A** | [**Vortimo OSINT-tool**](https://www.vortimo.com/) | Browser Extension | Freemium | 🟢 Passive | ✅ | `url, keyword` → `entity_graph, archived_pages, emails` |
| **B** | [**Sputnik OSINT Browser Extension**](https://github.com/mitchmoser/sputnik) ([GitHub](https://github.com/mitchmoser/sputnik)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `ip, domain, url` → `malware_iocs, whois, open_ports` |

### [Mitaka](https://github.com/ninoseki/mitaka) `[S-Tier]`
- **ID**: `mitaka` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ninoseki/mitaka`](https://github.com/ninoseki/mitaka)
- **Inputs**: `ip`, `domain`, `url`, `file_hash`, `asn`, `crypto_address`, `email` → **Outputs**: `malware_iocs`, `whois`, `open_ports`
- **Platforms**: Chrome, Firefox · **Tags**: `context-menu-pivot`, `defang-refang`, `80-engines`, `analyst-speed`, `flagship`
- **Overview**: Indispensable open-source browser extension allowing analysts to highlight any IP, domain, URL, hash, ASN, CVE, or BTC address (even defanged `example[.]com`!) and right-click pivot to 80+ OSINT engines.
- **Quick-Start / Tradecraft**: `Highlight `1[.]1[.]1[.]1` or a SHA-256 hash on any threat report -> Right-Click -> Mitaka -> Shodan / Censys / VT / URLScan!`

### [Vortimo OSINT-tool](https://www.vortimo.com/) `[A-Tier]`
- **ID**: `vortimo` · **Type**: `Browser Extension` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `url`, `keyword` → **Outputs**: `entity_graph`, `archived_pages`, `emails`, `phones`
- **Platforms**: Chrome, Windows, macOS, Linux · **Tags**: `selector-extraction`, `browsing-graph`, `case-notes`, `chrome-extension`
- **Overview**: Browser investigation companion recording visited pages, auto-extracting selectors (emails, phones, handles, GPS coordinates, crypto addresses), highlighting recurring entities across tabs, and building link graphs.
- **Quick-Start / Tradecraft**: `Run Vortimo inside a dedicated Chromium investigation profile to auto-highlight cross-page entity overlaps.`

### [Sputnik OSINT Browser Extension](https://github.com/mitchmoser/sputnik) `[B-Tier]`
- **ID**: `sputnik-extension` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mitchmoser/sputnik`](https://github.com/mitchmoser/sputnik)
- **Inputs**: `ip`, `domain`, `url`, `file_hash` → **Outputs**: `malware_iocs`, `whois`, `open_ports`
- **Platforms**: Chrome, Firefox · **Tags**: `ioc-context-menu`, `lightweight`, `open-source-extension`
- **Overview**: Lightweight open-source right-click Chrome/Firefox context-menu extension launching rapid free lookups on highlighted IPs, domains, URLs, and file hashes.
- **Quick-Start / Tradecraft**: `Highlight any observable in browser -> Right-Click -> Sputnik.`

---

## OPSEC & Fingerprint Hygiene

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Mullvad Browser**](https://mullvad.net/en/browser) ([GitHub](https://github.com/mullvad/mullvad-browser)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `url` → `opsec_protection` |
| **S** | [**uBlock Origin**](https://github.com/gorhill/uBlock) ([GitHub](https://github.com/gorhill/uBlock)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `url` → `opsec_protection` |
| **A** | [**BrowserLeaks & EFF Cover Your Tracks**](https://browserleaks.com/) | Web Platform | Free | 🟢 Passive | ✅ | `url` → `opsec_protection, metadata` |
| **A** | [**Firefox Multi-Account Containers**](https://github.com/mozilla/multi-account-containers) ([GitHub](https://github.com/mozilla/multi-account-containers)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `url` → `opsec_protection` |
| **A** | [**Whoogle Search**](https://github.com/benbusby/whoogle-search) ([GitHub](https://github.com/benbusby/whoogle-search)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `keyword, domain` → `urls, opsec_protection` |

### [Mullvad Browser](https://mullvad.net/en/browser) `[S-Tier]`
- **ID**: `mullvad-browser` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mullvad/mullvad-browser`](https://github.com/mullvad/mullvad-browser)
- **Inputs**: `url` → **Outputs**: `opsec_protection`
- **Platforms**: Windows, macOS, Linux · **Tags**: `anti-fingerprinting`, `tor-project-collab`, `clearnet-opsec`, `no-telemetry`, `flagship`
- **Overview**: Co-engineered by The Tor Project and Mullvad VPN: delivers Tor Browser's identical anti-fingerprinting (letterboxing, canvas/font protection, zero telemetry) for clearnet OSINT over a VPN without Tor CAPTCHAs!
- **Quick-Start / Tradecraft**: `Pair Mullvad Browser + a clean VPN exit when Tor exit nodes are blocked by Cloudflare or target social networks!`

### [uBlock Origin](https://github.com/gorhill/uBlock) `[S-Tier]`
- **ID**: `ublock-origin` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`gorhill/uBlock`](https://github.com/gorhill/uBlock)
- **Inputs**: `url` → **Outputs**: `opsec_protection`
- **Platforms**: Firefox, Chrome · **Tags**: `tracker-blocking`, `malvertising-defense`, `logger-inspector`, `opsec-essential`
- **Overview**: Mandatory OPSEC browser shield blocking malicious ad-tech beacons, drive-by phishing skimmers, third-party tracking pixels, and unwanted beacon callbacks when visiting suspect target websites.
- **Quick-Start / Tradecraft**: `Open uBlock Origin's Logger window while loading a suspect site to inspect every hidden third-party request in real time!`

### [BrowserLeaks & EFF Cover Your Tracks](https://browserleaks.com/) `[A-Tier]`
- **ID**: `browserleaks` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `url` → **Outputs**: `opsec_protection`, `metadata`
- **Platforms**: Web · **Tags**: `webrtc-leak-test`, `canvas-fingerprint`, `opsec-check`, `dns-leak`
- **Overview**: Comprehensive OPSEC self-audit suite testing your investigation browser for WebRTC local-IP leaks, DNS leaks, Canvas/WebGL/AudioContext hashes, system font entropy, and timezone mismatches.
- **Quick-Start / Tradecraft**: `Run https://browserleaks.com/webrtc and `/ip` BEFORE touching any target infrastructure to confirm Timezone == VPN Country and zero WebRTC leaks!`

### [Firefox Multi-Account Containers](https://github.com/mozilla/multi-account-containers) `[A-Tier]`
- **ID**: `firefox-containers` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mozilla/multi-account-containers`](https://github.com/mozilla/multi-account-containers)
- **Inputs**: `url` → **Outputs**: `opsec_protection`
- **Platforms**: Firefox · **Tags**: `cookie-isolation`, `sock-puppets`, `session-compartmentalization`, `mozilla`
- **Overview**: Official Mozilla extension isolating cookies, `localStorage`, and indexedDB into color-coded per-tab containers—preventing Facebook, Google, or LinkedIn sock puppets from cross-contaminating sessions.
- **Quick-Start / Tradecraft**: `Assign dedicated per-persona containers + container-specific SOCKS5/HTTP proxies so each sock puppet exits its own residential IP.`

### [Whoogle Search](https://github.com/benbusby/whoogle-search) `[A-Tier]`
- **ID**: `whoogle-search` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`benbusby/whoogle-search`](https://github.com/benbusby/whoogle-search)
- **Inputs**: `keyword`, `domain` → **Outputs**: `urls`, `opsec_protection`
- **Platforms**: Docker, Linux, Python, Web · **Tags**: `google-proxy`, `self-hosted`, `zero-telemetry`, `opsec-dorking`
- **Overview**: Self-hosted, single-container ad-free and telemetry-free Google search proxy stripping AMP links, tracking cookies, IP referrer headers, and JavaScript fingerprinting.
- **Quick-Start / Tradecraft**: `docker run --publish 5000:5000 --detach --name whoogle-search benbusby/whoogle-search:latest`

---

## AI Audio & Translation Tools

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**OpenAI Whisper (Local Speech-to-Text)**](https://github.com/openai/whisper) ([GitHub](https://github.com/openai/whisper)) | CLI | OSS / Free | 🟢 Passive | ✅ | `audio, video` → `documents, metadata` |

### [OpenAI Whisper (Local Speech-to-Text)](https://github.com/openai/whisper) `[S-Tier]`
- **ID**: `whisper-openai` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`openai/whisper`](https://github.com/openai/whisper)
- **Inputs**: `audio`, `video` → **Outputs**: `documents`, `metadata`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `offline-transcription`, `99-languages`, `radio-translation`, `opsec-safe`, `flagship`
- **Overview**: Open-weight multilingual speech recognition and English-translation model running 100% offline (`whisper.cpp` / `faster-whisper`) to transcribe foreign-language radio intercepts, podcasts, and leaked videos.
- **Quick-Start / Tradecraft**: `pipx install openai-whisper && whisper foreign_clip.mp4 --model large-v3 --task translate`

---

## OSINT MCP Servers & AI Agents

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**OpenOSINT (AI Agent + Passive MCP Server)**](https://github.com/OpenOSINT/OpenOSINT) ([GitHub](https://github.com/OpenOSINT/OpenOSINT)) | AI / MCP | OSS / Free | 🟡 Hybrid | ✅ | `email, username, domain` → `social_profiles, breach_records, dns_records` |
| **A** | [**Clearfront (Self-OSINT & MCP)**](https://github.com/scottmartinanderson/clearfront) ([GitHub](https://github.com/scottmartinanderson/clearfront)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `username, email, domain` → `social_profiles, breach_records, subdomains` |
| **A** | [**OSINT Toolbox MCP**](https://github.com/renkagod/osint-toolbox-mcp) ([GitHub](https://github.com/renkagod/osint-toolbox-mcp)) | AI / MCP | OSS / Free | 🟡 Hybrid | ✅ | `username, email, domain` → `social_profiles, emails, subdomains` |
| **A** | [**osint-mcp-server (badchars)**](https://github.com/badchars/osint-mcp-server) ([GitHub](https://github.com/badchars/osint-mcp-server)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `domain, ip, asn` → `subdomains, dns_records, certificates` |
| **A** | [**Sanctions Screening MCP Server**](https://github.com/cyanheads/sanctions-screening-mcp-server) ([GitHub](https://github.com/cyanheads/sanctions-screening-mcp-server)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `person_name, company` → `sanctions_hits, corporate_records` |
| **A** | [**satellite-mcp**](https://github.com/badchars/satellite-mcp) ([GitHub](https://github.com/badchars/satellite-mcp)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `coordinates, vessel_imo, aircraft_hex` → `satellite_imagery, geolocation, flight_tracks` |
| **A** | [**Sift (Corporate & Financial Cross-Reference MCP)**](https://github.com/mefos-lab/sift) ([GitHub](https://github.com/mefos-lab/sift)) | AI / MCP | OSS / Free | 🟢 Passive | 🔑 | `company, person_name` → `corporate_records, sanctions_hits, entity_graph` |
| **A** | [**world-intel-mcp**](https://github.com/marc-shade/world-intel-mcp) ([GitHub](https://github.com/marc-shade/world-intel-mcp)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword, person_name` → `geolocation, sanctions_hits, flight_tracks` |

### [OpenOSINT (AI Agent + Passive MCP Server)](https://github.com/OpenOSINT/OpenOSINT) `[S-Tier]`
- **ID**: `openosint` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`OpenOSINT/OpenOSINT`](https://github.com/OpenOSINT/OpenOSINT)
- **Inputs**: `email`, `username`, `domain`, `ip`, `phone`, `keyword` → **Outputs**: `social_profiles`, `breach_records`, `dns_records`, `open_ports`, `whois`
- **Platforms**: Linux, macOS, Windows, Python, Web · **Tags**: `mcp-server`, `passive-by-default`, `claude-code`, `ollama`, `agentic-osint`, `flagship`
- **Overview**: Open-source passive-by-default OSINT engine exposing 20+ real recon tools (email, username, breach, RDAP, Shodan, Censys, VT, AbuseIPDB, GDELT) via CLI, REPL, Web UI, and native Model Context Protocol (MCP).
- **Quick-Start / Tradecraft**: `uvx --from openosint openosint-mcp  # Exposes 20 strictly passive tools by default unless --allow-active is passed!`

### [Clearfront (Self-OSINT & MCP)](https://github.com/scottmartinanderson/clearfront) `[A-Tier]`
- **ID**: `clearfront` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`scottmartinanderson/clearfront`](https://github.com/scottmartinanderson/clearfront)
- **Inputs**: `username`, `email`, `domain`, `image` → **Outputs**: `social_profiles`, `breach_records`, `subdomains`, `entity_graph`
- **Platforms**: Linux, macOS, Python, Web · **Tags**: `self-osint`, `executive-protection`, `mcp`, `evidence-graph`
- **Overview**: Local self-OSINT and executive-protection scanner bundling 30 tools over CLI, Web Console, and MCP—correlating Sherlock, Maigret, Holehe, HIBP, Hudson Rock, crt.sh, and EXIF into an evidence graph.
- **Quick-Start / Tradecraft**: `pip install clearfront && clearfront`

### [OSINT Toolbox MCP](https://github.com/renkagod/osint-toolbox-mcp) `[A-Tier]`
- **ID**: `osint-toolbox-mcp` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`renkagod/osint-toolbox-mcp`](https://github.com/renkagod/osint-toolbox-mcp)
- **Inputs**: `username`, `email`, `domain`, `phone`, `image` → **Outputs**: `social_profiles`, `emails`, `subdomains`, `phones`, `metadata`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `local-cli-mcp`, `17-tools`, `keyless`, `docker-sandbox`
- **Overview**: Local keyless MCP server orchestrating 12 classic OSINT CLIs on your own machine—Sherlock, Maigret, Blackbird, Holehe, GHunt, theHarvester, SpiderFoot, Subfinder, dnstwist, PhoneInfoga, and ExifTool!
- **Quick-Start / Tradecraft**: `Run via Docker image or `uvx` to drive local Sherlock/Maigret/Holehe/Subfinder/ExifTool from an AI assistant.`

### [osint-mcp-server (badchars)](https://github.com/badchars/osint-mcp-server) `[A-Tier]`
- **ID**: `osint-mcp-server` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`badchars/osint-mcp-server`](https://github.com/badchars/osint-mcp-server)
- **Inputs**: `domain`, `ip`, `asn`, `url` → **Outputs**: `subdomains`, `dns_records`, `certificates`, `open_ports`, `archived_pages`
- **Platforms**: Linux, macOS, Windows, Node.js · **Tags**: `mcp-server`, `parallel-recon`, `21-keyless-tools`, `attack-surface`
- **Overview**: 37-tool Model Context Protocol server querying 12 OSINT providers in parallel—merging crt.sh, SecurityTrails, VirusTotal, Shodan, Censys, BGP, GeoIP, WHOIS, and Wayback CDX.
- **Quick-Start / Tradecraft**: `Connect `badchars/osint-mcp-server` to Claude Code / Cursor for zero-key DNS, crt.sh, BGP, and Wayback correlation.`

### [Sanctions Screening MCP Server](https://github.com/cyanheads/sanctions-screening-mcp-server) `[A-Tier]`
- **ID**: `sanctions-screening-mcp` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`cyanheads/sanctions-screening-mcp-server`](https://github.com/cyanheads/sanctions-screening-mcp-server)
- **Inputs**: `person_name`, `company` → **Outputs**: `sanctions_hits`, `corporate_records`
- **Platforms**: Linux, macOS, Windows, Node.js · **Tags**: `offline-sanctions`, `zero-leak-opsec`, `mcp-server`, `sqlite-fts5`
- **Overview**: Mirrors consolidated OFAC, EU, UK, and UN sanctions lists plus GLEIF LEI lookups into a local SQLite FTS5 index so AI agents screen targets 100% offline with zero data leakage!
- **Quick-Start / Tradecraft**: `npx -y @cyanheads/sanctions-screening-mcp-server`

### [satellite-mcp](https://github.com/badchars/satellite-mcp) `[A-Tier]`
- **ID**: `satellite-mcp` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`badchars/satellite-mcp`](https://github.com/badchars/satellite-mcp)
- **Inputs**: `coordinates`, `vessel_imo`, `aircraft_hex`, `keyword` → **Outputs**: `satellite_imagery`, `geolocation`, `flight_tracks`, `vessel_tracks`
- **Platforms**: Linux, macOS, Windows, Node.js · **Tags**: `geoint-mcp`, `171-tools`, `sentinel-firms`, `overpass-agent`
- **Overview**: 171-tool GEOINT Model Context Protocol server unifying Sentinel-2/Landsat scene discovery, NASA FIRMS wildfire thermal hits, night-lights change math, ADS-B/AIS, and OpenStreetMap Overpass queries.
- **Quick-Start / Tradecraft**: `npx satellite-mcp`

### [Sift (Corporate & Financial Cross-Reference MCP)](https://github.com/mefos-lab/sift) `[A-Tier]`
- **ID**: `sift-mcp` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`mefos-lab/sift`](https://github.com/mefos-lab/sift)
- **Inputs**: `company`, `person_name` → **Outputs**: `corporate_records`, `sanctions_hits`, `entity_graph`
- **Platforms**: Linux, macOS, Python · **Tags**: `finint-mcp`, `shell-company-detection`, `edgar-companies-house`, `80-tools`
- **Overview**: 80-tool MCP server cross-referencing OpenSanctions, ICIJ Offshore Leaks, UK Companies House, SEC EDGAR, CourtListener, GLEIF, and Wikidata with 24 shell-company structural detectors.
- **Quick-Start / Tradecraft**: `Clone `mefos-lab/sift` and configure free OpenSanctions/Companies House keys for automated corporate network investigations.`

### [world-intel-mcp](https://github.com/marc-shade/world-intel-mcp) `[A-Tier]`
- **ID**: `world-intel-mcp` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`marc-shade/world-intel-mcp`](https://github.com/marc-shade/world-intel-mcp)
- **Inputs**: `coordinates`, `keyword`, `person_name`, `company` → **Outputs**: `geolocation`, `sanctions_hits`, `flight_tracks`, `signal_telemetry`
- **Platforms**: Linux, macOS, Python · **Tags**: `situational-awareness-mcp`, `gdelt-acled`, `nga-maritime`, `120-tools`
- **Overview**: 120-tool situational-awareness MCP server aggregating GDELT news timelines, ACLED conflict events, OpenSky military aircraft, NGA maritime warnings, submarine cables, and OFAC sanctions.
- **Quick-Start / Tradecraft**: `Clone `marc-shade/world-intel-mcp` to expose 30+ public geopolitical feeds to local or API AI agents.`

---

## Sock Puppet & Identity Compartmentalization

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Privacy.com / Virtual Burner Cards**](https://privacy.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `keyword` → `opsec_protection` |
| **A** | [**SimpleLogin / Proton Pass Email Aliases**](https://simplelogin.io/) ([GitHub](https://github.com/simplelogin/app)) | Web Platform | Freemium | 🟢 Passive | 🔑 | `email` → `opsec_protection` |

### [Privacy.com / Virtual Burner Cards](https://privacy.com/) `[A-Tier]`
- **ID**: `privacy-com` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword` → **Outputs**: `opsec_protection`
- **Platforms**: Web, Chrome, Firefox · **Tags**: `burner-cards`, `financial-opsec`, `merchant-locked`, `sock-puppets`
- **Overview**: Generates merchant-locked, spend-capped virtual payment cards with custom billing aliases—preventing OSINT SaaS billing breaches or rogue registries from leaking an investigator's personal credit card.
- **Quick-Start / Tradecraft**: `Create single-merchant capped virtual cards whenever paying court/registry fees or commercial OSINT trial subscriptions.`

### [SimpleLogin / Proton Pass Email Aliases](https://simplelogin.io/) `[A-Tier]`
- **ID**: `simplelogin-aliases` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`simplelogin/app`](https://github.com/simplelogin/app)
- **Inputs**: `email` → **Outputs**: `opsec_protection`
- **Platforms**: Web, Docker, Chrome, Firefox · **Tags**: `sock-puppet-emails`, `compartmentalization`, `open-source`, `proton`
- **Overview**: Open-source email-aliasing infrastructure generating unique compartmentalized burner/sock-puppet email addresses per OSINT platform so leaked database breaches never correlate back to the analyst.
- **Quick-Start / Tradecraft**: `Never reuse an email address across two investigation portals or sock-puppet accounts!`

---
[⬅️ Back to Master Index](../README.md) · [◀ 📻 SIGINT, Wireless, SDR & Space](./19-sigint-wireless-space-rf.md)

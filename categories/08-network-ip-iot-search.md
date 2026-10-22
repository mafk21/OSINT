[⬅️ Back to Master Index](../README.md) · [◀ 🌐 Domains, DNS & ASM](./07-domain-dns-asm.md) · [💬 Social Media (SOCMINT) ▶](./09-social-media-socmint.md)

# 📡 08. Cyberspace Search Engines, IP, ASN, BGP & Internet Telemetry (`NETINT`)

> **Scope**: Internet-wide port/banner search engines, exposed IoT/ICS/OT device indexes, BGP/ASN routing analyzers, residential proxy/VPN detectors, and global internet outage monitors.
>
> **OPSEC Advisory**: Searching Shodan, Censys, FOFA, ZoomEye, Netlas, or GreyNoise queries pre-indexed scan databases and is completely passive with zero packets sent to the target IP.

**Discipline Telemetry**: `30` Verified Tools · `9` S-Tier Flagships · `29` Passive · `16` Free/Open-Source

## Subcategories
- [Cyberspace Banner Search Engines](#cyberspace-banner-search-engines) (12)
- [Scanner & Noise Intelligence](#scanner-noise-intelligence) (4)
- [ASN, BGP & GeoIP Intelligence](#asn,-bgp-geoip-intelligence) (8)
- [VPN, Proxy & Anonymizer Intel](#vpn,-proxy-anonymizer-intel) (1)
- [Internet Outage & Censorship Telemetry](#internet-outage-censorship-telemetry) (4)
- [Active Network Discovery](#active-network-discovery) (1)

---

## Cyberspace Banner Search Engines

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Censys Search**](https://search.censys.io/) ([GitHub](https://github.com/censys/censys-python)) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, certificates, tech_stack` |
| **S** | [**FOFA**](https://en.fofa.info/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, certificates, tech_stack` |
| **S** | [**Shodan**](https://www.shodan.io/) ([GitHub](https://github.com/achillean/shodan-python)) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, certificates, tech_stack` |
| **S** | [**Shodan InternetDB**](https://internetdb.shodan.io/) | API / Service | Free | 🟢 Passive | ✅ | `ip` → `open_ports, tech_stack, dns_records` |
| **A** | [**Criminal IP**](https://www.criminalip.io/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, keyword` → `open_ports, malware_iocs, certificates` |
| **A** | [**Netlas.io**](https://netlas.io/) ([GitHub](https://github.com/netlas-io/netlas-python)) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, dns_records, certificates` |
| **A** | [**Uncover (ProjectDiscovery)**](https://github.com/projectdiscovery/uncover) ([GitHub](https://github.com/projectdiscovery/uncover)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `domain, ip, asn` → `ip_addresses, open_ports, subdomains` |
| **A** | [**ZoomEye**](https://www.zoomeye.ai/) ([GitHub](https://github.com/knownsec/ZoomEye-python)) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, tech_stack, certificates` |
| **B** | [**360 Quake Cyberspace Mapping**](https://quake.360.net/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, certificates, tech_stack` |
| **B** | [**BinaryEdge**](https://www.binaryedge.io/) ([GitHub](https://github.com/binaryedge/pybinaryedge)) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, certificates, tech_stack` |
| **B** | [**Hunter.how**](https://hunter.how/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, certificates, tech_stack` |
| **B** | [**ONYPHE**](https://www.onyphe.io/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `ip, domain, asn` → `open_ports, dns_records, malware_iocs` |

### [Censys Search](https://search.censys.io/) `[S-Tier]`
- **ID**: `censys` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`censys/censys-python`](https://github.com/censys/censys-python)
- **Inputs**: `ip`, `domain`, `asn`, `company`, `keyword` → **Outputs**: `open_ports`, `certificates`, `tech_stack`, `malware_iocs`, `ip_addresses`
- **Platforms**: Web, CLI, Python · **Tags**: `65535-ports`, `tls-certificates`, `jarm`, `c2-hunting`, `origin-ip`, `flagship`
- **Overview**: Continuous internet-wide scanner indexing billions of services across all 65,535 TCP ports plus the deepest historical X.509 TLS certificate repository—unmatched for C2 and origin-IP hunting.
- **Quick-Start / Tradecraft**: `pip install censys && censys view 8.8.8.8`

### [FOFA](https://en.fofa.info/) `[S-Tier]`
- **ID**: `fofa` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `ip`, `domain`, `asn`, `keyword` → **Outputs**: `open_ports`, `certificates`, `tech_stack`, `ip_addresses`
- **Platforms**: Web, CLI, Python · **Tags**: `cyberspace-mapping`, `icon-hash`, `apac-coverage`, `banner-search`
- **Overview**: Massive cyberspace asset search engine indexing global web titles, HTTP headers, body hashes, TLS certificates, icon hashes, and APAC/global infrastructure often missed by Western crawlers.
- **Quick-Start / Tradecraft**: `Query `domain="example.com" || cert="example.com"` on https://en.fofa.info/.`

### [Shodan](https://www.shodan.io/) `[S-Tier]`
- **ID**: `shodan` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`achillean/shodan-python`](https://github.com/achillean/shodan-python)
- **Inputs**: `ip`, `domain`, `asn`, `company`, `coordinates`, `keyword` → **Outputs**: `open_ports`, `certificates`, `tech_stack`, `geolocation`, `malware_iocs`
- **Platforms**: Web, CLI, Python, Chrome, Firefox · **Tags**: `iot-search`, `banners`, `favicon-hash`, `ics-scada`, `jarm`, `flagship`
- **Overview**: World's premier search engine for internet-connected servers, IoT devices, ICS/SCADA controllers, RTSP cameras, open databases, TLS certificates, JARM hashes, and favicon fingerprints.
- **Quick-Start / Tradecraft**: `pip install shodan && shodan host 8.8.8.8  # Search web: ssl.cert.subject.cn:"example.com"`

### [Shodan InternetDB](https://internetdb.shodan.io/) `[S-Tier]`
- **ID**: `shodan-internetdb` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip` → **Outputs**: `open_ports`, `tech_stack`, `dns_records`
- **Platforms**: Web, CLI, Python · **Tags**: `keyless-api`, `free-shodan`, `open-ports`, `cve-lookup`, `fast-enrichment`
- **Overview**: Completely free, keyless, fast REST API maintained by Shodan returning open ports, CPE software tags, hostnames, tags (`vpn`, `tor`, `cloud`), and known CVEs for any IPv4 address.
- **Quick-Start / Tradecraft**: `curl -s https://internetdb.shodan.io/1.1.1.1 | jq`

### [Criminal IP](https://www.criminalip.io/) `[A-Tier]`
- **ID**: `criminal-ip` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `ip`, `domain`, `keyword` → **Outputs**: `open_ports`, `malware_iocs`, `certificates`, `geolocation`
- **Platforms**: Web, Chrome · **Tags**: `ip-risk-score`, `vpn-detection`, `banner-search`, `cti`
- **Overview**: CTI-focused cyberspace asset and IP risk search engine scoring inbound/outbound IP maliciousness, VPN/Tor/proxy masking, exposed ports, and phishing domains.
- **Quick-Start / Tradecraft**: `Inspect any IPv4 address on https://www.criminalip.io/ for combined open-port + VPN/proxy + Abuse score.`

### [Netlas.io](https://netlas.io/) `[A-Tier]`
- **ID**: `netlas` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`netlas-io/netlas-python`](https://github.com/netlas-io/netlas-python)
- **Inputs**: `ip`, `domain`, `asn`, `company`, `email` → **Outputs**: `open_ports`, `dns_records`, `certificates`, `whois`, `subdomains`
- **Platforms**: Web, CLI, Python · **Tags**: `easm`, `passive-dns`, `lucene-dorks`, `spyse-alternative`
- **Overview**: Attack-surface and internet intelligence search engine unifying IPv4 responses, Passive DNS, WHOIS domains, and Certificate Transparency into one Lucene query interface.
- **Quick-Start / Tradecraft**: `pip install netlas && netlas search 'host:*.example.com'`

### [Uncover (ProjectDiscovery)](https://github.com/projectdiscovery/uncover) `[A-Tier]`
- **ID**: `uncover` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`projectdiscovery/uncover`](https://github.com/projectdiscovery/uncover)
- **Inputs**: `domain`, `ip`, `asn`, `company`, `keyword` → **Outputs**: `ip_addresses`, `open_ports`, `subdomains`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `meta-search`, `shodan-censys-fofa`, `unix-pipe`
- **Overview**: Go CLI wrapper querying Shodan, Censys, FOFA, Quake, Hunter, ZoomEye, Netlas, CriminalIP, and PublicWWW simultaneously and piping deduplicated `ip:port` targets straight into Unix pipelines.
- **Quick-Start / Tradecraft**: `uncover -q 'ssl:"example.com"' -e shodan,censys,fofa -silent`

### [ZoomEye](https://www.zoomeye.ai/) `[A-Tier]`
- **ID**: `zoomeye` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`knownsec/ZoomEye-python`](https://github.com/knownsec/ZoomEye-python)
- **Inputs**: `ip`, `domain`, `asn`, `keyword` → **Outputs**: `open_ports`, `tech_stack`, `certificates`, `geolocation`
- **Platforms**: Web, CLI, Python · **Tags**: `cyberspace-engine`, `iot-firmware`, `host-search`, `knownsec`
- **Overview**: Knownsec's global cyberspace search engine cataloging IPv4/IPv6 host banners, web component fingerprints, IoT firmware versions, and historical port exposure.
- **Quick-Start / Tradecraft**: `pip install zoomeye && zoomeye search 'ssl:"example.com"'`

### [360 Quake Cyberspace Mapping](https://quake.360.net/) `[B-Tier]`
- **ID**: `quake-360` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `ip`, `domain`, `asn`, `keyword` → **Outputs**: `open_ports`, `certificates`, `tech_stack`
- **Platforms**: Web, CLI · **Tags**: `apac-cyberspace`, `favicon-search`, `host-banners`
- **Overview**: Cyberspace asset search engine with deep Asian/global IPv4/IPv6 banner, favicon hash, JARM, and ICS device indexing.
- **Quick-Start / Tradecraft**: `Combine with `uncover` alongside FOFA and ZoomEye for maximum APAC infrastructure visibility.`

### [BinaryEdge](https://www.binaryedge.io/) `[B-Tier]`
- **ID**: `binaryedge` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`binaryedge/pybinaryedge`](https://github.com/binaryedge/pybinaryedge)
- **Inputs**: `ip`, `domain`, `asn` → **Outputs**: `open_ports`, `certificates`, `tech_stack`
- **Platforms**: Web, Python · **Tags**: `internet-scanner`, `port-banners`, `screenshots`, `asm`
- **Overview**: Internet-wide scanning and threat-telemetry platform indexing open ports, exposed services, screenshots, torrents, and data-leak misconfigurations.
- **Quick-Start / Tradecraft**: `Cross-reference BinaryEdge host history against Shodan and Censys.`

### [Hunter.how](https://hunter.how/) `[B-Tier]`
- **ID**: `hunter-how` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `ip`, `domain`, `asn`, `keyword` → **Outputs**: `open_ports`, `certificates`, `tech_stack`
- **Platforms**: Web · **Tags**: `asset-search`, `c2-hunting`, `favicon-pivot`
- **Overview**: Internet-facing asset discovery search engine tracking global HTTP services, TLS certificates, favicon hashes, and C2 infrastructure fingerprints.
- **Quick-Start / Tradecraft**: `Search `cert.subject-cn="example.com"` at https://hunter.how/.`

### [ONYPHE](https://www.onyphe.io/) `[B-Tier]`
- **ID**: `onyphe` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `ip`, `domain`, `asn` → **Outputs**: `open_ports`, `dns_records`, `malware_iocs`
- **Platforms**: Web, CLI · **Tags**: `european-cti`, `asm`, `datascan`, `threatlists`
- **Overview**: European cyber defense and ASM search engine correlating passive DNS, active internet port scans (`datascan`), threatlists, and GeoIP exposure.
- **Quick-Start / Tradecraft**: `Query `category:datascan domain:example.com` on https://www.onyphe.io/.`

---

## Scanner & Noise Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GreyNoise Visualizer**](https://viz.greynoise.io/) ([GitHub](https://github.com/GreyNoise-Intelligence/pygreynoise)) | Search Engine | Freemium | 🟢 Passive | ✅ | `ip, asn, keyword` → `malware_iocs, open_ports, geolocation` |
| **A** | [**AbuseIPDB**](https://www.abuseipdb.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `ip, asn` → `malware_iocs, whois, geolocation` |
| **A** | [**Spamhaus IP & Domain Reputation Checker**](https://check.spamhaus.org/) | Web Platform | Free | 🟢 Passive | ✅ | `ip, domain, asn` → `malware_iocs, whois` |
| **B** | [**MultiRBL.valli.org**](https://multirbl.valli.org/) | Web Platform | Free | 🟢 Passive | ✅ | `ip, domain` → `malware_iocs, dns_records` |

### [GreyNoise Visualizer](https://viz.greynoise.io/) `[S-Tier]`
- **ID**: `greynoise` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`GreyNoise-Intelligence/pygreynoise`](https://github.com/GreyNoise-Intelligence/pygreynoise)
- **Inputs**: `ip`, `asn`, `keyword` → **Outputs**: `malware_iocs`, `open_ports`, `geolocation`
- **Platforms**: Web, CLI, Python · **Tags**: `mass-scanners`, `riot-benign`, `honeypot-telemetry`, `alert-triage`, `flagship`
- **Overview**: Global passive honeypot sensor grid distinguishing benign mass internet scanners (Shodan, Censys, Googlebot) and opportunistic botnets from targeted human attacks.
- **Quick-Start / Tradecraft**: `curl -s https://api.greynoise.io/v3/community/8.8.8.8 | jq`

### [AbuseIPDB](https://www.abuseipdb.com/) `[A-Tier]`
- **ID**: `abuseipdb` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip`, `asn` → **Outputs**: `malware_iocs`, `whois`, `geolocation`
- **Platforms**: Web · **Tags**: `ip-reputation`, `abuse-reports`, `cidr-check`, `free-api`
- **Overview**: Crowdsourced malicious IP reputation database aggregating millions of brute-force, port-scan, web-exploit, and spam abuse reports with ISP/usage-type metadata and free API.
- **Quick-Start / Tradecraft**: `curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode 'ipAddress=1.2.3.4' -H 'Key: YOUR_KEY' -H 'Accept: application/json'`

### [Spamhaus IP & Domain Reputation Checker](https://check.spamhaus.org/) `[A-Tier]`
- **ID**: `spamhaus-lookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip`, `domain`, `asn` → **Outputs**: `malware_iocs`, `whois`
- **Platforms**: Web · **Tags**: `spamhaus-drop`, `bulletproof-hosting`, `botnet-xbl`, `domain-reputation`
- **Overview**: Authoritative lookup across Spamhaus SBL (spam/cybercrime hosting), XBL (infected botnet IPs), PBL, DROP (hijacked netblocks—Don't Route Or Peer!), and DBL (malicious domains).
- **Quick-Start / Tradecraft**: `Check whether a shady hosting ASN appears on Spamhaus ASN-DROP (`spamhaus.org/blocklists/do-not-route-or-peer/`).`

### [MultiRBL.valli.org](https://multirbl.valli.org/) `[B-Tier]`
- **ID**: `multirbl` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip`, `domain` → **Outputs**: `malware_iocs`, `dns_records`
- **Platforms**: Web · **Tags**: `300-dnsbls`, `rbl-check`, `mail-reputation`, `botnet-ips`
- **Overview**: Checks any IPv4, IPv6, or domain simultaneously against 300+ public DNSBL/RBL spam, botnet, Tor, and exploit blacklists in a single view.
- **Quick-Start / Tradecraft**: `Lookup sender IPs from email headers on https://multirbl.valli.org/lookup/.`

---

## ASN, BGP & GeoIP Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Hurricane Electric BGP Toolkit**](https://bgp.he.net/) | Web Platform | Free | 🟢 Passive | ✅ | `ip, asn, company` → `ip_addresses, whois, dns_records` |
| **S** | [**IPinfo.io**](https://ipinfo.io/) ([GitHub](https://github.com/ipinfo/cli)) | API / Service | Freemium | 🟢 Passive | ✅ | `ip, asn` → `geolocation, whois, corporate_records` |
| **S** | [**RIPEstat**](https://stat.ripe.net/) | Web Platform | Free | 🟢 Passive | ✅ | `ip, asn, domain` → `whois, ip_addresses, geolocation` |
| **A** | [**asn (Network Recon CLI)**](https://github.com/nitefood/asn) ([GitHub](https://github.com/nitefood/asn)) | CLI | OSS / Free | 🟢 Passive | ✅ | `ip, asn, domain` → `ip_addresses, open_ports, whois` |
| **A** | [**asnmap (ProjectDiscovery)**](https://github.com/projectdiscovery/asnmap) ([GitHub](https://github.com/projectdiscovery/asnmap)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `asn, ip, domain` → `ip_addresses, whois` |
| **A** | [**BGP.Tools**](https://bgp.tools/) | Web Platform | Free | 🟢 Passive | ✅ | `ip, asn, domain` → `ip_addresses, whois, entity_graph` |
| **A** | [**Metabigor**](https://github.com/j3ssie/metabigor) ([GitHub](https://github.com/j3ssie/metabigor)) | CLI | OSS / Free | 🟢 Passive | ✅ | `company, asn, ip` → `ip_addresses, open_ports, subdomains` |
| **A** | [**PeeringDB**](https://www.peeringdb.com/) ([GitHub](https://github.com/peeringdb/peeringdb)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `asn, company` → `corporate_records, geolocation, emails` |

### [Hurricane Electric BGP Toolkit](https://bgp.he.net/) `[S-Tier]`
- **ID**: `he-bgp-toolkit` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip`, `asn`, `company`, `domain` → **Outputs**: `ip_addresses`, `whois`, `dns_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `bgp`, `asn`, `cidr-prefixes`, `peering`, `hurricane-electric`, `flagship`
- **Overview**: Essential global BGP routing table explorer mapping Autonomous System Numbers (ASNs), announced IPv4/IPv6 CIDR prefixes, upstream/peer graphs, IXP memberships, RPKI validity, and IRR records.
- **Quick-Start / Tradecraft**: `Search a company name at https://bgp.he.net/ to enumerate every owned ASN and announced IPv4/IPv6 netblock.`

### [IPinfo.io](https://ipinfo.io/) `[S-Tier]`
- **ID**: `ipinfo` · **Type**: `API / Service` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ipinfo/cli`](https://github.com/ipinfo/cli)
- **Inputs**: `ip`, `asn` → **Outputs**: `geolocation`, `whois`, `corporate_records`
- **Platforms**: Web, CLI, Linux, macOS, Windows, Go · **Tags**: `geoip`, `asn-lookup`, `anycast`, `cli`, `high-accuracy`
- **Overview**: High-accuracy IP geolocation, ASN, carrier, company ownership, Anycast, Abuse contact, and privacy/VPN detection API & CLI (`ipinfo`).
- **Quick-Start / Tradecraft**: `curl -s https://ipinfo.io/8.8.8.8/json | jq  # Or install `ipinfo` CLI for bulk CIDR enrichment`

### [RIPEstat](https://stat.ripe.net/) `[S-Tier]`
- **ID**: `ripestat` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip`, `asn`, `domain` → **Outputs**: `whois`, `ip_addresses`, `geolocation`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `ripe-ncc`, `historical-bgp`, `rir-whois`, `keyless-api`, `routing-history`
- **Overview**: RIPE NCC's authoritative visual dashboard and keyless open REST API providing historical BGP routing, prefix hijacks, RIR allocation WHOIS across ARIN/RIPE/APNIC/LACNIC/AFRINIC, and GeoIP.
- **Quick-Start / Tradecraft**: `curl -s 'https://stat.ripe.net/data/whois/data.json?resource=193.0.0.0/21' | jq`

### [asn (Network Recon CLI)](https://github.com/nitefood/asn) `[A-Tier]`
- **ID**: `asn-cli` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`nitefood/asn`](https://github.com/nitefood/asn)
- **Inputs**: `ip`, `asn`, `domain`, `company` → **Outputs**: `ip_addresses`, `open_ports`, `whois`, `geolocation`
- **Platforms**: Linux, macOS, Docker · **Tags**: `asn-recon`, `cidr-expansion`, `shodan-internetdb`, `bash-cli`
- **Overview**: Feature-packed Bash network recon CLI and web server chaining ASN lookup, RPKI validity, BGP stats, IP reputation, GeoIP, Shodan InternetDB, and organization CIDR expansion.
- **Quick-Start / Tradecraft**: `asn example.com  # Or search org netblocks: asn 'Target Corp'`

### [asnmap (ProjectDiscovery)](https://github.com/projectdiscovery/asnmap) `[A-Tier]`
- **ID**: `asnmap` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`projectdiscovery/asnmap`](https://github.com/projectdiscovery/asnmap)
- **Inputs**: `asn`, `ip`, `domain`, `company` → **Outputs**: `ip_addresses`, `whois`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `org-to-cidr`, `asn-mapping`, `golang`
- **Overview**: CLI & Go library swiftly mapping organization names, domain names, IPs, or AS numbers into clean CIDR netblock ranges ready for passive or active recon.
- **Quick-Start / Tradecraft**: `asnmap -org 'CLOUDFLARE' -silent`

### [BGP.Tools](https://bgp.tools/) `[A-Tier]`
- **ID**: `bgpview-radar` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `ip`, `asn`, `domain`, `company` → **Outputs**: `ip_addresses`, `whois`, `entity_graph`
- **Platforms**: Web, CLI · **Tags**: `bgp-tools`, `rpki`, `upstream-graph`, `whois-port-43`
- **Overview**: Ultra-clean modern BGP routing table, IRR/RPKI validator, IXP LAN explorer, and live route propagation monitor used by network engineers and infrastructure investigators.
- **Quick-Start / Tradecraft**: `whois -h bgp.tools ' -v 1.1.1.1'  # Instant CLI ASN + prefix + AS-name lookup!`

### [Metabigor](https://github.com/j3ssie/metabigor) `[A-Tier]`
- **ID**: `metabigor` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`j3ssie/metabigor`](https://github.com/j3ssie/metabigor)
- **Inputs**: `company`, `asn`, `ip`, `domain` → **Outputs**: `ip_addresses`, `open_ports`, `subdomains`
- **Platforms**: Linux, macOS, Docker, Go · **Tags**: `keyless-osint`, `netblock-discovery`, `internetdb-pipe`, `golang`
- **Overview**: Keyless Go intelligence utility discovering ASN/CIDR netblocks by company name, running Shodan InternetDB enrichment across whole IP lists, and parsing reverse WHOIS without API keys.
- **Quick-Start / Tradecraft**: `echo 'Target Corp' | metabigor net --org -v`

### [PeeringDB](https://www.peeringdb.com/) `[A-Tier]`
- **ID**: `peeringdb` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`peeringdb/peeringdb`](https://github.com/peeringdb/peeringdb)
- **Inputs**: `asn`, `company` → **Outputs**: `corporate_records`, `geolocation`, `emails`
- **Platforms**: Web · **Tags**: `ixp`, `datacenters`, `noc-contacts`, `physical-infrastructure`
- **Overview**: Global interconnection database where network operators list physical colocation datacenters, Internet Exchange Points (IXPs), NOC contacts, and peering policies for every ASN.
- **Quick-Start / Tradecraft**: `Look up an ASN on https://www.peeringdb.com/ to identify the exact physical datacenter buildings where its routers sit.`

---

## VPN, Proxy & Anonymizer Intel

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Spur.us Context**](https://spur.us/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `ip` → `geolocation, malware_iocs, opsec_protection` |

### [Spur.us Context](https://spur.us/) `[S-Tier]`
- **ID**: `spur-us` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `ip` → **Outputs**: `geolocation`, `malware_iocs`, `opsec_protection`
- **Platforms**: Web · **Tags**: `residential-proxies`, `vpn-attribution`, `anonymizer-intel`, `fraud-cti`, `flagship`
- **Overview**: Premier IP anonymization intelligence service identifying commercial VPN exit nodes, Tor relays, datacenter proxies, and—crucially—illicit residential proxy botnets (Hola, Oxylabs, BrightData, SOCKS5 malware).
- **Quick-Start / Tradecraft**: `Look up suspect login/attacker IPs at `https://spur.us/context/<IP>` to determine if traffic exited a residential proxy or specific VPN brand.`

---

## Internet Outage & Censorship Telemetry

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Cloudflare Radar & URL Scanner**](https://radar.cloudflare.com/) | Web Platform | Free | 🟢 Passive | ✅ | `asn, url, domain` → `signal_telemetry, dns_records, certificates` |
| **A** | [**IODA (Internet Outage Detection and Analysis)**](https://ioda.inetintel.cc.gatech.edu/) | Web Platform | Free | 🟢 Passive | ✅ | `asn, coordinates, keyword` → `signal_telemetry, geolocation` |
| **A** | [**OONI Explorer (Open Observatory of Network Interference)**](https://explorer.ooni.org/) ([GitHub](https://github.com/ooni/probe)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `domain, url, asn` → `signal_telemetry, dns_records` |
| **B** | [**Censored Planet Observatory**](https://censoredplanet.org/) ([GitHub](https://github.com/censoredplanet/censoredplanet-analysis)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `domain, asn, keyword` → `signal_telemetry, dns_records` |

### [Cloudflare Radar & URL Scanner](https://radar.cloudflare.com/) `[A-Tier]`
- **ID**: `cloudflare-radar` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `asn`, `url`, `domain`, `keyword` → **Outputs**: `signal_telemetry`, `dns_records`, `certificates`, `tech_stack`
- **Platforms**: Web · **Tags**: `internet-shutdowns`, `bgp-leaks`, `traffic-anomalies`, `url-scanner`
- **Overview**: Global internet traffic, BGP route-leak, DDoS trend, Layer-7 outage monitor, and free headless URL/DOM scanner powered by Cloudflare's global edge telemetry.
- **Quick-Start / Tradecraft**: `Monitor national/ISP internet blackouts during crises at https://radar.cloudflare.com/outages-center.`

### [IODA (Internet Outage Detection and Analysis)](https://ioda.inetintel.cc.gatech.edu/) `[A-Tier]`
- **ID**: `ioda` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `asn`, `coordinates`, `keyword` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Web · **Tags**: `internet-blackouts`, `conflict-osint`, `censorship`, `bgp-telemetry`
- **Overview**: Georgia Tech Internet Intelligence Lab dashboard detecting country, sub-national region, and ASN internet blackouts in near real time using BGP, active probing, and darknet telescope signals.
- **Quick-Start / Tradecraft**: `Verify regional wartime/election internet shutdown claims down to province and ASN level on IODA.`

### [OONI Explorer (Open Observatory of Network Interference)](https://explorer.ooni.org/) `[A-Tier]`
- **ID**: `ooni-explorer` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ooni/probe`](https://github.com/ooni/probe)
- **Inputs**: `domain`, `url`, `asn` → **Outputs**: `signal_telemetry`, `dns_records`
- **Platforms**: Web, Linux, macOS, Windows · **Tags**: `censorship-evidence`, `sni-blocking`, `dns-tampering`, `human-rights-osint`
- **Overview**: World's largest open dataset of empirical network censorship measurements across 200+ countries—proving DNS tampering, TLS SNI blocking, HTTP blocking, and instant-messaging blocks.
- **Quick-Start / Tradecraft**: `Query https://explorer.ooni.org/ by country + domain to cite cryptographic network-interference measurements.`

### [Censored Planet Observatory](https://censoredplanet.org/) `[B-Tier]`
- **ID**: `censored-planet` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`censoredplanet/censoredplanet-analysis`](https://github.com/censoredplanet/censoredplanet-analysis)
- **Inputs**: `domain`, `asn`, `keyword` → **Outputs**: `signal_telemetry`, `dns_records`
- **Platforms**: Web · **Tags**: `remote-censorship-measurement`, `middleboxes`, `dpi-detection`, `academic`
- **Overview**: University of Michigan remote measurement platform continuously tracking DNS, TCP/IP, HTTP, and HTTPS censorship middleboxes across 200+ countries without requiring local volunteer probes.
- **Quick-Start / Tradecraft**: `Explore Censored Planet Dashboard alongside OONI Explorer and IODA to triangulate state firewall changes.`

---

## Active Network Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Nmap**](https://nmap.org/) ([GitHub](https://github.com/nmap/nmap)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, certificates, tech_stack` |

### [Nmap](https://nmap.org/) `[A-Tier]`
- **ID**: `nmap` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`nmap/nmap`](https://github.com/nmap/nmap)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `certificates`, `tech_stack`
- **Platforms**: Linux, macOS, Windows, Docker · **Tags**: `port-scanner`, `nse-scripts`, `banner-grabbing`, `active-recon`
- **Overview**: Universal open-source network mapper and NSE scripting engine for authorized service banner grabbing, TLS cert extraction (`ssl-cert`), HTTP title enumeration, and OS fingerprinting.
- **Quick-Start / Tradecraft**: `nmap -sV --script=ssl-cert,http-title,http-favicon -p 80,443,8080,8443 target.example.com  # Active!`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🌐 Domains, DNS & ASM](./07-domain-dns-asm.md) · [💬 Social Media (SOCMINT) ▶](./09-social-media-socmint.md)

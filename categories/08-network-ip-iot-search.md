[⬅️ Back to Master Index](../README.md) · [◀ 🌐 Domains, DNS & ASM](./07-domain-dns-asm.md) · [💬 Social Media (SOCMINT) ▶](./09-social-media-socmint.md)

# 📡 08. Cyberspace Search Engines, IP, ASN, BGP & Internet Telemetry (`NETINT`)

> **Scope**: Internet-wide port/banner search engines, exposed IoT/ICS/OT device indexes, BGP/ASN routing analyzers, residential proxy/VPN detectors, and global internet outage monitors.
>
> **OPSEC Advisory**: Searching Shodan, Censys, FOFA, ZoomEye, Netlas, or GreyNoise queries pre-indexed scan databases and is completely passive with zero packets sent to the target IP.

**Discipline Telemetry**: `61` Verified Tools · `23` S-Tier Flagships · `36` Passive · `47` Free/Open-Source

## Subcategories
- [Cyberspace Banner Search Engines](#cyberspace-banner-search-engines) (12)
- [Scanner & Noise Intelligence](#scanner-noise-intelligence) (4)
- [ASN, BGP & GeoIP Intelligence](#asn,-bgp-geoip-intelligence) (8)
- [VPN, Proxy & Anonymizer Intel](#vpn,-proxy-anonymizer-intel) (1)
- [Internet Outage & Censorship Telemetry](#internet-outage-censorship-telemetry) (4)
- [Active Network Discovery](#active-network-discovery) (1)
- [Active Port & Banner Scanners](#active-port-banner-scanners) (5)
- [CIDR & Subnet Slicing](#cidr-subnet-slicing) (1)
- [Internet-Wide Active Research](#internet-wide-active-research) (3)
- [Service & Protocol Fingerprinting](#service-protocol-fingerprinting) (3)
- [TLS & Crypto Active Auditors](#tls-crypto-active-auditors) (2)
- [LAN & Enterprise Service Enum](#lan-enterprise-service-enum) (10)
- [Traffic Inspection & Replay](#traffic-inspection-replay) (1)
- [Vulnerability & CPE Intelligence](#vulnerability-cpe-intelligence) (1)
- [Packet & Traffic Forensics](#packet-traffic-forensics) (5)

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

## Active Port & Banner Scanners

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Masscan**](https://github.com/robertdavidgraham/masscan) ([GitHub](https://github.com/robertdavidgraham/masscan)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, asn` → `open_ports, ip_addresses, certificates` |
| **S** | [**RustScan**](https://github.com/bee-san/RustScan) ([GitHub](https://github.com/bee-san/RustScan)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, tech_stack` |
| **S** | [**Naabu (ProjectDiscovery)**](https://github.com/projectdiscovery/naabu) ([GitHub](https://github.com/projectdiscovery/naabu)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain, asn` → `open_ports, ip_addresses` |
| **A** | [**nmap-vulners NSE**](https://github.com/vulnersCom/nmap-vulners) ([GitHub](https://github.com/vulnersCom/nmap-vulners)) | Library | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, tech_stack, malware_iocs` |
| **A** | [**Vulscan (Nmap Offline CVE NSE)**](https://github.com/scipag/vulscan) ([GitHub](https://github.com/scipag/vulscan)) | Library | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, tech_stack, malware_iocs` |

### [Masscan](https://github.com/robertdavidgraham/masscan) `[S-Tier]`
- **ID**: `masscan` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`robertdavidgraham/masscan`](https://github.com/robertdavidgraham/masscan)
- **Inputs**: `ip`, `asn` → **Outputs**: `open_ports`, `ip_addresses`, `certificates`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `port-scanner`, `syn-scan`, `banner-grabbing`, `cidr`, `active`
- **Overview**: Asynchronous TCP SYN packet scanner capable of sweeping entire CIDR blocks or global IPv4 space in minutes with optional TCP/SSL banner grabbing.
- **Quick-Start / Tradecraft**: `sudo masscan 198.51.100.0/24 -p80,443,22,8080 --banners --rate 1000`

### [RustScan](https://github.com/bee-san/RustScan) `[S-Tier]`
- **ID**: `rustscan` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`bee-san/RustScan`](https://github.com/bee-san/RustScan)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Rust · **Tags**: `rust`, `port-scanner`, `nmap-pipeline`, `active`
- **Overview**: Modern async Rust active port scanner checking all 65,535 TCP ports in seconds and automatically piping open ports into Nmap service scripts.
- **Quick-Start / Tradecraft**: `rustscan -a example.com -- -sV -sC`

### [Naabu (ProjectDiscovery)](https://github.com/projectdiscovery/naabu) `[S-Tier]`
- **ID**: `naabu` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/naabu`](https://github.com/projectdiscovery/naabu)
- **Inputs**: `ip`, `domain`, `asn` → **Outputs**: `open_ports`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `port-scanner`, `projectdiscovery`, `syn-scan`, `active`
- **Overview**: Reliable Go SYN/CONNECT active port scanner featuring CDN/WAF IP exclusion, Nmap integration, ASN/CIDR input support, and JSON pipeline output.
- **Quick-Start / Tradecraft**: `naabu -host example.com -top-ports 1000 -exclude-cdn`

### [nmap-vulners NSE](https://github.com/vulnersCom/nmap-vulners) `[A-Tier]`
- **ID**: `nmap-vulners` · **Type**: `Library` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`vulnersCom/nmap-vulners`](https://github.com/vulnersCom/nmap-vulners)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `tech_stack`, `malware_iocs`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `nmap-nse`, `cve-mapping`, `service-scan`, `active`
- **Overview**: Nmap Scripting Engine (NSE) plugin correlating live `-sV` service banners from active scans directly against CVE and exploit intelligence.
- **Quick-Start / Tradecraft**: `nmap -sV --script vulners example.com`

### [Vulscan (Nmap Offline CVE NSE)](https://github.com/scipag/vulscan) `[A-Tier]`
- **ID**: `vulscan-nse` · **Type**: `Library` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`scipag/vulscan`](https://github.com/scipag/vulscan)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `tech_stack`, `malware_iocs`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `nmap-nse`, `offline-cve`, `active-scan`
- **Overview**: Offline-DB Nmap NSE module enriching active service-version scans (`nmap -sV`) with local NVD, Exploit-DB, and OSVDB vulnerability tables.
- **Quick-Start / Tradecraft**: `nmap -sV --script=vulscan/vulscan.nse example.com`

---

## CIDR & Subnet Slicing

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**mapcidr**](https://github.com/projectdiscovery/mapcidr) ([GitHub](https://github.com/projectdiscovery/mapcidr)) | CLI | OSS / Free | 🟢 Passive | ✅ | `asn, ip` → `ip_addresses` |

### [mapcidr](https://github.com/projectdiscovery/mapcidr) `[A-Tier]`
- **ID**: `mapcidr` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/mapcidr`](https://github.com/projectdiscovery/mapcidr)
- **Inputs**: `asn`, `ip` → **Outputs**: `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `cidr`, `subnet`, `projectdiscovery`, `netblocks`
- **Overview**: Subnet utility for slicing, aggregating, shuffling, and filtering CIDR netblocks prior to active port and HTTP sweeps.
- **Quick-Start / Tradecraft**: `mapcidr -cidr 198.51.100.0/24 -sbc 64`

---

## Internet-Wide Active Research

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ZMap**](https://github.com/zmap/zmap) ([GitHub](https://github.com/zmap/zmap)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, asn` → `open_ports, ip_addresses` |
| **S** | [**ZGrab 2.0**](https://github.com/zmap/zgrab2) ([GitHub](https://github.com/zmap/zgrab2)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, certificates, tech_stack` |
| **A** | [**ZDNS**](https://github.com/zmap/zdns) ([GitHub](https://github.com/zmap/zdns)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip` → `dns_records, ip_addresses` |

### [ZMap](https://github.com/zmap/zmap) `[S-Tier]`
- **ID**: `zmap` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`zmap/zmap`](https://github.com/zmap/zmap)
- **Inputs**: `ip`, `asn` → **Outputs**: `open_ports`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS · **Tags**: `zmap`, `internet-measurement`, `stateless-scan`, `active`
- **Overview**: Fast single-packet stateless network scanner built for academic and enterprise Internet-wide active measurement surveys.
- **Quick-Start / Tradecraft**: `sudo zmap -p 443 198.51.100.0/24 -o open_443.csv`

### [ZGrab 2.0](https://github.com/zmap/zgrab2) `[S-Tier]`
- **ID**: `zgrab2` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`zmap/zgrab2`](https://github.com/zmap/zgrab2)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `certificates`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Go · **Tags**: `banner-grabber`, `ics-scada`, `tls`, `ssh`, `zmap`, `active`
- **Overview**: Stateful Go application-layer active banner grabber supporting HTTP, TLS, SSH, SMTP, FTP, IMAP, MySQL, Postgres, Redis, Siemens S7, Modbus, and BACnet.
- **Quick-Start / Tradecraft**: `echo 198.51.100.10 | zgrab2 tls`

### [ZDNS](https://github.com/zmap/zdns) `[A-Tier]`
- **ID**: `zdns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`zmap/zdns`](https://github.com/zmap/zdns)
- **Inputs**: `domain`, `ip` → **Outputs**: `dns_records`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Go · **Tags**: `dns-scanner`, `zmap`, `bulk-dns`, `active`
- **Overview**: High-speed Go active DNS lookup utility built by the ZMap project outputting rich JSON telemetry including authority chains and resolver trace.
- **Quick-Start / Tradecraft**: `echo example.com | zdns A --name-servers=8.8.8.8:53`

---

## Service & Protocol Fingerprinting

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**fingerprintx (Praetorian)**](https://github.com/praetorian-inc/fingerprintx) ([GitHub](https://github.com/praetorian-inc/fingerprintx)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, tech_stack, certificates` |
| **S** | [**ssh-audit**](https://github.com/jtesta/ssh-audit) ([GitHub](https://github.com/jtesta/ssh-audit)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `tech_stack, open_ports, metadata` |
| **B** | [**rmiscout (Bishop Fox)**](https://github.com/BishopFox/rmiscout) ([GitHub](https://github.com/BishopFox/rmiscout)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, tech_stack, metadata` |

### [fingerprintx (Praetorian)](https://github.com/praetorian-inc/fingerprintx) `[S-Tier]`
- **ID**: `fingerprintx` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`praetorian-inc/fingerprintx`](https://github.com/praetorian-inc/fingerprintx)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `tech_stack`, `certificates`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `service-fingerprinting`, `praetorian`, `non-standard-ports`, `active`
- **Overview**: Standalone Go active service fingerprinter identifying 40+ TCP/UDP protocols (HTTP, SSH, RDP, RTSP, MQTT, Kafka, JDWP, IPSec, SNMP) on arbitrary ports.
- **Quick-Start / Tradecraft**: `naabu -host example.com -silent | fingerprintx --json`

### [ssh-audit](https://github.com/jtesta/ssh-audit) `[S-Tier]`
- **ID**: `ssh-audit` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`jtesta/ssh-audit`](https://github.com/jtesta/ssh-audit)
- **Inputs**: `ip`, `domain` → **Outputs**: `tech_stack`, `open_ports`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `ssh`, `kexinit`, `banner-fingerprinting`, `os-detection`, `active`
- **Overview**: Zero-dependency Python active SSH server & client fingerprinter grabbing SSH banners, host-key algorithms, KEX/MAC lists, and inferring OS/distro builds.
- **Quick-Start / Tradecraft**: `ssh-audit -j example.com`

### [rmiscout (Bishop Fox)](https://github.com/BishopFox/rmiscout) `[B-Tier]`
- **ID**: `rmiscout` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`BishopFox/rmiscout`](https://github.com/BishopFox/rmiscout)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `java-rmi`, `service-enum`, `bishopfox`, `active`
- **Overview**: Active Java RMI registry inspector enumerating exposed RMI object names and method signatures across enterprise application ports.
- **Quick-Start / Tradecraft**: `rmiscout.sh wordlist -i names.txt 198.51.100.10 1099`

---

## TLS & Crypto Active Auditors

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**testssl.sh**](https://github.com/drwetter/testssl.sh) ([GitHub](https://github.com/drwetter/testssl.sh)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip, url` → `certificates, tech_stack, metadata` |
| **A** | [**SSLyze**](https://github.com/nabla-c0d3/sslyze) ([GitHub](https://github.com/nabla-c0d3/sslyze)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip` → `certificates, subdomains, metadata` |

### [testssl.sh](https://github.com/drwetter/testssl.sh) `[S-Tier]`
- **ID**: `testssl-sh` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`drwetter/testssl.sh`](https://github.com/drwetter/testssl.sh)
- **Inputs**: `domain`, `ip`, `url` → **Outputs**: `certificates`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Docker · **Tags**: `tls`, `ssl`, `x509`, `starttls`, `ciphers`, `active`
- **Overview**: Gold-standard portable Bash active SSL/TLS scanner inspecting protocols (SSLv2–TLSv1.3), ciphers, X.509 chains, STARTTLS services, ALPN, and flaws.
- **Quick-Start / Tradecraft**: `testssl.sh --fast https://example.com`

### [SSLyze](https://github.com/nabla-c0d3/sslyze) `[A-Tier]`
- **ID**: `sslyze` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`nabla-c0d3/sslyze`](https://github.com/nabla-c0d3/sslyze)
- **Inputs**: `domain`, `ip` → **Outputs**: `certificates`, `subdomains`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `ssl`, `tls`, `certificates`, `ocsp`, `active`
- **Overview**: Fast Python CLI and library for active SSL/TLS server configuration scanning, certificate SAN extraction, OCSP stapling checks, and elliptic curve enumeration.
- **Quick-Start / Tradecraft**: `sslyze example.com:443 --json_out=tls_report.json`

---

## LAN & Enterprise Service Enum

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**arp-scan**](https://github.com/royhills/arp-scan) ([GitHub](https://github.com/royhills/arp-scan)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip` → `ip_addresses, metadata, tech_stack` |
| **S** | [**NetExec (nxc)**](https://github.com/Pennyw0rth/NetExec) ([GitHub](https://github.com/Pennyw0rth/NetExec)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `open_ports, tech_stack, usernames` |
| **A** | [**enum4linux-ng**](https://github.com/cddmp/enum4linux-ng) ([GitHub](https://github.com/cddmp/enum4linux-ng)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `usernames, tech_stack, metadata` |
| **A** | [**SMBMap**](https://github.com/ShawnDEvans/smbmap) ([GitHub](https://github.com/ShawnDEvans/smbmap)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `documents, metadata, open_ports` |
| **A** | [**onesixtyone**](https://github.com/trailofbits/onesixtyone) ([GitHub](https://github.com/trailofbits/onesixtyone)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, asn` → `tech_stack, open_ports, metadata` |
| **A** | [**windapsearch**](https://github.com/ropnop/windapsearch) ([GitHub](https://github.com/ropnop/windapsearch)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `usernames, emails, person_records` |
| **S** | [**Impacket Network Protocol Scripts**](https://github.com/fortra/impacket) ([GitHub](https://github.com/fortra/impacket)) | Framework | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `tech_stack, usernames, metadata` |
| **S** | [**BloodHound Community Edition**](https://github.com/SpecterOps/BloodHound) ([GitHub](https://github.com/SpecterOps/BloodHound)) | Desktop App | OSS / Free | 🔴 Active | ✅ | `domain, company` → `entity_graph, usernames, person_records` |
| **A** | [**Certipy**](https://github.com/ly4k/Certipy) ([GitHub](https://github.com/ly4k/Certipy)) | CLI | OSS / Free | 🔴 Active | 🔑 | `domain, ip` → `certificates, tech_stack, entity_graph` |
| **A** | [**Responder**](https://github.com/lgandx/Responder) ([GitHub](https://github.com/lgandx/Responder)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `ip` → `usernames, tech_stack, ip_addresses` |

### [arp-scan](https://github.com/royhills/arp-scan) `[A-Tier]`
- **ID**: `arp-scan` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`royhills/arp-scan`](https://github.com/royhills/arp-scan)
- **Inputs**: `ip` → **Outputs**: `ip_addresses`, `metadata`, `tech_stack`
- **Platforms**: CLI, Linux, macOS · **Tags**: `arp`, `mac-oui`, `layer2`, `lan-discovery`, `active`
- **Overview**: Active Layer-2 ARP packet scanner discovering all live hosts on local Ethernet/Wi-Fi segments and mapping MAC hardware addresses to IEEE OUI vendors.
- **Quick-Start / Tradecraft**: `sudo arp-scan --localnet`

### [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) `[S-Tier]`
- **ID**: `netexec` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`Pennyw0rth/NetExec`](https://github.com/Pennyw0rth/NetExec)
- **Inputs**: `ip`, `domain` → **Outputs**: `open_ports`, `tech_stack`, `usernames`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `smb`, `ldap`, `active-directory`, `winrm`, `active-enum`
- **Overview**: Community-maintained successor to CrackMapExec performing rapid active SMB, LDAP, WinRM, MSSQL, RDP, SSH, and FTP host/domain/signing metadata enumeration.
- **Quick-Start / Tradecraft**: `nxc smb 198.51.100.0/24`

### [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) `[A-Tier]`
- **ID**: `enum4linux-ng` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`cddmp/enum4linux-ng`](https://github.com/cddmp/enum4linux-ng)
- **Inputs**: `ip`, `domain` → **Outputs**: `usernames`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Docker, Python · **Tags**: `smb`, `rpc`, `netbios`, `samba`, `active-enum`
- **Overview**: Modern Python rewrite of enum4linux actively enumerating Windows/Samba SMB/RPC/NetBIOS shares, OS versions, AD domain SIDs, and users with JSON export.
- **Quick-Start / Tradecraft**: `enum4linux-ng -A 198.51.100.10 -oJ smb_recon`

### [SMBMap](https://github.com/ShawnDEvans/smbmap) `[A-Tier]`
- **ID**: `smbmap` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`ShawnDEvans/smbmap`](https://github.com/ShawnDEvans/smbmap)
- **Inputs**: `ip`, `domain` → **Outputs**: `documents`, `metadata`, `open_ports`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `smb`, `null-session`, `shares`, `active`
- **Overview**: Active SMB share enumeration tool listing drive permissions, anonymous/null-session shares, and directory trees across target hosts and subnets.
- **Quick-Start / Tradecraft**: `smbmap -H 198.51.100.10 -u '' -p ''`

### [onesixtyone](https://github.com/trailofbits/onesixtyone) `[A-Tier]`
- **ID**: `onesixtyone` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`trailofbits/onesixtyone`](https://github.com/trailofbits/onesixtyone)
- **Inputs**: `ip`, `asn` → **Outputs**: `tech_stack`, `open_ports`, `metadata`
- **Platforms**: CLI, Linux, macOS · **Tags**: `snmp`, `udp-161`, `router-recon`, `trailofbits`, `active`
- **Overview**: Fast UDP/161 active SNMP scanner maintained by Trail of Bits for discovering exposed SNMP community strings and sysDescr hardware/OS banners.
- **Quick-Start / Tradecraft**: `onesixtyone -c communities.txt -i hosts.txt`

### [windapsearch](https://github.com/ropnop/windapsearch) `[A-Tier]`
- **ID**: `windapsearch` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`ropnop/windapsearch`](https://github.com/ropnop/windapsearch)
- **Inputs**: `ip`, `domain` → **Outputs**: `usernames`, `emails`, `person_records`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `ldap`, `active-directory`, `domain-controller`, `active`
- **Overview**: Fast Go CLI actively querying LDAP/LDAPS domain controllers to enumerate Active Directory domain naming contexts, users, SPNs, and computers.
- **Quick-Start / Tradecraft**: `windapsearch -d dc.example.com -m metadata`

### [Impacket Network Protocol Scripts](https://github.com/fortra/impacket) `[S-Tier]`
- **ID**: `impacket-recon` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`fortra/impacket`](https://github.com/fortra/impacket)
- **Inputs**: `ip`, `domain` → **Outputs**: `tech_stack`, `usernames`, `metadata`, `open_ports`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `ntlm-info`, `rpc`, `smb`, `os-version`, `active`
- **Overview**: Canonical Python network protocol suite featuring `rpcdump.py`, `samrdump.py`, `DumpNTLMInfo.py`, and `lookupsid.py` for active Windows/SMB/RPC OS/domain fingerprinting.
- **Quick-Start / Tradecraft**: `DumpNTLMInfo.py 198.51.100.10`

### [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) `[S-Tier]`
- **ID**: `bloodhound-ce` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`SpecterOps/BloodHound`](https://github.com/SpecterOps/BloodHound)
- **Inputs**: `domain`, `company` → **Outputs**: `entity_graph`, `usernames`, `person_records`
- **Platforms**: Web, Linux, macOS, Windows, Docker, Go · **Tags**: `active-directory`, `graph-analysis`, `entra-id`, `specterops`
- **Overview**: Graph-theory Active Directory and Entra ID relationship analyzer visualizing domain trusts, group memberships, and identity attack paths.
- **Quick-Start / Tradecraft**: `bloodhound-cli containers up`

### [Certipy](https://github.com/ly4k/Certipy) `[A-Tier]`
- **ID**: `certipy-ad` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`ly4k/Certipy`](https://github.com/ly4k/Certipy)
- **Inputs**: `domain`, `ip` → **Outputs**: `certificates`, `tech_stack`, `entity_graph`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `adcs`, `enterprise-pki`, `certificates`, `active`
- **Overview**: Active Directory Certificate Services (AD CS) enumerator mapping enterprise PKI CAs, certificate templates, and enrollment endpoints.
- **Quick-Start / Tradecraft**: `certipy find -u user@corp.local -dc-ip 10.0.0.1`

### [Responder](https://github.com/lgandx/Responder) `[A-Tier]`
- **ID**: `responder-llmnr` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`lgandx/Responder`](https://github.com/lgandx/Responder)
- **Inputs**: `ip` → **Outputs**: `usernames`, `tech_stack`, `ip_addresses`
- **Platforms**: CLI, Linux, Python · **Tags**: `llmnr`, `mdns`, `netbios`, `lan-osint`
- **Overview**: Local network LLMNR, NBT-NS, and mDNS analyzer (`--analyze` passive mode) inventorying broadcast hostnames, OS builds, and SMB signing posture.
- **Quick-Start / Tradecraft**: `sudo python3 Responder.py -I eth0 --analyze`

---

## Traffic Inspection & Replay

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Proxify (ProjectDiscovery)**](https://github.com/projectdiscovery/proxify) ([GitHub](https://github.com/projectdiscovery/proxify)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, metadata, secrets` |

### [Proxify (ProjectDiscovery)](https://github.com/projectdiscovery/proxify) `[A-Tier]`
- **ID**: `proxify` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/proxify`](https://github.com/projectdiscovery/proxify)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `metadata`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `mitm-proxy`, `http-capture`, `projectdiscovery`, `active`
- **Overview**: Portable MITM HTTP/HTTPS/SOCKS5 capture and traffic-dumping proxy recording every endpoint and header touched during active browser recon.
- **Quick-Start / Tradecraft**: `proxify -http-addr 127.0.0.1:8888 -output traffic_logs/`

---

## Vulnerability & CPE Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**vulnx (ProjectDiscovery)**](https://github.com/projectdiscovery/vulnx) ([GitHub](https://github.com/projectdiscovery/vulnx)) | CLI | OSS / Free | 🟢 Passive | ✅ | `keyword` → `malware_iocs, tech_stack, metadata` |

### [vulnx (ProjectDiscovery)](https://github.com/projectdiscovery/vulnx) `[A-Tier]`
- **ID**: `vulnx-cli` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/vulnx`](https://github.com/projectdiscovery/vulnx)
- **Inputs**: `keyword` → **Outputs**: `malware_iocs`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `cve`, `kev`, `epss`, `projectdiscovery`
- **Overview**: Fast CLI querying CVE, EPSS, KEV, CPE, and Nuclei template coverage across fingerprinted server versions discovered during active recon.
- **Quick-Start / Tradecraft**: `vulnx search 'openssh' --json`

---

## Packet & Traffic Forensics

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Wireshark / tshark**](https://github.com/wireshark/wireshark) ([GitHub](https://github.com/wireshark/wireshark)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `document, ip, mac_bssid` → `ip_addresses, dns_records, certificates` |
| **S** | [**Zeek Network Security Monitor**](https://github.com/zeek/zeek) ([GitHub](https://github.com/zeek/zeek)) | Framework | OSS / Free | 🟢 Passive | ✅ | `document, ip` → `dns_records, certificates, urls` |
| **S** | [**Suricata**](https://github.com/OISF/suricata) ([GitHub](https://github.com/OISF/suricata)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, ip` → `malware_iocs, dns_records, certificates` |
| **A** | [**Malcolm (CISA Network Traffic Suite)**](https://github.com/cisagov/Malcolm) ([GitHub](https://github.com/cisagov/Malcolm)) | Framework | OSS / Free | 🟢 Passive | ✅ | `document, ip, domain` → `entity_graph, dns_records, ip_addresses` |
| **B** | [**nDPI (Deep Packet Inspection)**](https://github.com/ntop/nDPI) ([GitHub](https://github.com/ntop/nDPI)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, ip` → `tech_stack, metadata, ip_addresses` |

### [Wireshark / tshark](https://github.com/wireshark/wireshark) `[S-Tier]`
- **ID**: `wireshark` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`wireshark/wireshark`](https://github.com/wireshark/wireshark)
- **Inputs**: `document`, `ip`, `mac_bssid` → **Outputs**: `ip_addresses`, `dns_records`, `certificates`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `pcap`, `tshark`, `protocol-dissection`, `tls-sni`
- **Overview**: Industry-standard network protocol analyzer and `tshark` CLI dissecting 3,000+ protocols, TLS SNIs, DNS queries, and JA3/JA4 fingerprints from PCAPs.
- **Quick-Start / Tradecraft**: `tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name`

### [Zeek Network Security Monitor](https://github.com/zeek/zeek) `[S-Tier]`
- **ID**: `zeek-nsm` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`zeek/zeek`](https://github.com/zeek/zeek)
- **Inputs**: `document`, `ip` → **Outputs**: `dns_records`, `certificates`, `urls`, `malware_iocs`
- **Platforms**: CLI, Linux, macOS, Docker · **Tags**: `zeek`, `pcap-osint`, `passive-dns`, `x509`
- **Overview**: Passive network traffic analysis framework converting PCAPs into structured `dns.log`, `ssl.log`, `http.log`, `x509.log`, and file-hash telemetry.
- **Quick-Start / Tradecraft**: `zeek -r capture.pcap`

### [Suricata](https://github.com/OISF/suricata) `[S-Tier]`
- **ID**: `suricata-ids` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`OISF/suricata`](https://github.com/OISF/suricata)
- **Inputs**: `document`, `ip` → **Outputs**: `malware_iocs`, `dns_records`, `certificates`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Rust · **Tags**: `eve-json`, `ja4`, `pcap-analysis`, `ids`
- **Overview**: High-performance network threat engine extracting `eve.json` HTTP, TLS JA3/JA4, DNS, SSH, and malware IOC alerts from packet captures.
- **Quick-Start / Tradecraft**: `suricata -r capture.pcap -l ./logs`

### [Malcolm (CISA Network Traffic Suite)](https://github.com/cisagov/Malcolm) `[A-Tier]`
- **ID**: `cisa-malcolm` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`cisagov/Malcolm`](https://github.com/cisagov/Malcolm)
- **Inputs**: `document`, `ip`, `domain` → **Outputs**: `entity_graph`, `dns_records`, `ip_addresses`, `malware_iocs`
- **Platforms**: Web, Linux, macOS, Docker · **Tags**: `cisa`, `arkime`, `zeek`, `pcap-graph`
- **Overview**: CISA's turnkey PCAP and Zeek/Arkime/Suricata visual analytics stack for deep network forensics, ASN mapping, and protocol graphing.
- **Quick-Start / Tradecraft**: `./scripts/start # Upload PCAP in Arkime/Dashboards`

### [nDPI (Deep Packet Inspection)](https://github.com/ntop/nDPI) `[B-Tier]`
- **ID**: `ntop-ndpi` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ntop/nDPI`](https://github.com/ntop/nDPI)
- **Inputs**: `document`, `ip` → **Outputs**: `tech_stack`, `metadata`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `dpi`, `encrypted-traffic`, `ja3`, `pcap`
- **Overview**: Open-source deep packet inspection toolkit (`ndpiReader`) identifying encrypted application protocols, VPNs, Tor, and TLS fingerprints.
- **Quick-Start / Tradecraft**: `ndpiReader -i capture.pcap -v 2`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🌐 Domains, DNS & ASM](./07-domain-dns-asm.md) · [💬 Social Media (SOCMINT) ▶](./09-social-media-socmint.md)

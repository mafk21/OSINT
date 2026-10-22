[⬅️ Back to Master Index](../README.md) · [◀ 🔓 Breaches & Infostealers](./06-breaches-leaks-stealers.md) · [📡 Cyberspace & Network Search ▶](./08-network-ip-iot-search.md)

# 🌐 07. Domain, DNS, Certificate Transparency & Attack Surface Management (`DNSINT`)

> **Scope**: Passive DNS history, RDAP/WHOIS attribution, Certificate Transparency (CT) log monitors, subdomain enumerators, typosquatting detectors, and web technology profilers.
>
> **OPSEC Advisory**: Querying Certificate Transparency (`crt.sh`), passive DNS (`SecurityTrails`), and RDAP is 100% passive. Running `httpx`, `Katana`, or DNS brute-forcing touches target servers and leaves logs.

**Discipline Telemetry**: `38` Verified Tools · `11` S-Tier Flagships · `24` Passive · `29` Free/Open-Source

## Subcategories
- [Tech Profiling & Tag Pivoting](#tech-profiling-tag-pivoting) (4)
- [Certificate Transparency](#certificate-transparency) (3)
- [Passive DNS & Historical WHOIS](#passive-dns-historical-whois) (12)
- [Brand & Typosquatting Recon](#brand-typosquatting-recon) (2)
- [Active Web Probing & Crawling](#active-web-probing-crawling) (5)
- [Subdomain & Asset Discovery](#subdomain-asset-discovery) (6)
- [Archive URL Mining](#archive-url-mining) (4)
- [DNS Diagnostics & Topology](#dns-diagnostics-topology) (2)

---

## Tech Profiling & Tag Pivoting

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**BuiltWith**](https://builtwith.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, url, keyword` → `tech_stack, entity_graph` |
| **A** | [**DNSlytics**](https://dnslytics.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, ip, asn` → `dns_records, whois, ip_addresses` |
| **A** | [**Wappalyzer**](https://www.wappalyzer.com/) | Browser Extension | Freemium | 🟢 Passive | ✅ | `url, domain` → `tech_stack` |
| **B** | [**WhatWeb**](https://github.com/urbanadventurer/WhatWeb) ([GitHub](https://github.com/urbanadventurer/WhatWeb)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain, ip` → `tech_stack, metadata` |

### [BuiltWith](https://builtwith.com/) `[S-Tier]`
- **ID**: `builtwith` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `url`, `keyword` → **Outputs**: `tech_stack`, `entity_graph`
- **Platforms**: Web, Chrome, Firefox · **Tags**: `analytics-pivot`, `adsense-id`, `tech-profiler`, `relationships-tab`, `flagship`
- **Overview**: Profiles 100,000+ web technologies AND tracks shared Google Analytics, Tag Manager, AdSense, Facebook Pixel, and Cloudflare IDs across historical crawls to link covert sister sites.
- **Quick-Start / Tradecraft**: `Open the 'Relationships' tab (`builtwith.com/relationships/example.com`) to reveal hidden sites sharing analytics/pixel IDs!`

### [DNSlytics](https://dnslytics.com/) `[A-Tier]`
- **ID**: `dnslytics` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `ip`, `asn`, `keyword` → **Outputs**: `dns_records`, `whois`, `ip_addresses`, `entity_graph`
- **Platforms**: Web, Chrome, Firefox · **Tags**: `reverse-adsense`, `reverse-mx`, `spf-pivoting`, `asn-intel`
- **Overview**: Domain, IP, ASN, and reverse-tracker intelligence engine supporting Reverse Analytics, Reverse AdSense, Reverse NS/MX, and SPF domain relationship mapping.
- **Quick-Start / Tradecraft**: `Pivot on SPF `include:` mechanisms and shared nameservers via https://dnslytics.com/.`

### [Wappalyzer](https://www.wappalyzer.com/) `[A-Tier]`
- **ID**: `wappalyzer` · **Type**: `Browser Extension` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `url`, `domain` → **Outputs**: `tech_stack`
- **Platforms**: Chrome, Firefox, Web · **Tags**: `tech-stack`, `cms-detection`, `browser-extension`, `waf-cdn`
- **Overview**: Browser extension and technographic lookup identifying CMS platforms, JS frameworks, WAFs, CDNs, analytics trackers, payment processors, and server headers on any webpage.
- **Quick-Start / Tradecraft**: `Install Wappalyzer in your investigation browser to fingerprint web stacks passively as you browse.`

### [WhatWeb](https://github.com/urbanadventurer/WhatWeb) `[B-Tier]`
- **ID**: `whatweb` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`urbanadventurer/WhatWeb`](https://github.com/urbanadventurer/WhatWeb)
- **Inputs**: `url`, `domain`, `ip` → **Outputs**: `tech_stack`, `metadata`
- **Platforms**: Linux, macOS, Docker · **Tags**: `1800-plugins`, `fingerprinting`, `kali-default`, `cms-scanner`
- **Overview**: Next-generation web scanner packing 1,800+ plugins to fingerprint CMS versions, blogging platforms, JS libraries, analytics IDs, web servers, and embedded IoT admin panels.
- **Quick-Start / Tradecraft**: `whatweb -a 1 https://example.com  # Stealthy single-request aggression level 1`

---

## Certificate Transparency

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**crt.sh (Certificate Transparency Search)**](https://crt.sh/) ([GitHub](https://github.com/crtsh/certwatch_db)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `domain, company` → `certificates, subdomains` |
| **A** | [**Cert Spotter**](https://sslmate.com/certspotter/) ([GitHub](https://github.com/SSLMate/certspotter)) | CLI | Freemium | 🟢 Passive | ✅ | `domain` → `certificates, subdomains` |
| **A** | [**tlsx (ProjectDiscovery)**](https://github.com/projectdiscovery/tlsx) ([GitHub](https://github.com/projectdiscovery/tlsx)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain, asn` → `certificates, subdomains` |

### [crt.sh (Certificate Transparency Search)](https://crt.sh/) `[S-Tier]`
- **ID**: `crt-sh` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`crtsh/certwatch_db`](https://github.com/crtsh/certwatch_db)
- **Inputs**: `domain`, `company` → **Outputs**: `certificates`, `subdomains`
- **Platforms**: Web, CLI · **Tags**: `certificate-transparency`, `keyless-api`, `postgres-sql`, `subdomains`, `flagship`
- **Overview**: Sectigo's free, keyless Certificate Transparency log search engine with direct public PostgreSQL SQL access (`crt.sh:5432`)—exposing every publicly trusted SSL/TLS cert and SAN subdomain ever issued.
- **Quick-Start / Tradecraft**: `curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u`

### [Cert Spotter](https://sslmate.com/certspotter/) `[A-Tier]`
- **ID**: `certspotter` · **Type**: `CLI` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`SSLMate/certspotter`](https://github.com/SSLMate/certspotter)
- **Inputs**: `domain` → **Outputs**: `certificates`, `subdomains`
- **Platforms**: Linux, macOS, Go, Web · **Tags**: `ct-monitoring`, `sslmate`, `shadow-it`, `golang`
- **Overview**: Open-source Go daemon and SSLMate API monitoring Certificate Transparency logs in real time for unauthorized certificates, shadow IT subdomains, and phishing clones.
- **Quick-Start / Tradecraft**: `curl -s 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names' | jq`

### [tlsx (ProjectDiscovery)](https://github.com/projectdiscovery/tlsx) `[A-Tier]`
- **ID**: `tlsx` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/tlsx`](https://github.com/projectdiscovery/tlsx)
- **Inputs**: `ip`, `domain`, `asn` → **Outputs**: `certificates`, `subdomains`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `san-extraction`, `jarm`, `cidr-cert-scan`
- **Overview**: Fast TLS connection grabber extracting SAN/CN domain lists, JARM hashes, JA3 fingerprints, certificate serials, and expired/mismatched origin certificates across CIDR blocks.
- **Quick-Start / Tradecraft**: `echo 198.51.100.0/24 | tlsx -san -cn -silent  # Reveals virtual-host domains bound to raw IPs!`

---

## Passive DNS & Historical WHOIS

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**DNSDumpster**](https://dnsdumpster.com/) | Web Platform | Free | 🟢 Passive | ✅ | `domain` → `dns_records, subdomains, ip_addresses` |
| **S** | [**ICANN Centralized Zone Data Service (CZDS)**](https://czds.icann.org/) | Dataset / Registry | Free | 🟢 Passive | 🔑 | `domain, keyword` → `dns_records, subdomains` |
| **S** | [**SecurityTrails**](https://securitytrails.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `domain, ip, email` → `dns_records, subdomains, whois` |
| **S** | [**Whoxy**](https://www.whoxy.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, email, person_name` → `whois, subdomains, emails` |
| **A** | [**DomainTools Iris**](https://www.domaintools.com/) | Web Platform | Paid | 🟢 Passive | 🔑 | `domain, ip, email` → `whois, dns_records, entity_graph` |
| **A** | [**ICANN Lookup (Official RDAP)**](https://lookup.icann.org/) | Web Platform | Free | 🟢 Passive | ✅ | `domain` → `whois, dns_records` |
| **A** | [**RapidDNS**](https://rapiddns.io/) | Search Engine | Free | 🟢 Passive | ✅ | `domain, ip` → `subdomains, dns_records, ip_addresses` |
| **A** | [**ViewDNS.info**](https://viewdns.info/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, ip, email` → `dns_records, whois, ip_addresses` |
| **B** | [**CompleteDNS (Historical Nameserver Changes)**](https://completedns.com/dns-history/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `domain` → `dns_records, whois` |
| **B** | [**digga**](https://github.com/nicholasgasior/digga) | Web Platform | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `dns_records, whois, certificates` |
| **B** | [**DomainBigData**](https://domainbigdata.com/) | Web Platform | Free | 🟢 Passive | ✅ | `domain, email, person_name` → `whois, emails, ip_addresses` |
| **B** | [**Robtex**](https://www.robtex.com/) | Web Platform | Free | 🟢 Passive | ✅ | `domain, ip, asn` → `dns_records, ip_addresses, entity_graph` |

### [DNSDumpster](https://dnsdumpster.com/) `[S-Tier]`
- **ID**: `dnsdumpster` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `subdomains`, `ip_addresses`, `entity_graph`
- **Platforms**: Web · **Tags**: `dns-graph`, `subdomain-map`, `xlsx-export`, `hackertarget`
- **Overview**: HackerTarget's free domain reconnaissance portal mapping MX, NS, TXT, A records, netblock owners, open banners, and auto-generated network topology graphs.
- **Quick-Start / Tradecraft**: `Query any domain on https://dnsdumpster.com/ and download the XLSX host spreadsheet and PNG topology map.`

### [ICANN Centralized Zone Data Service (CZDS)](https://czds.icann.org/) `[S-Tier]`
- **ID**: `icann-czds` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain`, `keyword` → **Outputs**: `dns_records`, `subdomains`
- **Platforms**: Web, Python · **Tags**: `full-zone-files`, `gtld-zones`, `newly-registered-domains`, `icann-official`, `flagship`
- **Overview**: Official free ICANN portal allowing researchers to request and download complete daily authoritative DNS zone files (`.com`, `.net`, `.org`, and 1,100+ gTLDs)—every active domain name on Earth!
- **Quick-Start / Tradecraft**: `Apply free at https://czds.icann.org/ to `ripgrep` raw daily TLD zone files locally for brand/keyword monitoring with zero API fees!`

### [SecurityTrails](https://securitytrails.com/) `[S-Tier]`
- **ID**: `securitytrails` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain`, `ip`, `email` → **Outputs**: `dns_records`, `subdomains`, `whois`, `ip_addresses`
- **Platforms**: Web · **Tags**: `historical-dns`, `origin-ip`, `cloudflare-bypass`, `whois-history`, `flagship`
- **Overview**: Premier historical DNS and WHOIS time-machine tracking multi-year A, AAAA, MX, NS, and TXT record changes—essential for unmasking pre-Cloudflare origin server IPs.
- **Quick-Start / Tradecraft**: `Inspect Historical A Records on SecurityTrails to locate the origin IP before a domain migrated behind a CDN.`

### [Whoxy](https://www.whoxy.com/) `[S-Tier]`
- **ID**: `whoxy` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `email`, `person_name`, `company` → **Outputs**: `whois`, `subdomains`, `emails`
- **Platforms**: Web · **Tags**: `reverse-whois`, `historical-whois`, `pre-gdpr`, `sister-domains`
- **Overview**: High-value historical WHOIS and Reverse WHOIS API/search engine indexing pre-GDPR registrant names, emails, company strings, and 20+ years of domain ownership changes.
- **Quick-Start / Tradecraft**: `Run Reverse WHOIS by email or company name at https://www.whoxy.com/ to uncover every domain registered by the same actor.`

### [DomainTools Iris](https://www.domaintools.com/) `[A-Tier]`
- **ID**: `domaintools` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain`, `ip`, `email` → **Outputs**: `whois`, `dns_records`, `entity_graph`, `malware_iocs`
- **Platforms**: Web · **Tags**: `iris-investigate`, `enterprise-cti`, `whois-archive`, `domain-risk`
- **Overview**: Enterprise domain intelligence standard offering 20+ years of WHOIS snapshots, Passive DNS, domain risk scoring, and multi-hop infrastructure pivot graphs for CTI teams.
- **Quick-Start / Tradecraft**: `Pivot across shared SSL hashes, registrant emails, and nameserver clusters inside DomainTools Iris.`

### [ICANN Lookup (Official RDAP)](https://lookup.icann.org/) `[A-Tier]`
- **ID**: `icann-lookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain` → **Outputs**: `whois`, `dns_records`
- **Platforms**: Web · **Tags**: `rdap`, `authoritative-whois`, `icann`, `domain-age`
- **Overview**: Authoritative Registration Data Access Protocol (RDAP) client querying gTLD registries directly for registrar IANA IDs, registry lock status, creation/expiry timestamps, and nameservers.
- **Quick-Start / Tradecraft**: `Query https://lookup.icann.org/ or raw JSON RDAP (`https://rdap.org/domain/example.com`).`

### [RapidDNS](https://rapiddns.io/) `[A-Tier]`
- **ID**: `rapiddns` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `ip` → **Outputs**: `subdomains`, `dns_records`, `ip_addresses`
- **Platforms**: Web · **Tags**: `keyless-subdomains`, `reverse-ip`, `cidr-dns`, `fast-passive`
- **Overview**: Fast, completely free, keyless web and API passive DNS lookup returning subdomains (`rapiddns.io/subdomain/example.com`) and same-IP virtual hosts (`rapiddns.io/sameip/<IP>`).
- **Quick-Start / Tradecraft**: `curl -s 'https://rapiddns.io/subdomain/example.com?full=1' | grep -oE '[a-zA-Z0-9._-]+\.example\.com' | sort -u`

### [ViewDNS.info](https://viewdns.info/) `[A-Tier]`
- **ID**: `viewdns-info` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `ip`, `email`, `person_name` → **Outputs**: `dns_records`, `whois`, `ip_addresses`
- **Platforms**: Web · **Tags**: `ip-history`, `reverse-ip`, `reverse-ns`, `swiss-army-knife`
- **Overview**: Swiss-army web toolkit bundling 20+ domain/IP utilities: Reverse IP Lookup, Reverse WHOIS, IP History,Reverse MX/NS, Chinese Firewall Test, DNSSEC check, and ASN lookup.
- **Quick-Start / Tradecraft**: `Use ViewDNS IP History (`viewdns.info/iphistory/`) as a fast keyless check for historical origin IPs.`

### [CompleteDNS (Historical Nameserver Changes)](https://completedns.com/dns-history/) `[B-Tier]`
- **ID**: `completedns` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `whois`
- **Platforms**: Web · **Tags**: `ns-history`, `nameserver-changes`, `domain-transfers`
- **Overview**: Tracks multi-year authoritative `NS` nameserver history for domains—helpful for spotting when a domain switched from registrar parking to Cloudflare or bulletproof hosting.
- **Quick-Start / Tradecraft**: `Inspect historical NS transitions to date exact domain ownership handovers.`

### [digga](https://github.com/nicholasgasior/digga) `[B-Tier]`
- **ID**: `digga` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `whois`, `certificates`, `subdomains`
- **Platforms**: Web, CLI · **Tags**: `rdap`, `spf-dmarc`, `tls`, `no-account`
- **Overview**: Browser and CLI domain research toolkit combining DNS, RDAP, WHOIS, passive subdomain discovery, IP/ASN enrichment, SPF/DMARC checks, and TLS inspection with no signup.
- **Quick-Start / Tradecraft**: `Run quick domain diagnostics via digga for unified RDAP, DNS, email-auth, and TLS chain output.`

### [DomainBigData](https://domainbigdata.com/) `[B-Tier]`
- **ID**: `domainbigdata` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `email`, `person_name` → **Outputs**: `whois`, `emails`, `ip_addresses`
- **Platforms**: Web · **Tags**: `legacy-whois`, `reverse-registrant`, `free-whois-pivot`
- **Overview**: Free historical WHOIS, registrant name, registrant email, and same-IP correlation portal useful for unmasking pre-redaction legacy domain portfolios.
- **Quick-Start / Tradecraft**: `Query registrant emails or legacy personal domains on https://domainbigdata.com/.`

### [Robtex](https://www.robtex.com/) `[B-Tier]`
- **ID**: `robtex` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `ip`, `asn` → **Outputs**: `dns_records`, `ip_addresses`, `entity_graph`
- **Platforms**: Web · **Tags**: `passive-dns`, `route-graph`, `shared-ip`, `free`
- **Overview**: Veteran passive DNS, BGP route, Autonomous System, and shared-host relationship grapher visualizing forward and reverse DNS links.
- **Quick-Start / Tradecraft**: `Inspect `https://www.robtex.com/dns-lookup/example.com` for quick shared-nameserver and BGP route graphs.`

---

## Brand & Typosquatting Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**dnstwist**](https://github.com/elceef/dnstwist) ([GitHub](https://github.com/elceef/dnstwist)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, ip_addresses, whois` |
| **A** | [**openSquat**](https://github.com/atenreiro/opensquat) ([GitHub](https://github.com/atenreiro/opensquat)) | CLI | OSS / Free | 🟢 Passive | ✅ | `keyword, domain` → `subdomains, malware_iocs, certificates` |

### [dnstwist](https://github.com/elceef/dnstwist) `[S-Tier]`
- **ID**: `dnstwist` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`elceef/dnstwist`](https://github.com/elceef/dnstwist)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `ip_addresses`, `whois`, `malware_iocs`
- **Platforms**: Linux, macOS, Windows, Docker, Python, Web · **Tags**: `typosquatting`, `homograph-idn`, `phishing-detection`, `phash-lsh`
- **Overview**: Domain permutation engine detecting homograph attacks, typosquatting, bitsquatting, and brand-impersonation phishing domains with MX/A resolution, GeoIP, and visual/fuzzy pHash web page comparison.
- **Quick-Start / Tradecraft**: `dnstwist --registered --whois --lsh https://example.com  # Web version: https://dnstwister.report`

### [openSquat](https://github.com/atenreiro/opensquat) `[A-Tier]`
- **ID**: `opensquat` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`atenreiro/opensquat`](https://github.com/atenreiro/opensquat)
- **Inputs**: `keyword`, `domain` → **Outputs**: `subdomains`, `malware_iocs`, `certificates`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `newly-registered-domains`, `brand-protection`, `homoglyphs`, `ct-logs`
- **Overview**: Monitors newly registered domains (NRDs) daily against brand keywords using Levenshtein distance, homoglyphs, Certificate Transparency streams, and PhishTank checks.
- **Quick-Start / Tradecraft**: `python3 opensquat.py -k keywords.txt --ct`

---

## Active Web Probing & Crawling

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**httpx (ProjectDiscovery)**](https://github.com/projectdiscovery/httpx) ([GitHub](https://github.com/projectdiscovery/httpx)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip, url` → `tech_stack, certificates, metadata` |
| **A** | [**hakrawler**](https://github.com/hakluke/hakrawler) ([GitHub](https://github.com/hakluke/hakrawler)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, subdomains` |
| **A** | [**Katana**](https://github.com/projectdiscovery/katana) ([GitHub](https://github.com/projectdiscovery/katana)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, secrets, tech_stack` |
| **A** | [**Nuclei (Exposure & OSINT Templates)**](https://github.com/projectdiscovery/nuclei) ([GitHub](https://github.com/projectdiscovery/nuclei)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `url, domain, username` → `social_profiles, tech_stack, secrets` |
| **B** | [**Cariddi**](https://github.com/edoardottt/cariddi) ([GitHub](https://github.com/edoardottt/cariddi)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url` → `urls, secrets` |

### [httpx (ProjectDiscovery)](https://github.com/projectdiscovery/httpx) `[S-Tier]`
- **ID**: `httpx` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/httpx`](https://github.com/projectdiscovery/httpx)
- **Inputs**: `domain`, `ip`, `url` → **Outputs**: `tech_stack`, `certificates`, `metadata`, `urls`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `http-prober`, `favicon-hash`, `jarm`, `tech-detect`
- **Overview**: Fast multi-purpose Go HTTP toolkit probing discovered hosts for status codes, HTML titles, TLS certs, JARM hashes, favicon `mmh3` hashes, tech stacks, ASN info, and CDN detection.
- **Quick-Start / Tradecraft**: `cat subs.txt | httpx -title -tech-detect -status-code -favicon -jarm -asn -json -o live.json`

### [hakrawler](https://github.com/hakluke/hakrawler) `[A-Tier]`
- **ID**: `hakrawler` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`hakluke/hakrawler`](https://github.com/hakluke/hakrawler)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `subdomains`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `unix-pipeline`, `fast-crawler`, `js-endpoints`, `hakluke`
- **Overview**: Simple, fast Go CLI web crawler designed for chaining in Unix pipelines (`echo https://example.com | hakrawler`) to discover JS endpoints, subdomains, and forms.
- **Quick-Start / Tradecraft**: `echo https://example.com | hakrawler -subs -u`

### [Katana](https://github.com/projectdiscovery/katana) `[A-Tier]`
- **ID**: `katana` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/katana`](https://github.com/projectdiscovery/katana)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `secrets`, `tech_stack`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `headless-crawler`, `js-parsing`, `endpoint-discovery`
- **Overview**: Next-generation Go web crawling and spidering framework supporting both standard HTTP and headless Chromium JS rendering to extract hidden API routes, JS files, and forms.
- **Quick-Start / Tradecraft**: `katana -u https://example.com -jc -kf all -silent`

### [Nuclei (Exposure & OSINT Templates)](https://github.com/projectdiscovery/nuclei) `[A-Tier]`
- **ID**: `nuclei` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/nuclei`](https://github.com/projectdiscovery/nuclei)
- **Inputs**: `url`, `domain`, `username` → **Outputs**: `social_profiles`, `tech_stack`, `secrets`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `yaml-templates`, `osint-templates`, `exposure-checks`
- **Overview**: YAML template-driven scanner featuring dedicated `osint/`, `exposures/`, `token-spray/`, and `technologies/` template suites ( ONLY run active probes against explicitly authorized targets!).
- **Quick-Start / Tradecraft**: `nuclei -t http/osint/ -var user=target_handle  # Built-in 700+ OSINT username templates!`

### [Cariddi](https://github.com/edoardottt/cariddi) `[B-Tier]`
- **ID**: `cariddi` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`edoardottt/cariddi`](https://github.com/edoardottt/cariddi)
- **Inputs**: `domain`, `url` → **Outputs**: `urls`, `secrets`
- **Platforms**: Linux, macOS, Windows, Go · **Tags**: `endpoint-hunter`, `secret-scanner`, `golang`
- **Overview**: Go crawler taking lists of domains/URLs to hunt API endpoints, exposed secrets/keys, backup extensions, and error disclosures.
- **Quick-Start / Tradecraft**: `cat urls.txt | cariddi -s -e`

---

## Subdomain & Asset Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**OWASP Amass**](https://github.com/owasp-amass/amass) ([GitHub](https://github.com/owasp-amass/amass)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain, asn, ip` → `subdomains, dns_records, ip_addresses` |
| **S** | [**Subfinder**](https://github.com/projectdiscovery/subfinder) ([GitHub](https://github.com/projectdiscovery/subfinder)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `subdomains` |
| **A** | [**assetfinder**](https://github.com/tomnomnom/assetfinder) ([GitHub](https://github.com/tomnomnom/assetfinder)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `subdomains` |
| **A** | [**Findomain**](https://github.com/Findomain/Findomain) ([GitHub](https://github.com/Findomain/Findomain)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `subdomains, ip_addresses` |
| **A** | [**OneForAll**](https://github.com/shmilylty/OneForAll) ([GitHub](https://github.com/shmilylty/OneForAll)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `subdomains, dns_records, ip_addresses` |
| **A** | [**ProjectDiscovery Chaos Public Bug-Bounty Dataset**](https://chaos.projectdiscovery.io/) ([GitHub](https://github.com/projectdiscovery/chaos-client)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `domain, company` → `subdomains` |

### [OWASP Amass](https://github.com/owasp-amass/amass) `[S-Tier]`
- **ID**: `owasp-amass` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`owasp-amass/amass`](https://github.com/owasp-amass/amass)
- **Inputs**: `domain`, `asn`, `ip`, `company` → **Outputs**: `subdomains`, `dns_records`, `ip_addresses`, `whois`, `entity_graph`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `owasp`, `attack-surface`, `bgp-asn`, `subdomain-enum`, `flagship`
- **Overview**: Flagship OWASP external attack-surface mapping engine combining 50+ passive DNS/CT/ASN/archive sources, BGP netblock expansion, and Open Asset Model graph storage.
- **Quick-Start / Tradecraft**: `amass enum -passive -d example.com  # Always pass -passive for zero target interaction`

### [Subfinder](https://github.com/projectdiscovery/subfinder) `[S-Tier]`
- **ID**: `subfinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/subfinder`](https://github.com/projectdiscovery/subfinder)
- **Inputs**: `domain` → **Outputs**: `subdomains`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `passive-subdomains`, `fast`, `golang`, `flagship`
- **Overview**: ProjectDiscovery's ultra-fast passive subdomain enumeration Go CLI querying 40+ passive certificate, DNS, archive, and threat-intel sources in seconds without touching target DNS.
- **Quick-Start / Tradecraft**: `subfinder -d example.com -all -silent -o subs.txt`

### [assetfinder](https://github.com/tomnomnom/assetfinder) `[A-Tier]`
- **ID**: `assetfinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/assetfinder`](https://github.com/tomnomnom/assetfinder)
- **Inputs**: `domain` → **Outputs**: `subdomains`
- **Platforms**: Linux, macOS, Windows, Go · **Tags**: `tomnomnom`, `unix-philosophy`, `passive-subdomains`, `golang`
- **Overview**: TomNomNom's minimalist, lightning-fast Go binary querying crt.sh, CertSpotter, HackerTarget, ThreatMiner, Wayback, and Facebook CT logs for related domains and subdomains.
- **Quick-Start / Tradecraft**: `assetfinder --subs-only example.com | sort -u`

### [Findomain](https://github.com/Findomain/Findomain) `[A-Tier]`
- **ID**: `findomain` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`Findomain/Findomain`](https://github.com/Findomain/Findomain)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `ip_addresses`
- **Platforms**: Linux, macOS, Windows, Docker, Rust · **Tags**: `rust`, `subdomain-monitoring`, `fast`, `webhook-alerts`
- **Overview**: Blazing-fast Rust subdomain recognition engine supporting passive API aggregation, continuous monitoring, headless screenshots, HTTP probing, and Discord/Slack/Telegram new-asset alerts.
- **Quick-Start / Tradecraft**: `findomain -t example.com -q`

### [OneForAll](https://github.com/shmilylty/OneForAll) `[A-Tier]`
- **ID**: `oneforall` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`shmilylty/OneForAll`](https://github.com/shmilylty/OneForAll)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`, `ip_addresses`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `subdomain-collection`, `takeover-check`, `multi-source`
- **Overview**: Comprehensive Python subdomain collection framework integrating certificate logs, passive DNS datasets, search engines, ASN lookups, and subdomain takeover checks.
- **Quick-Start / Tradecraft**: `python3 oneforall.py --target example.com run`

### [ProjectDiscovery Chaos Public Bug-Bounty Dataset](https://chaos.projectdiscovery.io/) `[A-Tier]`
- **ID**: `chaos-dataset` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/chaos-client`](https://github.com/projectdiscovery/chaos-client)
- **Inputs**: `domain`, `company` → **Outputs**: `subdomains`
- **Platforms**: Web, CLI, Go · **Tags**: `projectdiscovery`, `bulk-subdomains`, `continuous-dns`, `free-dataset`
- **Overview**: Continuously updated passive DNS and subdomain dataset covering thousands of major global technology, finance, and enterprise programs with instant ZIP downloads and Go CLI.
- **Quick-Start / Tradecraft**: `chaos -d example.com -silent`

---

## Archive URL Mining

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**waymore**](https://github.com/xnl-h4ck3r/waymore) ([GitHub](https://github.com/xnl-h4ck3r/waymore)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain, url` → `archived_pages, urls, secrets` |
| **A** | [**gau (GetAllUrls)**](https://github.com/lc/gau) ([GitHub](https://github.com/lc/gau)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `urls, archived_pages` |
| **A** | [**ParamSpider**](https://github.com/devanshbatham/ParamSpider) ([GitHub](https://github.com/devanshbatham/ParamSpider)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `urls, archived_pages` |
| **A** | [**waybackurls**](https://github.com/tomnomnom/waybackurls) ([GitHub](https://github.com/tomnomnom/waybackurls)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `urls, archived_pages` |

### [waymore](https://github.com/xnl-h4ck3r/waymore) `[S-Tier]`
- **ID**: `waymore` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`xnl-h4ck3r/waymore`](https://github.com/xnl-h4ck3r/waymore)
- **Inputs**: `domain`, `url` → **Outputs**: `archived_pages`, `urls`, `secrets`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `wayback`, `common-crawl`, `historical-js`, `passive-mining`, `xnl-h4ck3r`
- **Overview**: Downloads archived URLs AND actual historical HTTP responses for a domain across Wayback Machine, Common Crawl, AlienVault OTX, URLScan, and VirusTotal simultaneously.
- **Quick-Start / Tradecraft**: `pipx install waymore && waymore -i example.com -mode U  # Passive URL extraction across 5 archives`

### [gau (GetAllUrls)](https://github.com/lc/gau) `[A-Tier]`
- **ID**: `gau` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`lc/gau`](https://github.com/lc/gau)
- **Inputs**: `domain` → **Outputs**: `urls`, `archived_pages`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `passive-urls`, `otx`, `wayback`, `golang`
- **Overview**: Fetches known historical URLs for any domain from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan without touching the target.
- **Quick-Start / Tradecraft**: `echo example.com | gau --subs | sort -u > historical_urls.txt`

### [ParamSpider](https://github.com/devanshbatham/ParamSpider) `[A-Tier]`
- **ID**: `paramspider` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`devanshbatham/ParamSpider`](https://github.com/devanshbatham/ParamSpider)
- **Inputs**: `domain` → **Outputs**: `urls`, `archived_pages`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `wayback-mining`, `url-parameters`, `passive-recon`
- **Overview**: Mines URL query parameters (`?id=`, `?redirect=`, `?file=`) from dark corners of Web Archives passively without sending fuzzing traffic to the target server.
- **Quick-Start / Tradecraft**: `paramspider -d example.com`

### [waybackurls](https://github.com/tomnomnom/waybackurls) `[A-Tier]`
- **ID**: `waybackurls` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/waybackurls`](https://github.com/tomnomnom/waybackurls)
- **Inputs**: `domain` → **Outputs**: `urls`, `archived_pages`
- **Platforms**: Linux, macOS, Windows, Go · **Tags**: `tomnomnom`, `wayback-cdx`, `endpoint-mining`, `passive`
- **Overview**: Classic Unix-pipe Go CLI fetching historical URL snapshots from Wayback Machine, Common Crawl, and VirusTotal for any line-delimited list of domains.
- **Quick-Start / Tradecraft**: `cat domains.txt | waybackurls | grep -E '\.(json|xml|conf|bak|env|pdf)$'`

---

## DNS Diagnostics & Topology

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**dnsx (ProjectDiscovery)**](https://github.com/projectdiscovery/dnsx) ([GitHub](https://github.com/projectdiscovery/dnsx)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip` → `dns_records, ip_addresses, subdomains` |
| **B** | [**DNSViz**](https://dnsviz.net/) ([GitHub](https://github.com/dnsviz/dnsviz)) | Web Platform | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, entity_graph` |

### [dnsx (ProjectDiscovery)](https://github.com/projectdiscovery/dnsx) `[A-Tier]`
- **ID**: `dnsx` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/dnsx`](https://github.com/projectdiscovery/dnsx)
- **Inputs**: `domain`, `ip` → **Outputs**: `dns_records`, `ip_addresses`, `subdomains`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `dns-resolver`, `wildcard-filtering`, `ptr-sweep`
- **Overview**: High-speed Go multi-purpose DNS toolkit querying A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, and ASN data with wildcard filtering across millions of subdomains.
- **Quick-Start / Tradecraft**: `cat subs.txt | dnsx -a -cname -resp -silent`

### [DNSViz](https://dnsviz.net/) `[B-Tier]`
- **ID**: `dnsviz` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`dnsviz/dnsviz`](https://github.com/dnsviz/dnsviz)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `entity_graph`
- **Platforms**: Web, Linux, Python · **Tags**: `dnssec`, `delegation-graph`, `nameserver-topology`
- **Overview**: Visualizes DNS delegation hierarchies, authoritative nameserver glue records, and full DNSSEC chain-of-trust cryptographic signatures from the root zone down.
- **Quick-Start / Tradecraft**: `Analyze complex zone delegations and DNSSEC misconfigurations visually at https://dnsviz.net/.`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🔓 Breaches & Infostealers](./06-breaches-leaks-stealers.md) · [📡 Cyberspace & Network Search ▶](./08-network-ip-iot-search.md)

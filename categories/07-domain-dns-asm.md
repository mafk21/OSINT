[⬅️ Back to Master Index](../README.md) · [◀ 🔓 Breaches & Infostealers](./06-breaches-leaks-stealers.md) · [📡 Cyberspace & Network Search ▶](./08-network-ip-iot-search.md)

# 🌐 07. Domain, DNS, Certificate Transparency & Attack Surface Management (`DNSINT`)

> **Scope**: Passive DNS history, RDAP/WHOIS attribution, Certificate Transparency (CT) log monitors, subdomain enumerators, typosquatting detectors, and web technology profilers.
>
> **OPSEC Advisory**: Querying Certificate Transparency (`crt.sh`), passive DNS (`SecurityTrails`), and RDAP is 100% passive. Running `httpx`, `Katana`, or DNS brute-forcing touches target servers and leaves logs.

**Discipline Telemetry**: `92` Verified Tools · `29` S-Tier Flagships · `31` Passive · `82` Free/Open-Source

## Subcategories
- [Tech Profiling & Tag Pivoting](#tech-profiling-tag-pivoting) (4)
- [Certificate Transparency](#certificate-transparency) (3)
- [Passive DNS & Historical WHOIS](#passive-dns-historical-whois) (12)
- [Brand & Typosquatting Recon](#brand-typosquatting-recon) (2)
- [Active Web Probing & Crawling](#active-web-probing-crawling) (5)
- [Subdomain & Asset Discovery](#subdomain-asset-discovery) (6)
- [Archive URL Mining](#archive-url-mining) (4)
- [DNS Diagnostics & Topology](#dns-diagnostics-topology) (2)
- [Active Web & VHost Discovery](#active-web-vhost-discovery) (5)
- [Active DNS Resolution & Bruteforce](#active-dns-resolution-bruteforce) (7)
- [Active DNS Enumeration](#active-dns-enumeration) (5)
- [Subdomain Enumeration](#subdomain-enumeration) (2)
- [Subdomain Takeover Detection](#subdomain-takeover-detection) (7)
- [Web Tech & WAF Fingerprinting](#web-tech-waf-fingerprinting) (8)
- [Active Parameter & JS Recon](#active-parameter-js-recon) (8)
- [Active Web Spiders](#active-web-spiders) (1)
- [Active Web Probing](#active-web-probing) (6)
- [Root Domain & TLD Discovery](#root-domain-tld-discovery) (1)
- [Historical URL Discovery](#historical-url-discovery) (2)
- [Passive Subdomain & DNS History](#passive-subdomain-dns-history) (1)
- [Analytics & Ad-Tag Attribution](#analytics-ad-tag-attribution) (1)

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

## Active Web & VHost Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ffuf (Fuzz Faster U Fool)**](https://github.com/ffuf/ffuf) ([GitHub](https://github.com/ffuf/ffuf)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain, ip` → `urls, subdomains, tech_stack` |
| **S** | [**Gobuster**](https://github.com/OJ/gobuster) ([GitHub](https://github.com/OJ/gobuster)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url` → `subdomains, urls, dns_records` |
| **S** | [**feroxbuster**](https://github.com/epi052/feroxbuster) ([GitHub](https://github.com/epi052/feroxbuster)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, documents, tech_stack` |
| **A** | [**dirsearch**](https://github.com/maurosoria/dirsearch) ([GitHub](https://github.com/maurosoria/dirsearch)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, documents, secrets` |
| **A** | [**VHostScan**](https://github.com/codingo/VHostScan) ([GitHub](https://github.com/codingo/VHostScan)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain` → `subdomains, urls` |

### [ffuf (Fuzz Faster U Fool)](https://github.com/ffuf/ffuf) `[S-Tier]`
- **ID**: `ffuf` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`ffuf/ffuf`](https://github.com/ffuf/ffuf)
- **Inputs**: `url`, `domain`, `ip` → **Outputs**: `urls`, `subdomains`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `fuzzer`, `vhost-discovery`, `directory-bruteforce`, `active-recon`
- **Overview**: Blazing-fast Go active web fuzzer for hidden directory discovery, virtual-host (`Host:` header) subdomain enumeration, and GET/POST parameter discovery.
- **Quick-Start / Tradecraft**: `ffuf -w wordlist.txt -u https://example.com/FUZZ -mc 200,301,302,403`

### [Gobuster](https://github.com/OJ/gobuster) `[S-Tier]`
- **ID**: `gobuster` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`OJ/gobuster`](https://github.com/OJ/gobuster)
- **Inputs**: `domain`, `url` → **Outputs**: `subdomains`, `urls`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `dns-bruteforce`, `vhost`, `dirbusting`, `s3-buckets`, `active`
- **Overview**: Multi-mode Go active enumeration tool supporting URI/directory brute-forcing (`dir`), DNS subdomain brute-forcing (`dns`), VHost (`vhost`), S3 (`s3`), and GCS (`gcs`).
- **Quick-Start / Tradecraft**: `gobuster dns -d example.com -w subdomains.txt`

### [feroxbuster](https://github.com/epi052/feroxbuster) `[S-Tier]`
- **ID**: `feroxbuster` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`epi052/feroxbuster`](https://github.com/epi052/feroxbuster)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `documents`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Rust · **Tags**: `content-discovery`, `rust`, `recursive`, `active-recon`
- **Overview**: Fast, recursive Rust active content discovery tool featuring automatic link extraction from responses, smart wildcard filtering, and rate-limit tuning.
- **Quick-Start / Tradecraft**: `feroxbuster -u https://example.com -w raft-medium-directories.txt`

### [dirsearch](https://github.com/maurosoria/dirsearch) `[A-Tier]`
- **ID**: `dirsearch` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`maurosoria/dirsearch`](https://github.com/maurosoria/dirsearch)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `documents`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `web-path-scanner`, `backup-files`, `active-recon`
- **Overview**: Feature-rich Python active web path scanner discovering hidden admin panels, backup archives, configuration files, and API endpoints.
- **Quick-Start / Tradecraft**: `dirsearch -u https://example.com -e php,json,bak,zip`

### [VHostScan](https://github.com/codingo/VHostScan) `[A-Tier]`
- **ID**: `vhostscan` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`codingo/VHostScan`](https://github.com/codingo/VHostScan)
- **Inputs**: `ip`, `domain` → **Outputs**: `subdomains`, `urls`
- **Platforms**: CLI, Linux, macOS, Docker, Python · **Tags**: `vhost`, `fuzzy-hashing`, `internal-hosts`, `active`
- **Overview**: Active virtual-host scanner performing reverse lookups and fuzzy page-length comparison to discover non-public VHosts behind load balancers and CDNs.
- **Quick-Start / Tradecraft**: `VHostScan -t 198.51.100.10 -b example.com`

---

## Active DNS Resolution & Bruteforce

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**MassDNS**](https://github.com/blechschmidt/massdns) ([GitHub](https://github.com/blechschmidt/massdns)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains, dns_records, ip_addresses` |
| **S** | [**puredns**](https://github.com/d3mondev/puredns) ([GitHub](https://github.com/d3mondev/puredns)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains, dns_records, ip_addresses` |
| **S** | [**shuffledns**](https://github.com/projectdiscovery/shuffledns) ([GitHub](https://github.com/projectdiscovery/shuffledns)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains, dns_records, ip_addresses` |
| **A** | [**AlterX**](https://github.com/projectdiscovery/alterx) ([GitHub](https://github.com/projectdiscovery/alterx)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains` |
| **B** | [**SubBrute**](https://github.com/TheRook/subbrute) ([GitHub](https://github.com/TheRook/subbrute)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains, dns_records` |
| **A** | [**gotator**](https://github.com/Josue87/gotator) ([GitHub](https://github.com/Josue87/gotator)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `subdomains` |
| **A** | [**AltDNS**](https://github.com/infosec-au/altdns) ([GitHub](https://github.com/infosec-au/altdns)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `subdomains, dns_records` |

### [MassDNS](https://github.com/blechschmidt/massdns) `[S-Tier]`
- **ID**: `massdns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`blechschmidt/massdns`](https://github.com/blechschmidt/massdns)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Docker · **Tags**: `dns-resolver`, `high-speed`, `subdomain-bruteforce`, `active`
- **Overview**: High-performance C stub DNS resolver capable of resolving hundreds of thousands of subdomain candidates per second across public resolver pools.
- **Quick-Start / Tradecraft**: `massdns -r resolvers.txt -t A subdomains.txt -o S -w live_hosts.txt`

### [puredns](https://github.com/d3mondev/puredns) `[S-Tier]`
- **ID**: `puredns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`d3mondev/puredns`](https://github.com/d3mondev/puredns)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Go · **Tags**: `wildcard-filtering`, `dns-bruteforce`, `massdns`, `active`
- **Overview**: Fast active domain resolver and subdomain brute-forcing tool atop MassDNS that accurately filters wildcard DNS responses and poisoned resolvers.
- **Quick-Start / Tradecraft**: `puredns bruteforce wordlist.txt example.com -r resolvers.txt`

### [shuffledns](https://github.com/projectdiscovery/shuffledns) `[S-Tier]`
- **ID**: `shuffledns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/shuffledns`](https://github.com/projectdiscovery/shuffledns)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `projectdiscovery`, `dns-bruteforce`, `massdns`, `active`
- **Overview**: ProjectDiscovery Go wrapper around MassDNS for active subdomain brute-forcing and mass wildcard-aware resolution.
- **Quick-Start / Tradecraft**: `shuffledns -d example.com -w wordlist.txt -r resolvers.txt -mode bruteforce`

### [AlterX](https://github.com/projectdiscovery/alterx) `[A-Tier]`
- **ID**: `alterx` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/alterx`](https://github.com/projectdiscovery/alterx)
- **Inputs**: `domain` → **Outputs**: `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `permutations`, `subdomain-alteration`, `projectdiscovery`, `active`
- **Overview**: Customizable DSL-based subdomain permutation generator designed to pipe smart naming patterns directly into dnsx for active subdomain discovery.
- **Quick-Start / Tradecraft**: `subfinder -d example.com | alterx | dnsx`

### [SubBrute](https://github.com/TheRook/subbrute) `[B-Tier]`
- **ID**: `subbrute` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`TheRook/subbrute`](https://github.com/TheRook/subbrute)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `open-resolvers`, `subdomain-bruteforce`, `dns`
- **Overview**: DNS meta-query spider distributing active subdomain brute-forcing across open DNS resolvers without sending direct UDP traffic to target nameservers.
- **Quick-Start / Tradecraft**: `python3 subbrute.py example.com`

### [gotator](https://github.com/Josue87/gotator) `[A-Tier]`
- **ID**: `gotator` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Josue87/gotator`](https://github.com/Josue87/gotator)
- **Inputs**: `domain` → **Outputs**: `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `subdomain-permutations`, `altdns`, `go`
- **Overview**: Fast Go subdomain permutation generator creating environment, region, and numeric variations ready for active puredns/shuffledns resolution.
- **Quick-Start / Tradecraft**: `gotator -sub subdomains.txt -perm permutations.txt -depth 1`

### [AltDNS](https://github.com/infosec-au/altdns) `[A-Tier]`
- **ID**: `altdns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`infosec-au/altdns`](https://github.com/infosec-au/altdns)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `alterations`, `subdomain-bruteforce`, `dns`, `active`
- **Overview**: Subdomain discovery tool generating word/number alterations of known subdomains and optionally resolving all candidates live against DNS.
- **Quick-Start / Tradecraft**: `altdns -i subdomains.txt -o data_output -w words.txt -r -s resolved.txt`

---

## Active DNS Enumeration

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**DNSRecon**](https://github.com/darkoperator/dnsrecon) ([GitHub](https://github.com/darkoperator/dnsrecon)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip, asn` → `dns_records, subdomains, ip_addresses` |
| **A** | [**dnsenum**](https://github.com/fwaeytens/dnsenum) ([GitHub](https://github.com/fwaeytens/dnsenum)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, subdomains, ip_addresses` |
| **A** | [**hakrevdns**](https://github.com/hakluke/hakrevdns) ([GitHub](https://github.com/hakluke/hakrevdns)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, asn` → `subdomains, dns_records` |
| **A** | [**hakip2host**](https://github.com/hakluke/hakip2host) ([GitHub](https://github.com/hakluke/hakip2host)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, asn` → `subdomains, certificates, dns_records` |
| **A** | [**Cero (Go TLS SAN Scraper)**](https://github.com/glebarez/cero) ([GitHub](https://github.com/glebarez/cero)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain, asn` → `subdomains, certificates` |

### [DNSRecon](https://github.com/darkoperator/dnsrecon) `[S-Tier]`
- **ID**: `dnsrecon` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`darkoperator/dnsrecon`](https://github.com/darkoperator/dnsrecon)
- **Inputs**: `domain`, `ip`, `asn` → **Outputs**: `dns_records`, `subdomains`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `axfr`, `zone-transfer`, `dnssec-walk`, `srv`, `active`
- **Overview**: Classic Python active DNS reconnaissance tool testing AXFR zone transfers, NSEC/NSEC3 zone walking, SRV records, reverse PTR sweeps, and cache snooping.
- **Quick-Start / Tradecraft**: `dnsrecon -d example.com -a`

### [dnsenum](https://github.com/fwaeytens/dnsenum) `[A-Tier]`
- **ID**: `dnsenum` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`fwaeytens/dnsenum`](https://github.com/fwaeytens/dnsenum)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `subdomains`, `ip_addresses`, `whois`
- **Platforms**: CLI, Linux, macOS · **Tags**: `axfr`, `reverse-dns`, `dns-enum`, `active`
- **Overview**: Multi-threaded Perl active DNS enumerator performing MX/NS lookups, AXFR zone transfer attempts, dictionary brute-forcing, and C-class reverse sweeps.
- **Quick-Start / Tradecraft**: `dnsenum example.com`

### [hakrevdns](https://github.com/hakluke/hakrevdns) `[A-Tier]`
- **ID**: `hakrevdns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`hakluke/hakrevdns`](https://github.com/hakluke/hakrevdns)
- **Inputs**: `ip`, `asn` → **Outputs**: `subdomains`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `reverse-dns`, `ptr-sweep`, `cidr`, `hakluke`, `active`
- **Overview**: High-speed Go reverse DNS (PTR) lookup scanner sweeping IPv4 addresses and CIDR netblocks to uncover hidden corporate hostnames and internal naming.
- **Quick-Start / Tradecraft**: `prips 198.51.100.0/24 | hakrevdns`

### [hakip2host](https://github.com/hakluke/hakip2host) `[A-Tier]`
- **ID**: `hakip2host` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`hakluke/hakip2host`](https://github.com/hakluke/hakip2host)
- **Inputs**: `ip`, `asn` → **Outputs**: `subdomains`, `certificates`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `ssl-san`, `ptr`, `ip-to-domain`, `hakluke`, `active`
- **Overview**: Active IP-to-hostname resolver combining live TLS port 443 SAN/CN certificate extraction with reverse PTR DNS queries across target IP ranges.
- **Quick-Start / Tradecraft**: `cat ips.txt | hakip2host`

### [Cero (Go TLS SAN Scraper)](https://github.com/glebarez/cero) `[A-Tier]`
- **ID**: `cero-tls` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`glebarez/cero`](https://github.com/glebarez/cero)
- **Inputs**: `ip`, `domain`, `asn` → **Outputs**: `subdomains`, `certificates`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `tls-san`, `cidr-sweep`, `cert-scraping`, `active`
- **Overview**: Ultra-fast concurrent Go scanner connecting directly to arbitrary ports across IP/CIDR ranges to harvest X.509 certificate SAN domain names.
- **Quick-Start / Tradecraft**: `cero 198.51.100.0/24 -p 443,8443`

---

## Subdomain Enumeration

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Sublist3r**](https://github.com/aboul3la/Sublist3r) ([GitHub](https://github.com/aboul3la/Sublist3r)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `subdomains, open_ports` |
| **A** | [**Knockpy**](https://github.com/guelfoweb/knock) ([GitHub](https://github.com/guelfoweb/knock)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `subdomains, dns_records, certificates` |

### [Sublist3r](https://github.com/aboul3la/Sublist3r) `[A-Tier]`
- **ID**: `sublist3r` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`aboul3la/Sublist3r`](https://github.com/aboul3la/Sublist3r)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `open_ports`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `subdomains`, `hybrid-recon`, `subbrute`, `ports`
- **Overview**: Popular Python subdomain discovery tool combining passive search engine/CT scraping with optional integrated SubBrute active DNS brute-forcing (`-b`).
- **Quick-Start / Tradecraft**: `sublist3r -d example.com -b -p 80,443`

### [Knockpy](https://github.com/guelfoweb/knock) `[A-Tier]`
- **ID**: `knockpy` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`guelfoweb/knock`](https://github.com/guelfoweb/knock)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`, `certificates`, `ip_addresses`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `subdomains`, `tls-certs`, `bruteforce`, `hybrid`
- **Overview**: Modular Python tool enumerating subdomains on a target domain through passive reconnaissance and active dictionary + HTTP/HTTPS/TLS certificate checks.
- **Quick-Start / Tradecraft**: `knockpy -d example.com --recon --bruteforce`

---

## Subdomain Takeover Detection

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**dnsReaper**](https://github.com/punk-security/dnsReaper) ([GitHub](https://github.com/punk-security/dnsReaper)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, subdomains, metadata` |
| **S** | [**BadDNS (Black Lantern Security)**](https://github.com/blacklanternsecurity/baddns) ([GitHub](https://github.com/blacklanternsecurity/baddns)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, subdomains, metadata` |
| **A** | [**Subzy**](https://github.com/PentestPad/subzy) ([GitHub](https://github.com/PentestPad/subzy)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url` → `subdomains, dns_records, metadata` |
| **A** | [**Subjack**](https://github.com/haccer/subjack) ([GitHub](https://github.com/haccer/subjack)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains, dns_records` |
| **A** | [**Subdominator**](https://github.com/Stratus-Security/Subdominator) ([GitHub](https://github.com/Stratus-Security/Subdominator)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `subdomains, dns_records, metadata` |
| **A** | [**DNSTake**](https://github.com/pwnesia/dnstake) ([GitHub](https://github.com/pwnesia/dnstake)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, subdomains` |
| **A** | [**second-order**](https://github.com/mhmdiaa/second-order) ([GitHub](https://github.com/mhmdiaa/second-order)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, subdomains, secrets` |

### [dnsReaper](https://github.com/punk-security/dnsReaper) `[S-Tier]`
- **ID**: `dnsreaper` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`punk-security/dnsReaper`](https://github.com/punk-security/dnsReaper)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `subdomains`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `subdomain-takeover`, `dangling-dns`, `cname`, `active`
- **Overview**: High-accuracy active DNS and subdomain takeover scanner checking 50+ cloud/SaaS takeover signatures across live DNS records or zone files.
- **Quick-Start / Tradecraft**: `docker run --rm punksecurity/dnsreaper file --filename subdomains.txt`

### [BadDNS (Black Lantern Security)](https://github.com/blacklanternsecurity/baddns) `[S-Tier]`
- **ID**: `baddns` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`blacklanternsecurity/baddns`](https://github.com/blacklanternsecurity/baddns)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `subdomains`, `metadata`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `subdomain-takeover`, `ns-takeover`, `mx-takeover`, `bls`
- **Overview**: Comprehensive active DNS takeover detector auditing CNAME, NS, MX, TXT, and NSEC records plus live HTTP responses for dangling resource hijacks.
- **Quick-Start / Tradecraft**: `baddns sub.example.com`

### [Subzy](https://github.com/PentestPad/subzy) `[A-Tier]`
- **ID**: `subzy` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`PentestPad/subzy`](https://github.com/PentestPad/subzy)
- **Inputs**: `domain`, `url` → **Outputs**: `subdomains`, `dns_records`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `subdomain-takeover`, `cname`, `go`, `active`
- **Overview**: Fast Go active subdomain takeover verifier matching live HTTP response fingerprints against can-i-take-over-xyz signatures.
- **Quick-Start / Tradecraft**: `subzy run --targets subdomains.txt`

### [Subjack](https://github.com/haccer/subjack) `[A-Tier]`
- **ID**: `subjack` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`haccer/subjack`](https://github.com/haccer/subjack)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `subdomain-takeover`, `dangling-cname`, `active`
- **Overview**: Concurrent Go subdomain takeover scanner inspecting live CNAME records, NXDOMAIN responses, and unclaimed cloud provider error pages.
- **Quick-Start / Tradecraft**: `subjack -w subdomains.txt -t 50 -ssl -v`

### [Subdominator](https://github.com/Stratus-Security/Subdominator) `[A-Tier]`
- **ID**: `subdominator` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`Stratus-Security/Subdominator`](https://github.com/Stratus-Security/Subdominator)
- **Inputs**: `domain` → **Outputs**: `subdomains`, `dns_records`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `subdomain-takeover`, `dangling-dns`, `active-recon`
- **Overview**: High-speed low-false-positive active subdomain takeover detector covering cloud storage, SaaS, CDN, and unclaimed DNS delegation vectors.
- **Quick-Start / Tradecraft**: `Subdominator -l subdomains.txt`

### [DNSTake](https://github.com/pwnesia/dnstake) `[A-Tier]`
- **ID**: `dnstake` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`pwnesia/dnstake`](https://github.com/pwnesia/dnstake)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `ns-takeover`, `hosted-zone`, `route53`, `active`
- **Overview**: Fast Go scanner testing delegated authoritative nameservers (AWS Route53, Cloudflare, DigitalOcean, NS1) for missing hosted DNS zones vulnerable to takeover.
- **Quick-Start / Tradecraft**: `cat subdomains.txt | dnstake -c 50`

### [second-order](https://github.com/mhmdiaa/second-order) `[A-Tier]`
- **ID**: `second-order` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`mhmdiaa/second-order`](https://github.com/mhmdiaa/second-order)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `subdomains`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `second-order-takeover`, `broken-links`, `js-hijack`, `active`
- **Overview**: Active web crawler inspecting embedded `<script>`, `<iframe>`, and `<a>` links on target pages to detect unclaimed external domains and S3 buckets.
- **Quick-Start / Tradecraft**: `second-order -base https://example.com -config config.json`

---

## Web Tech & WAF Fingerprinting

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**WAFW00F**](https://github.com/EnableSecurity/wafw00f) ([GitHub](https://github.com/EnableSecurity/wafw00f)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `tech_stack, metadata` |
| **A** | [**cdncheck (ProjectDiscovery)**](https://github.com/projectdiscovery/cdncheck) ([GitHub](https://github.com/projectdiscovery/cdncheck)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `ip, domain` → `tech_stack, ip_addresses, metadata` |
| **A** | [**wappalyzergo**](https://github.com/projectdiscovery/wappalyzergo) ([GitHub](https://github.com/projectdiscovery/wappalyzergo)) | Library | OSS / Free | 🔴 Active | ✅ | `url, domain` → `tech_stack, metadata` |
| **A** | [**CMSeeK**](https://github.com/Tuhinshubhra/CMSeeK) ([GitHub](https://github.com/Tuhinshubhra/CMSeeK)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `tech_stack, usernames, urls` |
| **S** | [**WPScan**](https://github.com/wpscanteam/wpscan) ([GitHub](https://github.com/wpscanteam/wpscan)) | CLI | Freemium | 🔴 Active | ✅ | `url, domain` → `usernames, tech_stack, urls` |
| **A** | [**Nikto**](https://github.com/sullo/nikto) ([GitHub](https://github.com/sullo/nikto)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain, ip` → `tech_stack, urls, certificates` |
| **B** | [**WhatWaf**](https://github.com/Ekultek/WhatWaf) ([GitHub](https://github.com/Ekultek/WhatWaf)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `tech_stack, metadata` |
| **B** | [**identYwaf**](https://github.com/stamparm/identYwaf) ([GitHub](https://github.com/stamparm/identYwaf)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `tech_stack, metadata` |

### [WAFW00F](https://github.com/EnableSecurity/wafw00f) `[S-Tier]`
- **ID**: `wafw00f` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`EnableSecurity/wafw00f`](https://github.com/EnableSecurity/wafw00f)
- **Inputs**: `url`, `domain` → **Outputs**: `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `waf-detection`, `fingerprinting`, `http-probing`, `active`
- **Overview**: Definitive active Web Application Firewall fingerprinter identifying 150+ commercial and cloud WAFs via crafted HTTP probe responses and headers.
- **Quick-Start / Tradecraft**: `wafw00f https://example.com`

### [cdncheck (ProjectDiscovery)](https://github.com/projectdiscovery/cdncheck) `[A-Tier]`
- **ID**: `cdncheck` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/cdncheck`](https://github.com/projectdiscovery/cdncheck)
- **Inputs**: `ip`, `domain` → **Outputs**: `tech_stack`, `ip_addresses`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `cdn`, `waf`, `origin-ip`, `projectdiscovery`
- **Overview**: Fast utility detecting whether target IPs or hosts belong to CDNs, WAFs, or public cloud providers so active scanners only target true origin servers.
- **Quick-Start / Tradecraft**: `cat hosts.txt | cdncheck -resp`

### [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) `[A-Tier]`
- **ID**: `wappalyzergo` · **Type**: `Library` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/wappalyzergo`](https://github.com/projectdiscovery/wappalyzergo)
- **Inputs**: `url`, `domain` → **Outputs**: `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `wappalyzer`, `tech-fingerprinting`, `http`, `go`
- **Overview**: High-performance Go library and active HTTP response analyzer identifying CMSs, JS frameworks, analytics trackers, and server stacks.
- **Quick-Start / Tradecraft**: `httpx -u https://example.com -td # Powered by wappalyzergo`

### [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) `[A-Tier]`
- **ID**: `cmseek` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`Tuhinshubhra/CMSeeK`](https://github.com/Tuhinshubhra/CMSeeK)
- **Inputs**: `url`, `domain` → **Outputs**: `tech_stack`, `usernames`, `urls`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `cms-detection`, `wordpress`, `joomla`, `active-recon`
- **Overview**: Active CMS detection and enumeration suite fingerprinting 180+ Content Management Systems plus WordPress/Joomla users, themes, plugins, and versions.
- **Quick-Start / Tradecraft**: `python3 cmseek.py -u https://example.com`

### [WPScan](https://github.com/wpscanteam/wpscan) `[S-Tier]`
- **ID**: `wpscan` · **Type**: `CLI` · **Pricing**: `Freemium` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`wpscanteam/wpscan`](https://github.com/wpscanteam/wpscan)
- **Inputs**: `url`, `domain` → **Outputs**: `usernames`, `tech_stack`, `urls`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker · **Tags**: `wordpress`, `author-enum`, `plugins`, `active-scanner`
- **Overview**: Flagship active WordPress reconnaissance scanner enumerating author usernames, installed plugins/themes, XML-RPC, config backups, and version metadata.
- **Quick-Start / Tradecraft**: `wpscan --url https://example.com --enumerate u,vp,vt`

### [Nikto](https://github.com/sullo/nikto) `[A-Tier]`
- **ID**: `nikto` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`sullo/nikto`](https://github.com/sullo/nikto)
- **Inputs**: `url`, `domain`, `ip` → **Outputs**: `tech_stack`, `urls`, `certificates`, `metadata`
- **Platforms**: CLI, Linux, macOS, Docker · **Tags**: `web-scanner`, `server-headers`, `exposed-files`, `active`
- **Overview**: Open-source active web server scanner checking 7,000+ dangerous files, server misconfigurations, HTTP headers, and outdated server software.
- **Quick-Start / Tradecraft**: `nikto -h https://example.com`

### [WhatWaf](https://github.com/Ekultek/WhatWaf) `[B-Tier]`
- **ID**: `whatwaf` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`Ekultek/WhatWaf`](https://github.com/Ekultek/WhatWaf)
- **Inputs**: `url`, `domain` → **Outputs**: `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `waf`, `firewall-detection`, `http`, `active`
- **Overview**: Advanced active firewall and WAF detection tool identifying 100+ web application firewalls via HTTP response anomalies and header signatures.
- **Quick-Start / Tradecraft**: `whatwaf -u https://example.com`

### [identYwaf](https://github.com/stamparm/identYwaf) `[B-Tier]`
- **ID**: `identywaf` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`stamparm/identYwaf`](https://github.com/stamparm/identYwaf)
- **Inputs**: `url`, `domain` → **Outputs**: `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `waf-fingerprinting`, `blind-detection`, `active`
- **Overview**: Blind and non-blind active WAF identification utility scoring HTTP rejection patterns against 80+ firewall signature profiles.
- **Quick-Start / Tradecraft**: `python3 identYwaf.py https://example.com`

---

## Active Parameter & JS Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Arjun**](https://github.com/s0md3v/Arjun) ([GitHub](https://github.com/s0md3v/Arjun)) | CLI | OSS / Free | 🔴 Active | ✅ | `url` → `urls, metadata` |
| **S** | [**jsluice (Bishop Fox)**](https://github.com/BishopFox/jsluice) ([GitHub](https://github.com/BishopFox/jsluice)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `url, repo_code` → `urls, secrets, subdomains` |
| **A** | [**LinkFinder**](https://github.com/GerbenJavado/LinkFinder) ([GitHub](https://github.com/GerbenJavado/LinkFinder)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, subdomains` |
| **S** | [**xnLinkFinder**](https://github.com/xnl-h4ck3r/xnLinkFinder) ([GitHub](https://github.com/xnl-h4ck3r/xnLinkFinder)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, subdomains, metadata` |
| **B** | [**getJS**](https://github.com/003random/getJS) ([GitHub](https://github.com/003random/getJS)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls` |
| **A** | [**subjs**](https://github.com/lc/subjs) ([GitHub](https://github.com/lc/subjs)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls` |
| **S** | [**gf (Grep-Friend Pattern Wrapper)**](https://github.com/tomnomnom/gf) ([GitHub](https://github.com/tomnomnom/gf)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, url, repo_code` → `secrets, urls, subdomains` |
| **B** | [**qsreplace**](https://github.com/tomnomnom/qsreplace) ([GitHub](https://github.com/tomnomnom/qsreplace)) | CLI | OSS / Free | 🟢 Passive | ✅ | `url` → `urls` |

### [Arjun](https://github.com/s0md3v/Arjun) `[S-Tier]`
- **ID**: `arjun` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`s0md3v/Arjun`](https://github.com/s0md3v/Arjun)
- **Inputs**: `url` → **Outputs**: `urls`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `parameter-discovery`, `api-recon`, `http`, `active`
- **Overview**: Smart HTTP parameter discovery suite finding hidden GET, POST, JSON, and XML query parameters via chunked differential response comparison.
- **Quick-Start / Tradecraft**: `arjun -u https://api.example.com/v1/user`

### [jsluice (Bishop Fox)](https://github.com/BishopFox/jsluice) `[S-Tier]`
- **ID**: `jsluice` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`BishopFox/jsluice`](https://github.com/BishopFox/jsluice)
- **Inputs**: `url`, `repo_code` → **Outputs**: `urls`, `secrets`, `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `javascript`, `ast`, `endpoints`, `secrets`, `bishopfox`
- **Overview**: AST-powered Go analyzer extracting API URLs, relative routes, query parameters, cloud buckets, and hardcoded secrets from fetched JavaScript bundles.
- **Quick-Start / Tradecraft**: `jsluice urls <(curl -s https://example.com/app.js)`

### [LinkFinder](https://github.com/GerbenJavado/LinkFinder) `[A-Tier]`
- **ID**: `linkfinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`GerbenJavado/LinkFinder`](https://github.com/GerbenJavado/LinkFinder)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `javascript`, `endpoints`, `sourcemaps`, `active`
- **Overview**: Python script discovering hidden API endpoints, internal routes, and parameters inside live remote JavaScript files and source maps.
- **Quick-Start / Tradecraft**: `python3 linkfinder.py -i https://example.com/main.js -o cli`

### [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) `[S-Tier]`
- **ID**: `xnlinkfinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`xnl-h4ck3r/xnLinkFinder`](https://github.com/xnl-h4ck3r/xnLinkFinder)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `subdomains`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `js-recon`, `endpoints`, `wordlist-gen`, `active`
- **Overview**: Advanced active crawler and JavaScript analyzer harvesting hidden endpoints, custom target wordlists, and API parameters across entire domains.
- **Quick-Start / Tradecraft**: `xnLinkFinder -i https://example.com -sp https://example.com -d 2`

### [getJS](https://github.com/003random/getJS) `[B-Tier]`
- **ID**: `getjs` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`003random/getJS`](https://github.com/003random/getJS)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `javascript`, `scraper`, `go`, `active`
- **Overview**: Fast Go CLI actively fetching web pages and extracting all linked external and inline JavaScript asset URLs for downstream endpoint analysis.
- **Quick-Start / Tradecraft**: `getJS --url https://example.com --complete`

### [subjs](https://github.com/lc/subjs) `[A-Tier]`
- **ID**: `subjs` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`lc/subjs`](https://github.com/lc/subjs)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `javascript`, `pipeline`, `endpoints`, `active`
- **Overview**: Go pipeline tool actively fetching live pages across subdomain lists to extract every referenced JavaScript file URL for secret and route carving.
- **Quick-Start / Tradecraft**: `cat live_urls.txt | subjs`

### [gf (Grep-Friend Pattern Wrapper)](https://github.com/tomnomnom/gf) `[S-Tier]`
- **ID**: `tomnomnom-gf` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/gf`](https://github.com/tomnomnom/gf)
- **Inputs**: `document`, `url`, `repo_code` → **Outputs**: `secrets`, `urls`, `subdomains`
- **Platforms**: CLI, Linux, macOS, Go · **Tags**: `grep-patterns`, `tomnomnom`, `js-carving`, `secrets`
- **Overview**: Pattern-matching wrapper around `grep` for rapidly carving AWS keys, URLs, S3 buckets, base64 blobs, and debug parameters out of HTTP/JS dumps.
- **Quick-Start / Tradecraft**: `gf aws-keys ./responses/`

### [qsreplace](https://github.com/tomnomnom/qsreplace) `[B-Tier]`
- **ID**: `tomnomnom-qsreplace` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/qsreplace`](https://github.com/tomnomnom/qsreplace)
- **Inputs**: `url` → **Outputs**: `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `url-dedup`, `query-params`, `tomnomnom`, `pipeline`
- **Overview**: Pipeline URL query-string normalizer deduplicating parameter combinations across large historical Wayback and spider endpoint lists.
- **Quick-Start / Tradecraft**: `cat urls.txt | qsreplace -a`

---

## Active Web Spiders

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GoSpider**](https://github.com/jaeles-project/gospider) ([GitHub](https://github.com/jaeles-project/gospider)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, subdomains, secrets` |

### [GoSpider](https://github.com/jaeles-project/gospider) `[S-Tier]`
- **ID**: `gospider` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`jaeles-project/gospider`](https://github.com/jaeles-project/gospider)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `subdomains`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `web-spider`, `s3-extraction`, `js-crawler`, `active`
- **Overview**: Fast concurrent Go active web spider parsing HTML, JavaScript, sitemaps, and robots.txt while extracting subdomains, AWS S3 buckets, and link graphs.
- **Quick-Start / Tradecraft**: `gospider -s https://example.com -c 10 -d 2 --other-source`

---

## Active Web Probing

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**httprobe**](https://github.com/tomnomnom/httprobe) ([GitHub](https://github.com/tomnomnom/httprobe)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `urls, open_ports` |
| **A** | [**meg (tomnomnom)**](https://github.com/tomnomnom/meg) ([GitHub](https://github.com/tomnomnom/meg)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url` → `urls, metadata, documents` |
| **A** | [**Corsy**](https://github.com/s0md3v/Corsy) ([GitHub](https://github.com/s0md3v/Corsy)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, metadata, tech_stack` |
| **B** | [**CORScanner**](https://github.com/chenjj/CORScanner) ([GitHub](https://github.com/chenjj/CORScanner)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, metadata` |
| **B** | [**hakcheckurl**](https://github.com/hakluke/hakcheckurl) ([GitHub](https://github.com/hakluke/hakcheckurl)) | CLI | OSS / Free | 🔴 Active | ✅ | `url` → `urls, metadata` |
| **B** | [**fff (Fast Fetching Friend)**](https://github.com/tomnomnom/fff) ([GitHub](https://github.com/tomnomnom/fff)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `archived_pages, metadata, secrets` |

### [httprobe](https://github.com/tomnomnom/httprobe) `[A-Tier]`
- **ID**: `httprobe` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/httprobe`](https://github.com/tomnomnom/httprobe)
- **Inputs**: `domain` → **Outputs**: `urls`, `open_ports`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `http-probe`, `live-hosts`, `tomnomnom`, `active`
- **Overview**: Minimalist high-concurrency Go tool taking lists of domains and probing for working live HTTP and HTTPS listeners across standard and custom ports.
- **Quick-Start / Tradecraft**: `cat subdomains.txt | httprobe -p http:8080 -p https:8443`

### [meg (tomnomnom)](https://github.com/tomnomnom/meg) `[A-Tier]`
- **ID**: `tomnomnom-meg` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/meg`](https://github.com/tomnomnom/meg)
- **Inputs**: `domain`, `url` → **Outputs**: `urls`, `metadata`, `documents`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `polite-probing`, `multi-host`, `tomnomnom`, `active`
- **Overview**: Low-noise active HTTP fetcher requesting specific paths (/.well-known/security.txt, /robots.txt, /.git/HEAD) across many hosts without flooding any single target.
- **Quick-Start / Tradecraft**: `meg -d 1000 paths.txt hosts.txt ./out`

### [Corsy](https://github.com/s0md3v/Corsy) `[A-Tier]`
- **ID**: `corsy` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`s0md3v/Corsy`](https://github.com/s0md3v/Corsy)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `metadata`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `cors`, `origin-reflection`, `http-headers`, `active`
- **Overview**: Lightweight Python active scanner testing target web endpoints for Cross-Origin Resource Sharing (CORS) trust misconfigurations and origin reflections.
- **Quick-Start / Tradecraft**: `python3 corsy.py -u https://api.example.com`

### [CORScanner](https://github.com/chenjj/CORScanner) `[B-Tier]`
- **ID**: `corscanner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`chenjj/CORScanner`](https://github.com/chenjj/CORScanner)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `cors-audit`, `api-security`, `active-recon`
- **Overview**: Fast multi-threaded Python active CORS misconfiguration scanner auditing lists of domains and API endpoints for overly permissive ACAO/ACAC headers.
- **Quick-Start / Tradecraft**: `corscanner -i urls.txt -t 50`

### [hakcheckurl](https://github.com/hakluke/hakcheckurl) `[B-Tier]`
- **ID**: `hakcheckurl` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`hakluke/hakcheckurl`](https://github.com/hakluke/hakcheckurl)
- **Inputs**: `url` → **Outputs**: `urls`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `status-codes`, `http-probe`, `hakluke`, `active`
- **Overview**: Fast concurrent Go tool taking URL streams on stdin and actively probing HTTP response status codes across large recon inventories.
- **Quick-Start / Tradecraft**: `cat urls.txt | hakcheckurl`

### [fff (Fast Fetching Friend)](https://github.com/tomnomnom/fff) `[B-Tier]`
- **ID**: `tomnomnom-fff` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/fff`](https://github.com/tomnomnom/fff)
- **Inputs**: `url`, `domain` → **Outputs**: `archived_pages`, `metadata`, `secrets`
- **Platforms**: CLI, Linux, macOS, Go · **Tags**: `http-archiver`, `headers`, `tomnomnom`, `active`
- **Overview**: Streamlined active HTTP fetcher saving raw response headers and bodies per URL into structured disk hierarchies for rapid offline grep/secret analysis.
- **Quick-Start / Tradecraft**: `cat urls.txt | fff -d 50 -S -o responses/`

---

## Root Domain & TLD Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**tldfinder (ProjectDiscovery)**](https://github.com/projectdiscovery/tldfinder) ([GitHub](https://github.com/projectdiscovery/tldfinder)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `company, domain, keyword` → `subdomains, dns_records, whois` |

### [tldfinder (ProjectDiscovery)](https://github.com/projectdiscovery/tldfinder) `[A-Tier]`
- **ID**: `tldfinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/tldfinder`](https://github.com/projectdiscovery/tldfinder)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `subdomains`, `dns_records`, `whois`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `tld-discovery`, `root-domains`, `brand-asm`, `projectdiscovery`
- **Overview**: Streamlined tool for discovering corporate root domains, Country-Code TLDs, and private brand TLDs through active DNS and passive registry sources.
- **Quick-Start / Tradecraft**: `tldfinder -d example`

---

## Historical URL Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**URLFinder (ProjectDiscovery)**](https://github.com/projectdiscovery/urlfinder) ([GitHub](https://github.com/projectdiscovery/urlfinder)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `urls, subdomains` |
| **S** | [**unfurl**](https://github.com/tomnomnom/unfurl) ([GitHub](https://github.com/tomnomnom/unfurl)) | CLI | OSS / Free | 🟢 Passive | ✅ | `url` → `subdomains, urls, metadata` |

### [URLFinder (ProjectDiscovery)](https://github.com/projectdiscovery/urlfinder) `[A-Tier]`
- **ID**: `urlfinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/urlfinder`](https://github.com/projectdiscovery/urlfinder)
- **Inputs**: `domain` → **Outputs**: `urls`, `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `url-discovery`, `projectdiscovery`, `wayback`, `passive`
- **Overview**: High-speed passive URL harvester aggregating historical endpoints across CommonCrawl, Wayback Machine, AlienVault OTX, and URLScan.
- **Quick-Start / Tradecraft**: `urlfinder -d example.com`

### [unfurl](https://github.com/tomnomnom/unfurl) `[S-Tier]`
- **ID**: `tomnomnom-unfurl` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tomnomnom/unfurl`](https://github.com/tomnomnom/unfurl)
- **Inputs**: `url` → **Outputs**: `subdomains`, `urls`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `url-parsing`, `tomnomnom`, `pipeline`, `wayback`
- **Overview**: Pipeline URL parser slicing massive Wayback/CommonCrawl URL lists into unique subdomains, paths, query keys, and parameter values.
- **Quick-Start / Tradecraft**: `cat urls.txt | unfurl --unique domains`

---

## Passive Subdomain & DNS History

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**haktrails**](https://github.com/hakluke/haktrails) ([GitHub](https://github.com/hakluke/haktrails)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `domain, ip, company` → `subdomains, dns_records, whois` |

### [haktrails](https://github.com/hakluke/haktrails) `[A-Tier]`
- **ID**: `haktrails` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`hakluke/haktrails`](https://github.com/hakluke/haktrails)
- **Inputs**: `domain`, `ip`, `company` → **Outputs**: `subdomains`, `dns_records`, `whois`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `securitytrails`, `passive-dns`, `hakluke`, `pipeline`
- **Overview**: Go CLI querying SecurityTrails passive DNS, historical WHOIS, and associated domain endpoints in Unix pipelines.
- **Quick-Start / Tradecraft**: `echo example.com | haktrails subdomains`

---

## Analytics & Ad-Tag Attribution

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Wayback Google Analytics (Bellingcat)**](https://github.com/bellingcat/wayback-google-analytics) ([GitHub](https://github.com/bellingcat/wayback-google-analytics)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain, url` → `entity_graph, archived_pages, metadata` |

### [Wayback Google Analytics (Bellingcat)](https://github.com/bellingcat/wayback-google-analytics) `[S-Tier]`
- **ID**: `bellingcat-wayback-ga` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`bellingcat/wayback-google-analytics`](https://github.com/bellingcat/wayback-google-analytics)
- **Inputs**: `domain`, `url` → **Outputs**: `entity_graph`, `archived_pages`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `bellingcat`, `google-analytics`, `wayback`, `attribution`
- **Overview**: Bellingcat Python CLI scraping historical Wayback Machine snapshots to extract `UA-`, `G-`, and `GTM-` tracking codes across time to link covert site networks.
- **Quick-Start / Tradecraft**: `wayback-google-analytics -u https://example.com`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🔓 Breaches & Infostealers](./06-breaches-leaks-stealers.md) · [📡 Cyberspace & Network Search ▶](./08-network-ip-iot-search.md)

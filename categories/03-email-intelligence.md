[⬅️ Back to Master Index](../README.md) · [◀ 🕵️ Username & Handle Recon](./02-username-enumeration.md) · [📱 Phone & Messaging OSINT ▶](./04-phone-messaging-osint.md)

# 📧 03. Email Intelligence, Account Enumeration & Corporate Address Discovery (`EMAILINT`)

> **Scope**: Account registration checkers (password-reset/OAuth side-channels), Google workspace/GAIA profilers, corporate email pattern harvesters, reputation scorers, and SMTP/MX verifiers.
>
> **OPSEC Advisory**: Some password-reset enumeration modules can trigger 'password reset requested' emails or SMS alerts on poorly designed websites. Stick to silent registration-check tools (e.g., Holehe passive modules, Epieos, GHunt) for covert work.

**Discipline Telemetry**: `30` Verified Tools · `10` S-Tier Flagships · `21` Passive · `20` Free/Open-Source

## Subcategories
- [Reverse Email & Phone Portals](#reverse-email-phone-portals) (2)
- [Google Ecosystem Intelligence](#google-ecosystem-intelligence) (1)
- [Email Breach & Pivot Tools](#email-breach-pivot-tools) (1)
- [Email-to-Account Enumerators](#email-to-account-enumerators) (4)
- [Corporate Email & Subdomain Harvesters](#corporate-email-subdomain-harvesters) (9)
- [Email Infrastructure & Headers](#email-infrastructure-headers) (2)
- [Cryptographic Identity Pivots](#cryptographic-identity-pivots) (1)
- [Email Reputation & Verification](#email-reputation-verification) (3)
- [Developer Email Attribution](#developer-email-attribution) (1)
- [Email-to-Phone Pivoting](#email-to-phone-pivoting) (1)
- [Active Email Verification](#active-email-verification) (3)
- [Mail Server & SMTP Posture](#mail-server-smtp-posture) (2)

---

## Reverse Email & Phone Portals

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Epieos**](https://epieos.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `email, phone` → `social_profiles, person_records, geolocation` |
| **B** | [**AnalyzeID**](https://analyzeid.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `domain, email` → `whois, entity_graph, urls` |

### [Epieos](https://epieos.com/) `[S-Tier]`
- **ID**: `epieos` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email`, `phone` → **Outputs**: `social_profiles`, `person_records`, `geolocation`
- **Platforms**: Web · **Tags**: `reverse-email`, `reverse-phone`, `google-maps`, `zero-notification`, `flagship`
- **Overview**: Zero-alert web reverse-lookup platform uncovering Google GAIA IDs, Maps contributions, Skype handles, Gravatar, Chess.com, Flickr, Strava, and linked social accounts from an email address or phone number.
- **Quick-Start / Tradecraft**: `Query an email or E.164 phone number directly at https://epieos.com/ for instant account correlation.`

### [AnalyzeID](https://analyzeid.com/) `[B-Tier]`
- **ID**: `analyzeid` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `email` → **Outputs**: `whois`, `entity_graph`, `urls`
- **Platforms**: Web · **Tags**: `website-owner-pivot`, `adsense-correlation`, `sister-sites`
- **Overview**: Finds sibling domains and web properties operated by the same owner by correlating historical WHOIS emails, Google Analytics IDs, AdSense pub IDs, and nameservers.
- **Quick-Start / Tradecraft**: `Enter a suspect domain on https://analyzeid.com/ to surface shared WHOIS emails and analytics tags.`

---

## Google Ecosystem Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GHunt**](https://github.com/mxrch/GHunt) ([GitHub](https://github.com/mxrch/GHunt)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `email, url, document` → `person_records, social_profiles, geolocation` |

### [GHunt](https://github.com/mxrch/GHunt) `[S-Tier]`
- **ID**: `ghunt` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`mxrch/GHunt`](https://github.com/mxrch/GHunt)
- **Inputs**: `email`, `url`, `document` → **Outputs**: `person_records`, `social_profiles`, `geolocation`, `metadata`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `google-osint`, `gaia-id`, `gmail`, `google-maps-reviews`, `google-docs`
- **Overview**: Offensive Google OSINT framework extracting GAIA IDs, display names, profile photos, Google Maps reviews/geolocations, Calendar availability, and Drive document owners from any Gmail address or Google Doc URL.
- **Quick-Start / Tradecraft**: `pipx install ghunt && ghunt login && ghunt email target@gmail.com`

---

## Email Breach & Pivot Tools

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**h8mail**](https://github.com/khast3x/h8mail) ([GitHub](https://github.com/khast3x/h8mail)) | CLI | OSS / Free | 🟢 Passive | ✅ | `email, domain, username` → `breach_records, emails, social_profiles` |

### [h8mail](https://github.com/khast3x/h8mail) `[S-Tier]`
- **ID**: `h8mail` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`khast3x/h8mail`](https://github.com/khast3x/h8mail)
- **Inputs**: `email`, `domain`, `username` → **Outputs**: `breach_records`, `emails`, `social_profiles`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `breach-hunting`, `email-chasing`, `local-dumps`, `api-integration`
- **Overview**: Email OSINT and password-breach hunting CLI supporting local `.gz`/cleartext breach compilations alongside HIBP, Snusbase, Leak-Lookup, IntelX, DeHashed, Hunter.io, and EmailRep recursive pivoting.
- **Quick-Start / Tradecraft**: `pipx install h8mail && h8mail -t target@example.com --chase`

---

## Email-to-Account Enumerators

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Holehe**](https://github.com/megadose/holehe) ([GitHub](https://github.com/megadose/holehe)) | CLI | OSS / Free | 🟢 Passive | ✅ | `email` → `social_profiles, metadata` |
| **A** | [**MailAccess**](https://github.com/KatrielMoses/MailAccess) ([GitHub](https://github.com/KatrielMoses/MailAccess)) | CLI | OSS / Free | 🟢 Passive | ✅ | `email` → `social_profiles, breach_records, entity_graph` |
| **A** | [**MOSINT**](https://github.com/alpkeskin/mosint) ([GitHub](https://github.com/alpkeskin/mosint)) | CLI | OSS / Free | 🟢 Passive | ✅ | `email` → `social_profiles, breach_records, dns_records` |
| **B** | [**Buster**](https://github.com/sham00n/buster) ([GitHub](https://github.com/sham00n/buster)) | CLI | OSS / Free | 🟢 Passive | ✅ | `email, person_name, domain` → `emails, social_profiles, breach_records` |

### [Holehe](https://github.com/megadose/holehe) `[S-Tier]`
- **ID**: `holehe` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`megadose/holehe`](https://github.com/megadose/holehe)
- **Inputs**: `email` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `email-osint`, `account-enumeration`, `no-alert`, `silent-check`, `flagship`
- **Overview**: Checks whether an email address is registered across 120+ websites (Spotify, Instagram, X, GitHub, Adobe, Gravatar, Imgur, Office365) via silent registration/login checks without alerting the target.
- **Quick-Start / Tradecraft**: `pipx install holehe && holehe --only-used target@example.com`

### [MailAccess](https://github.com/KatrielMoses/MailAccess) `[A-Tier]`
- **ID**: `mailaccess` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`KatrielMoses/MailAccess`](https://github.com/KatrielMoses/MailAccess)
- **Inputs**: `email` → **Outputs**: `social_profiles`, `breach_records`, `entity_graph`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `keyless`, `identity-clustering`, `hudson-rock`, `email-footprint`
- **Overview**: All-in-one keyless Python email OSINT engine combining Holehe, WhatsMyName, Hudson Rock infostealer telemetry, and cross-platform identity clustering with confidence scoring.
- **Quick-Start / Tradecraft**: `pip install mailaccess && mailaccess target@example.com`

### [MOSINT](https://github.com/alpkeskin/mosint) `[A-Tier]`
- **ID**: `mosint` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`alpkeskin/mosint`](https://github.com/alpkeskin/mosint)
- **Inputs**: `email` → **Outputs**: `social_profiles`, `breach_records`, `dns_records`, `emails`
- **Platforms**: Linux, macOS, Windows, Go · **Tags**: `golang`, `automated-email-osint`, `breach-check`, `dns-mx`
- **Overview**: Fast Go-based automated email OSINT CLI aggregating breach lookups, social scan checks, EmailRep scoring, Hunter.io related emails, DNS/MX records, and Google dork results into JSON.
- **Quick-Start / Tradecraft**: `go install -v github.com/alpkeskin/mosint/v3/cmd/mosint@latest && mosint target@example.com`

### [Buster](https://github.com/sham00n/buster) `[B-Tier]`
- **ID**: `buster-email` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`sham00n/buster`](https://github.com/sham00n/buster)
- **Inputs**: `email`, `person_name`, `domain` → **Outputs**: `emails`, `social_profiles`, `breach_records`, `whois`
- **Platforms**: Linux, macOS, Python · **Tags**: `email-permutations`, `reverse-email`, `breach-pivot`
- **Overview**: Advanced email reconnaissance CLI generating work email permutations from name+domain, reversing emails to social accounts, hunting breaches, and resolving linked domains.
- **Quick-Start / Tradecraft**: `buster -e target@example.com`

---

## Corporate Email & Subdomain Harvesters

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Hunter.io**](https://hunter.io/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `domain, company, email` → `emails, person_records` |
| **S** | [**theHarvester**](https://github.com/laramies/theHarvester) ([GitHub](https://github.com/laramies/theHarvester)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain, company` → `emails, subdomains, person_records` |
| **A** | [**CrossLinked**](https://github.com/m8sec/CrossLinked) ([GitHub](https://github.com/m8sec/CrossLinked)) | CLI | OSS / Free | 🟢 Passive | ✅ | `company, domain` → `emails, person_records, usernames` |
| **B** | [**ContactOut**](https://contactout.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `person_name, company, url` → `emails, phones, person_records` |
| **B** | [**linkedin2username**](https://github.com/initstring/linkedin2username) ([GitHub](https://github.com/initstring/linkedin2username)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `company` → `emails, person_records` |
| **B** | [**OpenLeads**](https://github.com/openleads-dev/openleads) ([GitHub](https://github.com/openleads-dev/openleads)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain, company` → `emails, person_records` |
| **B** | [**RocketReach**](https://rocketreach.co/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `person_name, company, domain` → `emails, phones, person_records` |
| **B** | [**Skymem**](http://www.skymem.info/) | Search Engine | Freemium | 🟢 Passive | ✅ | `domain, company` → `emails` |
| **B** | [**Snov.io**](https://snov.io/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `domain, company, person_name` → `emails, person_records` |

### [Hunter.io](https://hunter.io/) `[S-Tier]`
- **ID**: `hunter-io` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain`, `company`, `email`, `person_name` → **Outputs**: `emails`, `person_records`
- **Platforms**: Web, Chrome, Firefox · **Tags**: `email-pattern`, `corporate-emails`, `verifier`, `lead-enrichment`
- **Overview**: Corporate email intelligence engine indexing public web pages to reveal a domain's naming pattern (`{first}.{last}@domain`), verified employee addresses, citation URLs, and SMTP deliverability.
- **Quick-Start / Tradecraft**: `Search a company domain on https://hunter.io/ to identify email format and public citation sources.`

### [theHarvester](https://github.com/laramies/theHarvester) `[S-Tier]`
- **ID**: `theharvester` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`laramies/theHarvester`](https://github.com/laramies/theHarvester)
- **Inputs**: `domain`, `company` → **Outputs**: `emails`, `subdomains`, `person_records`, `ip_addresses`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `email-harvesting`, `domain-recon`, `kali-default`, `50-sources`
- **Overview**: Classic early-stage passive recon CLI harvesting employee email addresses, names, subdomains, IPs, and URLs for a target domain across 50+ public search engines, CT logs, and threat feeds.
- **Quick-Start / Tradecraft**: `theHarvester -d example.com -b crtsh,duckduckgo,brave,rapiddns,urlscan -f report.html`

### [CrossLinked](https://github.com/m8sec/CrossLinked) `[A-Tier]`
- **ID**: `crosslinked` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`m8sec/CrossLinked`](https://github.com/m8sec/CrossLinked)
- **Inputs**: `company`, `domain` → **Outputs**: `emails`, `person_records`, `usernames`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `linkedin-scraping`, `serp-based`, `employee-enum`, `corporate-emails`
- **Overview**: LinkedIn employee enumeration tool scraping Google and Bing SERPs (zero LinkedIn login required) to generate validated corporate email lists and username formats (`{f}{last}@company.com`).
- **Quick-Start / Tradecraft**: `pipx install crosslinked && crosslinked -f '{first}.{last}@example.com' 'Example Corp'`

### [ContactOut](https://contactout.com/) `[B-Tier]`
- **ID**: `contactout` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `person_name`, `company`, `url` → **Outputs**: `emails`, `phones`, `person_records`
- **Platforms**: Web, Chrome · **Tags**: `executive-osint`, `linkedin-enrichment`, `work-emails`
- **Overview**: Professional contact database indexing personal and work email addresses plus phone numbers tied to 300M+ LinkedIn and GitHub profiles.
- **Quick-Start / Tradecraft**: `Query a LinkedIn profile URL in ContactOut's dashboard to cross-reference personal/corporate email leads.`

### [linkedin2username](https://github.com/initstring/linkedin2username) `[B-Tier]`
- **ID**: `linkedin2username` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`initstring/linkedin2username`](https://github.com/initstring/linkedin2username)
- **Inputs**: `company` → **Outputs**: `emails`, `person_records`
- **Platforms**: Linux, macOS, Python · **Tags**: `linkedin`, `employee-list`, `username-generation`
- **Overview**: Generates targeted employee username and email lists from company LinkedIn pages for authorized OSINT footprinting and credential exposure audits.
- **Quick-Start / Tradecraft**: `python3 linkedin2username.py -c target-company -d example.com`

### [OpenLeads](https://github.com/openleads-dev/openleads) `[B-Tier]`
- **ID**: `openleads` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`openleads-dev/openleads`](https://github.com/openleads-dev/openleads)
- **Inputs**: `domain`, `company` → **Outputs**: `emails`, `person_records`
- **Platforms**: Linux, macOS, Python · **Tags**: `keyless`, `corporate-contacts`, `sec-edgar`, `openalex`
- **Overview**: Local, keyless CLI discovering organizational contacts and work emails from public sources (OpenStreetMap, GitHub, OpenAlex, SEC EDGAR, team pages) while labeling each as found, pattern, or guessed.
- **Quick-Start / Tradecraft**: `openleads search example.com`

### [RocketReach](https://rocketreach.co/) `[B-Tier]`
- **ID**: `rocketreach` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `person_name`, `company`, `domain` → **Outputs**: `emails`, `phones`, `person_records`, `corporate_records`
- **Platforms**: Web, Chrome · **Tags**: `org-charts`, `executive-contacts`, `email-discovery`
- **Overview**: Executive and corporate contact intelligence search engine correlating professional histories, direct work emails, and org charts across millions of companies.
- **Quick-Start / Tradecraft**: `Search executive name + company at https://rocketreach.co/ to identify verified email formats.`

### [Skymem](http://www.skymem.info/) `[B-Tier]`
- **ID**: `skymem` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `company` → **Outputs**: `emails`
- **Platforms**: Web · **Tags**: `domain-emails`, `naming-convention`, `quick-lookup`
- **Overview**: Fast public corporate email index displaying discovered `@domain` email formats and crawled public business contact addresses.
- **Quick-Start / Tradecraft**: `Search a domain on Skymem alongside Hunter.io to confirm corporate `{first}.{last}` vs `{f}{last}` naming conventions.`

### [Snov.io](https://snov.io/) `[B-Tier]`
- **ID**: `snov-io` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `domain`, `company`, `person_name` → **Outputs**: `emails`, `person_records`
- **Platforms**: Web, Chrome · **Tags**: `b2b-contacts`, `email-finder`, `chrome-extension`
- **Overview**: B2B email finder and technology-stack lookup extension surfacing employee addresses, roles, and SMTP verification status for corporate domains.
- **Quick-Start / Tradecraft**: `Run domain search on https://snov.io/ to compare discovered staff emails with Hunter.io.`

---

## Email Infrastructure & Headers

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**MXToolbox SuperTool**](https://mxtoolbox.com/SuperTool.aspx) | Web Platform | Freemium | 🟡 Hybrid | ✅ | `domain, ip, document` → `dns_records, whois, tech_stack` |
| **A** | [**EasyDMARC SPF / DMARC / BIMI & DKIM Lookup**](https://easydmarc.com/tools) | Web Platform | Free | 🟢 Passive | ✅ | `domain` → `dns_records, emails, tech_stack` |

### [MXToolbox SuperTool](https://mxtoolbox.com/SuperTool.aspx) `[S-Tier]`
- **ID**: `mxtoolbox` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain`, `ip`, `document` → **Outputs**: `dns_records`, `whois`, `tech_stack`
- **Platforms**: Web · **Tags**: `mx-records`, `spf`, `dmarc`, `dkim`, `email-header-analyzer`
- **Overview**: Comprehensive DNS/mail diagnostics suite analyzing MX providers (Google Workspace, Microsoft 365, Proofpoint, Mimecast), SPF include chains, DMARC policies, DKIM selectors, SMTP banners, and RBL blacklists.
- **Quick-Start / Tradecraft**: `Paste raw `Received:` email headers into https://mxtoolbox.com/EmailHeaders.aspx to trace sender hops and origination IPs.`

### [EasyDMARC SPF / DMARC / BIMI & DKIM Lookup](https://easydmarc.com/tools) `[A-Tier]`
- **ID**: `dkim-selector-lookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `emails`, `tech_stack`
- **Platforms**: Web · **Tags**: `spf-saas-recon`, `dmarc-rua-pivot`, `bimi-certificates`, `vendor-discovery`
- **Overview**: Inspects SPF `include:` third-party SaaS vendors (Zendesk, Salesforce, HubSpot, Mailgun, SendGrid), DMARC `rua=` reporting mailboxes, and BIMI brand SVG certificates!
- **Quick-Start / Tradecraft**: `Inspect a company's SPF `TXT` & `_dmarc.` records—SPF leaks internal SaaS vendors and DMARC `rua=mailto:` reveals parent security teams!`

---

## Cryptographic Identity Pivots

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Proton Mail HKP Key Lookup**](https://mail.proton.me/) | API / Service | Free | 🟢 Passive | ✅ | `email` → `metadata, certificates` |

### [Proton Mail HKP Key Lookup](https://mail.proton.me/) `[S-Tier]`
- **ID**: `proton-key-lookup` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email` → **Outputs**: `metadata`, `certificates`
- **Platforms**: Web, CLI · **Tags**: `protonmail-osint`, `account-creation-date`, `openpgp-hkp`, `keyless-api`, `flagship`
- **Overview**: Queries Proton's public OpenPGP WKD/HKP endpoint (`api.protonmail.ch/pks/lookup`) to confirm whether a `@proton.me` / `@protonmail.com` / custom-domain Proton account exists and retrieve its exact creation Unix timestamp!
- **Quick-Start / Tradecraft**: `curl -s 'https://api.protonmail.ch/pks/lookup?op=index&search=target@proton.me'  # Timestamp after `pub:255:` is exact Unix creation second!`

---

## Email Reputation & Verification

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**EmailRep.io**](https://emailrep.io/) | API / Service | Freemium | 🟢 Passive | ✅ | `email` → `social_profiles, breach_records, malware_iocs` |
| **A** | [**Reacher**](https://github.com/reacherhq/check-if-email-exists) ([GitHub](https://github.com/reacherhq/check-if-email-exists)) | API / Service | OSS / Free | 🔴 Active | ✅ | `email` → `emails, dns_records` |
| **B** | [**Verifalia Email Verifier**](https://verifalia.com/validate-email) | Web Platform | Freemium | 🔴 Active | ✅ | `email` → `emails, dns_records` |

### [EmailRep.io](https://emailrep.io/) `[A-Tier]`
- **ID**: `emailrep` · **Type**: `API / Service` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `email` → **Outputs**: `social_profiles`, `breach_records`, `malware_iocs`
- **Platforms**: Web, Python · **Tags**: `email-reputation`, `sublime-security`, `fraud-detection`, `social-presence`
- **Overview**: Sublime Security's email reputation and threat-enrichment API returning address age, domain risk, breach appearances, disposable/spoofable flags, and associated social profiles.
- **Quick-Start / Tradecraft**: `curl -s https://emailrep.io/target@example.com | jq`

### [Reacher](https://github.com/reacherhq/check-if-email-exists) `[A-Tier]`
- **ID**: `reacher` · **Type**: `API / Service` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`reacherhq/check-if-email-exists`](https://github.com/reacherhq/check-if-email-exists)
- **Inputs**: `email` → **Outputs**: `emails`, `dns_records`
- **Platforms**: Linux, Docker, Rust, Web · **Tags**: `rust`, `smtp-verification`, `catch-all`, `disposable-check`
- **Overview**: 100% open-source Rust email verification engine checking syntax, MX records, disposable providers, catch-all configuration, and live SMTP mailbox existence without sending an actual email.
- **Quick-Start / Tradecraft**: `docker run -p 8080:8080 reacherhq/backend:latest`

### [Verifalia Email Verifier](https://verifalia.com/validate-email) `[B-Tier]`
- **ID**: `verifalia` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct)
- **Inputs**: `email` → **Outputs**: `emails`, `dns_records`
- **Platforms**: Web · **Tags**: `smtp-check`, `catch-all`, `disposable-email`, `validation`
- **Overview**: Real-time online email syntax, MX/DNS, disposable-address, catch-all server, and non-intrusive SMTP mailbox verifier with detailed diagnostic logs.
- **Quick-Start / Tradecraft**: `Test suspect corporate/burner addresses on https://verifalia.com/validate-email to confirm live mailbox acceptance.`

---

## Developer Email Attribution

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**GitRecon**](https://github.com/GONZOsint/gitrecon) ([GitHub](https://github.com/GONZOsint/gitrecon)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username` → `emails, person_records, social_profiles` |

### [GitRecon](https://github.com/GONZOsint/gitrecon) `[A-Tier]`
- **ID**: `gitrecon` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`GONZOsint/gitrecon`](https://github.com/GONZOsint/gitrecon)
- **Inputs**: `username` → **Outputs**: `emails`, `person_records`, `social_profiles`
- **Platforms**: Linux, macOS, Python · **Tags**: `github-emails`, `gitlab`, `commit-authors`, `developer-osint`
- **Overview**: Scans GitHub and GitLab user profiles, commit histories, PGP keys, and public event streams to uncover developer email addresses, full names, avatars, and organization memberships.
- **Quick-Start / Tradecraft**: `python3 gitrecon.py -u target_github_user -s github`

---

## Email-to-Phone Pivoting

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**email2phonenumber**](https://github.com/martinvigo/email2phonenumber) ([GitHub](https://github.com/martinvigo/email2phonenumber)) | CLI | OSS / Free | 🔴 Active | ✅ | `email` → `phones` |

### [email2phonenumber](https://github.com/martinvigo/email2phonenumber) `[B-Tier]`
- **ID**: `email2phonenumber` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`martinvigo/email2phonenumber`](https://github.com/martinvigo/email2phonenumber)
- **Inputs**: `email` → **Outputs**: `phones`
- **Platforms**: Linux, macOS, Python · **Tags**: `masked-phone`, `password-reset-correlation`, `nanpa`, `email-pivot`
- **Overview**: OSINT utility implementing Martin Vigo's password-reset masking correlation technique—combining masked phone digits (`***-***-8492`) from public reset pages with regional NANPA/carrier prefixes.
- **Quick-Start / Tradecraft**: `Use 'scrape' and 'generate' modes carefully; note active reset requests may notify targets on some sites.`

---

## Active Email Verification

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**UhOh365**](https://github.com/Raikia/UhOh365) ([GitHub](https://github.com/Raikia/UhOh365)) | CLI | OSS / Free | 🔴 Active | ✅ | `email, domain` → `emails, usernames, metadata` |
| **A** | [**smtp-user-enum**](https://github.com/pentestmonkey/smtp-user-enum) ([GitHub](https://github.com/pentestmonkey/smtp-user-enum)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, ip, username` → `emails, usernames` |
| **A** | [**onedrive_user_enum**](https://github.com/nyxgeek/onedrive_user_enum) ([GitHub](https://github.com/nyxgeek/onedrive_user_enum)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, username, company` → `emails, usernames, urls` |

### [UhOh365](https://github.com/Raikia/UhOh365) `[S-Tier]`
- **ID**: `uhoh365` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`Raikia/UhOh365`](https://github.com/Raikia/UhOh365)
- **Inputs**: `email`, `domain` → **Outputs**: `emails`, `usernames`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `o365`, `m365`, `email-enum`, `active-recon`
- **Overview**: Unauthenticated Microsoft 365 / Exchange Online email address existence enumerator querying Autodiscover responses without triggering login lockouts.
- **Quick-Start / Tradecraft**: `python3 UhOh365.py emails.txt`

### [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) `[A-Tier]`
- **ID**: `smtp-user-enum` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`pentestmonkey/smtp-user-enum`](https://github.com/pentestmonkey/smtp-user-enum)
- **Inputs**: `domain`, `ip`, `username`, `email` → **Outputs**: `emails`, `usernames`
- **Platforms**: CLI, Linux, macOS · **Tags**: `smtp`, `vrfy`, `rcpt-to`, `active-enum`
- **Overview**: Classic active SMTP server account enumeration tool probing VRFY, EXPN, and RCPT TO commands directly against target mail gateways.
- **Quick-Start / Tradecraft**: `smtp-user-enum -M VRFY -U users.txt -t mail.example.com`

### [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) `[A-Tier]`
- **ID**: `onedrive-user-enum` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`nyxgeek/onedrive_user_enum`](https://github.com/nyxgeek/onedrive_user_enum)
- **Inputs**: `domain`, `username`, `company` → **Outputs**: `emails`, `usernames`, `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `onedrive`, `sharepoint`, `m365`, `active-user-enum`
- **Overview**: Active corporate OneDrive for Business / SharePoint URL prober validating Microsoft 365 usernames and email addresses without sign-in audit events.
- **Quick-Start / Tradecraft**: `python3 onedrive_enum.py -d example.com -U users.txt`

---

## Mail Server & SMTP Posture

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**checkdmarc**](https://github.com/domainaware/checkdmarc) ([GitHub](https://github.com/domainaware/checkdmarc)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain` → `dns_records, certificates, metadata` |
| **A** | [**Ruler (SensePost Exchange Recon)**](https://github.com/sensepost/ruler) ([GitHub](https://github.com/sensepost/ruler)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, email` → `emails, urls, tech_stack` |

### [checkdmarc](https://github.com/domainaware/checkdmarc) `[S-Tier]`
- **ID**: `checkdmarc` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`domainaware/checkdmarc`](https://github.com/domainaware/checkdmarc)
- **Inputs**: `domain` → **Outputs**: `dns_records`, `certificates`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `smtp`, `starttls`, `dmarc`, `spf`, `mx-recon`
- **Overview**: Python CLI and library that actively queries DNS and connects to live MX servers via SMTP STARTTLS to validate SPF, DMARC, BIMI, MTA-STS, DNSSEC, and TLS certs.
- **Quick-Start / Tradecraft**: `checkdmarc example.com`

### [Ruler (SensePost Exchange Recon)](https://github.com/sensepost/ruler) `[A-Tier]`
- **ID**: `sensepost-ruler` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`sensepost/ruler`](https://github.com/sensepost/ruler)
- **Inputs**: `domain`, `email` → **Outputs**: `emails`, `urls`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `exchange`, `autodiscover`, `mail-recon`, `active`
- **Overview**: Microsoft Exchange and Autodiscover reconnaissance tool mapping Exchange MAPI/RPC endpoints, domain autodiscover records, and mail infrastructure.
- **Quick-Start / Tradecraft**: `ruler --domain example.com autodiscover`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🕵️ Username & Handle Recon](./02-username-enumeration.md) · [📱 Phone & Messaging OSINT ▶](./04-phone-messaging-osint.md)

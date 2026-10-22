[⬅️ Back to Master Index](../README.md) · [◀ 📱 Phone & Messaging OSINT](./04-phone-messaging-osint.md) · [🔓 Breaches & Infostealers ▶](./06-breaches-leaks-stealers.md)

# 🪪 05. People Search, Public Records, Voter, Court & Genealogy Databases (`HUMINT`)

> **Scope**: Identity resolution engines, federal and state court dockets, voter/property registries, genealogy archives, missing-persons toolkits, and international wanted/interpol notices.
>
> **OPSEC Advisory**: Public-record portals and commercial people-search aggregators log searcher IP addresses and account sessions; never query sensitive targets from personal networks or non-compartmentalized accounts.

**Discipline Telemetry**: `29` Verified Tools · `5` S-Tier Flagships · `29` Passive · `24` Free/Open-Source

## Subcategories
- [Court & Legal Records](#court-legal-records) (7)
- [Global Country Registries](#global-country-registries) (2)
- [Power Networks & Political Records](#power-networks-political-records) (4)
- [Genealogy & Vital Records](#genealogy-vital-records) (4)
- [US People Aggregators](#us-people-aggregators) (4)
- [Professional License Registries](#professional-license-registries) (2)
- [Law Enforcement & Missing Persons](#law-enforcement-missing-persons) (5)
- [Enterprise Identity Resolution](#enterprise-identity-resolution) (1)

---

## Court & Legal Records

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**CourtListener & RECAP Archive**](https://www.courtlistener.com/) ([GitHub](https://github.com/freelawproject/courtlistener)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `person_records, corporate_records, archived_pages` |
| **S** | [**Judyrecords**](https://www.judyrecords.com/) | Search Engine | Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `person_records, corporate_records` |
| **S** | [**Lumen Database (Harvard Berkman Klein Center)**](https://lumendatabase.org/) ([GitHub](https://github.com/berkmancenter/lumendatabase)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `person_name, company, domain` → `corporate_records, person_records, urls` |
| **S** | [**PACER (US Federal Courts)**](https://pacer.uscourts.gov/) | Dataset / Registry | Paid | 🟢 Passive | 🔑 | `person_name, company, keyword` → `person_records, corporate_records` |
| **A** | [**BAILII (British & Irish Legal Information Institute)**](https://www.bailii.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `person_records, corporate_records` |
| **A** | [**Justia Dockets & Filings**](https://dockets.justia.com/) | Search Engine | Free | 🟢 Passive | ✅ | `person_name, company` → `person_records, corporate_records` |
| **B** | [**UK National Archives — Find Case Law**](https://caselaw.nationalarchives.gov.uk/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `person_records, corporate_records` |

### [CourtListener & RECAP Archive](https://www.courtlistener.com/) `[S-Tier]`
- **ID**: `courtlistener` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`freelawproject/courtlistener`](https://github.com/freelawproject/courtlistener)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `person_records`, `corporate_records`, `archived_pages`
- **Platforms**: Web, Chrome, Firefox · **Tags**: `recap`, `pacer-free`, `federal-dockets`, `free-law-project`, `flagship`
- **Overview**: Free Law Project's open legal archive containing millions of US federal PACER filings, judicial opinions, oral arguments, judge financial disclosures, and real-time docket alerts.
- **Quick-Start / Tradecraft**: `Always search CourtListener's RECAP tab before paying per-page PACER fees; install the RECAP browser extension.`

### [Judyrecords](https://www.judyrecords.com/) `[S-Tier]`
- **ID**: `judyrecords` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `us-courts`, `760m-cases`, `civil-criminal`, `full-text-search`, `flagship`
- **Overview**: Free full-text search engine indexing 760+ million US federal and state court cases, dockets, civil lawsuits, criminal filings, and small-claims records nationwide.
- **Quick-Start / Tradecraft**: `Wrap full names or rare street addresses in quotes (`"John Q. Doe"`) on https://www.judyrecords.com/.`

### [Lumen Database (Harvard Berkman Klein Center)](https://lumendatabase.org/) `[S-Tier]`
- **ID**: `lumendatabase` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`berkmancenter/lumendatabase`](https://github.com/berkmancenter/lumendatabase)
- **Inputs**: `person_name`, `company`, `domain`, `url` → **Outputs**: `corporate_records`, `person_records`, `urls`, `documents`
- **Platforms**: Web · **Tags**: `streisand-effect`, `dmca-takedowns`, `reputation-laundering`, `harvard-berkman`, `flagship`
- **Overview**: Collects millions of DMCA takedown, defamation, court-order, and reputation-management removal notices sent to Google, X, YouTube, and GitHub—frequently unmasking who hired PR firms to scrub links!
- **Quick-Start / Tradecraft**: `When Google says 'Some results may have been removed', click the Lumen link or search https://lumendatabase.org/ for the exact removed URLs!`

### [PACER (US Federal Courts)](https://pacer.uscourts.gov/) `[S-Tier]`
- **ID**: `pacer` · **Type**: `Dataset / Registry` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `federal-courts`, `bankruptcy`, `indictments`, `official-records`
- **Overview**: Official US Judiciary portal providing authoritative access to federal appellate, district, and bankruptcy court dockets, indictments, civil complaints, and exhibits.
- **Quick-Start / Tradecraft**: `Quarterly fees under $30 are waived automatically by the US Administrative Office of the Courts.`

### [BAILII (British & Irish Legal Information Institute)](https://www.bailii.org/) `[A-Tier]`
- **ID**: `bailii` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `uk-courts`, `ireland`, `privy-council`, `offshore-litigation`
- **Overview**: Primary free full-text database of British, Irish, Scottish, Northern Irish, European, and Privy Council court judgments and tribunal rulings.
- **Quick-Start / Tradecraft**: `Search Privy Council decisions on BAILII to uncover appellate litigation from BVI, Cayman, and Bermuda offshore entities.`

### [Justia Dockets & Filings](https://dockets.justia.com/) `[A-Tier]`
- **ID**: `justia-dockets` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `dockets`, `lawsuits`, `party-search`, `us-legal`
- **Overview**: Free searchable index of US federal district and appellate court dockets filterable by party name, state, court, nature of suit, and filing date.
- **Quick-Start / Tradecraft**: `Filter by Nature of Suit (e.g., Fraud, Trademark, RICO) alongside entity/person names at https://dockets.justia.com/.`

### [UK National Archives — Find Case Law](https://caselaw.nationalarchives.gov.uk/) `[B-Tier]`
- **ID**: `uk-find-case-law` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `uk-osint`, `high-court`, `judgments`, `national-archives`
- **Overview**: Official UK National Archives repository publishing High Court, Court of Appeal, Supreme Court, and Upper Tribunal judgments as structured XML/HTML.
- **Quick-Start / Tradecraft**: `Search commercial court and freezing-order judgments at https://caselaw.nationalarchives.gov.uk/.`

---

## Global Country Registries

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Worldwide OSINT Tools Map (cipher387)**](https://cipher387.github.io/osintmap/) ([GitHub](https://github.com/cipher387/osintmap)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword` → `person_records, corporate_records, geolocation` |
| **A** | [**OSINT-for-Countries Directory**](https://github.com/wddadk/OSINT-for-countries) ([GitHub](https://github.com/wddadk/OSINT-for-countries)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `keyword` → `person_records, corporate_records` |

### [Worldwide OSINT Tools Map (cipher387)](https://cipher387.github.io/osintmap/) `[S-Tier]`
- **ID**: `osint-tools-map` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`cipher387/osintmap`](https://github.com/cipher387/osintmap)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `person_records`, `corporate_records`, `geolocation`
- **Platforms**: Web · **Tags**: `country-osint`, `cadastres`, `national-registries`, `interactive-map`, `flagship`
- **Overview**: Interactive world map plotting 600+ country-specific official databases—land cadastres, national business registers, court portals, license-plate checks, and voter/resident directories.
- **Quick-Start / Tradecraft**: `Click any country pin on https://cipher387.github.io/osintmap/ to jump straight to local judicial/cadastral registries.`

### [OSINT-for-Countries Directory](https://github.com/wddadk/OSINT-for-countries) `[A-Tier]`
- **ID**: `osint-for-countries` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`wddadk/OSINT-for-countries`](https://github.com/wddadk/OSINT-for-countries)
- **Inputs**: `keyword` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `193-countries`, `regional-osint`, `public-records`, `international`
- **Overview**: Structured encyclopedia of local OSINT portals across all 193 UN member states and territories—covering ministries of justice, tax IDs, property records, procurement, and local search engines.
- **Quick-Start / Tradecraft**: `Browse country markdown guides in `wddadk/OSINT-for-countries` when investigating unfamiliar jurisdictions.`

---

## Power Networks & Political Records

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**DOJ FARA eFile Search**](https://efile.fara.gov/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `corporate_records, person_records, archived_pages` |
| **A** | [**FEC Individual Contributions Search**](https://www.fec.gov/data/receipts/individual-contributions/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company` → `person_records, geolocation` |
| **A** | [**LittleSis**](https://littlesis.org/) ([GitHub](https://github.com/public-accountability/littlesis-rails)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `person_name, company` → `entity_graph, person_records, corporate_records` |
| **A** | [**OpenSecrets**](https://www.opensecrets.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company` → `person_records, corporate_records` |

### [DOJ FARA eFile Search](https://efile.fara.gov/) `[A-Tier]`
- **ID**: `fara-efile` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `archived_pages`
- **Platforms**: Web · **Tags**: `fara`, `foreign-influence`, `lobbying-contracts`, `doj`
- **Overview**: US Department of Justice Foreign Agents Registration Act database containing unredacted contracts, wire amounts, PR retainers, and meeting logs between foreign principals and US lobbyists.
- **Quick-Start / Tradecraft**: `Full-text search exhibit PDFs on https://efile.fara.gov/ for foreign ministries, sovereign funds, and PR firms.`

### [FEC Individual Contributions Search](https://www.fec.gov/data/receipts/individual-contributions/) `[A-Tier]`
- **ID**: `fec-campaign-finance` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company` → **Outputs**: `person_records`, `geolocation`
- **Platforms**: Web · **Tags**: `fec`, `political-donations`, `employer-attribution`, `official-us-gov`
- **Overview**: Official US Federal Election Commission database of itemized political contributions, exposing contributor full names, residential cities/ZIPs, employers, and job titles.
- **Quick-Start / Tradecraft**: `Query target name or employer at https://www.fec.gov/data/receipts/individual-contributions/ for high-confidence employment verification.`

### [LittleSis](https://littlesis.org/) `[A-Tier]`
- **ID**: `littlesis` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`public-accountability/littlesis-rails`](https://github.com/public-accountability/littlesis-rails)
- **Inputs**: `person_name`, `company` → **Outputs**: `entity_graph`, `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `power-networks`, `board-members`, `lobbying`, `oligograph`, `accountability`
- **Overview**: Watchdog 'involuntary social network' database mapping board memberships, lobbying ties, campaign donations, family links, and revolving-door relationships among executives and public officials.
- **Quick-Start / Tradecraft**: `Use LittleSis Oligograph tool to build annotated relationship maps of executives, foundations, and political donors.`

### [OpenSecrets](https://www.opensecrets.org/) `[A-Tier]`
- **ID**: `opensecrets` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company` → **Outputs**: `person_records`, `corporate_records`
- **Platforms**: Web · **Tags**: `campaign-finance`, `fara`, `lobbying`, `donor-lookup`, `employer-address`
- **Overview**: Nonpartisan research database tracking US federal campaign contributions, PACs, dark-money 501(c)(4) flows, FARA foreign-agent registrations, congressional stock trades, and lobbying disclosures.
- **Quick-Start / Tradecraft**: `Search OpenSecrets Donor Lookup—itemized FEC filings frequently reveal a donor's exact employer, occupation, and ZIP/city!`

---

## Genealogy & Vital Records

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**FamilySearch**](https://www.familysearch.org/) | Dataset / Registry | Free | 🟢 Passive | 🔑 | `person_name, keyword` → `person_records, geolocation` |
| **A** | [**Newspapers.com & Chronicling America (LOC)**](https://chroniclingamerica.loc.gov/) | Search Engine | Freemium | 🟢 Passive | ✅ | `person_name, company, keyword` → `person_records, archived_pages` |
| **B** | [**Ancestry**](https://www.ancestry.com/) | Web Platform | Paid | 🟢 Passive | 🔑 | `person_name` → `person_records, geolocation` |
| **B** | [**Find a Grave**](https://www.findagrave.com/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name` → `person_records, geolocation` |

### [FamilySearch](https://www.familysearch.org/) `[A-Tier]`
- **ID**: `familysearch` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `person_name`, `keyword` → **Outputs**: `person_records`, `geolocation`
- **Platforms**: Web · **Tags**: `genealogy`, `vital-records`, `immigration`, `global-archives`
- **Overview**: World's largest free genealogical archive indexing billions of digitized civil birth/marriage/death certificates, census rolls, immigration manifests, and naturalization records globally.
- **Quick-Start / Tradecraft**: `Create a free research account to search unindexed municipal civil-registry microfilm scans worldwide.`

### [Newspapers.com & Chronicling America (LOC)](https://chroniclingamerica.loc.gov/) `[A-Tier]`
- **ID**: `newspapers-com` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `person_records`, `archived_pages`
- **Platforms**: Web · **Tags**: `local-newspapers`, `police-blotters`, `ocr-archives`, `library-of-congress`
- **Overview**: Library of Congress (`chroniclingamerica.loc.gov`, free) and commercial regional newspaper OCR archives surfacing local arrest blotters, marriage announcements, property sales, and obituaries unindexed by Google.
- **Quick-Start / Tradecraft**: `Search regional print newspapers by town + surname to uncover pre-internet court/police blotter items.`

### [Ancestry](https://www.ancestry.com/) `[B-Tier]`
- **ID**: `ancestry` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `person_name` → **Outputs**: `person_records`, `geolocation`
- **Platforms**: Web · **Tags**: `high-school-yearbooks`, `city-directories`, `family-trees`, `vital-records`
- **Overview**: Commercial genealogical archive indexing US/UK/European city directories, high-school yearbooks, draft cards, marriage indexes, voters rolls, and user-uploaded family trees.
- **Quick-Start / Tradecraft**: `US High School Yearbooks (1900–2016) on Ancestry often provide verified juvenile/young-adult facial photos and middle names.`

### [Find a Grave](https://www.findagrave.com/) `[B-Tier]`
- **ID**: `find-a-grave` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name` → **Outputs**: `person_records`, `geolocation`
- **Platforms**: Web · **Tags**: `obituaries`, `relatives`, `vital-records`, `genealogy`
- **Overview**: Crowdsourced global cemetery and obituary index listing 230M+ memorials, often containing full obituaries naming living spouses, children, siblings, and hometowns.
- **Quick-Start / Tradecraft**: `Search deceased relatives' memorials to map living family trees and maiden names.`

---

## US People Aggregators

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**FastPeopleSearch**](https://www.fastpeoplesearch.com/) | Search Engine | Free | 🟢 Passive | ✅ | `person_name, phone, keyword` → `person_records, phones, emails` |
| **A** | [**TruePeopleSearch**](https://www.truepeoplesearch.com/) | Search Engine | Free | 🟢 Passive | ✅ | `person_name, phone, keyword` → `person_records, phones, emails` |
| **B** | [**ClustrMaps**](https://clustrmaps.com/) | Search Engine | Free | 🟢 Passive | ✅ | `person_name, keyword` → `person_records, geolocation, corporate_records` |
| **B** | [**That'sThem**](https://thatsthem.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `person_name, email, phone` → `person_records, phones, emails` |

### [FastPeopleSearch](https://www.fastpeoplesearch.com/) `[A-Tier]`
- **ID**: `fastpeoplesearch` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `phone`, `keyword` → **Outputs**: `person_records`, `phones`, `emails`, `geolocation`
- **Platforms**: Web · **Tags**: `us-people-search`, `relatives`, `address-history`, `reverse-phone`
- **Overview**: Free US public-records aggregator linking full names, historical residential addresses, landline/wireless numbers, known relatives, and household associates.
- **Quick-Start / Tradecraft**: `Accessible from US IP ranges; pivot across historical street addresses to confirm co-residents and associates.`

### [TruePeopleSearch](https://www.truepeoplesearch.com/) `[A-Tier]`
- **ID**: `truepeoplesearch` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `phone`, `keyword` → **Outputs**: `person_records`, `phones`, `emails`, `geolocation`
- **Platforms**: Web · **Tags**: `us-people-search`, `reverse-address`, `phone-lookup`, `free`
- **Overview**: Free US people-search directory offering reverse name, reverse phone, and reverse street-address lookups with associated emails and relative trees.
- **Quick-Start / Tradecraft**: `Cross-reference results between FastPeopleSearch and TruePeopleSearch to filter stale credit-header noise.`

### [ClustrMaps](https://clustrmaps.com/) `[B-Tier]`
- **ID**: `clustrmaps` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `keyword` → **Outputs**: `person_records`, `geolocation`, `corporate_records`
- **Platforms**: Web · **Tags**: `property-records`, `residents`, `address-pivot`, `us-osint`
- **Overview**: Aggregates US municipal property deeds, neighborhood demographics, corporate officer filings, and resident histories by person name or street parcel.
- **Quick-Start / Tradecraft**: `Search a US street address on https://clustrmaps.com/ to list historical residents and linked LLCs.`

### [That'sThem](https://thatsthem.com/) `[B-Tier]`
- **ID**: `thatsthem` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `email`, `phone`, `vin`, `ip` → **Outputs**: `person_records`, `phones`, `emails`, `geolocation`
- **Platforms**: Web · **Tags**: `reverse-email`, `reverse-address`, `us-records`, `vin-lookup`
- **Overview**: People and asset lookup portal supporting reverse address, reverse phone, reverse email, VIN, and IP-to-household correlation across US consumer datasets.
- **Quick-Start / Tradecraft**: `Run free daily reverse-address or reverse-email queries at https://thatsthem.com/.`

---

## Professional License Registries

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**FINRA BrokerCheck & SEC IAPD**](https://brokercheck.finra.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company` → `person_records, corporate_records, sanctions_hits` |
| **B** | [**US NPPES NPI Registry (Healthcare Providers)**](https://npiregistry.cms.hhs.gov/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, phone` → `person_records, corporate_records, phones` |

### [FINRA BrokerCheck & SEC IAPD](https://brokercheck.finra.org/) `[A-Tier]`
- **ID**: `finra-brokercheck` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company` → **Outputs**: `person_records`, `corporate_records`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `financial-advisers`, `employment-history`, `regulatory-actions`, `finra`
- **Overview**: Official regulatory background portal for US securities brokers, investment advisers, and firms—detailing 10-year employment histories, exams, customer disputes, and regulatory sanctions.
- **Quick-Start / Tradecraft**: `Download full Detailed BrokerCheck PDF reports to inspect outside business activities (OBAs) and alias disclosures.`

### [US NPPES NPI Registry (Healthcare Providers)](https://npiregistry.cms.hhs.gov/) `[B-Tier]`
- **ID**: `npi-registry` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `phone` → **Outputs**: `person_records`, `corporate_records`, `phones`, `geolocation`
- **Platforms**: Web · **Tags**: `medical-licenses`, `npi`, `healthcare-fraud`, `free-api`
- **Overview**: Official HHS/CMS database and free REST API of every licensed US physician, clinic, pharmacist, and healthcare provider with practice addresses, taxonomies, and phone numbers.
- **Quick-Start / Tradecraft**: `curl -s 'https://npiregistry.cms.hhs.gov/api/?version=2.1&last_name=Smith&state=NY&limit=5' | jq`

---

## Law Enforcement & Missing Persons

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**INTERPOL Red & Yellow Notices**](https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name` → `person_records, sanctions_hits` |
| **B** | [**Europe's Most Wanted (Europol / ENFAST)**](https://eumostwanted.eu/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name` → `person_records, sanctions_hits` |
| **B** | [**FBI Wanted & Kidnappings API**](https://www.fbi.gov/wanted) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, keyword` → `person_records, sanctions_hits` |
| **B** | [**US Federal Bureau of Prisons (BOP) Locator**](https://www.bop.gov/inmateloc/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name` → `person_records` |
| **B** | [**VINELink**](https://vinelink.vineapps.com/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name` → `person_records` |

### [INTERPOL Red & Yellow Notices](https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices) `[A-Tier]`
- **ID**: `interpol-red-notices` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name` → **Outputs**: `person_records`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `interpol`, `wanted-fugitives`, `missing-persons`, `kyc-aml`
- **Overview**: Official INTERPOL public portal listing internationally wanted fugitives (Red Notices) and missing persons (Yellow Notices) filterable by nationality, age, name, and issuing country.
- **Quick-Start / Tradecraft**: `Cross-check international KYC/due-diligence subjects against INTERPOL Red Notices (also indexed in OpenSanctions).`

### [Europe's Most Wanted (Europol / ENFAST)](https://eumostwanted.eu/) `[B-Tier]`
- **ID**: `europol-most-wanted` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name` → **Outputs**: `person_records`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `europol`, `enfast`, `european-fugitives`, `aml-kyc`
- **Overview**: European Network of Fugitive Active Search Teams & Europol public fugitive portal listing high-priority European wanted suspects and crime summaries.
- **Quick-Start / Tradecraft**: `Screen high-risk European KYC subjects against https://eumostwanted.eu/ and INTERPOL Red Notices.`

### [FBI Wanted & Kidnappings API](https://www.fbi.gov/wanted) `[B-Tier]`
- **ID**: `fbi-most-wanted` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `keyword` → **Outputs**: `person_records`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `fbi`, `cyber-most-wanted`, `public-api`, `fugitives`
- **Overview**: Official FBI database and keyless public JSON API (`api.fbi.gov/wanted/v1/list`) covering cyber fugitives, transnational crime targets, terrorism suspects, and missing persons.
- **Quick-Start / Tradecraft**: `curl -s 'https://api.fbi.gov/wanted/v1/list?field_offices=newyork' | jq '.items[].title'`

### [US Federal Bureau of Prisons (BOP) Locator](https://www.bop.gov/inmateloc/) `[B-Tier]`
- **ID**: `bop-inmate-locator` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name` → **Outputs**: `person_records`
- **Platforms**: Web · **Tags**: `federal-prisons`, `bop`, `release-dates`, `official-us-gov`
- **Overview**: Official lookup of federal inmates incarcerated from 1982 to the present, including BOP register numbers, current facility, age, and projected/actual release dates.
- **Quick-Start / Tradecraft**: `Query by first/last name or BOP Register Number at https://www.bop.gov/inmateloc/.`

### [VINELink](https://vinelink.vineapps.com/) `[B-Tier]`
- **ID**: `vinelink` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name` → **Outputs**: `person_records`
- **Platforms**: Web · **Tags**: `custody-status`, `inmate-lookup`, `us-corrections`
- **Overview**: US nationwide correctional custody and offender status lookup portal covering thousands of county jails and state Departments of Corrections.
- **Quick-Start / Tradecraft**: `Select US state and search custody status by name/ID at https://vinelink.vineapps.com/.`

---

## Enterprise Identity Resolution

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Pipl**](https://pipl.com/) | Web Platform | Paid | 🟢 Passive | 🔑 | `person_name, email, phone` → `person_records, emails, phones` |

### [Pipl](https://pipl.com/) `[A-Tier]`
- **ID**: `pipl` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `person_name`, `email`, `phone`, `username` → **Outputs**: `person_records`, `emails`, `phones`, `social_profiles`, `geolocation`
- **Platforms**: Web · **Tags**: `identity-resolution`, `kyc`, `fraud-investigation`, `enterprise`
- **Overview**: Enterprise identity-resolution platform linking billions of cross-referenced non-public/public identity attributes (names, handles, phones, career history, global addresses) for fraud and LE analysts.
- **Quick-Start / Tradecraft**: `Enterprise subscription required; combine subtle partial selectors (e.g., handle + city) to disambiguate common names.`

---
[⬅️ Back to Master Index](../README.md) · [◀ 📱 Phone & Messaging OSINT](./04-phone-messaging-osint.md) · [🔓 Breaches & Infostealers ▶](./06-breaches-leaks-stealers.md)

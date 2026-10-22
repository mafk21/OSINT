[⬅️ Back to Master Index](../README.md) · [◀ ✈️ Aviation, Maritime & Transport](./13-aviation-maritime-transport.md) · [⛓️ Crypto & Blockchain OSINT ▶](./15-crypto-blockchain-web3.md)

# 🏛️ 14. Corporate Registries, Beneficial Ownership, Sanctions, Trade & Financial OSINT (`FININT`)

> **Scope**: Global company registries, beneficial ownership (PSC/UBO) databases, offshore leak archives, consolidated OFAC/EU/UN/PEP sanctions screens, SEC/procurement filings, and patent/trademark portals.
>
> **OPSEC Advisory**: Official corporate registries in a few jurisdictions (e.g., certain European/Asian portals) require citizen eID login and log who accessed a company dossier; check registry anonymity rules first.

**Discipline Telemetry**: `25` Verified Tools · `11` S-Tier Flagships · `25` Passive · `19` Free/Open-Source

## Subcategories
- [Global Company Registries](#global-company-registries) (8)
- [Investigative Leak & Filing Archives](#investigative-leak-filing-archives) (2)
- [Sanctions, PEPs & Watchlists](#sanctions,-peps-watchlists) (4)
- [Nonprofits, Procurement & Tenders](#nonprofits,-procurement-tenders) (4)
- [Securities & Financial Filings](#securities-financial-filings) (2)
- [Regulatory & Enforcement Records](#regulatory-enforcement-records) (1)
- [Trade & Intellectual Property](#trade-intellectual-property) (3)
- [Venture & Market Intelligence](#venture-market-intelligence) (1)

---

## Global Company Registries

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GLEIF Legal Entity Identifier (LEI) Search**](https://search.gleif.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `corporate_records, entity_graph` |
| **S** | [**OpenCorporates**](https://opencorporates.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records, entity_graph` |
| **S** | [**Pappers.fr (French Corporate & UBO Intelligence)**](https://www.pappers.fr/) | Web Platform | Freemium | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records, documents` |
| **S** | [**UK Companies House & Overseas Entities Register**](https://find-and-update.company-information.service.gov.uk/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records, documents` |
| **A** | [**EU e-Justice Business & Insolvency Registers Portal**](https://e-justice.europa.eu/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `corporate_records` |
| **A** | [**Handelsregister.de (Official German Commercial Register)**](https://www.handelsregister.de/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `corporate_records, person_records, documents` |
| **A** | [**North Data**](https://www.northdata.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `company, person_name` → `corporate_records, person_records, entity_graph` |
| **A** | [**Open Ownership Register**](https://register.openownership.org/) ([GitHub](https://github.com/openownership/data-standard)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `person_name, company` → `corporate_records, person_records, entity_graph` |

### [GLEIF Legal Entity Identifier (LEI) Search](https://search.gleif.org/) `[S-Tier]`
- **ID**: `gleif-lei-search` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `lei-lookup`, `parent-subsidiary`, `counterparty-kyb`, `free-api`
- **Overview**: Global Legal Entity Identifier Foundation database mapping 2.6M+ financial counterparties worldwide—explicitly disclosing 'Level 2' Direct Accounting Parent and Ultimate Parent ownership chains!
- **Quick-Start / Tradecraft**: `curl -s 'https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=Example' | jq`

### [OpenCorporates](https://opencorporates.com/) `[S-Tier]`
- **ID**: `opencorporates` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `220m-companies`, `director-search`, `140-jurisdictions`, `kyb`, `flagship`
- **Overview**: World's largest open database of legal entities—normalizing 220M+ company registrations and 290M+ officer/director records across 140+ national and state jurisdictions with direct registry provenance.
- **Quick-Start / Tradecraft**: `Switch search tab from 'Companies' to 'Officers' on https://opencorporates.com/ to find every company directed by a person globally!`

### [Pappers.fr (French Corporate & UBO Intelligence)](https://www.pappers.fr/) `[S-Tier]`
- **ID**: `pappers-fr` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`, `entity_graph`
- **Platforms**: Web · **Tags**: `france-osint`, `siren-siret`, `beneficial-owners`, `free-pdf-filings`, `flagship`
- **Overview**: Open French corporate intelligence platform enriching INSEE/INPI/BODACC data—providing free downloadable PDF statutes, annual accounts, director networks, and Registre des Bénéficiaires Effectifs!
- **Quick-Start / Tradecraft**: `Search any French company or director name on https://www.pappers.fr/ for free downloadable incorporation PDFs and UBO trees!`

### [UK Companies House & Overseas Entities Register](https://find-and-update.company-information.service.gov.uk/) `[S-Tier]`
- **ID**: `uk-companies-house` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`
- **Platforms**: Web, Python · **Tags**: `uk-osint`, `beneficial-ownership`, `psc-register`, `overseas-entities`, `free-api`, `flagship`
- **Overview**: Gold-standard completely free corporate registry providing full PDF incorporation deeds, annual accounts, officer DOBs/addresses, Persons with Significant Control (PSC), and Overseas Entities owning UK property!
- **Quick-Start / Tradecraft**: `Always inspect the 'People -> Persons with significant control' tab and 'Register of Overseas Entities' filings!`

### [EU e-Justice Business & Insolvency Registers Portal](https://e-justice.europa.eu/) `[A-Tier]`
- **ID**: `eu-ejustice-registers` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`
- **Platforms**: Web · **Tags**: `eu-bris`, `insolvency-registers`, `land-registers`, `27-member-states`
- **Overview**: Official European Union gateway linking interconnected national commercial registers (BRIS), insolvency registers, and land cadastres across all 27 EU member states.
- **Quick-Start / Tradecraft**: `Use the EU e-Justice Business Registers country matrix to jump straight to official state registries and avoid scam clone sites.`

### [Handelsregister.de (Official German Commercial Register)](https://www.handelsregister.de/) `[A-Tier]`
- **ID**: `handelsregister-de` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`
- **Platforms**: Web · **Tags**: `germany-osint`, `gesellschafterliste`, `free-shareholder-lists`, `official-registry`
- **Overview**: Official federal portal of German state commercial courts—since August 2022, complete PDF articles of association, officer appointments, and full GmbH shareholder lists (`Gesellschafterliste`) are 100% free with no login!
- **Quick-Start / Tradecraft**: `Click `DK` (Dokumentenbaum) on https://www.handelsregister.de/ to download free scanned GmbH shareholder PDFs (`Liste der Gesellschafter`)!`

### [North Data](https://www.northdata.com/) `[A-Tier]`
- **ID**: `north-data` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name` → **Outputs**: `corporate_records`, `person_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `european-companies`, `handelsregister`, `visual-corporate-graph`, `ubo`
- **Overview**: Visual European corporate intelligence engine automatically graphing director networks, gazette filings, UBO changes, and financials across Germany (`Handelsregister`), France, UK, Switzerland, Spain, and EU states.
- **Quick-Start / Tradecraft**: `Search any European company or director on https://www.northdata.com/ for instant interactive corporate network charts.`

### [Open Ownership Register](https://register.openownership.org/) `[A-Tier]`
- **ID**: `openownership` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`openownership/data-standard`](https://github.com/openownership/data-standard)
- **Inputs**: `person_name`, `company` → **Outputs**: `corporate_records`, `person_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `beneficial-ownership`, `bods-standard`, `ubo-transparency`, `anti-corruption`
- **Overview**: Transnational beneficial-ownership database expressed in the Beneficial Ownership Data Standard (BODS), linking natural-person UBOs across UK, Denmark, Slovakia, Ukraine, and extractive registries.
- **Quick-Start / Tradecraft**: `Query natural persons on https://register.openownership.org/ to view percentage shareholdings and control rights.`

---

## Investigative Leak & Filing Archives

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ICIJ Offshore Leaks Database**](https://offshoreleaks.icij.org/) ([GitHub](https://github.com/ICIJ/datashare)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `corporate_records, person_records, entity_graph` |
| **S** | [**OCCRP Aleph**](https://aleph.occrp.org/) ([GitHub](https://github.com/alephdata/aleph)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `person_name, company, email` → `corporate_records, person_records, documents` |

### [ICIJ Offshore Leaks Database](https://offshoreleaks.icij.org/) `[S-Tier]`
- **ID**: `icij-offshore-leaks` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ICIJ/datashare`](https://github.com/ICIJ/datashare)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `panama-papers`, `pandora-papers`, `paradise-papers`, `shell-companies`, `ubo`, `flagship`
- **Overview**: Interactive graph database from the International Consortium of Investigative Journalists spanning 810,000+ offshore shell companies, trusts, and foundations from Panama, Pandora, Paradise, and Bahamas Papers.
- **Quick-Start / Tradecraft**: `Explore interactive Neo4j officer/intermediary/address graphs on https://offshoreleaks.icij.org/ or download the full CSV graph.`

### [OCCRP Aleph](https://aleph.occrp.org/) `[S-Tier]`
- **ID**: `occrp-aleph` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`alephdata/aleph`](https://github.com/alephdata/aleph)
- **Inputs**: `person_name`, `company`, `email`, `phone`, `vessel_imo`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`, `entity_graph`
- **Platforms**: Web, Docker, Python · **Tags**: `occrp`, `investigative-journalism`, `followthemoney`, `cross-border-corruption`, `flagship`
- **Overview**: Organized Crime and Corruption Reporting Project's flagship investigative data platform cross-indexing hundreds of millions of leaked emails, land registries, gazettes, procurement files, and corporate filings.
- **Quick-Start / Tradecraft**: `Search names, passport numbers, IBANs, or company strings across 300+ public datasets on https://aleph.occrp.org/.`

---

## Sanctions, PEPs & Watchlists

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**OpenSanctions**](https://www.opensanctions.org/) ([GitHub](https://github.com/opensanctions/opensanctions)) | Dataset / Registry | Freemium | 🟢 Passive | ✅ | `person_name, company, vessel_imo` → `sanctions_hits, corporate_records, person_records` |
| **S** | [**US Treasury OFAC Sanctions List Search**](https://sanctionssearch.ofac.treas.gov/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, vessel_imo` → `sanctions_hits` |
| **A** | [**EU Sanctions Map**](https://www.sanctionsmap.eu/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `sanctions_hits` |
| **A** | [**World Bank Listing of Ineligible (Debarred) Firms & Individuals**](https://www.worldbank.org/en/projects-operations/procurement/debarred-firms) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, person_name` → `sanctions_hits, corporate_records` |

### [OpenSanctions](https://www.opensanctions.org/) `[S-Tier]`
- **ID**: `opensanctions` · **Type**: `Dataset / Registry` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`opensanctions/opensanctions`](https://github.com/opensanctions/opensanctions)
- **Inputs**: `person_name`, `company`, `vessel_imo`, `aircraft_hex`, `crypto_address` → **Outputs**: `sanctions_hits`, `corporate_records`, `person_records`, `entity_graph`
- **Platforms**: Web, Docker, Python · **Tags**: `ofac-eu-un`, `pep-screening`, `shadow-fleet`, `followthemoney`, `bulk-data`, `flagship`
- **Overview**: Open-source entity graph normalizing 1.8M+ sanctioned entities, Politically Exposed Persons (PEPs), shadow-fleet vessels, aircraft, crypto wallets, and criminal warrants across 475+ official global sources.
- **Quick-Start / Tradecraft**: `Search free at https://www.opensanctions.org/search/ or self-host `yente` (`docker run -p 8000:8000 ghcr.io/opensanctions/yente:latest`).`

### [US Treasury OFAC Sanctions List Search](https://sanctionssearch.ofac.treas.gov/) `[S-Tier]`
- **ID**: `ofac-sanctions-search` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `vessel_imo`, `aircraft_hex`, `crypto_address` → **Outputs**: `sanctions_hits`
- **Platforms**: Web · **Tags**: `ofac-sdn`, `us-treasury`, `fuzzy-matching`, `sanctioned-crypto`
- **Overview**: Authoritative US Treasury Office of Foreign Assets Control fuzzy-matching lookup covering SDN and Consolidated Non-SDN lists—including sanctioned passport IDs, IMO numbers, tail numbers, and BTC/ETH/USDT addresses.
- **Quick-Start / Tradecraft**: `Set Minimum Name Score slider to 85 on https://sanctionssearch.ofac.treas.gov/ or search digital currency addresses in the ID field.`

### [EU Sanctions Map](https://www.sanctionsmap.eu/) `[A-Tier]`
- **ID**: `eu-sanctions-map` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `sanctions_hits`
- **Platforms**: Web · **Tags**: `eu-sanctions`, `asset-freezes`, `embargoes`, `official-eu`
- **Overview**: Official European Commission interactive map detailing EU restrictive measures, arms embargoes, asset-freeze lists, and legal Council Regulations regime-by-regime.
- **Quick-Start / Tradecraft**: `Export consolidated EU Financial Sanctions Files or inspect regime legal bases at https://www.sanctionsmap.eu/.`

### [World Bank Listing of Ineligible (Debarred) Firms & Individuals](https://www.worldbank.org/en/projects-operations/procurement/debarred-firms) `[A-Tier]`
- **ID**: `world-bank-debarred` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name` → **Outputs**: `sanctions_hits`, `corporate_records`
- **Platforms**: Web · **Tags**: `world-bank`, `procurement-fraud`, `cross-debarment`, `anti-corruption`
- **Overview**: Official multilateral development bank cross-debarment table sanctioning companies and individuals caught in procurement fraud, collusion, or corruption across global infrastructure projects.
- **Quick-Start / Tradecraft**: `Cross-check international engineering, construction, and consulting vendors against World Bank Debarred Firms.`

---

## Nonprofits, Procurement & Tenders

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ProPublica Nonprofit Explorer**](https://projects.propublica.org/nonprofits/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records, documents` |
| **A** | [**SAM.gov (System for Award Management)**](https://sam.gov/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, sanctions_hits, emails` |
| **A** | [**TED (Tenders Electronic Daily — EU)**](https://ted.europa.eu/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `corporate_records, documents` |
| **A** | [**USAspending.gov**](https://www.usaspending.gov/) ([GitHub](https://github.com/fedspendingtransparency/usaspending-api)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `company, keyword` → `corporate_records, documents` |

### [ProPublica Nonprofit Explorer](https://projects.propublica.org/nonprofits/) `[S-Tier]`
- **ID**: `propublica-nonprofit-explorer` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`
- **Platforms**: Web · **Tags**: `irs-form-990`, `nonprofits`, `foundation-grants`, `executive-compensation`
- **Overview**: Full-text search over 14M+ IRS Form 990 tax filings from US 501(c) tax-exempt organizations, foundations, think tanks, and trade associations—exposing executive pay, Schedule I grants, and board members.
- **Quick-Start / Tradecraft**: `Search Schedule I & Schedule J inside Form 990 XML/PDFs on ProPublica to trace dark-money foundation grants and contractor fees.`

### [SAM.gov (System for Award Management)](https://sam.gov/) `[A-Tier]`
- **ID**: `sam-gov` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `sanctions_hits`, `emails`, `phones`
- **Platforms**: Web · **Tags**: `cage-code`, `uei`, `debarments`, `government-contractors`
- **Overview**: Official US portal for federal contractor registrations (CAGE codes, UEIs, physical addresses, points of contact) and Federal Exclusions/Debarments.
- **Quick-Start / Tradecraft**: `Look up any CAGE code or company name in SAM.gov Entity Information to extract Government Business POC emails and phones.`

### [TED (Tenders Electronic Daily — EU)](https://ted.europa.eu/) `[A-Tier]`
- **ID**: `ted-eu-tenders` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`, `documents`
- **Platforms**: Web · **Tags**: `eu-procurement`, `contract-awards`, `government-tenders`, `europe`
- **Overview**: Official European Union public-procurement journal publishing multi-year tender notices and contract award notices (winning vendors, contract values, buyer ministries) across Europe.
- **Quick-Start / Tradecraft**: `Filter by 'Contract award notice' + winner name on https://ted.europa.eu/ to audit public-sector revenue of European firms.`

### [USAspending.gov](https://www.usaspending.gov/) `[A-Tier]`
- **ID**: `usaspending` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`fedspendingtransparency/usaspending-api`](https://github.com/fedspendingtransparency/usaspending-api)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`, `documents`
- **Platforms**: Web, Python · **Tags**: `federal-contracts`, `defense-procurement`, `sub-awards`, `official-us-gov`
- **Overview**: Official open-data source of US federal government spending—tracking prime contracts, defense awards, sub-awards, grants, recipient UEIs, and agency obligations.
- **Quick-Start / Tradecraft**: `Use Advanced Award Search on https://www.usaspending.gov/search to trace prime-to-subcontractor award flows.`

---

## Securities & Financial Filings

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**SEC EDGAR Full-Text Search**](https://www.sec.gov/edgar/searchedgar/companysearch) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records, documents` |
| **B** | [**OpenInsider (SEC Form 4 Insider Trading Screener)**](http://openinsider.com/) | Search Engine | Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records` |

### [SEC EDGAR Full-Text Search](https://www.sec.gov/edgar/searchedgar/companysearch) `[S-Tier]`
- **ID**: `sec-edgar` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`
- **Platforms**: Web, Python · **Tags**: `sec-filings`, `exhibit-21-subsidiaries`, `form-4-insiders`, `full-text-edgar`, `flagship`
- **Overview**: US Securities and Exchange Commission full-text search across every 10-K, 10-Q, 8-K, Form 4 insider trade, 13F fund portfolio, and Exhibit 21 subsidiary list filed since 2001.
- **Quick-Start / Tradecraft**: `Use https://www.sec.gov/edgar/search/ (`EFTS`) to search Exhibit 21 (`EX-21`) for complete global subsidiary trees of public companies!`

### [OpenInsider (SEC Form 4 Insider Trading Screener)](http://openinsider.com/) `[B-Tier]`
- **ID**: `openinsider` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`
- **Platforms**: Web · **Tags**: `sec-form-4`, `insider-selling`, `executive-holdings`, `financial-osint`
- **Overview**: Clean, instant screener over real-time SEC Form 4 filings tracking executive, director, and 10%-owner cluster stock purchases and liquidations across US public companies.
- **Quick-Start / Tradecraft**: `Filter cluster sales ahead of corporate breach or litigation announcements on http://openinsider.com/.`

---

## Regulatory & Enforcement Records

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Violation Tracker & Subsidy Tracker (Good Jobs First)**](https://violationtrackerglobal.goodjobsfirst.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword` → `corporate_records, sanctions_hits` |

### [Violation Tracker & Subsidy Tracker (Good Jobs First)](https://violationtrackerglobal.goodjobsfirst.org/) `[S-Tier]`
- **ID**: `violation-tracker-global` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `regulatory-fines`, `fcpa-bribery`, `environmental-violations`, `due-diligence`, `flagship`
- **Overview**: Searchable database cataloging corporate regulatory fines, environmental penalties, FCPA bribery settlements, labor violations, and antitrust actions across 40+ countries ($1T+ in tracked penalties!).
- **Quick-Start / Tradecraft**: `Search parent or subsidiary names on https://violationtrackerglobal.goodjobsfirst.org/ during ESG, M&A, or vendor due diligence!`

---

## Trade & Intellectual Property

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Google Patents**](https://patents.google.com/) | Search Engine | Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `corporate_records, person_records, documents` |
| **A** | [**UN Comtrade Database**](https://comtradeplus.un.org/) | Dataset / Registry | Freemium | 🟢 Passive | ✅ | `keyword` → `corporate_records` |
| **A** | [**WIPO Global Brand & PatentScope Databases**](https://branddb.wipo.int/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, person_name, image` → `corporate_records, person_records` |

### [Google Patents](https://patents.google.com/) `[A-Tier]`
- **ID**: `google-patents` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `corporate_records`, `person_records`, `documents`
- **Platforms**: Web · **Tags**: `patent-reassignments`, `r-and-d-recon`, `inventors`, `100-offices`
- **Overview**: Indexes 100M+ patent publications across 100+ patent offices worldwide with OCR'd drawings, assignee reassignment histories (who sold IP to whom!), and non-patent academic citations.
- **Quick-Start / Tradecraft**: `Search `assignee:"Target Company"` or `inventor:"Full Name"` on https://patents.google.com/.`

### [UN Comtrade Database](https://comtradeplus.un.org/) `[A-Tier]`
- **ID**: `un-comtrade` · **Type**: `Dataset / Registry` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `corporate_records`
- **Platforms**: Web, Python · **Tags**: `bilateral-trade`, `hs-codes`, `sanctions-circumvention`, `mirror-trade-analysis`
- **Overview**: United Nations repository of official bilateral international trade statistics by 6-digit HS commodity code—essential for spotting sanctions-transshipment spikes ('mirror data' discrepancies).
- **Quick-Start / Tradecraft**: `Compare Country A's reported exports to Country B vs. Country B's reported imports to spot customs evasion.`

### [WIPO Global Brand & PatentScope Databases](https://branddb.wipo.int/) `[A-Tier]`
- **ID**: `wipo-brand-db` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `person_name`, `image`, `keyword` → **Outputs**: `corporate_records`, `person_records`
- **Platforms**: Web · **Tags**: `trademarks`, `logo-image-search`, `patents`, `inventor-addresses`, `wipo`
- **Overview**: World Intellectual Property Organization search engine across 70+ million trademark, logo, Madrid international registration, and PCT patent filings—often revealing stealth product launches and applicant addresses.
- **Quick-Start / Tradecraft**: `Search inventor full names in PatentScope—early patent filings routinely list inventors' unredacted home cities/addresses!`

---

## Venture & Market Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Crunchbase**](https://www.crunchbase.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `company, person_name` → `corporate_records, person_records, entity_graph` |

### [Crunchbase](https://www.crunchbase.com/) `[B-Tier]`
- **ID**: `crunchbase` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `company`, `person_name` → **Outputs**: `corporate_records`, `person_records`, `entity_graph`
- **Platforms**: Web · **Tags**: `venture-capital`, `cap-table-signals`, `acquisitions`, `founders`
- **Overview**: Startup, venture-capital, M&A acquisition, investor syndicate, and executive biography database covering private technology companies worldwide.
- **Quick-Start / Tradecraft**: `Map shared angel investors and board seats across early-stage private companies on https://www.crunchbase.com/.`

---
[⬅️ Back to Master Index](../README.md) · [◀ ✈️ Aviation, Maritime & Transport](./13-aviation-maritime-transport.md) · [⛓️ Crypto & Blockchain OSINT ▶](./15-crypto-blockchain-web3.md)

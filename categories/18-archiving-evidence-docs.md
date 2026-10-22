[⬅️ Back to Master Index](../README.md) · [◀ 🛡️ Threat Intel, Malware & IOCs](./17-threat-intel-malware-cti.md) · [📻 SIGINT, Wireless, SDR & Space ▶](./19-sigint-wireless-space-rf.md)

# 🗄️ 18. Web Archiving, Forensic Evidence Capture, Document Metadata & Grey Literature (`ARCHINT`)

> **Scope**: Historical web caches, tamper-evident forensic browser recorders (WARC/WACZ/SHA-256), headless screenshotters, document metadata extractors, FOIA portals, and academic/scientific search engines.
>
> **OPSEC Advisory**: Submitting a target's private/unindexed URL to `web.archive.org/save` or `archive.today` causes their crawler to fetch the URL immediately and makes the snapshot publicly discoverable!

**Discipline Telemetry**: `23` Verified Tools · `8` S-Tier Flagships · `15` Passive · `19` Free/Open-Source

## Subcategories
- [Historical Web Archives](#historical-web-archives) (6)
- [Forensic Evidence Capture](#forensic-evidence-capture) (6)
- [Document Sanitization & Safety](#document-sanitization-safety) (1)
- [FOIA & Primary Document Portals](#foia-primary-document-portals) (3)
- [Academic & Grey Literature](#academic-grey-literature) (3)
- [Visual Recon Screenshotters](#visual-recon-screenshotters) (2)
- [Document Metadata Extraction](#document-metadata-extraction) (2)

---

## Historical Web Archives

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**archive.today (archive.ph / archive.is)**](https://archive.ph/) | Web Platform | Free | 🟡 Hybrid | ✅ | `url, domain` → `archived_pages` |
| **S** | [**Wayback Machine (Internet Archive)**](https://web.archive.org/) ([GitHub](https://github.com/internetarchive/wayback)) | Search Engine | Free | 🟢 Passive | ✅ | `url, domain, keyword` → `archived_pages, urls, documents` |
| **A** | [**ArchiveBox**](https://archivebox.io/) ([GitHub](https://github.com/ArchiveBox/ArchiveBox)) | Framework | OSS / Free | 🔴 Active | ✅ | `url` → `archived_pages, documents` |
| **A** | [**Common Crawl Index**](https://commoncrawl.org/) ([GitHub](https://github.com/commoncrawl/cc-crawl-statistics)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `domain, url, keyword` → `archived_pages, urls, entity_graph` |
| **A** | [**Ghostarchive**](https://ghostarchive.org/) | Web Platform | Free | 🟡 Hybrid | ✅ | `url` → `archived_pages` |
| **A** | [**Memento TimeTravel**](http://timetravel.mementoweb.org/) | Search Engine | Free | 🟢 Passive | ✅ | `url` → `archived_pages` |

### [archive.today (archive.ph / archive.is)](https://archive.ph/) `[S-Tier]`
- **ID**: `archive-today` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct)
- **Inputs**: `url`, `domain` → **Outputs**: `archived_pages`
- **Platforms**: Web · **Tags**: `archive-ph`, `dom-snapshot`, `social-preservation`, `anti-deletion`, `flagship`
- **Overview**: High-fidelity DOM + screenshot web archiver capturing JavaScript-heavy pages, social threads, and news articles that block `archive.org` `robots.txt` rules.
- **Quick-Start / Tradecraft**: `Search `https://archive.ph/<domain>/*` passively first! Submitting a NEW URL in the top red box actively fetches the target!`

### [Wayback Machine (Internet Archive)](https://web.archive.org/) `[S-Tier]`
- **ID**: `wayback-machine` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`internetarchive/wayback`](https://github.com/internetarchive/wayback)
- **Inputs**: `url`, `domain`, `keyword` → **Outputs**: `archived_pages`, `urls`, `documents`
- **Platforms**: Web, Chrome, Firefox, Python · **Tags**: `internet-archive`, `900b-pages`, `cdx-api`, `deleted-websites`, `flagship`
- **Overview**: Humanity's digital memory indexing 900+ billion archived web captures since 1996, backed by the powerful CDX Server API for wildcard subdomain discovery, MIME filtering, and deleted-content recovery.
- **Quick-Start / Tradecraft**: `Use `https://web.archive.org/web/*/<domain>/*` to list every unique file & URL ever crawled under a target domain!`

### [ArchiveBox](https://archivebox.io/) `[A-Tier]`
- **ID**: `archivebox` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`ArchiveBox/ArchiveBox`](https://github.com/ArchiveBox/ArchiveBox)
- **Inputs**: `url` → **Outputs**: `archived_pages`, `documents`
- **Platforms**: Docker, Linux, macOS, Python · **Tags**: `self-hosted-wayback`, `warc`, `multi-format-preservation`, `docker`
- **Overview**: Powerful open-source self-hosted internet archiving server ingesting URLs/bookmarks/RSS and saving HTML, SingleFile, WARC, PDF, PNG screenshots, `yt-dlp` media, and Git repos locally.
- **Quick-Start / Tradecraft**: `docker compose run archivebox add 'https://example.com/post'`

### [Common Crawl Index](https://commoncrawl.org/) `[A-Tier]`
- **ID**: `common-crawl` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`commoncrawl/cc-crawl-statistics`](https://github.com/commoncrawl/cc-crawl-statistics)
- **Inputs**: `domain`, `url`, `keyword` → **Outputs**: `archived_pages`, `urls`, `entity_graph`
- **Platforms**: Web, Python · **Tags**: `petabyte-crawl`, `webgraph-backlinks`, `athena-sql`, `cdx-index`
- **Overview**: Open non-profit repository of petabyte-scale monthly raw web crawls (WARC/WAT/WET) and host-level link graphs since 2008—enabling passive inbound backlink and body-text searches.
- **Quick-Start / Tradecraft**: `curl -s 'https://index.commoncrawl.org/CC-MAIN-2026-26-index?url=*.example.com&output=json' | head`

### [Ghostarchive](https://ghostarchive.org/) `[A-Tier]`
- **ID**: `ghostarchive` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct)
- **Inputs**: `url` → **Outputs**: `archived_pages`
- **Platforms**: Web · **Tags**: `video-archive`, `social-posts`, `web-preservation`
- **Overview**: Fast public web and video archiver specializing in preserving YouTube videos, social media posts, and short-lived pages before takedowns.
- **Quick-Start / Tradecraft**: `Check Ghostarchive when Wayback Machine or Archive.today missed a deleted YouTube upload or social post.`

### [Memento TimeTravel](http://timetravel.mementoweb.org/) `[A-Tier]`
- **ID**: `memento-timetravel` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `url` → **Outputs**: `archived_pages`
- **Platforms**: Web, Chrome · **Tags**: `25-web-archives`, `national-libraries`, `meta-wayback`, `rfc-7089`
- **Overview**: Meta-archive aggregator federated across 25+ national libraries and web archives simultaneously (Wayback, Archive.today, UK Web Archive, Library of Congress, Stanford, Icelandic, Portuguese archives)!
- **Quick-Start / Tradecraft**: `Query Memento TimeTravel whenever `web.archive.org` returns 0 snapshots—national web archives often captured country-TLD sites!`

---

## Forensic Evidence Capture

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ArchiveWeb.page (Webrecorder)**](https://archiveweb.page/) ([GitHub](https://github.com/webrecorder/archiveweb.page)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `url` → `archived_pages` |
| **S** | [**Hunchly**](https://www.hunchly.com/) | Desktop App | Paid | 🟢 Passive | 🔑 | `url, keyword` → `archived_pages, metadata, entity_graph` |
| **S** | [**SingleFile**](https://github.com/gildas-lormeau/SingleFile) ([GitHub](https://github.com/gildas-lormeau/SingleFile)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `url` → `archived_pages` |
| **A** | [**Browsertrix Crawler (Webrecorder)**](https://github.com/webrecorder/browsertrix-crawler) ([GitHub](https://github.com/webrecorder/browsertrix-crawler)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `archived_pages` |
| **A** | [**Forensic OSINT**](https://www.forensicosint.com/) | Browser Extension | Paid | 🟢 Passive | 🔑 | `url` → `archived_pages, metadata` |
| **A** | [**Perma.cc (Harvard Library Innovation Lab)**](https://perma.cc/) ([GitHub](https://github.com/harvard-lil/perma)) | Web Platform | Freemium | 🔴 Active | 🔑 | `url` → `archived_pages` |

### [ArchiveWeb.page (Webrecorder)](https://archiveweb.page/) `[S-Tier]`
- **ID**: `archiveweb-page` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`webrecorder/archiveweb.page`](https://github.com/webrecorder/archiveweb.page)
- **Inputs**: `url` → **Outputs**: `archived_pages`
- **Platforms**: Chrome, Windows, macOS, Linux · **Tags**: `webrecorder`, `wacz-warc`, `interactive-replay`, `berkeley-protocol`, `flagship`
- **Overview**: Webrecorder's open-source Chromium extension & desktop app capturing interactive scrolling social feeds, video streams, and dynamic XHR traffic into cryptographically signed `.wacz` ISO-standard web archives!
- **Quick-Start / Tradecraft**: `Use ArchiveWeb.page + ReplayWeb.page for Berkeley Protocol-compliant human-rights & war-crimes digital evidence preservation!`

### [Hunchly](https://www.hunchly.com/) `[S-Tier]`
- **ID**: `hunchly` · **Type**: `Desktop App` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `url`, `keyword` → **Outputs**: `archived_pages`, `metadata`, `entity_graph`
- **Platforms**: Windows, macOS, Linux, Chrome · **Tags**: `forensic-capture`, `sha256-chain-of-custody`, `court-admissible`, `maltego`, `flagship`
- **Overview**: Gold-standard commercial forensic browser capture suite automatically recording, SHA-256 hashing, timestamping, full-text indexing, and selector-tagging every single webpage visited during an investigation.
- **Quick-Start / Tradecraft**: `Toggle Hunchly Capture ON at the start of every case so no ephemeral post vanishes unrecorded while browsing.`

### [SingleFile](https://github.com/gildas-lormeau/SingleFile) `[S-Tier]`
- **ID**: `singlefile` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`gildas-lormeau/SingleFile`](https://github.com/gildas-lormeau/SingleFile)
- **Inputs**: `url` → **Outputs**: `archived_pages`
- **Platforms**: Chrome, Firefox, CLI, Node.js · **Tags**: `local-evidence`, `self-contained-html`, `zero-cloud-leak`, `22k-stars`, `flagship`
- **Overview**: Essential open-source browser extension & CLI saving a complete, pixel-faithful rendered webpage (CSS, fonts, canvas, images embedded as data URIs) into a single self-contained `.html` file locally.
- **Quick-Start / Tradecraft**: `Save visited pages locally with SingleFile, then immediately run `sha256sum evidence.html >> case_hashes.txt`!`

### [Browsertrix Crawler (Webrecorder)](https://github.com/webrecorder/browsertrix-crawler) `[A-Tier]`
- **ID**: `browsertrix-crawler` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`webrecorder/browsertrix-crawler`](https://github.com/webrecorder/browsertrix-crawler)
- **Inputs**: `url`, `domain` → **Outputs**: `archived_pages`
- **Platforms**: Docker, Linux, macOS, Node.js · **Tags**: `webrecorder`, `automated-wacz`, `site-preservation`, `docker-crawler`
- **Overview**: Headless Chromium Docker crawler producing high-fidelity, replayable `.wacz` forensic web archives across entire multi-page websites, social profiles, or news portals automatically.
- **Quick-Start / Tradecraft**: `docker run -v $PWD/crawls:/crawls/ webrecorder/browsertrix-crawler crawl --url https://example.com --generateWACZ`

### [Forensic OSINT](https://www.forensicosint.com/) `[A-Tier]`
- **ID**: `forensic-osint` · **Type**: `Browser Extension` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `url` → **Outputs**: `archived_pages`, `metadata`
- **Platforms**: Chrome · **Tags**: `rfc3161-timestamps`, `auto-comment-expand`, `court-evidence`, `hunchly-alternative`
- **Overview**: Court-grade Chrome capture extension designed with law enforcement and digital-forensics examiners—automatically expanding nested social comments, recording RFC-3161 trusted timestamps, and signing PDF/ZIP evidence.
- **Quick-Start / Tradecraft**: `Use for evidentiary captures of long-scroll Facebook/Instagram/Reddit comment threads.`

### [Perma.cc (Harvard Library Innovation Lab)](https://perma.cc/) `[A-Tier]`
- **ID**: `perma-cc` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`harvard-lil/perma`](https://github.com/harvard-lil/perma)
- **Inputs**: `url` → **Outputs**: `archived_pages`
- **Platforms**: Web · **Tags**: `harvard-lil`, `court-citations`, `warc-standard`, `human-rights`
- **Overview**: Citation-grade web archiving platform built by Harvard Law School Library Innovation Lab producing immutable WARC/WACZ archives trusted by courts, law reviews, and human-rights tribunals.
- **Quick-Start / Tradecraft**: `Use Perma.cc for court-filing or academic exhibits requiring institutional preservation guarantees.`

---

## Document Sanitization & Safety

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Dangerzone (Freedom of the Press Foundation)**](https://dangerzone.rocks/) ([GitHub](https://github.com/freedomofpress/dangerzone)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `document` → `opsec_protection, documents` |

### [Dangerzone (Freedom of the Press Foundation)](https://dangerzone.rocks/) `[S-Tier]`
- **ID**: `dangerzone` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`freedomofpress/dangerzone`](https://github.com/freedomofpress/dangerzone)
- **Inputs**: `document` → **Outputs**: `opsec_protection`, `documents`
- **Platforms**: Linux, macOS, Windows, Docker · **Tags**: `safe-pdf`, `canarytoken-neutralizer`, `malware-disarm`, `freedom-of-press`, `flagship`
- **Overview**: Essential investigator OPSEC utility converting untrusted, potentially weaponized PDFs, Word docs, or spreadsheets from darknet/leak sources into safe pixel-reconstructed PDFs inside a networkless container!
- **Quick-Start / Tradecraft**: `ALWAYS run leaked `.docx`/`.pdf` files through Dangerzone—neutralizes both zero-day exploits AND hidden remote-pixel Canarytokens!`

---

## FOIA & Primary Document Portals

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**DocumentCloud & MuckRock**](https://www.documentcloud.org/) ([GitHub](https://github.com/MuckRock/documentcloud)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `documents, person_records, corporate_records` |
| **B** | [**FOIA.gov (Official US Federal FOIA Portal)**](https://www.foia.gov/) ([GitHub](https://github.com/usdoj/foia.gov)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `keyword, company, person_name` → `documents` |
| **B** | [**WhatDoTheyKnow & AskTheEU**](https://www.whatdotheyknow.com/) ([GitHub](https://github.com/mysociety/alaveteli)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `company, person_name, keyword` → `documents, corporate_records` |

### [DocumentCloud & MuckRock](https://www.documentcloud.org/) `[S-Tier]`
- **ID**: `documentcloud` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`MuckRock/documentcloud`](https://github.com/MuckRock/documentcloud)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `documents`, `person_records`, `corporate_records`
- **Platforms**: Web, Python · **Tags**: `muckrock`, `foia-releases`, `ocr-documents`, `newsroom-archives`, `flagship`
- **Overview**: Investigative journalism repository hosting millions of OCR'd primary-source court exhibits, leaked memos, police reports, and FOIA releases contributed by thousands of newsrooms worldwide.
- **Quick-Start / Tradecraft**: `Search exact entity strings on https://www.documentcloud.org/ and file/track US public-record requests via https://www.muckrock.com/.`

### [FOIA.gov (Official US Federal FOIA Portal)](https://www.foia.gov/) `[B-Tier]`
- **ID**: `foia-gov` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`usdoj/foia.gov`](https://github.com/usdoj/foia.gov)
- **Inputs**: `keyword`, `company`, `person_name` → **Outputs**: `documents`
- **Platforms**: Web · **Tags**: `foia-reading-rooms`, `federal-agencies`, `proactive-disclosures`
- **Overview**: Central US Department of Justice portal searching proactive agency 'FOIA Reading Room' disclosures and routing statutory Freedom of Information requests across 100+ federal agencies.
- **Quick-Start / Tradecraft**: `Search agency Electronic Reading Rooms via https://www.foia.gov/ before drafting a new statutory request.`

### [WhatDoTheyKnow & AskTheEU](https://www.whatdotheyknow.com/) `[B-Tier]`
- **ID**: `whatdotheyknow` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mysociety/alaveteli`](https://github.com/mysociety/alaveteli)
- **Inputs**: `company`, `person_name`, `keyword` → **Outputs**: `documents`, `corporate_records`
- **Platforms**: Web · **Tags**: `uk-foi`, `eu-transparency`, `government-disclosures`, `alaveteli`
- **Overview**: Public archive of over 1+ million UK Freedom of Information responses (`whatdotheyknow.com`) and EU institution access-to-documents disclosures (`asktheeu.org`).
- **Quick-Start / Tradecraft**: `Search past FOI responses before filing a new request—someone may have already unlocked the exact dataset!`

---

## Academic & Grey Literature

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**OpenAlex**](https://openalex.org/) ([GitHub](https://github.com/ourresearch/openalex-gui)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `documents, person_records, entity_graph` |
| **A** | [**Semantic Scholar & arXiv**](https://www.semanticscholar.org/) | Search Engine | Free | 🟢 Passive | ✅ | `person_name, company, keyword` → `documents, person_records, entity_graph` |
| **B** | [**CORE (Open Access Research Aggregator)**](https://core.ac.uk/) ([GitHub](https://github.com/oacore/dashboard)) | Search Engine | Freemium | 🟢 Passive | ✅ | `person_name, company, keyword` → `documents, person_records` |

### [OpenAlex](https://openalex.org/) `[S-Tier]`
- **ID**: `openalex` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ourresearch/openalex-gui`](https://github.com/ourresearch/openalex-gui)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `documents`, `person_records`, `entity_graph`
- **Platforms**: Web, Python · **Tags**: `academic-osint`, `co-author-networks`, `research-grants`, `institutional-ties`, `keyless-api`
- **Overview**: 100% open catalog of 250M+ global scholarly papers, patents, co-author institutional graphs, grant funders, and ORCID researcher histories with a fast keyless REST API.
- **Quick-Start / Tradecraft**: `Map defence/AI researcher co-authorship networks and lab funding grants via https://openalex.org/ or `api.openalex.org`.`

### [Semantic Scholar & arXiv](https://www.semanticscholar.org/) `[A-Tier]`
- **ID**: `semantic-scholar` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `documents`, `person_records`, `entity_graph`
- **Platforms**: Web, Python · **Tags**: `citation-graph`, `technical-osint`, `author-disambiguation`, `free-api`
- **Overview**: AI-indexed scientific literature graph (215M+ papers) with free bulk/REST APIs exposing citation influence graphs, institutional co-authors, defence lab affiliations, and funding acknowledgments.
- **Quick-Start / Tradecraft**: `curl -s 'https://api.semanticscholar.org/graph/v1/paper/search?query=synthetic+aperture+radar+ship+detection&limit=3' | jq`

### [CORE (Open Access Research Aggregator)](https://core.ac.uk/) `[B-Tier]`
- **ID**: `core-ac-uk` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`oacore/dashboard`](https://github.com/oacore/dashboard)
- **Inputs**: `person_name`, `company`, `keyword` → **Outputs**: `documents`, `person_records`
- **Platforms**: Web · **Tags**: `university-theses`, `dissertations`, `grey-literature`, `10k-repositories`
- **Overview**: World's largest aggregator of full-text open-access university theses, dissertations, institutional technical reports, and grey literature across 10,000+ global repositories.
- **Quick-Start / Tradecraft**: `Search graduate theses & university lab reports on https://core.ac.uk/ to profile technical specialists and dual-use labs.`

---

## Visual Recon Screenshotters

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**gowitness**](https://github.com/sensepost/gowitness) ([GitHub](https://github.com/sensepost/gowitness)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `archived_pages, tech_stack, certificates` |
| **B** | [**EyeWitness**](https://github.com/RedSiege/EyeWitness) ([GitHub](https://github.com/RedSiege/EyeWitness)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `archived_pages, tech_stack` |

### [gowitness](https://github.com/sensepost/gowitness) `[A-Tier]`
- **ID**: `gowitness` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`sensepost/gowitness`](https://github.com/sensepost/gowitness)
- **Inputs**: `url`, `domain` → **Outputs**: `archived_pages`, `tech_stack`, `certificates`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `bulk-screenshots`, `visual-triage`, `sensepost`, `golang`
- **Overview**: SensePost's headless Chromium web screenshot & visual-reconnaissance Go CLI capturing bulk screenshots, HTTP headers, TLS certs, and DOM logs across hundreds of discovered subdomains into an interactive gallery.
- **Quick-Start / Tradecraft**: `gowitness scan file -f live_urls.txt --write-db && gowitness report server`

### [EyeWitness](https://github.com/RedSiege/EyeWitness) `[B-Tier]`
- **ID**: `eyewitness` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`RedSiege/EyeWitness`](https://github.com/RedSiege/EyeWitness)
- **Inputs**: `url`, `domain` → **Outputs**: `archived_pages`, `tech_stack`
- **Platforms**: Linux, Docker, Python · **Tags**: `url-screenshots`, `default-creds-check`, `visual-recon`, `redsiege`
- **Overview**: Takes headless screenshots of lists of URLs/subdomains, extracts server headers, categorizes login portals/CMS types, and flags default credentials in an offline HTML report.
- **Quick-Start / Tradecraft**: `python3 EyeWitness.py -f urls.txt --web --no-prompt`

---

## Document Metadata Extraction

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Metagoofil / FOCA**](https://github.com/opsdisk/metagoofil) ([GitHub](https://github.com/opsdisk/metagoofil)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `domain` → `documents, metadata, usernames` |
| **A** | [**PDFiD & pdf-parser (Didier Stevens Suite)**](https://blog.didierstevens.com/programs/pdf-tools/) ([GitHub](https://github.com/DidierStevens/DidierStevensSuite)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document` → `metadata, malware_iocs` |

### [Metagoofil / FOCA](https://github.com/opsdisk/metagoofil) `[A-Tier]`
- **ID**: `metagoofil` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`opsdisk/metagoofil`](https://github.com/opsdisk/metagoofil)
- **Inputs**: `domain` → **Outputs**: `documents`, `metadata`, `usernames`, `emails`
- **Platforms**: Linux, macOS, Python · **Tags**: `document-dorking`, `author-metadata`, `internal-paths`, `foca-alternative`
- **Overview**: Automates dorking and downloading public `.pdf`, `.docx`, `.xlsx`, and `.pptx` files from a target domain so ExifTool can extract internal Active Directory usernames, software versions, and file paths.
- **Quick-Start / Tradecraft**: `python3 metagoofil.py -d example.com -t pdf,docx,xlsx -l 50 -o ./docs && exiftool ./docs/*`

### [PDFiD & pdf-parser (Didier Stevens Suite)](https://blog.didierstevens.com/programs/pdf-tools/) `[A-Tier]`
- **ID**: `didier-stevens-pdfid` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`DidierStevens/DidierStevensSuite`](https://github.com/DidierStevens/DidierStevensSuite)
- **Inputs**: `document` → **Outputs**: `metadata`, `malware_iocs`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `pdf-forensics`, `static-triage`, `incremental-updates`, `didier-stevens`
- **Overview**: Battle-tested Python forensics scripts statically inspecting raw PDF object trees (`/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, XMP streams, revision history) without rendering the PDF!
- **Quick-Start / Tradecraft**: `pdfid.py suspect.pdf && pdf-parser.py --stats suspect.pdf  # Zero-execution static inspection!`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🛡️ Threat Intel, Malware & IOCs](./17-threat-intel-malware-cti.md) · [📻 SIGINT, Wireless, SDR & Space ▶](./19-sigint-wireless-space-rf.md)

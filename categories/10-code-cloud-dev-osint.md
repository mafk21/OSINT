[⬅️ Back to Master Index](../README.md) · [◀ 💬 Social Media (SOCMINT)](./09-social-media-socmint.md) · [🛰️ GEOINT, Maps & Satellites ▶](./11-geoint-maps-satellites.md)

# 💻 10. Source Code, GitHub Recon, Secret Scanning & Multi-Cloud Enumeration (`CODEINT`)

> **Scope**: Git commit author attribution, leaked API key/secret verifiers, global HTML/JS source code search engines (analytics/adsense ID pivoting), and public AWS/Azure/GCP bucket enumerators.
>
> **OPSEC Advisory**: Cloning a public GitHub repo is passive, but running live credential verification (`trufflehog` without `--no-verification`) hits third-party APIs and can trigger canarytoken alerts!

**Discipline Telemetry**: `22` Verified Tools · `9` S-Tier Flagships · `19` Passive · `18` Free/Open-Source

## Subcategories
- [Multi-Cloud Asset Discovery](#multi-cloud-asset-discovery) (4)
- [Developer Activity Archives](#developer-activity-archives) (1)
- [Global Code & HTML Search Engines](#global-code-html-search-engines) (6)
- [Secret & Credential Scanners](#secret-credential-scanners) (5)
- [AI & ML Supply Chain OSINT](#ai-ml-supply-chain-osint) (1)
- [Package & Supply Chain Recon](#package-supply-chain-recon) (3)
- [API & Workspace Leaks](#api-workspace-leaks) (1)
- [Dork Automation](#dork-automation) (1)

---

## Multi-Cloud Asset Discovery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**AADInternals / Tenant ID & OpenID Recon**](https://aadinternals.com/osint/) ([GitHub](https://github.com/Gerenios/AADInternals)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `domain, email` → `subdomains, corporate_records, tech_stack` |
| **S** | [**cloud_enum**](https://github.com/initstring/cloud_enum) ([GitHub](https://github.com/initstring/cloud_enum)) | CLI | OSS / Free | 🔴 Active | ✅ | `company, domain, keyword` → `urls, tech_stack, secrets` |
| **A** | [**GrayhatWarfare**](https://buckets.grayhatwarfare.com/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `keyword, domain, company` → `urls, secrets, documents` |
| **B** | [**S3Scanner**](https://github.com/sa7mon/S3Scanner) ([GitHub](https://github.com/sa7mon/S3Scanner)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, keyword` → `urls, secrets` |

### [AADInternals / Tenant ID & OpenID Recon](https://aadinternals.com/osint/) `[S-Tier]`
- **ID**: `crt-azure-tenant-osint` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Gerenios/AADInternals`](https://github.com/Gerenios/AADInternals)
- **Inputs**: `domain`, `email` → **Outputs**: `subdomains`, `corporate_records`, `tech_stack`
- **Platforms**: Web, Windows, Linux · **Tags**: `entra-id`, `azure-tenant-domains`, `federated-domains`, `sister-companies`, `flagship`
- **Overview**: Passively enumerates any organization's Microsoft Entra ID (Azure AD) Tenant UUID, federated domains, SSO type, and cloud region via public OpenID/Autodiscover endpoints without credentials!
- **Quick-Start / Tradecraft**: `Visit https://aadinternals.com/osint/ and enter `example.com`—instantly lists EVERY subsidiary/acquired domain bound to the same Microsoft 365 tenant!`

### [cloud_enum](https://github.com/initstring/cloud_enum) `[S-Tier]`
- **ID**: `cloud-enum` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`initstring/cloud_enum`](https://github.com/initstring/cloud_enum)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `urls`, `tech_stack`, `secrets`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `aws-s3`, `azure-blob`, `gcp-storage`, `multi-cloud`, `bucket-enum`, `flagship`
- **Overview**: Multi-cloud OSINT enumeration tool mutating company/brand keywords to discover publicly accessible AWS S3 buckets, Azure Storage Blobs/Apps, and Google Cloud Storage buckets/AppEngine instances.
- **Quick-Start / Tradecraft**: `python3 cloud_enum.py -k examplecorp -k example-prod -t 10`

### [GrayhatWarfare](https://buckets.grayhatwarfare.com/) `[A-Tier]`
- **ID**: `grayhatwarfare` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword`, `domain`, `company` → **Outputs**: `urls`, `secrets`, `documents`
- **Platforms**: Web, Python · **Tags**: `open-s3-buckets`, `passive-bucket-search`, `cloud-leaks`
- **Overview**: Pre-indexed search engine over millions of open AWS S3, Azure Blob, Google Cloud Storage, and DigitalOcean Spaces buckets—enabling 100% passive filename and keyword searches.
- **Quick-Start / Tradecraft**: `Search filenames (`.bak`, `.xlsx`, `.pdf`, `companyname`) passively on https://buckets.grayhatwarfare.com/.`

### [S3Scanner](https://github.com/sa7mon/S3Scanner) `[B-Tier]`
- **ID**: `s3scanner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`sa7mon/S3Scanner`](https://github.com/sa7mon/S3Scanner)
- **Inputs**: `domain`, `keyword` → **Outputs**: `urls`, `secrets`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `s3-buckets`, `acl-audit`, `golang`, `cloud-osint`
- **Overview**: Concurrent Go tool auditing S3-compatible object storage buckets (AWS, GCP, DigitalOcean, Linode) for public READ/WRITE ACL misconfigurations and listing object contents.
- **Quick-Start / Tradecraft**: `s3scanner -bucket-file candidate_buckets.txt`

---

## Developer Activity Archives

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GH Archive**](https://www.gharchive.org/) ([GitHub](https://github.com/igrigorik/gharchive.org)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `username, repo_code, email` → `emails, archived_pages, social_profiles` |

### [GH Archive](https://www.gharchive.org/) `[S-Tier]`
- **ID**: `gharchive` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`igrigorik/gharchive.org`](https://github.com/igrigorik/gharchive.org)
- **Inputs**: `username`, `repo_code`, `email` → **Outputs**: `emails`, `archived_pages`, `social_profiles`
- **Platforms**: Web · **Tags**: `deleted-repos`, `github-timeline`, `bigquery`, `commit-emails`, `flagship`
- **Overview**: Records every public GitHub event timeline since 2011 (pushes, issues, PRs, stars, forks—including events from repos later deleted or made private!) queryable via Google BigQuery.
- **Quick-Start / Tradecraft**: `Query `githubarchive.day.*` in BigQuery or download hourly `.json.gz` dumps to recover wiped GitHub repos/emails!`

---

## Global Code & HTML Search Engines

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GitHub Native Code Search & `.patch` Trick**](https://github.com/search) | Search Engine | Free | 🟢 Passive | 🔑 | `repo_code, username, domain` → `emails, secrets, urls` |
| **S** | [**grep.app**](https://grep.app/) | Search Engine | Free | 🟢 Passive | ✅ | `keyword, domain, crypto_address` → `urls, secrets, subdomains` |
| **S** | [**PublicWWW**](https://publicwww.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `keyword, domain, crypto_address` → `urls, tech_stack, entity_graph` |
| **A** | [**Sourcegraph Code Search**](https://sourcegraph.com/search) ([GitHub](https://github.com/sourcegraph/sourcegraph)) | Search Engine | Freemium | 🟢 Passive | ✅ | `repo_code, keyword, email` → `urls, secrets, emails` |
| **B** | [**NerdyData**](https://www.nerdydata.com/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `keyword, domain` → `urls, tech_stack` |
| **B** | [**searchcode**](https://searchcode.com/) | Search Engine | Free | 🟢 Passive | ✅ | `keyword, domain, repo_code` → `urls, secrets` |

### [GitHub Native Code Search & `.patch` Trick](https://github.com/search) `[S-Tier]`
- **ID**: `github-code-search` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `repo_code`, `username`, `domain`, `keyword` → **Outputs**: `emails`, `secrets`, `urls`, `social_profiles`
- **Platforms**: Web · **Tags**: `patch-email-trick`, `ssh-keys`, `github-dorking`, `developer-attribution`
- **Overview**: GitHub's Rust-backed Blackbird code search engine supporting regex (`/pattern/`), `org:`, `path:`, and `symbol:`, plus appending `.patch` to any commit URL to reveal raw git author email headers.
- **Quick-Start / Tradecraft**: `Fetch `https://github.com/<user>.keys` (SSH pubkeys) & `https://api.github.com/users/<user>/events/public` (commit emails).`

### [grep.app](https://grep.app/) `[S-Tier]`
- **ID**: `grep-app` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `domain`, `crypto_address`, `repo_code` → **Outputs**: `urls`, `secrets`, `subdomains`
- **Platforms**: Web · **Tags**: `regex-code-search`, `github-index`, `fast`, `no-login`, `flagship`
- **Overview**: Sub-second regular-expression code search engine across 500,000+ public GitHub repositories—ideal for finding internal domains, custom SDK headers, wallet addresses, or unique error strings.
- **Quick-Start / Tradecraft**: `Toggle Regex mode on https://grep.app/ and search `([a-z0-9-]+\.)+targetcompany\.com`.`

### [PublicWWW](https://publicwww.com/) `[S-Tier]`
- **ID**: `publicwww` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `domain`, `crypto_address` → **Outputs**: `urls`, `tech_stack`, `entity_graph`
- **Platforms**: Web · **Tags**: `html-source-search`, `analytics-id-pivot`, `js-skimmers`, `sister-domains`, `flagship`
- **Overview**: Source-code search engine indexing the raw HTML, inline JavaScript, and CSS of 500M+ web pages—the ultimate weapon for pivoting on Google Analytics IDs, AdSense tags, crypto skimmers, or custom widgets.
- **Quick-Start / Tradecraft**: `Search `"UA-12345678"` or `"G-ABCDEF1234"` on https://publicwww.com/ to unmask every website operated by the same owner.`

### [Sourcegraph Code Search](https://sourcegraph.com/search) `[A-Tier]`
- **ID**: `sourcegraph` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`sourcegraph/sourcegraph`](https://github.com/sourcegraph/sourcegraph)
- **Inputs**: `repo_code`, `keyword`, `email`, `domain` → **Outputs**: `urls`, `secrets`, `emails`
- **Platforms**: Web, CLI · **Tags**: `commit-diff-search`, `structural-search`, `multi-forge`, `code-osint`
- **Overview**: Universal structural and regex code search across millions of open-source GitHub, GitLab, and package repositories, supporting commit-diff (`type:diff`) and author searches.
- **Quick-Start / Tradecraft**: `Search `type:diff author:target@example.com` on https://sourcegraph.com/search to inspect historical commits.`

### [NerdyData](https://www.nerdydata.com/) `[B-Tier]`
- **ID**: `nerdydata` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword`, `domain` → **Outputs**: `urls`, `tech_stack`
- **Platforms**: Web · **Tags**: `dom-search`, `tracking-pixels`, `technographics`
- **Overview**: Searches rendered HTML, JavaScript, meta tags, and embedded tracking snippets across hundreds of millions of homepages to link related web properties and technology footprints.
- **Quick-Start / Tradecraft**: `Search exact JS variable names or tracking snippet IDs on https://www.nerdydata.com/.`

### [searchcode](https://searchcode.com/) `[B-Tier]`
- **ID**: `searchcode` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `domain`, `repo_code` → **Outputs**: `urls`, `secrets`
- **Platforms**: Web · **Tags**: `legacy-forges`, `bitbucket-sourceforge`, `75b-lines`, `code-search`
- **Overview**: Indexes 75+ billion lines of open-source code across GitHub, Bitbucket, GitLab, Google Code archives, SourceForge, and Fedora—great for finding legacy/deleted repo mirrors.
- **Quick-Start / Tradecraft**: `Check https://searchcode.com/ when a repository was scrubbed from GitHub—mirrors on Bitbucket/SourceForge often persist!`

---

## Secret & Credential Scanners

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Gitleaks**](https://github.com/gitleaks/gitleaks) ([GitHub](https://github.com/gitleaks/gitleaks)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code` → `secrets, emails` |
| **S** | [**TruffleHog**](https://github.com/trufflesecurity/trufflehog) ([GitHub](https://github.com/trufflesecurity/trufflehog)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `repo_code, url, username` → `secrets, emails, urls` |
| **A** | [**git-hound**](https://github.com/tillson/git-hound) ([GitHub](https://github.com/tillson/git-hound)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `domain, keyword, repo_code` → `secrets, urls` |
| **A** | [**Nosey Parker**](https://github.com/praetorian-inc/noseyparker) ([GitHub](https://github.com/praetorian-inc/noseyparker)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, document` → `secrets, emails` |
| **B** | [**Gitrob / Shhgit**](https://github.com/eth0izzle/shhgit) ([GitHub](https://github.com/eth0izzle/shhgit)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, company` → `secrets, urls` |

### [Gitleaks](https://github.com/gitleaks/gitleaks) `[S-Tier]`
- **ID**: `gitleaks` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`gitleaks/gitleaks`](https://github.com/gitleaks/gitleaks)
- **Inputs**: `repo_code` → **Outputs**: `secrets`, `emails`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `git-forensics`, `hardcoded-secrets`, `fast`, `golang`, `flagship`
- **Overview**: Ultra-fast Go SAST/OSINT secret scanner parsing full Git reflogs, dangling commits, and directory trees for hardcoded API keys, JWTs, database URIs, and private keys.
- **Quick-Start / Tradecraft**: `gitleaks git -v https://github.com/example/repo.git`

### [TruffleHog](https://github.com/trufflesecurity/trufflehog) `[S-Tier]`
- **ID**: `trufflehog` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`trufflesecurity/trufflehog`](https://github.com/trufflesecurity/trufflehog)
- **Inputs**: `repo_code`, `url`, `username`, `company` → **Outputs**: `secrets`, `emails`, `urls`
- **Platforms**: Linux, macOS, Windows, Docker, Go · **Tags**: `secret-scanning`, `git-history`, `docker-layers`, `postman`, `flagship`
- **Overview**: Industry-leading open-source secret scanner with 800+ credential detectors across Git commit histories, GitHub orgs, S3 buckets, Docker images, Postman workspaces, and HuggingFace models.
- **Quick-Start / Tradecraft**: `trufflehog github --org=target-org --no-verification  # Pass --no-verification for strictly passive OSINT!`

### [git-hound](https://github.com/tillson/git-hound) `[A-Tier]`
- **ID**: `git-hound` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`tillson/git-hound`](https://github.com/tillson/git-hound)
- **Inputs**: `domain`, `keyword`, `repo_code` → **Outputs**: `secrets`, `urls`
- **Platforms**: Linux, macOS, Go · **Tags**: `github-dorking`, `subdomain-secrets`, `entropy-scoring`, `bug-bounty`
- **Overview**: Reconnaissance-oriented GitHub secret hunter combining target subdomain lists with custom regexes and Shannon entropy scoring to surface exposed internal credentials.
- **Quick-Start / Tradecraft**: `echo 'example.com' | git-hound`

### [Nosey Parker](https://github.com/praetorian-inc/noseyparker) `[A-Tier]`
- **ID**: `noseyparker` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`praetorian-inc/noseyparker`](https://github.com/praetorian-inc/noseyparker)
- **Inputs**: `repo_code`, `document` → **Outputs**: `secrets`, `emails`
- **Platforms**: Linux, macOS, Docker, Rust · **Tags**: `praetorian`, `rust`, `hyperscan`, `corpus-scanning`
- **Overview**: Praetorian's blazing-fast Rust command-line scanner using Hyperscan regex acceleration to extract secrets and PII from gigabytes of Git repositories, tarballs, and text corpora.
- **Quick-Start / Tradecraft**: `noseyparker scan --datastore np.db --git-url https://github.com/example/repo.git && noseyparker report -d np.db`

### [Gitrob / Shhgit](https://github.com/eth0izzle/shhgit) `[B-Tier]`
- **ID**: `gitrob` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`eth0izzle/shhgit`](https://github.com/eth0izzle/shhgit)
- **Inputs**: `repo_code`, `company` → **Outputs**: `secrets`, `urls`
- **Platforms**: Linux, macOS, Docker, Go · **Tags**: `secret-signatures`, `tfstate-leaks`, `ssh-keys`, `gitlab-github`
- **Overview**: Monitors real-time GitHub/GitLab/Bitbucket public commit streams or local repos against 120+ secret signatures and suspicious filenames (`id_rsa`, `.npmrc`, `credentials.xml`, `terraform.tfstate`).
- **Quick-Start / Tradecraft**: `Audit `.terraform.tfstate` and `.npmrc` hits carefully without invoking live third-party credentials.`

---

## AI & ML Supply Chain OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Hugging Face Hub Search (Models, Datasets & Spaces)**](https://huggingface.co/search/full-text) | Search Engine | Free | 🟢 Passive | ✅ | `company, domain, keyword` → `secrets, urls, documents` |

### [Hugging Face Hub Search (Models, Datasets & Spaces)](https://huggingface.co/search/full-text) `[S-Tier]`
- **ID**: `huggingface-osint` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `domain`, `keyword`, `username` → **Outputs**: `secrets`, `urls`, `documents`
- **Platforms**: Web · **Tags**: `huggingface-leaks`, `ai-osint`, `spaces-secrets`, `full-text-search`, `2026-essential`
- **Overview**: Full-text code and dataset search across 1M+ AI models, Spaces, and training datasets—increasingly leaking corporate `.env` keys, internal prompts, proprietary fine-tuning corpora, and employee handles!
- **Quick-Start / Tradecraft**: `Use https://huggingface.co/search/full-text?q=example.com to catch leaked internal API URLs and keys in public Spaces & READMEs!`

---

## Package & Supply Chain Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Docker Hub & Layer Inspector (`dive`)**](https://hub.docker.com/) ([GitHub](https://github.com/wagoodman/dive)) | CLI | OSS / Free | 🟢 Passive | ✅ | `company, username, repo_code` → `secrets, tech_stack` |
| **A** | [**Open Source Insights (deps.dev)**](https://deps.dev/) | Web Platform | Free | 🟢 Passive | ✅ | `repo_code, keyword` → `entity_graph, social_profiles, tech_stack` |
| **A** | [**PyPI & npm Registry Metadata API**](https://pypi.org/) | API / Service | Free | 🟢 Passive | ✅ | `username, repo_code, keyword` → `emails, person_records, metadata` |

### [Docker Hub & Layer Inspector (`dive`)](https://hub.docker.com/) `[A-Tier]`
- **ID**: `dockerhub-osint` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`wagoodman/dive`](https://github.com/wagoodman/dive)
- **Inputs**: `company`, `username`, `repo_code` → **Outputs**: `secrets`, `tech_stack`
- **Platforms**: Web, Linux, macOS, Windows, Go · **Tags**: `container-forensics`, `docker-layers`, `dive`, `secret-recovery`
- **Overview**: Searches public container registries (`hub.docker.com`, `ghcr.io`) and inspects deleted intermediate image filesystem layers (`dive`) where `.env` files or SSH keys were `rm`'d in a later layer.
- **Quick-Start / Tradecraft**: `Search org images on https://hub.docker.com/ then inspect deleted layer files locally with `dive org/image:tag`.`

### [Open Source Insights (deps.dev)](https://deps.dev/) `[A-Tier]`
- **ID**: `deps-dev` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `repo_code`, `keyword` → **Outputs**: `entity_graph`, `social_profiles`, `tech_stack`
- **Platforms**: Web · **Tags**: `supply-chain-osint`, `npm-pypi-cargo`, `maintainer-pivoting`, `google`
- **Overview**: Google's open-source package intelligence graph mapping dependency trees, maintainer accounts, Advisories, OpenSSF Scorecards, and linked source repos across npm, PyPI, Go, Maven, Cargo, and NuGet.
- **Quick-Start / Tradecraft**: `Look up packages published by a target developer handle across npm/PyPI/Cargo via `https://api.deps.dev/v3/systems/...`.`

### [PyPI & npm Registry Metadata API](https://pypi.org/) `[A-Tier]`
- **ID**: `npm-pypi-maintainer-osint` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `repo_code`, `keyword` → **Outputs**: `emails`, `person_records`, `metadata`
- **Platforms**: Web, CLI · **Tags**: `package-forensics`, `wheel-tarball-paths`, `maintainer-emails`, `keyless-api`
- **Overview**: Queries raw JSON package manifests (`pypi.org/pypi/<pkg>/json` and `registry.npmjs.org/<pkg>`)—exposing historical maintainer emails, author names, release timestamps, and local build paths inside `.whl`/`.tgz` tarballs!
- **Quick-Start / Tradecraft**: `curl -s https://registry.npmjs.org/<package> | jq '.versions[]."_npmUser"'  # Reveals historical publisher emails across every old version!`

---

## API & Workspace Leaks

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Postman Public API Network**](https://www.postman.com/explore) | Search Engine | Free | 🟢 Passive | ✅ | `company, domain, keyword` → `urls, secrets, emails` |

### [Postman Public API Network](https://www.postman.com/explore) `[A-Tier]`
- **ID**: `postman-explore` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `urls`, `secrets`, `emails`
- **Platforms**: Web · **Tags**: `postman-leaks`, `api-collections`, `environment-variables`, `shadow-apis`
- **Overview**: Global directory of public Postman workspaces, collections, and environment files—frequently leaking internal staging URLs, bearer tokens, GraphQL schemas, and developer names.
- **Quick-Start / Tradecraft**: `Search target company or domain on https://www.postman.com/explore filtered by Environments and Requests!`

---

## Dork Automation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**pagodo (Passive Google Dork)**](https://github.com/opsdisk/pagodo) ([GitHub](https://github.com/opsdisk/pagodo)) | CLI | OSS / Free | 🟢 Passive | ✅ | `domain` → `urls, secrets, documents` |

### [pagodo (Passive Google Dork)](https://github.com/opsdisk/pagodo) `[B-Tier]`
- **ID**: `pagodo` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`opsdisk/pagodo`](https://github.com/opsdisk/pagodo)
- **Inputs**: `domain` → **Outputs**: `urls`, `secrets`, `documents`
- **Platforms**: Linux, macOS, Python · **Tags**: `ghdb`, `google-dorks`, `automated-dorking`, `exploit-db`
- **Overview**: Automates scraping and rate-limited execution of thousands of Exploit-DB Google Hacking Database (GHDB) dorks scoped to a target domain.
- **Quick-Start / Tradecraft**: `python3 pagodo.py -d example.com -g dorks/all_google_dorks.txt -s -e 35.0`

---
[⬅️ Back to Master Index](../README.md) · [◀ 💬 Social Media (SOCMINT)](./09-social-media-socmint.md) · [🛰️ GEOINT, Maps & Satellites ▶](./11-geoint-maps-satellites.md)

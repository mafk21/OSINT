[⬅️ Back to Master Index](../README.md) · [◀ 💬 Social Media (SOCMINT)](./09-social-media-socmint.md) · [🛰️ GEOINT, Maps & Satellites ▶](./11-geoint-maps-satellites.md)

# 💻 10. Source Code, GitHub Recon, Secret Scanning & Multi-Cloud Enumeration (`CODEINT`)

> **Scope**: Git commit author attribution, leaked API key/secret verifiers, global HTML/JS source code search engines (analytics/adsense ID pivoting), and public AWS/Azure/GCP bucket enumerators.
>
> **OPSEC Advisory**: Cloning a public GitHub repo is passive, but running live credential verification (`trufflehog` without `--no-verification`) hits third-party APIs and can trigger canarytoken alerts!

**Discipline Telemetry**: `54` Verified Tools · `19` S-Tier Flagships · `30` Passive · `50` Free/Open-Source

## Subcategories
- [Multi-Cloud Asset Discovery](#multi-cloud-asset-discovery) (4)
- [Developer Activity Archives](#developer-activity-archives) (1)
- [Global Code & HTML Search Engines](#global-code-html-search-engines) (6)
- [Secret & Credential Scanners](#secret-credential-scanners) (9)
- [AI & ML Supply Chain OSINT](#ai-ml-supply-chain-osint) (1)
- [Package & Supply Chain Recon](#package-supply-chain-recon) (3)
- [API & Workspace Leaks](#api-workspace-leaks) (1)
- [Dork Automation](#dork-automation) (1)
- [Exposed VCS & Source Recon](#exposed-vcs-source-recon) (2)
- [Secret & Code Leaks](#secret-code-leaks) (1)
- [Cloud Asset & Bucket Enumeration](#cloud-asset-bucket-enumeration) (6)
- [API & GraphQL Active Recon](#api-graphql-active-recon) (6)
- [API Key Triage & Validation](#api-key-triage-validation) (1)
- [Cloud & Storage Enumeration](#cloud-storage-enumeration) (6)
- [Container & SBOM OSINT](#container-sbom-osint) (3)
- [IaC & Cloud Config Recon](#iac-cloud-config-recon) (3)

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
| **S** | [**detect-secrets (Yelp)**](https://github.com/Yelp/detect-secrets) ([GitHub](https://github.com/Yelp/detect-secrets)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, document` → `secrets, metadata` |
| **A** | [**git-secrets (AWS Labs)**](https://github.com/awslabs/git-secrets) ([GitHub](https://github.com/awslabs/git-secrets)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code` → `secrets` |
| **A** | [**Talisman (Thoughtworks)**](https://github.com/thoughtworks/talisman) ([GitHub](https://github.com/thoughtworks/talisman)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code` → `secrets, certificates` |
| **B** | [**Credential Detector**](https://github.com/ynori7/credential-detector) ([GitHub](https://github.com/ynori7/credential-detector)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, document` → `secrets` |

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

### [detect-secrets (Yelp)](https://github.com/Yelp/detect-secrets) `[S-Tier]`
- **ID**: `detect-secrets` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Yelp/detect-secrets`](https://github.com/Yelp/detect-secrets)
- **Inputs**: `repo_code`, `document` → **Outputs**: `secrets`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `secrets`, `entropy-scanning`, `git-history`, `yelp`
- **Overview**: Enterprise-grade secret detection suite scanning codebases and git histories using high-entropy heuristics and service-specific regex plugins.
- **Quick-Start / Tradecraft**: `detect-secrets scan --all-files ./target-repo`

### [git-secrets (AWS Labs)](https://github.com/awslabs/git-secrets) `[A-Tier]`
- **ID**: `aws-git-secrets` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`awslabs/git-secrets`](https://github.com/awslabs/git-secrets)
- **Inputs**: `repo_code` → **Outputs**: `secrets`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `aws-keys`, `git-commits`, `credential-leak`
- **Overview**: AWS Labs scanner inspecting commit logs and branches for leaked AWS access keys, session tokens, and cloud credential patterns.
- **Quick-Start / Tradecraft**: `git secrets --register-aws && git secrets --scan-history`

### [Talisman (Thoughtworks)](https://github.com/thoughtworks/talisman) `[A-Tier]`
- **ID**: `talisman-scanner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`thoughtworks/talisman`](https://github.com/thoughtworks/talisman)
- **Inputs**: `repo_code` → **Outputs**: `secrets`, `certificates`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `git-history`, `private-keys`, `secrets-osint`
- **Overview**: Git repository history analyzer detecting private keys, bearer tokens, high-entropy strings, and sensitive certificates across commits.
- **Quick-Start / Tradecraft**: `talisman --scan`

### [Credential Detector](https://github.com/ynori7/credential-detector) `[B-Tier]`
- **ID**: `credential-detector` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ynori7/credential-detector`](https://github.com/ynori7/credential-detector)
- **Inputs**: `repo_code`, `document` → **Outputs**: `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `config-files`, `credentials`, `static-analysis`
- **Overview**: Go static scanner parsing YAML, JSON, properties, XML, and source files to uncover hardcoded passwords, private keys, and tokens.
- **Quick-Start / Tradecraft**: `credential-detector /path/to/repo`

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

## Exposed VCS & Source Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**git-dumper**](https://github.com/arthaud/git-dumper) ([GitHub](https://github.com/arthaud/git-dumper)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `secrets, emails, usernames` |
| **A** | [**GitTools (GitFinder / Dumper / Extractor)**](https://github.com/internetwache/GitTools) ([GitHub](https://github.com/internetwache/GitTools)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url` → `secrets, emails, documents` |

### [git-dumper](https://github.com/arthaud/git-dumper) `[S-Tier]`
- **ID**: `git-dumper` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`arthaud/git-dumper`](https://github.com/arthaud/git-dumper)
- **Inputs**: `url`, `domain` → **Outputs**: `secrets`, `emails`, `usernames`, `documents`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `exposed-git`, `source-recovery`, `commit-history`, `active`
- **Overview**: Active Python tool reconstructing full Git repositories from web-exposed `/.git/` endpoints even when directory listing is disabled on the target web server.
- **Quick-Start / Tradecraft**: `git-dumper https://example.com/.git ./recovered_repo`

### [GitTools (GitFinder / Dumper / Extractor)](https://github.com/internetwache/GitTools) `[A-Tier]`
- **ID**: `gittools` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`internetwache/GitTools`](https://github.com/internetwache/GitTools)
- **Inputs**: `domain`, `url` → **Outputs**: `secrets`, `emails`, `documents`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `exposed-git`, `gitfinder`, `dangling-commits`, `active`
- **Overview**: Three-part active toolkit: GitFinder scans domain lists for exposed `/.git/HEAD`, GitDumper downloads objects, and GitExtractor recovers dangling commits.
- **Quick-Start / Tradecraft**: `python3 gitfinder.py -i domains.txt`

---

## Secret & Code Leaks

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**GitGot (Bishop Fox)**](https://github.com/BishopFox/GitGot) ([GitHub](https://github.com/BishopFox/GitGot)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `company, domain, keyword` → `secrets, emails, urls` |

### [GitGot (Bishop Fox)](https://github.com/BishopFox/GitGot) `[A-Tier]`
- **ID**: `gitgot` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`BishopFox/GitGot`](https://github.com/BishopFox/GitGot)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `secrets`, `emails`, `urls`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `github-dorking`, `secrets`, `bishopfox`, `codeint`
- **Overview**: Semi-automated, feedback-driven GitHub search tool rapidly triaging public code and gist results for target-specific credentials and secrets.
- **Quick-Start / Tradecraft**: `python3 gitgot.py -q 'example.com'`

---

## Cloud Asset & Bucket Enumeration

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**CloudFox (Bishop Fox)**](https://github.com/BishopFox/cloudfox) ([GitHub](https://github.com/BishopFox/cloudfox)) | CLI | OSS / Free | 🔴 Active | 🔑 | `company, domain` → `urls, ip_addresses, subdomains` |
| **A** | [**Cloudlist (ProjectDiscovery)**](https://github.com/projectdiscovery/cloudlist) ([GitHub](https://github.com/projectdiscovery/cloudlist)) | CLI | OSS / Free | 🟡 Hybrid | 🔑 | `company, domain` → `ip_addresses, subdomains, dns_records` |
| **A** | [**GCPBucketBrute (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/GCPBucketBrute) ([GitHub](https://github.com/RhinoSecurityLabs/GCPBucketBrute)) | CLI | OSS / Free | 🔴 Active | ✅ | `keyword, company, domain` → `urls, documents, secrets` |
| **S** | [**MicroBurst (NetSPI)**](https://github.com/NetSPI/MicroBurst) ([GitHub](https://github.com/NetSPI/MicroBurst)) | Framework | OSS / Free | 🔴 Active | ✅ | `company, domain, keyword` → `subdomains, urls, documents` |
| **B** | [**AWSBucketDump**](https://github.com/jordanpotti/AWSBucketDump) ([GitHub](https://github.com/jordanpotti/AWSBucketDump)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url, keyword` → `documents, secrets, urls` |
| **B** | [**CloudScraper**](https://github.com/jordanpotti/CloudScraper) ([GitHub](https://github.com/jordanpotti/CloudScraper)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, subdomains` |

### [CloudFox (Bishop Fox)](https://github.com/BishopFox/cloudfox) `[S-Tier]`
- **ID**: `cloudfox` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`BishopFox/cloudfox`](https://github.com/BishopFox/cloudfox)
- **Inputs**: `company`, `domain` → **Outputs**: `urls`, `ip_addresses`, `subdomains`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `aws`, `azure`, `gcp`, `cloud-recon`, `bishopfox`
- **Overview**: Cloud situational awareness CLI actively enumerating exposed endpoints, public buckets, IAM trusts, and internet-facing assets across AWS, Azure, and GCP.
- **Quick-Start / Tradecraft**: `cloudfox aws --profile target endpoints`

### [Cloudlist (ProjectDiscovery)](https://github.com/projectdiscovery/cloudlist) `[A-Tier]`
- **ID**: `cloudlist` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: Required (Account / API Key) · **GitHub**: [`projectdiscovery/cloudlist`](https://github.com/projectdiscovery/cloudlist)
- **Inputs**: `company`, `domain` → **Outputs**: `ip_addresses`, `subdomains`, `dns_records`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `multi-cloud`, `asset-inventory`, `projectdiscovery`, `asm`
- **Overview**: Multi-cloud inventory harvester pulling live public IPs, DNS records, and compute hostnames across AWS, GCP, Azure, Cloudflare, DigitalOcean, and Fastly.
- **Quick-Start / Tradecraft**: `cloudlist -pc provider-config.yaml | httpx`

### [GCPBucketBrute (Rhino Security Labs)](https://github.com/RhinoSecurityLabs/GCPBucketBrute) `[A-Tier]`
- **ID**: `gcpbucketbrute` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`RhinoSecurityLabs/GCPBucketBrute`](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
- **Inputs**: `keyword`, `company`, `domain` → **Outputs**: `urls`, `documents`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `gcs`, `google-cloud`, `bucket-bruteforce`, `iam`, `active`
- **Overview**: Active Google Cloud Storage enumerator brute-forcing bucket permutations and invoking unauthenticated `testIamPermissions` to detect public exposure.
- **Quick-Start / Tradecraft**: `python3 gcpbucketbrute.py -k example -u`

### [MicroBurst (NetSPI)](https://github.com/NetSPI/MicroBurst) `[S-Tier]`
- **ID**: `microburst` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`NetSPI/MicroBurst`](https://github.com/NetSPI/MicroBurst)
- **Inputs**: `company`, `domain`, `keyword` → **Outputs**: `subdomains`, `urls`, `documents`, `secrets`
- **Platforms**: CLI, Windows, Linux, macOS · **Tags**: `azure`, `blob-storage`, `netspi`, `cloud-enum`, `active`
- **Overview**: PowerShell active Azure reconnaissance toolkit enumerating unauthenticated Azure Blob containers, App Services, Key Vaults, databases, and tenant subdomains.
- **Quick-Start / Tradecraft**: `Invoke-EnumerateAzureBlobs -Base example`

### [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) `[B-Tier]`
- **ID**: `awsbucketdump` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`jordanpotti/AWSBucketDump`](https://github.com/jordanpotti/AWSBucketDump)
- **Inputs**: `domain`, `url`, `keyword` → **Outputs**: `documents`, `secrets`, `urls`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `s3`, `aws`, `open-buckets`, `active-recon`
- **Overview**: Active AWS S3 bucket crawler enumerating publicly listable S3 buckets and filtering object keys for sensitive keywords (.env, backup, credentials, xlsx).
- **Quick-Start / Tradecraft**: `python3 AWSBucketDump.py -l buckets.txt -g interesting_Keywords.txt`

### [CloudScraper](https://github.com/jordanpotti/CloudScraper) `[B-Tier]`
- **ID**: `cloudscraper` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`jordanpotti/CloudScraper`](https://github.com/jordanpotti/CloudScraper)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `subdomains`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `cloud-buckets`, `s3`, `azure-blob`, `spider`, `active`
- **Overview**: Active web spider searching target HTML and JavaScript source code for embedded Amazon S3, Azure Blob, and DigitalOcean Spaces cloud storage URLs.
- **Quick-Start / Tradecraft**: `python3 CloudScraper.py -u https://example.com`

---

## API & GraphQL Active Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Kiterunner (Assetnote)**](https://github.com/assetnote/kiterunner) ([GitHub](https://github.com/assetnote/kiterunner)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, tech_stack, metadata` |
| **A** | [**sj (swagger-jacker — Bishop Fox)**](https://github.com/BishopFox/sj) ([GitHub](https://github.com/BishopFox/sj)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, metadata, secrets` |
| **A** | [**graphql-cop**](https://github.com/dolevf/graphql-cop) ([GitHub](https://github.com/dolevf/graphql-cop)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, domain` → `urls, tech_stack, metadata` |
| **A** | [**Graphinder (Escape Technologies)**](https://github.com/Escape-Technologies/graphinder) ([GitHub](https://github.com/Escape-Technologies/graphinder)) | CLI | OSS / Free | 🔴 Active | ✅ | `domain, url` → `urls, subdomains, tech_stack` |
| **A** | [**Clairvoyance**](https://github.com/nikitastupin/clairvoyance) ([GitHub](https://github.com/nikitastupin/clairvoyance)) | CLI | OSS / Free | 🔴 Active | ✅ | `url` → `metadata, urls` |
| **S** | [**Nuclei Templates**](https://github.com/projectdiscovery/nuclei-templates) ([GitHub](https://github.com/projectdiscovery/nuclei-templates)) | Dataset / Registry | OSS / Free | 🔴 Active | ✅ | `url, domain, ip` → `tech_stack, secrets, social_profiles` |

### [Kiterunner (Assetnote)](https://github.com/assetnote/kiterunner) `[S-Tier]`
- **ID**: `kiterunner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`assetnote/kiterunner`](https://github.com/assetnote/kiterunner)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `api-discovery`, `swagger`, `assetnote`, `rest-routes`, `active`
- **Overview**: Contextual active API route discovery engine built by Assetnote testing HTTP methods, content-types, and OpenAPI/Swagger patterns against modern APIs.
- **Quick-Start / Tradecraft**: `kr scan https://api.example.com -w routes-large.kite`

### [sj (swagger-jacker — Bishop Fox)](https://github.com/BishopFox/sj) `[A-Tier]`
- **ID**: `swagger-jacker` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`BishopFox/sj`](https://github.com/BishopFox/sj)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `metadata`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `openapi`, `swagger`, `api-audit`, `bishopfox`, `active`
- **Overview**: Active OpenAPI/Swagger definition auditor discovering exposed specification files and checking which documented API endpoints respond unauthenticated.
- **Quick-Start / Tradecraft**: `sj brute -u https://api.example.com`

### [graphql-cop](https://github.com/dolevf/graphql-cop) `[A-Tier]`
- **ID**: `graphql-cop` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`dolevf/graphql-cop`](https://github.com/dolevf/graphql-cop)
- **Inputs**: `url`, `domain` → **Outputs**: `urls`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `graphql`, `introspection`, `api-recon`, `active`
- **Overview**: Active GraphQL endpoint reconnaissance and security auditor testing introspection exposure, GraphiQL consoles, field suggestions, and batching.
- **Quick-Start / Tradecraft**: `python3 graphql-cop.py -t https://api.example.com/graphql`

### [Graphinder (Escape Technologies)](https://github.com/Escape-Technologies/graphinder) `[A-Tier]`
- **ID**: `graphinder` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`Escape-Technologies/graphinder`](https://github.com/Escape-Technologies/graphinder)
- **Inputs**: `domain`, `url` → **Outputs**: `urls`, `subdomains`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Docker, Python · **Tags**: `graphql`, `endpoint-discovery`, `subdomains`, `active`
- **Overview**: Subdomain-wide active GraphQL endpoint finder combining subdomain discovery, JS script analysis, and path probing to locate hidden GraphQL APIs.
- **Quick-Start / Tradecraft**: `graphinder -d example.com`

### [Clairvoyance](https://github.com/nikitastupin/clairvoyance) `[A-Tier]`
- **ID**: `clairvoyance` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`nikitastupin/clairvoyance`](https://github.com/nikitastupin/clairvoyance)
- **Inputs**: `url` → **Outputs**: `metadata`, `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `graphql`, `schema-recovery`, `field-suggestions`, `active`
- **Overview**: Active GraphQL schema reconstruction tool recovering types, fields, and arguments via field-suggestion error messages even when introspection is disabled.
- **Quick-Start / Tradecraft**: `clairvoyance https://api.example.com/graphql -o schema.json`

### [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) `[S-Tier]`
- **ID**: `nuclei-templates` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates)
- **Inputs**: `url`, `domain`, `ip`, `username` → **Outputs**: `tech_stack`, `secrets`, `social_profiles`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `nuclei`, `yaml-templates`, `exposed-panels`, `osint-templates`, `active`
- **Overview**: Community-curated library of 10,000+ YAML active detection templates covering exposed panels, cloud misconfigurations, OSINT user checks, and tech fingerprints.
- **Quick-Start / Tradecraft**: `nuclei -u https://example.com -tags exposure,panel,tech`

---

## API Key Triage & Validation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**KeyHacks**](https://github.com/streaak/keyhacks) ([GitHub](https://github.com/streaak/keyhacks)) | Dataset / Registry | OSS / Free | 🟡 Hybrid | ✅ | `keyword, repo_code` → `secrets, metadata` |

### [KeyHacks](https://github.com/streaak/keyhacks) `[S-Tier]`
- **ID**: `keyhacks` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`streaak/keyhacks`](https://github.com/streaak/keyhacks)
- **Inputs**: `keyword`, `repo_code` → **Outputs**: `secrets`, `metadata`
- **Platforms**: Web, CLI · **Tags**: `api-keys`, `key-validation`, `secrets-triage`
- **Overview**: Canonical reference catalog of 150+ third-party API key formats and exact commands to verify whether a discovered API token is live.
- **Quick-Start / Tradecraft**: `Search KeyHacks for service curl validation snippet`

---

## Cloud & Storage Enumeration

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Prowler**](https://github.com/toniblyx/prowler) ([GitHub](https://github.com/toniblyx/prowler)) | CLI | OSS / Free | 🔴 Active | 🔑 | `company, domain` → `tech_stack, urls, secrets` |
| **S** | [**ScoutSuite (NCC Group)**](https://github.com/nccgroup/ScoutSuite) ([GitHub](https://github.com/nccgroup/ScoutSuite)) | CLI | OSS / Free | 🔴 Active | 🔑 | `company, domain` → `tech_stack, open_ports, urls` |
| **A** | [**Pacu (Rhino Security Labs)**](https://github.com/RhinoSecurityLabs/pacu) ([GitHub](https://github.com/RhinoSecurityLabs/pacu)) | Framework | OSS / Free | 🔴 Active | ✅ | `domain, company, username` → `usernames, secrets, tech_stack` |
| **A** | [**CloudMapper (Duo Labs)**](https://github.com/duo-labs/cloudmapper) ([GitHub](https://github.com/duo-labs/cloudmapper)) | CLI | OSS / Free | 🔴 Active | 🔑 | `company, domain` → `ip_addresses, open_ports, entity_graph` |
| **B** | [**Cloudsplaining (Salesforce)**](https://github.com/salesforce/cloudsplaining) ([GitHub](https://github.com/salesforce/cloudsplaining)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, repo_code` → `secrets, metadata` |
| **B** | [**SkyArk (Shadow Admin Recon)**](https://github.com/cyberark/SkyArk) ([GitHub](https://github.com/cyberark/SkyArk)) | Framework | OSS / Free | 🔴 Active | 🔑 | `company, domain` → `usernames, entity_graph, metadata` |

### [Prowler](https://github.com/toniblyx/prowler) `[S-Tier]`
- **ID**: `prowler-cloud` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`toniblyx/prowler`](https://github.com/toniblyx/prowler)
- **Inputs**: `company`, `domain` → **Outputs**: `tech_stack`, `urls`, `secrets`, `metadata`
- **Platforms**: CLI, Linux, macOS, Docker, Python · **Tags**: `aws`, `azure`, `gcp`, `cloud-inventory`, `active`
- **Overview**: Flagship open-source cloud security and asset inventory scanner mapping exposed S3/IAM/VPC/EKS/Azure/GCP/M365 services.
- **Quick-Start / Tradecraft**: `prowler aws --services s3 iam ec2`

### [ScoutSuite (NCC Group)](https://github.com/nccgroup/ScoutSuite) `[S-Tier]`
- **ID**: `scoutsuite` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`nccgroup/ScoutSuite`](https://github.com/nccgroup/ScoutSuite)
- **Inputs**: `company`, `domain` → **Outputs**: `tech_stack`, `open_ports`, `urls`, `entity_graph`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `multi-cloud`, `nccgroup`, `attack-surface`, `active`
- **Overview**: Multi-cloud reconnaissance and attack-surface auditing tool generating interactive HTML topology reports for AWS, Azure, GCP, and Oracle Cloud.
- **Quick-Start / Tradecraft**: `scout aws --report-dir ./scout-report`

### [Pacu (Rhino Security Labs)](https://github.com/RhinoSecurityLabs/pacu) `[A-Tier]`
- **ID**: `pacu-aws` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`RhinoSecurityLabs/pacu`](https://github.com/RhinoSecurityLabs/pacu)
- **Inputs**: `domain`, `company`, `username` → **Outputs**: `usernames`, `secrets`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Docker, Python · **Tags**: `aws-recon`, `iam-enum`, `s3`, `active`
- **Overview**: Modular AWS enumeration and reconnaissance framework mapping IAM principals, Lambda variables, S3 buckets, and cross-account trust.
- **Quick-Start / Tradecraft**: `pacu # run iam__enum_users_roles_policies_groups`

### [CloudMapper (Duo Labs)](https://github.com/duo-labs/cloudmapper) `[A-Tier]`
- **ID**: `cloudmapper` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`duo-labs/cloudmapper`](https://github.com/duo-labs/cloudmapper)
- **Inputs**: `company`, `domain` → **Outputs**: `ip_addresses`, `open_ports`, `entity_graph`
- **Platforms**: CLI, Linux, macOS, Docker, Python · **Tags**: `aws-topology`, `public-ips`, `network-graph`
- **Overview**: AWS network topology visualizer and public-exposure mapper discovering internet-facing EC2, ALB, RDS, and S3 endpoints.
- **Quick-Start / Tradecraft**: `python cloudmapper.py find_admins --account target`

### [Cloudsplaining (Salesforce)](https://github.com/salesforce/cloudsplaining) `[B-Tier]`
- **ID**: `cloudsplaining` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`salesforce/cloudsplaining`](https://github.com/salesforce/cloudsplaining)
- **Inputs**: `document`, `repo_code` → **Outputs**: `secrets`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `aws-iam`, `policy-analysis`, `salesforce`
- **Overview**: AWS IAM policy analyzer pinpointing resource exposure, data exfiltration paths, and cross-account privilege boundaries.
- **Quick-Start / Tradecraft**: `cloudsplaining scan-policy-file --input-file policy.json`

### [SkyArk (Shadow Admin Recon)](https://github.com/cyberark/SkyArk) `[B-Tier]`
- **ID**: `skyark-cloud` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`cyberark/SkyArk`](https://github.com/cyberark/SkyArk)
- **Inputs**: `company`, `domain` → **Outputs**: `usernames`, `entity_graph`, `metadata`
- **Platforms**: CLI, Windows, Linux, macOS · **Tags**: `shadow-admins`, `aws-iam`, `entra`, `cyberark`
- **Overview**: AWSStealth and AzureStealth cloud reconnaissance modules enumerating shadow administrative principals across AWS IAM and Microsoft Entra.
- **Quick-Start / Tradecraft**: `Import-Module ./SkyArk.ps1; Start-AWStealth`

---

## Container & SBOM OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Trivy (Aqua Security)**](https://github.com/aquasecurity/trivy) ([GitHub](https://github.com/aquasecurity/trivy)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `repo_code, url, domain` → `tech_stack, secrets, malware_iocs` |
| **A** | [**Syft (Anchore SBOM Extractor)**](https://github.com/anchore/syft) ([GitHub](https://github.com/anchore/syft)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, repo_code` → `tech_stack, metadata` |
| **A** | [**Grype**](https://github.com/anchore/grype) ([GitHub](https://github.com/anchore/grype)) | CLI | OSS / Free | 🟢 Passive | ✅ | `document, repo_code` → `malware_iocs, tech_stack` |

### [Trivy (Aqua Security)](https://github.com/aquasecurity/trivy) `[S-Tier]`
- **ID**: `trivy-scanner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`aquasecurity/trivy`](https://github.com/aquasecurity/trivy)
- **Inputs**: `repo_code`, `url`, `domain` → **Outputs**: `tech_stack`, `secrets`, `malware_iocs`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `container-osint`, `sbom`, `secrets`, `cve`
- **Overview**: All-in-one container image, git repository, filesystem, and Kubernetes scanner extracting SBOM packages, secrets, and CVEs.
- **Quick-Start / Tradecraft**: `trivy repo https://github.com/org/repo`

### [Syft (Anchore SBOM Extractor)](https://github.com/anchore/syft) `[A-Tier]`
- **ID**: `syft-sbom` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`anchore/syft`](https://github.com/anchore/syft)
- **Inputs**: `document`, `repo_code` → **Outputs**: `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `sbom`, `oci-containers`, `dependency-osint`
- **Overview**: Container image and binary filesystem Software Bill of Materials (SBOM) carver enumerating exact library versions across OCI layers.
- **Quick-Start / Tradecraft**: `syft alpine:latest -o cyclonedx-json`

### [Grype](https://github.com/anchore/grype) `[A-Tier]`
- **ID**: `grype-vuln` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`anchore/grype`](https://github.com/anchore/grype)
- **Inputs**: `document`, `repo_code` → **Outputs**: `malware_iocs`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `cve-matching`, `sbom`, `containers`
- **Overview**: Fast vulnerability matcher correlating container images and Syft SBOM inventories against NVD, GitHub Advisory, and distro feeds.
- **Quick-Start / Tradecraft**: `grype sbom:./target.sbom.json`

---

## IaC & Cloud Config Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Checkov**](https://github.com/bridgecrewio/checkov) ([GitHub](https://github.com/bridgecrewio/checkov)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, document` → `secrets, tech_stack, urls` |
| **B** | [**Terrascan**](https://github.com/tenable/terrascan) ([GitHub](https://github.com/tenable/terrascan)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, document` → `tech_stack, secrets, open_ports` |
| **A** | [**tfsec**](https://github.com/aquasecurity/tfsec) ([GitHub](https://github.com/tfsec/tfsec)) | CLI | OSS / Free | 🟢 Passive | ✅ | `repo_code, document` → `secrets, tech_stack` |

### [Checkov](https://github.com/bridgecrewio/checkov) `[A-Tier]`
- **ID**: `checkov-iac` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`bridgecrewio/checkov`](https://github.com/bridgecrewio/checkov)
- **Inputs**: `repo_code`, `document` → **Outputs**: `secrets`, `tech_stack`, `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `terraform`, `kubernetes`, `iac-osint`, `secrets`
- **Overview**: Static Infrastructure-as-Code analyzer auditing Terraform, CloudFormation, Helm, and Kubernetes manifests for public buckets and secrets.
- **Quick-Start / Tradecraft**: `checkov -d ./terraform`

### [Terrascan](https://github.com/tenable/terrascan) `[B-Tier]`
- **ID**: `terrascan-iac` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tenable/terrascan`](https://github.com/tenable/terrascan)
- **Inputs**: `repo_code`, `document` → **Outputs**: `tech_stack`, `secrets`, `open_ports`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `iac`, `terraform`, `kubernetes`, `cloud-exposure`
- **Overview**: Static code analyzer auditing Terraform, Kubernetes, Helm, and Kustomize repositories for exposed cloud storage, public security groups, and secrets.
- **Quick-Start / Tradecraft**: `terrascan scan -d ./iac-repo`

### [tfsec](https://github.com/aquasecurity/tfsec) `[A-Tier]`
- **ID**: `tfsec-scanner` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tfsec/tfsec`](https://github.com/tfsec/tfsec)
- **Inputs**: `repo_code`, `document` → **Outputs**: `secrets`, `tech_stack`
- **Platforms**: CLI, Linux, macOS, Windows, Go · **Tags**: `terraform`, `s3-exposure`, `aws-iam`, `go`
- **Overview**: Fast Go Terraform static analyzer pinpointing public S3 ACLs, unencrypted RDS snapshots, wildcard IAM roles, and hardcoded cloud keys.
- **Quick-Start / Tradecraft**: `tfsec ./terraform`

---
[⬅️ Back to Master Index](../README.md) · [◀ 💬 Social Media (SOCMINT)](./09-social-media-socmint.md) · [🛰️ GEOINT, Maps & Satellites ▶](./11-geoint-maps-satellites.md)

[⬅️ Back to Master Index](../README.md)

# 🎯 OSINT Search & Cyberspace Dorks Arsenal

`105` high-yield search operators across Google, Shodan, Censys, FOFA, ZoomEye, GitHub, URLScan.io, X, Wayback CDX, and `crt.sh` SQL.

> **CLI Tip**: Auto-substitute your target domain across all dorks instantly with:
> ```bash
> python3 scripts/osint.py dorks --target acme.com
> python3 scripts/osint.py dorks --engine Shodan --target acme.com
> ```

## Google (42 Dorks)

### Passive Subdomain Discovery (Exclude www) (`Domain & Attack Surface`)
Passively enumerate indexed subdomains of a target root domain without sending DNS queries to target authoritative servers.
```text
site:*.example.com -site:www.example.com
```

### Publicly Indexed Office & PDF Documents (`Document & Metadata`)
Harvest public documents to extract author usernames, internal software versions, printer names, and internal paths via ExifTool.
```text
site:example.com (ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx OR ext:csv)
```

### Exposed Environment & Config Files (`Secrets & Configs`)
Identify accidentally indexed configuration files and SQL dumps on web servers.
```text
site:example.com (ext:env OR ext:yaml OR ext:yml OR ext:ini OR ext:conf OR ext:sql) ("DB_PASSWORD" OR "API_KEY" OR "SECRET")
```

### Apache/Nginx Open Directory Listings (`Open Directories`)
Locate browsable web server directory listings exposing backups, raw media, or `.git` folders.
```text
site:example.com intitle:"index of /" ("parent directory" OR "backup" OR "uploads" OR ".git")
```

### Indexed AWS S3, Azure Blob & GCS Buckets (`Cloud Storage`)
Discover public cloud object storage buckets referencing a company, brand, or project slug.
```text
(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) "target-company"
```

### Passive Telegram Channel & Invite Link Discovery (`Messaging OSINT`)
Find public Telegram handles and private invite links indexed across the web without logging into Telegram.
```text
site:t.me ("target_keyword" OR "+joinchat" OR "t.me/+") -site:t.me/s/
```

### Telegram Web Preview Post Search (`Messaging OSINT`)
Search inside public Telegram channel web previews (`t.me/s/`) for exact phrases, handles, or wallet addresses.
```text
site:t.me/s/ "target_keyword"
```

### Discord Server Invite Discovery (`Messaging OSINT`)
Surface public Discord invite codes mentioning a brand, game, group, or threat keyword.
```text
(site:discord.gg OR site:discord.com/invite) "target_keyword"
```

### Public WhatsApp Group Invite Links (`Messaging OSINT`)
Discover indexed WhatsApp group invite URLs shared on forums, social bios, or websites.
```text
site:chat.whatsapp.com "target_keyword"
```

### Public Trello Boards & Notion Workspaces (`Cloud Workspaces`)
Uncover public project roadmaps, onboarding docs, or contractor boards accidentally set to public.
```text
(site:trello.com OR site:notion.site OR site:notion.so) "target_company"
```

### Exposed Google Docs, Sheets & Drive Folders (`Cloud Workspaces`)
Locate publicly shared spreadsheets, rosters, and Drive folders tied to an event or organization.
```text
site:docs.google.com/spreadsheets OR site:drive.google.com/drive/folders "target_keyword"
```

### LinkedIn Employee & Role X-Ray Search (`People & HUMINT`)
Enumerate company personnel and organizational structure without triggering LinkedIn's 'Who Viewed Your Profile' alerts.
```text
site:linkedin.com/in/ "Current" "Target Company" ("Security" OR "DevOps" OR "Director")
```

### Paste & Code Snippet Leak Sweep (`Breaches & Pastes`)
Search major paste and snippet hosts for leaked corporate email addresses or domains.
```text
(site:pastebin.com OR site:ghostbin.co OR site:rentry.co OR site:gist.github.com) "@example.com"
```

### Exposed Swagger / OpenAPI Documentation (`API & Attack Surface`)
Identify self-documented REST/GraphQL endpoints and internal API schemas.
```text
site:example.com (inurl:/swagger-ui OR inurl:/api-docs OR inurl:/openapi.json OR intitle:"Swagger UI")
```

### Public Jira Dashboards & Confluence Wikis (`Cloud Workspaces`)
Find unauthenticated Atlassian Confluence spaces and Jira issue trackers.
```text
(inurl:atlassian.net/wiki OR inurl:/secure/Dashboard.jspa) "target_company"
```

### Exposed Firebase Realtime Databases (`Cloud Storage`)
Discover mobile/web app Firebase Realtime Database endpoints indexed by Google (append `/.json` in authorized tests).
```text
site:firebaseio.com "target_keyword"
```

### Public Supabase Project Endpoints in Client Bundles (`Cloud Storage`)
Identify exposed PostgREST Supabase project URLs referenced alongside a target domain.
```text
"supabase.co/rest/v1" "example.com"
```

### Public Postman Collections & Environments (`API & Attack Surface`)
Surface developer Postman API workspaces indexed in Google.
```text
site:postman.com "example.com" ("collection" OR "environment" OR "workspace")
```

### Publicly Shared Cloud Meeting Recordings (`Cloud Workspaces`)
Locate publicly shared Loom walkthroughs or Zoom recordings discussing internal systems.
```text
(site:zoom.us/rec/share OR site:loom.com/share) "target_company"
```

### Bio-Link Aggregator Handle Discovery (`People & HUMINT`)
Uncover multi-platform bio-link trees linking a persona's secondary social, payment, and shop accounts.
```text
(site:linktr.ee OR site:beacons.ai OR site:carrd.co OR site:solo.to) "target_handle"
```

### Court Filings, Affidavits & Indictment PDFs (`Document & Metadata`)
Surface unindexed legal exhibits, criminal complaints, and civil affidavits hosted on law blogs or court mirrors.
```text
ext:pdf ("United States District Court" OR "Affidavit" OR "Indictment" OR "Case No.") "Target Name"
```

### Off-Chain Wallet Address Attribution Sweep (`Cryptocurrency OSINT`)
Exclude noisy block explorers so Google surfaces forum signatures, GitHub READMEs, or social bios where the owner posted their wallet.
```text
"0x742d35Cc6634C0532925a3b844Bc454e4438f44e" -site:etherscan.io -site:blockchair.com
```

### Indexed Hugging Face Spaces & Datasets (`AI & Cloud Leaks`)
Find public ML demos, datasets, and Gradio/Streamlit Spaces referencing corporate domains.
```text
site:huggingface.co ("example.com" OR "target_org") (inurl:spaces OR inurl:datasets)
```

### Indexed MCP Server Configs & Claude/Cursor Dotfiles (`Shadow AI & LLM Recon`)
Find leaked Model Context Protocol configurations revealing internal API URLs and tokens.
```text
site:example.com (inurl:".mcp.json" OR inurl:"claude_desktop_config.json" OR "mcpServers")
```

### Instagram Handle Bio, Reels & Third-Party Tags (`SOCMINT & Handle Pivots`)
Surface indexed Instagram profile bios, reels, and mentions by collaborators even without logging in.
```text
site:instagram.com "target_handle"
```

### Multi-Platform Handle Reuse Sweep (`SOCMINT & Handle Pivots`)
Pivot a single username across six major short-video and messaging ecosystems simultaneously.
```text
"target_handle" (site:tiktok.com OR site:snapchat.com OR site:x.com OR site:threads.net OR site:t.me OR site:youtube.com)
```

### Link-in-Bio Hub Discovery (Linktree / Beacons / Taplink) (`SOCMINT & Handle Pivots`)
Locate link-in-bio hubs that bundle a target's personal domains, shops, Telegrams, and booking phones.
```text
"target_handle" (site:linktr.ee OR site:beacons.ai OR site:bio.link OR site:taplink.cc OR site:carrd.co)
```

### WhatsApp `wa.me` Business Number Unmasking (`SOCMINT & Handle Pivots`)
Extract direct E.164 WhatsApp phone numbers linked to a social handle or brand.
```text
"target_handle" ("wa.me/" OR "api.whatsapp.com/send?phone=")
```

### Discord Server Invite Leaks Tied to Domain/Handle (`SOCMINT & Handle Pivots`)
Discover official or shadow community Discord servers linked to an organization or handle.
```text
("discord.gg/" OR "discord.com/invite/") "example.com"
```

### Calendly & Executive Booking Slugs (`SOCMINT & Handle Pivots`)
Enumerate employee names, roles, and meeting links via public Calendly scheduling pages.
```text
site:calendly.com "Target Corp" OR "example.com"
```

### Public Notion Sites & Internal Wikis (`Cloud & Collaboration Leaks`)
Uncover public Notion roadmaps, onboarding docs, and org charts referencing the target domain.
```text
(site:notion.site OR site:notion.so) "example.com"
```

### Exposed Postman API Collections & Environments (`Cloud & Collaboration Leaks`)
Find public developer Postman workspaces leaking staging URLs, headers, and sample bearer tokens.
```text
site:postman.com "example.com"
```

### Public Figma Design Files & Architecture Boards (`Cloud & Collaboration Leaks`)
Locate publicly shared UX prototypes and architecture diagrams revealing unreleased products.
```text
site:figma.com "Target Corp" OR "example.com"
```

### Indexed `terraform.tfstate` Infrastructure Maps (`Cloud & DevOps Exposure`)
Detect leaked Terraform state files containing full cloud resource graphs and outputs.
```text
site:example.com ext:tfstate OR inurl:"terraform.tfstate"
```

### Exposed Kubernetes `kubeconfig` & Cluster YAML (`Cloud & DevOps Exposure`)
Identify indexed Kubernetes configuration files leaking API server URLs.
```text
site:example.com ("apiVersion: v1" "clusters:" "certificate-authority-data")
```

### Firebase Realtime Database & Storage References (`Cloud & DevOps Exposure`)
Find mobile/web backend Firebase project slugs tied to a target domain.
```text
("firebaseio.com" OR "firebasestorage.googleapis.com") "example.com"
```

### Supabase Project URL & Anon Key References (`Cloud & DevOps Exposure`)
Locate Supabase backend project subdomains (`*.supabase.co`) embedded in client apps or docs.
```text
"supabase.co" "example.com"
```

### Indexed Slide Decks, Org Charts & Internal Briefings (`Document & Metadata OSINT`)
Recover public briefings and PDFs rich in author metadata and internal system names.
```text
site:example.com (filetype:pptx OR filetype:pdf) ("confidential" OR "internal use" OR "architecture" OR "roadmap")
```

### Indexed Spreadsheets, Rosters & Vendor Lists (`Document & Metadata OSINT`)
Surface accidentally indexed staff rosters and supplier contact spreadsheets.
```text
site:example.com (filetype:xlsx OR filetype:csv) ("email" OR "phone" OR "department" OR "vendor")
```

### Indexed `security.txt` & Bug Bounty Scope Files (`Cloud & DevOps Exposure`)
Passively read security contact emails, PGP keys, and canonical domain lists.
```text
site:example.com inurl:"/.well-known/security.txt"
```

### Indexed GraphQL Playgrounds & Apollo Consoles (`Cloud & DevOps Exposure`)
Discover interactive GraphQL API explorers indexed by search crawlers.
```text
site:example.com (inurl:"/graphql" OR inurl:"/graphiql" OR intitle:"GraphQL Playground")
```

### Indexed AWS S3, GCS & Azure Blob Buckets Mentioning Target (`Cloud & DevOps Exposure`)
Passively find public cloud object storage buckets containing files referencing the target.
```text
(site:s3.amazonaws.com OR site:storage.googleapis.com OR site:blob.core.windows.net) "target_company"
```

## Shodan (24 Dorks)

### Origin Servers via TLS Certificate Subject/CN (`Origin IP Discovery`)
Bypass CDN proxies by finding direct origin IPv4/IPv6 hosts presenting a TLS certificate for the target domain.
```text
ssl.cert.subject.cn:"example.com" -org:"Cloudflare"
```

### Favicon MurmurHash3 (`mmh3`) Pivot (`Infrastructure Pivoting`)
Locate all internet-facing servers sharing an identical web application or brand favicon hash (e.g., Spring Boot, Cobalt Strike, or custom company icon).
```text
http.favicon.hash:116323821
```

### Unauthenticated Elasticsearch & MongoDB Instances (`Exposed Databases`)
Audit an organization's netblocks for exposed, unauthenticated NoSQL/search clusters.
```text
org:"Target Corp" (product:"Elastic" port:9200 "cluster_name") OR (product:"MongoDB" port:27017 -"unauthorized")
```

### Unauthenticated RTSP Streams with Screenshots (`IoT & OT`)
Filter Shodan's pre-captured visual screenshots on RTSP port 554 within a geographic area.
```text
has_screenshot:true port:554 country:"US" city:"Chicago"
```

### Exposed Industrial Control Systems (Modbus / S7 / BACnet) (`IoT & OT`)
Passively check an ASN for internet-exposed SCADA/ICS industrial protocols.
```text
tag:"ics" (port:502 OR port:102 OR port:47808) asn:"AS12345"
```

### TLS JARM Fingerprint Pivot (`Threat Hunting`)
Hunt servers sharing an identical active TLS stack JARM fingerprint.
```text
ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
```

### Assets Flagged with Known CVEs in Netblock (`Vulnerability Intel`)
Identify hosts in an owned CIDR range with banner-inferred CVEs (requires Shodan Academic/Small Business+).
```text
net:198.51.100.0/24 has_vuln:true
```

### Suspected C2 Malleable Profile Indicators (`Threat Hunting`)
Track default or recycled adversary C2 certificates and beacon listeners.
```text
product:"Cobalt Strike Beacon" OR ssl.cert.serial:146473198
```

### Unauthenticated Prometheus Metrics & Grafana Dashboards (`Exposed Telemetry`)
Passively check Shodan for exposed observability dashboards leaking internal hostname topologies.
```text
(http.title:"Prometheus Time Series" port:9090) OR (http.title:"Grafana" "Anonymous") org:"Target Corp"
```

### Exposed Kubernetes API / Kubelet / etcd Ports (`Cloud Infrastructure`)
Identify internet-reachable Kubernetes control-plane and etcd banners inside a target ASN.
```text
(port:6443 OR port:10250 OR port:2379) ssl:"kubernetes" asn:"AS12345"
```

### Unauthenticated Internet-Exposed Ollama / vLLM Inference Servers (`AI & Cloud Leaks`)
Detect shadow-AI local LLM inference servers accidentally bound to `0.0.0.0:11434`.
```text
port:11434 "Ollama is running" org:"Target Corp"
```

### Starlink Satellite Terminal ASN & Dish Routers (`SIGINT & Satcom`)
Identify services hosted behind SpaceX Starlink (`AS14593`) satellite terminals in a country.
```text
asn:AS14593 has_ssl:true country:"UA"
```

### Unauthenticated Ollama LLM API Servers (:11434) (`Shadow AI & LLM Recon`)
Discover exposed self-hosted Ollama inference instances leaking loaded proprietary models via `/api/tags`.
```text
port:11434 "Ollama is running" org:"Target Corp"
```

### Exposed Open WebUI / Chat Portals (`Shadow AI & LLM Recon`)
Locate internal LLM chat frontends accidentally exposed on corporate subdomains or cloud IPs.
```text
http.title:"Open WebUI" ssl:"example.com"
```

### Exposed vLLM OpenAI-Compatible Inference Nodes (`Shadow AI & LLM Recon`)
Identify high-GPU vLLM inference endpoints serving fine-tuned enterprise weights.
```text
http.html:"/v1/models" "vllm" org:"Target Corp"
```

### Unauthenticated Qdrant RAG Vector Databases (`Shadow AI & LLM Recon`)
Find exposed RAG vector collections containing embedded internal documents and knowledge bases.
```text
http.title:"Qdrant" port:6333 org:"Target Corp"
```

### Exposed Milvus / Attu Vector Clusters (`Shadow AI & LLM Recon`)
Detect unauthenticated Milvus vector stores backing enterprise AI pipelines.
```text
port:19530 OR http.title:"Attu" org:"Target Corp"
```

### Exposed MLflow Experiment & Artifact Servers (`Shadow AI & LLM Recon`)
Uncover MLflow dashboards exposing S3 artifact paths, training datasets, and pipeline parameters.
```text
http.title:"MLflow" ssl:"example.com"
```

### Public Gradio ML Demo & Internal Prototypes (`Shadow AI & LLM Recon`)
Enumerate internal Gradio AI prototypes hosted across corporate cloud netblocks.
```text
http.html:"__gradio_mode__" ssl:"example.com"
```

### Exposed JupyterLab / Notebook Servers (`Shadow AI & LLM Recon`)
Locate data-science notebook servers tied to target TLS certificates.
```text
http.title:"Jupyter" ssl:"example.com"
```

### JARM TLS Stack Cluster Pivot (`Origin IP & TLS Fingerprinting`)
Cluster all global servers sharing an identical TLS ServerHello JARM stack hash.
```text
ssl.jarm:"2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb" ssl:"example.com"
```

### Kubernetes API (`:6443`) & etcd (`:2379`) Cert Pivot (`Origin IP & TLS Fingerprinting`)
Find raw cloud control-plane IPs holding certificates for the target domain.
```text
(port:6443 OR port:2379) ssl.cert.subject.cn:"example.com"
```

### Mail Server `:25/:587` TLS Cert Origin Leak (`Origin IP & TLS Fingerprinting`)
Unmask non-CDN origin subnets via self-hosted Postfix/Exchange mail gateways.
```text
(port:25 OR port:587) ssl:"example.com"
```

### Exposed RTSP / Network Video Recorders on Target ASN (`OT / IoT & Physical Recon`)
Assess exposed physical-security cameras and NVR appliances across corporate IP blocks.
```text
(port:554 OR "Server: hikvision" OR "dahua") org:"Target Corp"
```

## Censys (9 Dorks)

### Hosts Presenting Target Domain in TLS Leaf Cert (`Origin IP Discovery`)
Discover non-CDN hosts terminating TLS for `example.com` across all 65,535 scanned ports.
```text
services.tls.certificates.leaf_data.names: "example.com" and not autonomous_system.name: "CLOUDFLARE*"
```

### HTTP HTML Title & Body Hash Pivot (`Infrastructure Pivoting`)
Find matching login portals or clone pages across global IPv4/IPv6 hosts.
```text
services.http.response.html_title: "Internal Portal" and services.http.response.status_code: 200
```

### C2 Server Hunt via JARM + Non-Standard Port (`Threat Hunting`)
Combine JARM TLS stack fingerprinting with uncommon port filtering to isolate C2 servers.
```text
services.jarm.fingerprint: "2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb" and not services.port: {80, 443}
```

### HTTP Open Directory Servers on Non-Standard Ports (`Open Directories`)
Locate exposed directory listings hosted inside a specific cloud or ISP ASN.
```text
services.http.response.html_title: "Index of /" and autonomous_system.asn: 15169
```

### Self-Hosted MinIO & S3 XML Bucket Listings (`Cloud Storage`)
Find self-hosted MinIO/Ceph object stores returning unauthenticated S3 XML directory listings.
```text
services.http.response.body: "<ListBucketResult" and services.http.response.status_code: 200
```

### Clearnet Servers Advertising `Onion-Location` HTTP Header (`Dark Web Pivoting`)
Link `.onion` hidden services directly to clearnet servers advertising official `Onion-Location` headers.
```text
services.http.response.headers.key: "Onion-Location"
```

### X.509 SAN Sibling Domain & Origin IP Discovery (`Origin IP & TLS Fingerprinting`)
Find non-Cloudflare origin IPs presenting valid TLS certificates for `example.com`!
```text
services.tls.certificates.leaf_data.names: "example.com" and not autonomous_system.name: "CLOUDFLARE*"
```

### Open HTTP Directory Listings Across Target Certs (`Origin IP & TLS Fingerprinting`)
Spot exposed Apache/Nginx directory listings on target-owned TLS hosts.
```text
services.tls.certificates.leaf_data.names: "example.com" and services.http.response.html_title: "Index of /"
```

### SSH Host-Key Fingerprint Cross-Host Attribution (`Origin IP & TLS Fingerprinting`)
Prove two seemingly unrelated servers or `.onion` services are cloned from the same image via shared SSH host keys!
```text
services.ssh.server_host_key.fingerprint_sha256: "target_keyword"
```

## FOFA (5 Dorks)

### FOFA Favicon Hash & Domain Asset Search (`Infrastructure Pivoting`)
Correlate domain, TLS certificate, and favicon hash matches in FOFA's cyberspace index.
```text
domain="example.com" || cert="example.com" || icon_hash="-247388890"
```

### Brand Login Clone / Phishing Kit Hunt (`Brand Monitoring`)
Detect external phishing servers cloning your organization's SSO login title.
```text
title="ExampleCorp Single Sign-On" && domain!="example.com"
```

### Exposed Ray Cluster & ComfyUI GPU Dashboards (`Shadow AI & LLM Recon`)
Map distributed Ray compute clusters and generative AI nodes matching target certs.
```text
(title="Ray Dashboard" || title="ComfyUI") && cert="example.com"
```

### FOFA Favicon MurmurHash3 Origin Server Hunt (`Origin IP & TLS Fingerprinting`)
Locate direct IPv4 origins serving the exact brand favicon without CDN proxying.
```text
icon_hash="-247388890" && domain!="example.com"
```

### Spring Boot Actuator `/actuator/health` & `/env` (`Origin IP & TLS Fingerprinting`)
Identify Java Spring Boot microservice management endpoints on target certificates.
```text
body="\"_links\":{\"self\"" && cert="example.com"
```

## GitHub (13 Dorks)

### Hardcoded Tokens & Private Keys Linked to Domain (`Secrets & Configs`)
Hunt leaked AWS keys, Slack bot tokens, GitHub PATs, and SSH private keys referencing a target domain.
```text
"example.com" ("BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY" OR "AKIA" OR "ghp_" OR "xoxb-")
```

### Committed `.env` & Docker Compose Credentials (`Secrets & Configs`)
Find production environment files and container configs mentioning internal domains.
```text
"example.com" (path:.env OR path:docker-compose.yml OR path:application.properties) ("PASSWORD" OR "SECRET")
```

### Internal & Staging Hostnames in Public Code (`Domain & Attack Surface`)
Discover non-public staging, VPN, and intranet FQDNs leaked by developers or contractors.
```text
".corp.example.com" OR ".internal.example.com" OR ".staging.example.com"
```

### Commits Authored by Corporate Email Domain (`People & HUMINT`)
Identify personal GitHub accounts and side projects of employees committing with work email configs.
```text
author-email:@example.com OR committer-email:@example.com
```

### Leaked `terraform.tfstate` Infrastructure State Files (`Cloud Infrastructure`)
Discover accidentally committed Terraform state JSON files revealing complete cloud architecture and secrets.
```text
filename:terraform.tfstate "example.com" ("aws_db_instance" OR "aws_s3_bucket" OR "access_key")
```

### Exposed Kubernetes `kubeconfig` Certificates & Tokens (`Cloud Infrastructure`)
Audit GitHub for leaked Kubernetes cluster admin configuration files referencing corporate domains.
```text
"apiVersion: v1" "clusters:" "client-certificate-data" "example.com"
```

### Exposed `.npmrc` and `.pypirc` Registry Publish Tokens (`Secrets & Configs`)
Check for leaked package-registry authentication tokens tied to an organization.
```text
(filename:.npmrc "_authToken=") OR (filename:.pypirc "password =") "example"
```

### Leaked Supabase & Next.js Public/Service Env Vars (`Secrets & Code OSINT`)
Discover repositories linking target domains to Supabase projects and API keys.
```text
"example.com" ("NEXT_PUBLIC_SUPABASE_URL" OR "SUPABASE_SERVICE_ROLE_KEY")
```

### Production `docker-compose.yml` Infrastructure Topology (`Secrets & Code OSINT`)
Map internal microservices, Redis/Postgres ports, and reverse-proxy hostnames.
```text
"example.com" filename:docker-compose.yml
```

### GitHub Actions Cloud IAM Role ARNs (`Secrets & Code OSINT`)
Extract AWS Account IDs (12-digit numbers inside IAM ARNs) from public CI/CD workflows!
```text
"example.com" path:.github/workflows "arn:aws:iam::"
```

### Private `.npmrc` Scopes & Internal Registry URLs (`Secrets & Code OSINT`)
Uncover internal Artifactory/Nexus hostnames and scoped package namespaces (`@corp/*`).
```text
"example.com" filename:.npmrc
```

### Committed OpenAPI / Swagger Route Specifications (`Secrets & Code OSINT`)
Retrieve complete API endpoint schemas and auth definitions from public repos.
```text
"example.com" (filename:openapi.yaml OR filename:openapi.json OR filename:swagger.json)
```

### CI/CD `.gitlab-ci.yml` Staging & Runner Hosts (`Secrets & Code OSINT`)
Extract staging domains, container registries, and deployment SSH hosts.
```text
"example.com" filename:.gitlab-ci.yml
```

## URLScan.io (2 Dorks)

### Pivot Across Identical Page / Resource SHA-256 Hash (`Threat Hunting`)
Find every scanned webpage loading the exact same JavaScript skimmer, logo, or phishing kit resource.
```text
hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Reverse Domain Search by Page Domain & IP ASN (`Infrastructure Pivoting`)
Inspect historical DOM snapshots, outbound XHR requests, and HTTP redirect chains for a domain.
```text
page.domain:example.com OR task.tags:phishing
```

## Wayback CDX API (1 Dorks)

### Historical Backup, Config & Archive URLs via CDX (`Historical Archives`)
Query the Internet Archive CDX API directly for archived backups, configs, and JSON endpoints across all subdomains.
```text
https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(zip|bak|sql|env|json|xml|conf)$
```

## ZoomEye (2 Dorks)

### ZoomEye Favicon Hash & SSL Organization Match (`Infrastructure Pivoting`)
Pivot across matching application favicons and SSL certificate Common Names in ZoomEye.
```text
iconhash:"116323821" +ssl.cert.subject.cn:"example.com"
```

### ZoomEye Organization Certificate Sweep (`Origin IP & TLS Fingerprinting`)
Map global IPv4/IPv6 assets holding OV/EV certificates issued to the legal entity.
```text
ssl.cert.subject.organization:"Target Corp"
```

## X (Twitter) (1 Dorks)

### Eyewitness Video/Photo Geocode + Exact UTC Window (`Crisis & GEOINT`)
Isolate original eyewitness photos/videos posted near incident coordinates within a tight UTC time window.
```text
geocode:35.6895,139.6917,3km filter:media since:2026-08-15_08:00:00_UTC until:2026-08-15_12:00:00_UTC -filter:retweets
```

## crt.sh SQL (1 Dorks)

### Direct PostgreSQL Query against `crt.sh:5432` (`Certificate Transparency`)
Bypass web timeouts on massive domains by querying Sectigo's public read-only `certwatch` Postgres replica directly!
```text
psql -h crt.sh -p 5432 -U guest certwatch -c "SELECT DISTINCT ci.NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.example.com'));"
```

## URLScan (2 Dorks)

### URLScan DOM & Script Attribution Pivot (`Analytics & Ad-Tag Attribution`)
Inspect passive DOM snapshots, outgoing third-party script requests, and ASN history.
```text
page.domain:example.com OR task.domain:example.com
```

### Shared Google Analytics / GTM / AdSense Network Hunt (`Analytics & Ad-Tag Attribution`)
Uncover covert sister websites operated by the same actor via shared `G-XXXX` / `GTM-XXXX` IDs.
```text
filename:"gtag" AND page.body:"target_keyword"
```

## PublicWWW (2 Dorks)

### HTML Source Code `G-` / `GTM-` / `pub-` Reverse Lookup (`Analytics & Ad-Tag Attribution`)
Search 500M+ indexed web pages' raw HTML source to find every domain sharing an analytics or AdSense ID.
```text
"G-XXXXXXXXXX" OR "GTM-XXXXXXX"
```

### Embedded Corporate Script / CDN Asset Reverse Search (`Analytics & Ad-Tag Attribution`)
Discover partner, subsidiary, and white-label domains loading assets from the target's CDN.
```text
"cdn.example.com/"
```

## Netlas (1 Dorks)

### Netlas Historical WHOIS Organization & Email Reverse Lookup (`WHOIS & Corporate Pivots`)
Pivot from a corporate legal name to legacy domains registered prior to GDPR WHOIS redaction.
```text
whois.registrant.organization:"Target Corp"
```


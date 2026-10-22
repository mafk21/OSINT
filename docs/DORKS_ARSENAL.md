[⬅️ Back to Master Index](../README.md)

# 🎯 OSINT Search & Cyberspace Dorks Arsenal

`56` high-yield search operators across Google, Shodan, Censys, FOFA, ZoomEye, GitHub, URLScan.io, X, Wayback CDX, and `crt.sh` SQL.

> **CLI Tip**: Auto-substitute your target domain across all dorks instantly with:
> ```bash
> python3 scripts/osint.py dorks --target acme.com
> python3 scripts/osint.py dorks --engine Shodan --target acme.com
> ```

## Google (23 Dorks)

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

## Shodan (12 Dorks)

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

## Censys (6 Dorks)

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

## FOFA (2 Dorks)

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

## GitHub (7 Dorks)

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

## ZoomEye (1 Dorks)

### ZoomEye Favicon Hash & SSL Organization Match (`Infrastructure Pivoting`)
Pivot across matching application favicons and SSL certificate Common Names in ZoomEye.
```text
iconhash:"116323821" +ssl.cert.subject.cn:"example.com"
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


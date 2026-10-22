# Investigator OPSEC, Evidence Preservation & Ethical Tradecraft

> **Golden Rule of OSINT**: *Passive collection queries third-party indexes and public records without sending packets to the target. Active collection touches the target's servers, accounts, or devices and can alert them.*

---

## 1. Passive vs. Active Reconnaissance

Every tool in this Monster Database carries an explicit **`opsec`** classification (`Passive`, `Hybrid`, or `Active`):

| Mode | Network Behavior | Detection Risk | Examples |
| :--- | :--- | :--- | :--- |
| **Passive** | Queries third-party caches, scan archives, Certificate Transparency logs, or public registries. Zero packets hit target infrastructure. | **Minimal** (logged only by the third-party provider) | `crt.sh`, `Shodan`, `Censys`, `Wayback Machine`, `OpenSanctions`, `Equasis`, `Overpass Turbo` |
| **Hybrid** | Supports passive modules by default or via flags (`--passive`), alongside optional active probing modules. | **Low → High** (depends on flags!) | `SpiderFoot`, `OWASP Amass`, `BBOT`, `Recon-ng`, `TruffleHog`, `urlscan.io` |
| **Active** | Sends HTTP/DNS/SMTP/TCP requests directly to target domains, APIs, or servers, or triggers live crawls. | **High** (leaves your exit IP, User-Agent, and TLS JA3/JA4 in target logs) | `httpx`, `Katana`, `Nmap`, `dnstwist`, `Reacher`, `gowitness`, `TorBot` |

### Critical Traps That Accidentally Turn Passive into Active
1. **Submitting a URL to `web.archive.org/save` or `archive.ph`**: Searching existing snapshots is passive; clicking *Save Page Now* causes the archive's crawler to immediately fetch the target URL (and publishes that private URL to global archive feeds!).
2. **Running `trufflehog` without `--no-verification`**: Live credential verification makes real API calls against leaked keys—instantly tripping Canarytokens (`canarytokens.org`) planted by defenders!
3. **Opening leaked `.docx` / `.pdf` / `.xlsx` files directly**: Malicious documents and Canarytokens embed remote `1x1` tracking pixels, SMB UNC paths, or DNS beacons that phone home the moment Word or Adobe Reader opens them. **Always sanitize untrusted documents through [Dangerzone](https://dangerzone.rocks/) inside an offline VM.**
4. **Password-Reset Enumeration**: Poorly implemented password-reset pages dispatch *"Someone requested a password reset"* emails or SMS codes immediately. Stick to silent registration checks (`Holehe` passive modules, `Epieos`, `GHunt`) unless active interaction is authorized.

---

## 2. Workstation & Browser Compartmentalization

Never run OSINT investigations from your personal daily-driver browser or home residential IP.

### Tiered Isolation Architecture
- **Tier 1 (Low-Risk / Public Research)**: Dedicated browser binary ([Mullvad Browser](https://mullvad.net/en/browser) or ungoogled-chromium / Firefox profile with [Firefox Multi-Account Containers](https://github.com/mozilla/multi-account-containers) + [uBlock Origin](https://github.com/gorhill/uBlock)) routed through a reputable non-logging VPN.
- **Tier 2 (SOCMINT / Adversary Infrastructure)**: Disposable containerized browsers via [Kasm Workspaces](https://www.kasmweb.com/) or dedicated Virtual Machines ([Trace Labs OSINT VM](https://www.tracelabs.org/initiatives/osint-vm), [Tsurugi Linux](https://tsurugi-linux.org/)). Destroy and recreate containers between cases.
- **Tier 3 (Dark Web / Hostile Threat Actors / `.onion`)**: [Whonix](https://www.whonix.org/) two-VM architecture (Gateway + Workstation) inside VirtualBox/KVM or [Qubes OS](https://www.qubes-os.org/), or live-USB [Tails OS](https://tails.net/), with [Tor Browser](https://www.torproject.org/) set to **Safest** (JavaScript disabled).

### Pre-Flight Leak Checklist
Before starting sensitive collection, verify inside your investigation browser via [BrowserLeaks](https://browserleaks.com/):
- **IP & DNS**: Exit IP and all DNS resolvers belong exclusively to your VPN/proxy/Tor exit—zero ISP DNS leaks.
- **WebRTC**: `media.peerconnection.enabled = false` so STUN servers cannot leak your local LAN/WAN IP.
- **System Clock / Timezone**: Browser `Intl.DateTimeFormat().resolvedOptions().timeZone` matches your exit IP's region (mismatched UTC offsets instantly flag sock puppets!).

---

## 3. Sock Puppet Tradecraft

Platforms like Meta, LinkedIn, X, TikTok, and Telegram aggressively detect automated/burner accounts via behavioral and device-graph signals:

1. **Zero Cross-Contamination**: Never log into a sock puppet from an IP, browser profile, or mobile device that ever touched your personal accounts—otherwise *"People You May Know"* algorithms will recommend your sock puppet directly to your real contacts (or the target!).
2. **Dedicated Identity Artifacts**:
   - Unique alias/mailbox per platform ([SimpleLogin](https://simplelogin.io/) / Proton / dedicated domain).
   - Dedicated physical prepaid SIM (activated away from home cell towers on a wiped burner handset with **Contact Sync OFF**) rather than recycled public SMS-receive websites.
   - Merchant-locked virtual payment cards ([Privacy.com](https://privacy.com/)) if paid tiers are needed.
3. **Platform View Notifications**:
   - **LinkedIn** notifies targets of profile views unless set to Private Mode (and even Private Mode reveals *"Someone in [Industry]"*; prefer Google/Bing X-Ray dorks `site:linkedin.com/in/` first!).
   - **TikTok** has a *Profile View History* toggle—ensure it is disabled or browse logged out / via web tools.
   - **Telegram**: Never add a target's phone number to a handset address book that has mutual-contact visibility enabled.

---

## 4. Forensic Evidence Preservation (Berkeley Protocol Standard)

Online posts, C2 servers, and corporate pages vanish within minutes once an actor suspects scrutiny. Capture first, analyze second:

1. **Full-Fidelity Capture**:
   - Use [Hunchly](https://www.hunchly.com/) or [Forensic OSINT](https://www.forensicosint.com/) for automatic continuous background page capture with SHA-256 hashes.
   - Use [ArchiveWeb.page](https://archiveweb.page/) (Webrecorder) to record interactive `.wacz` archives of dynamic social feeds and videos, or [SingleFile](https://github.com/gildas-lormeau/SingleFile) for self-contained HTML snapshots.
   - Download raw video/audio streams immediately via `yt-dlp --write-info-json --write-subs`.
2. **Cryptographic Chain of Custody**:
   - Compute SHA-256 hashes over all captured files (`sha256sum * > manifest.sha256`) and record the exact **UTC timestamp**, full source URL, HTTP response headers, and resolving IP.
   - Store original captures read-only; run `exiftool`, `ffmpeg`, or image crops only on working copies.

---

## 5. Legal & Ethical Boundaries

This database is curated strictly for **authorized cybersecurity defense, threat intelligence, journalistic verification, academic research, human-rights documentation, due diligence, and lawful investigations**:
- OSINT means collecting **publicly available** information lawfully—never unauthorized credential stuffing, bypassing authentication, purchasing illegal darknet access, or harassing individuals.
- Respect regional data-protection frameworks (GDPR, CCPA, FCRA, computer misuse statutes) and platform terms applicable to your legal mandate.

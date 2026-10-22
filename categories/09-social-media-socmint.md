[⬅️ Back to Master Index](../README.md) · [◀ 📡 Cyberspace & Network Search](./08-network-ip-iot-search.md) · [💻 Code, Secrets & Cloud OSINT ▶](./10-code-cloud-dev-osint.md)

# 💬 09. Social Media Intelligence (SOCMINT) — X, Instagram, Reddit, TikTok, LinkedIn, YouTube (`SOCMINT`)

> **Scope**: Platform-specific collection, deleted-post recovery, social graph mapping, timestamp extraction, location-based post discovery, and cross-platform social listening tools.
>
> **OPSEC Advisory**: Platforms like LinkedIn, TikTok, and Instagram notify users of profile views or suggest 'People You May Know' if sock puppets share browser fingerprints, IPs, or phone numbers.

**Discipline Telemetry**: `31` Verified Tools · `11` S-Tier Flagships · `28` Passive · `26` Free/Open-Source

## Subcategories
- [Cross-Platform Academic & Disinfo Suites](#cross-platform-academic-disinfo-suites) (1)
- [YouTube & Video Platform OSINT](#youtube-video-platform-osint) (4)
- [Facebook & Instagram OSINT](#facebook-instagram-osint) (7)
- [Reddit & Forum Intelligence](#reddit-forum-intelligence) (5)
- [Location & Fitness App OSINT](#location-fitness-app-osint) (2)
- [X (Twitter) & Bluesky OSINT](#x-twitter-bluesky-osint) (3)
- [LinkedIn & Corporate SOCMINT](#linkedin-corporate-socmint) (1)
- [TikTok OSINT](#tiktok-osint) (1)
- [Regional Social Networks (VK / OK / Weibo)](#regional-social-networks-vk-ok-weibo) (1)
- [Decentralized Social OSINT](#decentralized-social-osint) (1)
- [Cross-Platform Social Search](#cross-platform-social-search) (2)
- [Media & Profile Archivers](#media-profile-archivers) (1)
- [X / Twitter OSINT](#x-twitter-osint) (1)
- [Fediverse & Decentralized Social](#fediverse-decentralized-social) (1)

---

## Cross-Platform Academic & Disinfo Suites

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**4CAT: Capture and Analysis Toolkit**](https://github.com/digitalmethodsinitiative/4cat) ([GitHub](https://github.com/digitalmethodsinitiative/4cat)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `keyword, username, url` → `social_profiles, entity_graph, archived_pages` |

### [4CAT: Capture and Analysis Toolkit](https://github.com/digitalmethodsinitiative/4cat) `[S-Tier]`
- **ID**: `4cat` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`digitalmethodsinitiative/4cat`](https://github.com/digitalmethodsinitiative/4cat)
- **Inputs**: `keyword`, `username`, `url` → **Outputs**: `social_profiles`, `entity_graph`, `archived_pages`
- **Platforms**: Docker, Linux, Python, Web · **Tags**: `disinformation`, `4chan`, `tiktok`, `telegram`, `computational-socmint`
- **Overview**: University of Amsterdam / OILab open-source social media capture and computational analysis platform supporting Telegram, TikTok, Reddit, 4chan, 8kun, Bluesky, Tumblr, and Gab.
- **Quick-Start / Tradecraft**: `git clone https://github.com/digitalmethodsinitiative/4cat && docker compose up -d`

---

## YouTube & Video Platform OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Filmot (YouTube Subtitle & Transcript Search)**](https://filmot.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `keyword, person_name, company` → `urls, metadata, archived_pages` |
| **S** | [**YouTube Metadata & Geofind (MattW)**](https://mattw.io/youtube-metadata/) ([GitHub](https://github.com/mattwright324/youtube-metadata)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `url, coordinates, keyword` → `metadata, geolocation, social_profiles` |
| **A** | [**Yark (YouTube Archiving Made Simple)**](https://github.com/Owez/yark) ([GitHub](https://github.com/Owez/yark)) | CLI | OSS / Free | 🟢 Passive | ✅ | `url, username` → `archived_pages, metadata` |
| **B** | [**YouTube DataViewer (Amnesty International)**](https://citizenevidence.amnestyusa.org/) | Web Platform | Free | 🟢 Passive | ✅ | `url` → `metadata, urls` |

### [Filmot (YouTube Subtitle & Transcript Search)](https://filmot.com/) `[S-Tier]`
- **ID**: `filmot` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `person_name`, `company` → **Outputs**: `urls`, `metadata`, `archived_pages`
- **Platforms**: Web · **Tags**: `youtube-transcripts`, `caption-search`, `1b-videos`, `spoken-word-osint`, `flagship`
- **Overview**: Full-text search engine indexing manual and auto-generated captions across 1+ billion YouTube videos in 100+ languages—pinpointing the exact second a name, company, or phrase was spoken on camera.
- **Quick-Start / Tradecraft**: `Search exact spoken quotes or obscure names across 1B+ YouTube auto-captions on https://filmot.com/.`

### [YouTube Metadata & Geofind (MattW)](https://mattw.io/youtube-metadata/) `[S-Tier]`
- **ID**: `mattw-youtube-metadata` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mattwright324/youtube-metadata`](https://github.com/mattwright324/youtube-metadata)
- **Inputs**: `url`, `coordinates`, `keyword` → **Outputs**: `metadata`, `geolocation`, `social_profiles`
- **Platforms**: Web · **Tags**: `youtube-osint`, `geofind`, `exact-upload-time`, `bulk-metadata`, `flagship`
- **Overview**: Extracts exact UTC upload timestamps, unlisted playlist associations, full-res thumbnails, channel IDs, tags, and geo-recording coordinates from YouTube videos; paired with MattW YouTube Geofind.
- **Quick-Start / Tradecraft**: `Paste any YouTube video/channel URL into https://mattw.io/youtube-metadata/ or search map pins at https://mattw.io/youtube-geofind/.`

### [Yark (YouTube Archiving Made Simple)](https://github.com/Owez/yark) `[A-Tier]`
- **ID**: `yark` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Owez/yark`](https://github.com/Owez/yark)
- **Inputs**: `url`, `username` → **Outputs**: `archived_pages`, `metadata`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `youtube-archiver`, `title-changes`, `deleted-videos`, `osint-preservation`
- **Overview**: Open-source Python YouTube channel archiver that tracks deleted videos, historical title/description edits, thumbnail swaps, and view-count timelines locally.
- **Quick-Start / Tradecraft**: `pipx install yark && yark new case_archive https://www.youtube.com/@channel && yark refresh case_archive`

### [YouTube DataViewer (Amnesty International)](https://citizenevidence.amnestyusa.org/) `[B-Tier]`
- **ID**: `amnesty-youtube-dataviewer` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `url` → **Outputs**: `metadata`, `urls`
- **Platforms**: Web · **Tags**: `amnesty-international`, `citizen-evidence`, `upload-timestamp`, `thumbnails`
- **Overview**: Amnesty International Citizen Evidence Lab's classic browser utility extracting exact UTC upload times and all 4 high-res thumbnails for one-click reverse image searching.
- **Quick-Start / Tradecraft**: `Paste any YouTube URL on https://citizenevidence.amnestyusa.org/ to confirm exact UTC upload time vs local solar shadows.`

---

## Facebook & Instagram OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Instaloader**](https://instaloader.github.io/) ([GitHub](https://github.com/instaloader/instaloader)) | CLI | OSS / Free | 🟢 Passive | ✅ | `username, url` → `social_profiles, metadata, geolocation` |
| **S** | [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library) | Web Platform | Free | 🟢 Passive | 🔑 | `keyword, username, url` → `social_profiles, metadata, entity_graph` |
| **S** | [**Who Posted What?**](https://whopostedwhat.com/) | Web Platform | Free | 🟢 Passive | 🔑 | `keyword, person_name, coordinates` → `social_profiles, urls, archived_pages` |
| **A** | [**Bellingcat Instagram Location Search**](https://github.com/bellingcat/instagram-location-search) ([GitHub](https://github.com/bellingcat/instagram-location-search)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `coordinates` → `geolocation, urls` |
| **A** | [**Toutatis**](https://github.com/megadose/toutatis) ([GitHub](https://github.com/megadose/toutatis)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `username` → `social_profiles, emails, phones` |
| **B** | [**Osintgram**](https://github.com/Datalux/Osintgram) ([GitHub](https://github.com/Datalux/Osintgram)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `username` → `social_profiles, emails, geolocation` |
| **B** | [**Sterra (Instagram Follower Graph Exporter)**](https://github.com/novitae/sterraxcyl) ([GitHub](https://github.com/novitae/sterraxcyl)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `username` → `social_profiles, entity_graph` |

### [Instaloader](https://instaloader.github.io/) `[S-Tier]`
- **ID**: `instaloader` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`instaloader/instaloader`](https://github.com/instaloader/instaloader)
- **Inputs**: `username`, `url` → **Outputs**: `social_profiles`, `metadata`, `geolocation`, `archived_pages`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `instagram`, `media-archiver`, `geotags`, `stories`, `flagship`
- **Overview**: Gold-standard open-source Python CLI and library downloading public/followed Instagram photos, videos, Reels, Stories, IGTV, captions, comments, timestamps, and geotags cleanly.
- **Quick-Start / Tradecraft**: `pipx install instaloader && instaloader --geotags --comments target_profile`

### [Meta Content Library](https://transparency.meta.com/researchtools/meta-content-library) `[S-Tier]`
- **ID**: `meta-content-library` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword`, `username`, `url` → **Outputs**: `social_profiles`, `metadata`, `entity_graph`
- **Platforms**: Web, Python · **Tags**: `facebook`, `instagram`, `crowdtangle-replacement`, `disinformation-research`
- **Overview**: Meta's official public-content research API and web workspace across Facebook and Instagram (the sanctioned replacement for CrowdTangle) available to qualified academic and investigative researchers.
- **Quick-Start / Tradecraft**: `Apply via ICPSR / Meta Transparency Portal for high-volume Facebook Page, Group, and Instagram public post search.`

### [Who Posted What?](https://whopostedwhat.com/) `[S-Tier]`
- **ID**: `who-posted-what` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword`, `person_name`, `coordinates` → **Outputs**: `social_profiles`, `urls`, `archived_pages`
- **Platforms**: Web · **Tags**: `facebook-search`, `date-filtering`, `henk-van-ess`, `socmint`, `flagship`
- **Overview**: Henk van Ess's non-public Facebook keyword-by-exact-date and entity-ID search builder, surfacing historical public Facebook posts, photos, and videos hidden by Facebook's native UI.
- **Quick-Start / Tradecraft**: `Log into an isolated Facebook sock-puppet browser session first, then generate date-bounded URLs on https://whopostedwhat.com/.`

### [Bellingcat Instagram Location Search](https://github.com/bellingcat/instagram-location-search) `[A-Tier]`
- **ID**: `bellingcat-instagram-location` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`bellingcat/instagram-location-search`](https://github.com/bellingcat/instagram-location-search)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `urls`
- **Platforms**: Linux, macOS, Python · **Tags**: `bellingcat`, `location-ids`, `geofencing`, `instagram`
- **Overview**: Discovers numeric Instagram Location IDs near any latitude/longitude coordinate pair so investigators can find eyewitness posts from crisis or incident venues.
- **Quick-Start / Tradecraft**: `pip install instagram-location-search && instagram-location-search --lat 51.5074 --lng -0.1278 --cookie <SESSION>`

### [Toutatis](https://github.com/megadose/toutatis) `[A-Tier]`
- **ID**: `toutatis` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`megadose/toutatis`](https://github.com/megadose/toutatis)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `emails`, `phones`, `metadata`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `instagram-osint`, `obfuscated-email`, `phone-hints`, `sessionid`
- **Overview**: Extracts account metadata from Instagram handles or numeric user IDs via mobile API endpoints—including obfuscated recovery email/phone hints, account ID, business contact fields, and bio links.
- **Quick-Start / Tradecraft**: `pipx install toutatis && toutatis -u target_handle -s <SOCKPUPPET_SESSIONID>`

### [Osintgram](https://github.com/Datalux/Osintgram) `[B-Tier]`
- **ID**: `osintgram` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`Datalux/Osintgram`](https://github.com/Datalux/Osintgram)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `emails`, `geolocation`, `entity_graph`
- **Platforms**: Linux, macOS, Docker, Python · **Tags**: `instagram`, `interactive-shell`, `tagged-users`, `followers`
- **Overview**: Interactive Python shell for analyzing target Instagram accounts—collecting commenter emails, tagged users, photo captions, hashtags, follower overlap, and location pins.
- **Quick-Start / Tradecraft**: `Use strictly with a aged burner Instagram session to prevent automated anti-bot account locks.`

### [Sterra (Instagram Follower Graph Exporter)](https://github.com/novitae/sterraxcyl) `[B-Tier]`
- **ID**: `sterra` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`novitae/sterraxcyl`](https://github.com/novitae/sterraxcyl)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `entity_graph`
- **Platforms**: Linux, macOS, Python · **Tags**: `mutual-followers`, `instagram-graph`, `sockpuppet-careful`, `csv-export`
- **Overview**: SOCMINT Python CLI exporting Instagram followers/following lists, intersecting mutual connections across multiple suspect accounts, and dumping CSV/Excel tables.
- **Quick-Start / Tradecraft**: `sterra -u target_handle --mutuals  # Run slowly from an aged burner session`

---

## Reddit & Forum Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**PullPush Reddit Archive**](https://search.pullpush.io/) | Search Engine | Free | 🟢 Passive | ✅ | `username, keyword, url` → `social_profiles, archived_pages` |
| **A** | [**Arctic Shift (Reddit Archive & Dumps)**](https://arctic-shift.photon-reddit.com/) ([GitHub](https://github.com/ArthurHeitmann/arctic_shift)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `username, keyword` → `social_profiles, archived_pages` |
| **A** | [**RedditMetis**](https://redditmetis.com/) | Web Platform | Free | 🟢 Passive | ✅ | `username` → `social_profiles, person_records, metadata` |
| **B** | [**4plebs Archive**](https://archive.4plebs.org/) | Search Engine | Free | 🟢 Passive | ✅ | `keyword, image, file_hash` → `archived_pages, urls` |
| **B** | [**Redective (Reddit Account Detective)**](https://www.redective.com/) | Web Platform | Free | 🟢 Passive | ✅ | `username` → `social_profiles, metadata` |

### [PullPush Reddit Archive](https://search.pullpush.io/) `[S-Tier]`
- **ID**: `pullpush` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `keyword`, `url` → **Outputs**: `social_profiles`, `archived_pages`
- **Platforms**: Web, Python · **Tags**: `reddit-osint`, `deleted-comments`, `pushshift-replacement`, `free-api`, `flagship`
- **Overview**: Community-operated Pushshift API drop-in replacement enabling keyword, subreddit, author, and date-range searches across historical, user-deleted, and moderator-removed Reddit posts and comments.
- **Quick-Start / Tradecraft**: `curl -s 'https://api.pullpush.io/reddit/search/comment/?author=spez&size=10' | jq`

### [Arctic Shift (Reddit Archive & Dumps)](https://arctic-shift.photon-reddit.com/) `[A-Tier]`
- **ID**: `arctic-shift` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ArthurHeitmann/arctic_shift`](https://github.com/ArthurHeitmann/arctic_shift)
- **Inputs**: `username`, `keyword` → **Outputs**: `social_profiles`, `archived_pages`
- **Platforms**: Web, Python · **Tags**: `reddit-archive`, `researcher-datasets`, `subreddit-exports`, `open-source`
- **Overview**: Researcher-grade Reddit archival search portal and monthly `.zst` torrent dataset project preserving billions of historical Reddit submissions and comments.
- **Quick-Start / Tradecraft**: `Use Arctic Shift's web search tool at https://arctic-shift.photon-reddit.com/search/ to export full user/subreddit histories.`

### [RedditMetis](https://redditmetis.com/) `[A-Tier]`
- **ID**: `redditmetis` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `person_records`, `metadata`
- **Platforms**: Web · **Tags**: `reddit-profiler`, `timezone-heatmap`, `stylometry`, `self-disclosures`
- **Overview**: Behavioral and linguistic profiler for Reddit accounts—calculating active-hour heatmaps (timezone inference), subreddit topic clusters, self-disclosed biographical statements, and vocabulary metrics.
- **Quick-Start / Tradecraft**: `Analyze `https://redditmetis.com/user/<username>` to infer sleep schedule timezone, profession, and city mentions.`

### [4plebs Archive](https://archive.4plebs.org/) `[B-Tier]`
- **ID**: `4plebs` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `image`, `file_hash` → **Outputs**: `archived_pages`, `urls`
- **Platforms**: Web · **Tags**: `4chan-archive`, `imageboards`, `md5-image-pivot`, `extremism-research`
- **Overview**: Searchable permanent archive of ephemeral 4chan imageboard boards (`/pol/`, `/tg/`, `/x/`, `/adv/`, `/hr/`, `/s4s/`), supporting full-text, tripcode, post ID, and image MD5 hash lookups.
- **Quick-Start / Tradecraft**: `Search image MD5 hashes on https://archive.4plebs.org/ to trace viral memes or leaked photos back to first post.`

### [Redective (Reddit Account Detective)](https://www.redective.com/) `[B-Tier]`
- **ID**: `redective` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `reddit-analytics`, `activity-hours`, `subreddit-footprint`
- **Overview**: Interactive Reddit profile analyzer charting word frequencies, active posting hours/days, top subreddits, and searchable comment tables.
- **Quick-Start / Tradecraft**: `Cross-compare Redective and RedditMetis charts for any target Reddit account.`

---

## Location & Fitness App OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Snapchat Snap Map**](https://map.snapchat.com/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `geolocation, urls` |
| **S** | [**Strava Global Heatmap**](https://www.strava.com/maps/global-heatmap) | Web Platform | Freemium | 🟢 Passive | 🔑 | `coordinates` → `geolocation` |

### [Snapchat Snap Map](https://map.snapchat.com/) `[S-Tier]`
- **ID**: `snap-map` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `urls`
- **Platforms**: Web · **Tags**: `breaking-news`, `geotagged-video`, `crisis-monitoring`, `no-login`
- **Overview**: Public web map surfacing real-time, geotagged vertical eyewitness videos uploaded to Snapchat's public 'Spotlight / Snap Map' layer during breaking events, protests, fires, and emergencies.
- **Quick-Start / Tradecraft**: `Open https://map.snapchat.com/ in any browser (no Snapchat account needed) and click blue/red heat clusters at incident coordinates.`

### [Strava Global Heatmap](https://www.strava.com/maps/global-heatmap) `[S-Tier]`
- **ID**: `strava-heatmap` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `gps-tracks`, `fitness-osint`, `patrol-routes`, `geoint-socmint`, `flagship`
- **Overview**: Global GPS activity heatmap aggregating billions of public running, cycling, patrol, and maritime/skiing GPS tracks—famous for revealing unmapped trails, compounds, and patrol perimeters.
- **Quick-Start / Tradecraft**: `Inspect remote facilities or trails on https://www.strava.com/maps/global-heatmap toggled by Sport Type (Run vs Ride vs Water).`

---

## X (Twitter) & Bluesky OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**X (Twitter) Native Advanced Search & Geocode**](https://x.com/search-advanced) | Search Engine | Free | 🟢 Passive | 🔑 | `username, keyword, coordinates` → `social_profiles, geolocation, urls` |
| **A** | [**ClearSky (Bluesky OSINT)**](https://clearsky.services/) | Web Platform | Free | 🟢 Passive | ✅ | `username, domain` → `social_profiles, metadata, entity_graph` |
| **A** | [**Xquik**](https://github.com/Xquik-dev/x-twitter-scraper) ([GitHub](https://github.com/Xquik-dev/x-twitter-scraper)) | CLI | Freemium | 🟢 Passive | 🔑 | `username, keyword` → `social_profiles, entity_graph, archived_pages` |

### [X (Twitter) Native Advanced Search & Geocode](https://x.com/search-advanced) `[S-Tier]`
- **ID**: `x-advanced-search` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `username`, `keyword`, `coordinates`, `url` → **Outputs**: `social_profiles`, `geolocation`, `urls`
- **Platforms**: Web · **Tags**: `twitter-operators`, `geocode-search`, `utc-timestamps`, `eyewitness-osint`
- **Overview**: Native Boolean operator engine supporting `from:`, `to:`, `since:YYYY-MM-DD_HH:MM:SS_UTC`, `until:`, `geocode:lat,lon,radius`, `url:`, `min_faves:`, and conversation thread reconstruction.
- **Quick-Start / Tradecraft**: `Search `geocode:48.8566,2.3522,2km since:2026-05-01_12:00:00_UTC until:2026-05-01_15:00:00_UTC` inside a logged-in sock puppet.`

### [ClearSky (Bluesky OSINT)](https://clearsky.services/) `[A-Tier]`
- **ID**: `clearsky` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `domain` → **Outputs**: `social_profiles`, `metadata`, `entity_graph`
- **Platforms**: Web · **Tags**: `bluesky`, `atproto`, `did-plc`, `handle-history`
- **Overview**: Real-time AT Protocol / Bluesky intelligence dashboard revealing immutable DID (`did:plc:...`) identifiers, handle change history, blocklists, moderation lists, and PDS server hosts.
- **Quick-Start / Tradecraft**: `Look up any `@user.bsky.social` or custom-domain handle on https://clearsky.services/ to view permanent DID and past handles.`

### [Xquik](https://github.com/Xquik-dev/x-twitter-scraper) `[A-Tier]`
- **ID**: `xquik` · **Type**: `CLI` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`Xquik-dev/x-twitter-scraper`](https://github.com/Xquik-dev/x-twitter-scraper)
- **Inputs**: `username`, `keyword` → **Outputs**: `social_profiles`, `entity_graph`, `archived_pages`
- **Platforms**: Linux, macOS, Node.js, Python, Web · **Tags**: `twitter-osint`, `x-search`, `follower-graph`, `mcp`
- **Overview**: Modern X/Twitter OSINT toolkit and MCP server supporting public post search, account triage, follower/following graph export, watchlist monitoring, and media preservation.
- **Quick-Start / Tradecraft**: `Use Xquik or native X Advanced Search (`from:user since:2025-01-01 until:2025-02-01 geocode:lat,lon,5km`).`

---

## LinkedIn & Corporate SOCMINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**LinkdTime (LinkedIn Post Timestamp Extractor)**](https://ollie-boyd.github.io/LinkdTime/) ([GitHub](https://github.com/Ollie-Boyd/LinkdTime)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `url` → `metadata` |

### [LinkdTime (LinkedIn Post Timestamp Extractor)](https://ollie-boyd.github.io/LinkdTime/) `[A-Tier]`
- **ID**: `linkdtime` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Ollie-Boyd/LinkdTime`](https://github.com/Ollie-Boyd/LinkdTime)
- **Inputs**: `url` → **Outputs**: `metadata`
- **Platforms**: Web · **Tags**: `linkedin-osint`, `exact-timestamp`, `chronolocation`, `activity-id`
- **Overview**: Extracts the exact UTC second a LinkedIn post or comment was published from its 19-digit activity URL ID—overcoming LinkedIn's vague '2w' or '3mo' relative UI labels.
- **Quick-Start / Tradecraft**: `Copy any LinkedIn post link (`.../activity-7182...`) into https://ollie-boyd.github.io/LinkdTime/ for exact UTC creation second.`

---

## TikTok OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**TikTok Timestamp & Snowflake Decoder**](https://dfir.blog/tinkering-with-tiktok-timestamps/) ([GitHub](https://github.com/bellingcat/tiktok-hashtag-analysis)) | CLI | OSS / Free | 🟢 Passive | ✅ | `url, keyword` → `metadata, social_profiles` |

### [TikTok Timestamp & Snowflake Decoder](https://dfir.blog/tinkering-with-tiktok-timestamps/) `[A-Tier]`
- **ID**: `bellingcat-tiktok-timestamp` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`bellingcat/tiktok-hashtag-analysis`](https://github.com/bellingcat/tiktok-hashtag-analysis)
- **Inputs**: `url`, `keyword` → **Outputs**: `metadata`, `social_profiles`
- **Platforms**: Web, Linux, macOS, Python · **Tags**: `tiktok-osint`, `binary-timestamp`, `bellingcat`, `hashtag-networks`
- **Overview**: Extracts exact down-to-the-second UTC creation timestamps encoded in the top 32 bits of 64-bit TikTok video IDs, paired with Bellingcat's TikTok Hashtag Analysis CLI.
- **Quick-Start / Tradecraft**: `python3 -c "vid=7345123456789012345; import datetime; print(datetime.datetime.fromtimestamp(vid>>32, datetime.timezone.utc))"`

---

## Regional Social Networks (VK / OK / Weibo)

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**VK.watch & FindClone / VK OSINT Operators**](https://vk.com/) | Search Engine | Free | 🟢 Passive | 🔑 | `coordinates, person_name, username` → `social_profiles, geolocation, person_records` |

### [VK.watch & FindClone / VK OSINT Operators](https://vk.com/) `[A-Tier]`
- **ID**: `vk-barkov-watch` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `coordinates`, `person_name`, `username`, `keyword` → **Outputs**: `social_profiles`, `geolocation`, `person_records`
- **Platforms**: Web · **Tags**: `vkontakte`, `geotagged-photos`, `radius-search`, `eurasia-osint`
- **Overview**: VKontakte native geolocation photo search (`vk.com/feed?section=search` map pin radius!) and archive profilers—unmatched for Eastern European, Russian, and Central Asian ground-level photo discovery.
- **Quick-Start / Tradecraft**: `Use VK's photo location map picker (100m–5km radius around coordinates) from an isolated burner VK session to surface local geotagged photos!`

---

## Decentralized Social OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Fediverse / Mastodon WebFinger & API Lookup**](https://instances.social/) | API / Service | Free | 🟢 Passive | ✅ | `username, email, url` → `social_profiles, metadata` |

### [Fediverse / Mastodon WebFinger & API Lookup](https://instances.social/) `[B-Tier]`
- **ID**: `mastodon-fediverse-search` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `email`, `url` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web, CLI · **Tags**: `activitypub`, `webfinger`, `mastodon`, `keyless-json`
- **Overview**: Queries RFC 7033 WebFinger (`/.well-known/webfinger?resource=acct:user@instance`) and public ActivityPub JSON actors (`https://mastodon.social/@user.json`) with zero authentication!
- **Quick-Start / Tradecraft**: `curl -s 'https://mastodon.social/@gargron.json' | jq '{id, published, summary, attachment}'  # Exact join timestamp + verified rel=me links!`

---

## Cross-Platform Social Search

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**Social Blade**](https://socialblade.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `username` → `social_profiles, metadata` |
| **B** | [**Social Searcher**](https://www.social-searcher.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `keyword, username, person_name` → `social_profiles, urls` |

### [Social Blade](https://socialblade.com/) `[B-Tier]`
- **ID**: `social-blade` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `follower-buying-detection`, `mass-deletions`, `channel-history`
- **Overview**: Tracks longitudinal subscriber/follower deltas, mass post-deletion drops, and engagement anomalies across YouTube, Twitch, Instagram, TikTok, X, and Facebook.
- **Quick-Start / Tradecraft**: `Check abrupt negative video-view spikes on Social Blade to spot channels that scrubbed incriminating uploads.`

### [Social Searcher](https://www.social-searcher.com/) `[B-Tier]`
- **ID**: `social-searcher` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `username`, `person_name` → **Outputs**: `social_profiles`, `urls`
- **Platforms**: Web · **Tags**: `multi-network`, `hashtag-monitoring`, `real-time-mentions`
- **Overview**: Real-time multi-network social search engine querying public mentions, hashtags, and sentiment across X, Facebook, YouTube, Instagram, Tumblr, Reddit, Flickr, Dailymotion, and VKontakte.
- **Quick-Start / Tradecraft**: `Run keyword/brand sweeps across 10+ networks simultaneously at https://www.social-searcher.com/.`

---

## Media & Profile Archivers

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**gallery-dl**](https://github.com/mikf/gallery-dl) ([GitHub](https://github.com/mikf/gallery-dl)) | CLI | OSS / Free | 🔴 Active | ✅ | `url, username` → `archived_pages, metadata, urls` |

### [gallery-dl](https://github.com/mikf/gallery-dl) `[S-Tier]`
- **ID**: `gallery-dl` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`mikf/gallery-dl`](https://github.com/mikf/gallery-dl)
- **Inputs**: `url`, `username` → **Outputs**: `archived_pages`, `metadata`, `urls`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `media-preservation`, `socmint`, `json-metadata`, `active`
- **Overview**: Command-line active media and JSON metadata downloader supporting 300+ imageboards, social platforms, Bluesky, Reddit, Mastodon, Flickr, and Tumblr.
- **Quick-Start / Tradecraft**: `gallery-dl --write-metadata https://bsky.app/profile/example.bsky.social`

---

## X / Twitter OSINT

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**twscrape**](https://github.com/vladkens/twscrape) ([GitHub](https://github.com/vladkens/twscrape)) | CLI | OSS / Free | 🔴 Active | 🔑 | `username, keyword, url` → `social_profiles, usernames, urls` |

### [twscrape](https://github.com/vladkens/twscrape) `[A-Tier]`
- **ID**: `twscrape` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: Required (Account / API Key) · **GitHub**: [`vladkens/twscrape`](https://github.com/vladkens/twscrape)
- **Inputs**: `username`, `keyword`, `url` → **Outputs**: `social_profiles`, `usernames`, `urls`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `twitter`, `x-osint`, `graphql-scraper`, `active`
- **Overview**: Async Python X/Twitter GraphQL API scraper rotating authenticated session pools to collect timelines, followers, search operators, and user IDs.
- **Quick-Start / Tradecraft**: `twscrape user_tweets elonmusk --limit 50`

---

## Fediverse & Decentralized Social

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**ATProto SDK & CLI (Bluesky)**](https://github.com/MarshalX/atproto) ([GitHub](https://github.com/MarshalX/atproto)) | Library | OSS / Free | 🟡 Hybrid | ✅ | `username, domain, keyword` → `social_profiles, dns_records, entity_graph` |

### [ATProto SDK & CLI (Bluesky)](https://github.com/MarshalX/atproto) `[A-Tier]`
- **ID**: `atproto-sdk` · **Type**: `Library` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`MarshalX/atproto`](https://github.com/MarshalX/atproto)
- **Inputs**: `username`, `domain`, `keyword` → **Outputs**: `social_profiles`, `dns_records`, `entity_graph`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `bluesky`, `atproto`, `did-plc`, `firehose`, `socmint`
- **Overview**: Python AT Protocol SDK and CLI querying Bluesky DID documents, PLC audit logs, live Jetstream/Firehose feeds, and social graphs.
- **Quick-Start / Tradecraft**: `pip install atproto && atproto-cli`

---
[⬅️ Back to Master Index](../README.md) · [◀ 📡 Cyberspace & Network Search](./08-network-ip-iot-search.md) · [💻 Code, Secrets & Cloud OSINT ▶](./10-code-cloud-dev-osint.md)

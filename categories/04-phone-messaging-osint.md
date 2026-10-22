[⬅️ Back to Master Index](../README.md) · [◀ 📧 Email Intelligence](./03-email-intelligence.md) · [🪪 People & Public Records ▶](./05-people-public-records.md)

# 📱 04. Phone Number, Carrier & Messaging App Intelligence (Telegram, Discord, WhatsApp) (`PHONEINT`)

> **Scope**: HLR/CNAM/carrier lookup frameworks, phone-to-account enumerators, and deep intelligence toolkits for Telegram channels/groups, Discord snowflake IDs/servers, and WhatsApp profiles.
>
> **OPSEC Advisory**: Syncing a target phone number in messaging apps via an investigator phone can expose your sock-puppet contact card if mutual-contact settings are misconfigured. Disable contact sync or use isolated virtual Android environments.

**Discipline Telemetry**: `26` Verified Tools · `7` S-Tier Flagships · `24` Passive · `20` Free/Open-Source

## Subcategories
- [Phone Number Recon](#phone-number-recon) (7)
- [Phone-to-Account Enumerators](#phone-to-account-enumerators) (1)
- [Telegram Intelligence](#telegram-intelligence) (11)
- [Discord Intelligence](#discord-intelligence) (3)
- [Caller ID & Crowdsourced Directories](#caller-id-crowdsourced-directories) (2)
- [WhatsApp Intelligence](#whatsapp-intelligence) (1)
- [VoIP & SIP Active Recon](#voip-sip-active-recon) (1)

---

## Phone Number Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Google libphonenumber Demo**](https://libphonenumber.appspot.com/) ([GitHub](https://github.com/google/libphonenumber)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `phone` → `phones, geolocation` |
| **S** | [**PhoneInfoga**](https://github.com/sundowndev/phoneinfoga) ([GitHub](https://github.com/sundowndev/phoneinfoga)) | CLI | OSS / Free | 🟢 Passive | ✅ | `phone` → `phones, geolocation, social_profiles` |
| **A** | [**FreeCarrierLookup**](https://freecarrierlookup.com/) | Web Platform | Free | 🟢 Passive | ✅ | `phone` → `phones` |
| **A** | [**Twilio Lookup v2**](https://www.twilio.com/docs/lookup/v2-api) | API / Service | Paid | 🟢 Passive | 🔑 | `phone` → `phones, person_records` |
| **B** | [**ITU National Numbering Plans**](https://www.itu.int/oth/T0202.aspx?parent=T0202) | Dataset / Registry | Free | 🟢 Passive | ✅ | `phone` → `phones, geolocation` |
| **B** | [**Numverify API**](https://numverify.com/) | API / Service | Freemium | 🟢 Passive | 🔑 | `phone` → `phones, geolocation` |
| **B** | [**SearchPhone**](https://github.com/HackUnderway/SearchPhone) ([GitHub](https://github.com/HackUnderway/SearchPhone)) | CLI | OSS / Free | 🟢 Passive | ✅ | `phone` → `phones, breach_records, social_profiles` |

### [Google libphonenumber Demo](https://libphonenumber.appspot.com/) `[S-Tier]`
- **ID**: `libphonenumber` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`google/libphonenumber`](https://github.com/google/libphonenumber)
- **Inputs**: `phone` → **Outputs**: `phones`, `geolocation`
- **Platforms**: Web, Python, Node.js · **Tags**: `validation`, `voip-detection`, `carrier`, `timezone`, `google`
- **Overview**: Google's canonical international telephone number parser validating number structure, line type (Fixed-Line, Mobile, VoIP, Toll-Free, Pager), original carrier allocation, and geographic timezone.
- **Quick-Start / Tradecraft**: `Enter any international number at https://libphonenumber.appspot.com/ before spending paid HLR/CNAM credits.`

### [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) `[S-Tier]`
- **ID**: `phoneinfoga` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`sundowndev/phoneinfoga`](https://github.com/sundowndev/phoneinfoga)
- **Inputs**: `phone` → **Outputs**: `phones`, `geolocation`, `social_profiles`
- **Platforms**: Linux, macOS, Windows, Docker, Go, Web · **Tags**: `phone-osint`, `e164`, `carrier-lookup`, `dorking`, `flagship`
- **Overview**: Leading open-source Go framework for international phone number reconnaissance—extracting E.164 country/carrier metadata, OVH/Numverify line types, and automated Google dork footprints across social/classified sites.
- **Quick-Start / Tradecraft**: `phoneinfoga scan -n "+14155552671"  # Or launch web UI: phoneinfoga serve -p 8080`

### [FreeCarrierLookup](https://freecarrierlookup.com/) `[A-Tier]`
- **ID**: `freecarrierlookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `phone` → **Outputs**: `phones`
- **Platforms**: Web · **Tags**: `ported-carrier`, `bandwidth-voip`, `nanpa`, `us-canada`
- **Overview**: Quick US/Canadian NPAC-ported carrier and wireless-vs-landline/VoIP checker revealing email-to-SMS/MMS gateway domains (e.g., `vtext.com`, `txt.att.net`, `Bandwidth.com`).
- **Quick-Start / Tradecraft**: `If FreeCarrierLookup returns `Bandwidth.com`, `Sinclair`, or `Twilio`, the target number is almost certainly a burner VoIP/Google Voice line!`

### [Twilio Lookup v2](https://www.twilio.com/docs/lookup/v2-api) `[A-Tier]`
- **ID**: `twilio-lookup` · **Type**: `API / Service` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `phone` → **Outputs**: `phones`, `person_records`
- **Platforms**: Web, Python, Node.js · **Tags**: `cnam`, `hlr-lookup`, `voip-detection`, `telecom-grade`
- **Overview**: Authoritative telecom API offering Line Type Intelligence (mobile, landline, non-fixed VoIP), Caller Name (US CNAM), SIM-swap indicators, and live HLR mobile network codes.
- **Quick-Start / Tradecraft**: `twilio api:lookups:v2:phone-numbers:fetch --phone-number '+14155552671' --fields caller_name,line_type_intelligence`

### [ITU National Numbering Plans](https://www.itu.int/oth/T0202.aspx?parent=T0202) `[B-Tier]`
- **ID**: `itu-national-numbering` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `phone` → **Outputs**: `phones`, `geolocation`
- **Platforms**: Web · **Tags**: `itu`, `international-prefixes`, `telecom-allocations`, `official-data`
- **Overview**: Authoritative International Telecommunication Union allocation tables documenting mobile operator prefixes, geographic area codes, and special-service ranges for every country.
- **Quick-Start / Tradecraft**: `Verify obscure international NDC/operator mobile block allocations directly from official ITU regulatory filings.`

### [Numverify API](https://numverify.com/) `[B-Tier]`
- **ID**: `numverify` · **Type**: `API / Service` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `phone` → **Outputs**: `phones`, `geolocation`
- **Platforms**: Web · **Tags**: `carrier-api`, `line-type`, `international-phones`
- **Overview**: Global phone validation and carrier-lookup REST API covering 232 countries, returning real-time carrier name, location, and mobile vs. VoIP/landline classification.
- **Quick-Start / Tradecraft**: `Integrate free-tier API key into PhoneInfoga or query `/api/validate?number=...` directly.`

### [SearchPhone](https://github.com/HackUnderway/SearchPhone) `[B-Tier]`
- **ID**: `searchphone` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`HackUnderway/SearchPhone`](https://github.com/HackUnderway/SearchPhone)
- **Inputs**: `phone` → **Outputs**: `phones`, `breach_records`, `social_profiles`
- **Platforms**: Linux, macOS, Python · **Tags**: `phone-toolkit`, `hudson-rock`, `multi-api`, `report-generator`
- **Overview**: Multi-API phone OSINT toolkit combining Numverify, Google/DuckDuckGo/Reddit/GitHub dorking, and Hudson Rock infostealer phone checks with automated HTML/JSON dossier generation.
- **Quick-Start / Tradecraft**: `python3 searchphone.py +14155552671`

---

## Phone-to-Account Enumerators

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Ignorant**](https://github.com/megadose/ignorant) ([GitHub](https://github.com/megadose/ignorant)) | CLI | OSS / Free | 🟢 Passive | ✅ | `phone` → `social_profiles` |

### [Ignorant](https://github.com/megadose/ignorant) `[S-Tier]`
- **ID**: `ignorant` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`megadose/ignorant`](https://github.com/megadose/ignorant)
- **Inputs**: `phone` → **Outputs**: `social_profiles`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `phone-to-account`, `silent-check`, `instagram`, `snapchat`, `megadose`
- **Overview**: From the creator of Holehe: silently checks whether a target phone number (country code + subscriber digits) is registered on Instagram, Snapchat, Amazon, and other major platforms.
- **Quick-Start / Tradecraft**: `pipx install ignorant && ignorant 1 4155552671`

---

## Telegram Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Telegram Native Public Preview (`t.me/s/`)**](https://telegram.org/) | Web Platform | Free | 🟢 Passive | ✅ | `username, url` → `social_profiles, archived_pages, metadata` |
| **S** | [**Telepathy**](https://github.com/prose-intelligence-ltd/Telepathy-Community) ([GitHub](https://github.com/prose-intelligence-ltd/Telepathy-Community)) | CLI | OSS / Free | 🟢 Passive | 🔑 | `username, url` → `social_profiles, entity_graph, archived_pages` |
| **S** | [**TGStat**](https://tgstat.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `keyword, username, url` → `social_profiles, entity_graph, metadata` |
| **A** | [**Telegago (Official Google CSE)**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) | Search Engine | Free | 🟢 Passive | ✅ | `keyword, username` → `social_profiles, urls` |
| **A** | [**TelegramDB**](https://www.telegramdb.org/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `username, keyword` → `social_profiles, entity_graph` |
| **A** | [**Telemetr.io**](https://telemetr.io/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `keyword, username` → `social_profiles, metadata, entity_graph` |
| **A** | [**Telethon**](https://github.com/LonamiWebs/Telethon) ([GitHub](https://github.com/LonamiWebs/Telethon)) | Library | OSS / Free | 🟢 Passive | 🔑 | `username, phone, keyword` → `social_profiles, archived_pages, metadata` |
| **A** | [**Tosint**](https://github.com/drego85/tosint) ([GitHub](https://github.com/drego85/tosint)) | CLI | OSS / Free | 🔴 Active | ✅ | `keyword, username` → `social_profiles, metadata` |
| **B** | [**Awesome Telegram OSINT Toolkit Index**](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) ([GitHub](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `keyword, username` → `social_profiles` |
| **B** | [**Lyzem**](https://lyzem.com/) | Search Engine | Free | 🟢 Passive | ✅ | `keyword` → `social_profiles, archived_pages` |
| **B** | [**TGScope**](https://tgscope.com/) | Search Engine | Free | 🟢 Passive | ✅ | `keyword, username, url` → `social_profiles, metadata` |

### [Telegram Native Public Preview (`t.me/s/`)](https://telegram.org/) `[S-Tier]`
- **ID**: `telegram-web-preview` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `url` → **Outputs**: `social_profiles`, `archived_pages`, `metadata`
- **Platforms**: Web · **Tags**: `zero-login-telegram`, `passive-preview`, `pagination-scraping`, `opsec-safe`
- **Overview**: Built-in unauthenticated clearnet web preview (`https://t.me/s/<channel_username>?before=<msg_id>`) allowing complete passive scraping and SingleFile archiving of public channels without a Telegram account!
- **Quick-Start / Tradecraft**: `Insert `/s/` into any public `https://t.me/<channel>` URL (`https://t.me/s/<channel>`) to browse & archive posts with zero Telegram login!`

### [Telepathy](https://github.com/prose-intelligence-ltd/Telepathy-Community) `[S-Tier]`
- **ID**: `telepathy` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`prose-intelligence-ltd/Telepathy-Community`](https://github.com/prose-intelligence-ltd/Telepathy-Community)
- **Inputs**: `username`, `url` → **Outputs**: `social_profiles`, `entity_graph`, `archived_pages`, `metadata`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `telegram-archiver`, `forward-network`, `gephi`, `member-export`
- **Overview**: Open-source Python Telegram OSINT CLI archiving full channel histories, media, member lists, top-poster statistics, user IDs, and Gephi-ready message-forwarding edge lists.
- **Quick-Start / Tradecraft**: `pip install telepathy && telepathy -t target_channel -c -f -m  # Use a burner Telegram API key`

### [TGStat](https://tgstat.com/) `[S-Tier]`
- **ID**: `tgstat` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `username`, `url` → **Outputs**: `social_profiles`, `entity_graph`, `metadata`
- **Platforms**: Web · **Tags**: `telegram`, `channel-search`, `citation-graph`, `2.8m-channels`, `flagship`
- **Overview**: Largest public Telegram analytics and discovery engine indexing 2.8M+ channels and groups by keyword, language, country, citation graph, subscriber history, and cross-channel reposts.
- **Quick-Start / Tradecraft**: `Search keywords or channel handles on https://tgstat.com/search before ever opening the Telegram client.`

### [Telegago (Official Google CSE)](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) `[A-Tier]`
- **ID**: `telegago-cse` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `username` → **Outputs**: `social_profiles`, `urls`
- **Platforms**: Web · **Tags**: `telegram-cse`, `invite-links`, `passive-search`, `no-login`
- **Overview**: Custom Google Programmable Search Engine tuned specifically for public Telegram channels, `t.me/s/` post previews, and `joinchat` invite links (use this official `cse.google.com` link only!).
- **Quick-Start / Tradecraft**: `Bookmark the exact `cse.google.com` URL (never visit the hijacked third-party telegago.com domain).`

### [TelegramDB](https://www.telegramdb.org/) `[A-Tier]`
- **ID**: `telegramdb` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `username`, `keyword` → **Outputs**: `social_profiles`, `entity_graph`
- **Platforms**: Web · **Tags**: `telegram`, `group-membership`, `numeric-id`, `channel-directory`
- **Overview**: Searchable database of public Telegram groups, supergroups, channels, and numeric user-to-group memberships accessible via web overview and bot commands.
- **Quick-Start / Tradecraft**: `Use numeric Telegram user IDs (never changeable even when `@username` changes) to pivot group memberships.`

### [Telemetr.io](https://telemetr.io/) `[A-Tier]`
- **ID**: `telemetr-io` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword`, `username` → **Outputs**: `social_profiles`, `metadata`, `entity_graph`
- **Platforms**: Web · **Tags**: `telegram-search`, `audience-overlap`, `channel-analytics`
- **Overview**: Global Telegram channel directory and full-text post search engine tracking audience overlap, channel mentions, country classifications, and historical deleted/edited post analytics.
- **Quick-Start / Tradecraft**: `Query channel topics, countries, and post keywords passively at https://telemetr.io/.`

### [Telethon](https://github.com/LonamiWebs/Telethon) `[A-Tier]`
- **ID**: `telethon` · **Type**: `Library` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`LonamiWebs/Telethon`](https://github.com/LonamiWebs/Telethon)
- **Inputs**: `username`, `phone`, `keyword` → **Outputs**: `social_profiles`, `archived_pages`, `metadata`
- **Platforms**: Linux, macOS, Windows, Python · **Tags**: `mtproto`, `telegram-api`, `python-sdk`, `custom-scrapers`
- **Overview**: Actively maintained asynchronous Python 3 MTProto client library for the Telegram API—the standard foundation for custom Telegram OSINT scrapers, channel monitors, and ID resolvers.
- **Quick-Start / Tradecraft**: `pip install telethon  # Authenticate inside an isolated sock-puppet session`

### [Tosint](https://github.com/drego85/tosint) `[A-Tier]`
- **ID**: `tosint` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`drego85/tosint`](https://github.com/drego85/tosint)
- **Inputs**: `keyword`, `username` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Linux, macOS, Python · **Tags**: `telegram-bot`, `phishing-triage`, `infostealer-c2`, `bot-token`
- **Overview**: Investigates exposed Telegram Bot API tokens (`bot<id>:<token>`) found in phishing kits, infostealer malware, or leaked repos—revealing bot handle, owner chat ID, group memberships, and permissions.
- **Quick-Start / Tradecraft**: `python3 tosint.py -t '<BOT_TOKEN>' -c '<CHAT_ID>'  # Read-only getMe/getChat inspection`

### [Awesome Telegram OSINT Toolkit Index](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT) `[B-Tier]`
- **ID**: `awesome-telegram-osint` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ItIsMeCall911/Awesome-Telegram-OSINT`](https://github.com/ItIsMeCall911/Awesome-Telegram-OSINT)
- **Inputs**: `keyword`, `username` → **Outputs**: `social_profiles`
- **Platforms**: Web · **Tags**: `telegram-tradecraft`, `reference`, `channel-catalogues`
- **Overview**: Community-maintained encyclopedia of Telegram OSINT tradecraft, numeric-ID tricks, group catalog search engines, archive scripts, and OPSEC pitfalls.
- **Quick-Start / Tradecraft**: `Consult before running Telegram investigations to check current working web mirrors and MTProto changes.`

### [Lyzem](https://lyzem.com/) `[B-Tier]`
- **ID**: `lyzem` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `social_profiles`, `archived_pages`
- **Platforms**: Web · **Tags**: `telegram`, `telegra-ph`, `keyword-search`
- **Overview**: Privacy-friendly web search engine indexing public Telegram channels, groups, bots, and Telegraph (`telegra.ph`) articles by keyword.
- **Quick-Start / Tradecraft**: `Include `telegra.ph` long-form manifestos/guides in keyword searches on https://lyzem.com/.`

### [TGScope](https://tgscope.com/) `[B-Tier]`
- **ID**: `tgscope` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `username`, `url` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `telegram`, `creation-date`, `3m-channels`, `event-tracking`
- **Overview**: Catalog and search engine covering 3M+ public Telegram channels with topic/language filters and a channel/supergroup creation-date estimator from numeric IDs.
- **Quick-Start / Tradecraft**: `Use TGScope's Channel Creation Date lookup to spot newly minted impersonation or scam channels.`

---

## Discord Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**DiscordLookup / Discord.id**](https://discord.id/) | Web Platform | Free | 🟢 Passive | ✅ | `username, keyword` → `social_profiles, metadata` |
| **B** | [**DISBOARD**](https://disboard.org/) | Search Engine | Free | 🟢 Passive | ✅ | `keyword` → `social_profiles` |
| **B** | [**DiscordLeaks (Unicorn Riot)**](https://discordleaks.unicornriot.ninja/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `keyword, username` → `social_profiles, archived_pages, person_records` |

### [DiscordLookup / Discord.id](https://discord.id/) `[A-Tier]`
- **ID**: `discord-lookup` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `username`, `keyword` → **Outputs**: `social_profiles`, `metadata`
- **Platforms**: Web · **Tags**: `discord`, `snowflake-id`, `creation-timestamp`, `avatar-hash`
- **Overview**: Decodes 64-bit Discord Snowflake IDs (users, servers, channels, messages) into exact UTC millisecond creation timestamps, avatar/banner CDN hashes, and public badge flags.
- **Quick-Start / Tradecraft**: `Enable Developer Mode in Discord -> Copy User/Server ID -> decode exact creation millisecond at https://discord.id/.`

### [DISBOARD](https://disboard.org/) `[B-Tier]`
- **ID**: `disboard` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `social_profiles`
- **Platforms**: Web · **Tags**: `discord-servers`, `server-discovery`, `community-index`
- **Overview**: Largest public Discord server directory searchable by tag, language, and member count—useful for discovering community servers linked to niche topics or handles.
- **Quick-Start / Tradecraft**: `Search tags and keywords on https://disboard.org/ and inspect invite JSON via `https://discord.com/api/v10/invites/<code>?with_counts=true`.`

### [DiscordLeaks (Unicorn Riot)](https://discordleaks.unicornriot.ninja/) `[B-Tier]`
- **ID**: `discordleaks` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `username` → **Outputs**: `social_profiles`, `archived_pages`, `person_records`
- **Platforms**: Web · **Tags**: `discord-archive`, `extremism-research`, `journalism`, `chat-logs`
- **Overview**: Journalistic public-interest searchable archive of hundreds of thousands of chat messages from extremist and hate-group Discord servers published by Unicorn Riot.
- **Quick-Start / Tradecraft**: `Search handles, Discord user IDs, or keywords across archived chat servers at https://discordleaks.unicornriot.ninja/.`

---

## Caller ID & Crowdsourced Directories

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Truecaller Web Lookup**](https://www.truecaller.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `phone` → `person_records, phones` |
| **B** | [**SpyDialer**](https://www.spydialer.com/) | Web Platform | Free | 🟢 Passive | ✅ | `phone, person_name, email` → `person_records, phones` |

### [Truecaller Web Lookup](https://www.truecaller.com/) `[A-Tier]`
- **ID**: `truecaller` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `phone` → **Outputs**: `person_records`, `phones`
- **Platforms**: Web · **Tags**: `caller-id`, `cnam`, `crowdsourced`, `mena-asia-latam`
- **Overview**: Global crowdsourced caller-ID directory capable of resolving subscriber display names, business labels, carrier info, and spam tags—particularly strong in South Asia, MENA, Africa, and Latin America.
- **Quick-Start / Tradecraft**: `Sign in ONLY with an isolated sock-puppet account (never sync personal contacts!) on https://www.truecaller.com/.`

### [SpyDialer](https://www.spydialer.com/) `[B-Tier]`
- **ID**: `spydialer` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `phone`, `person_name`, `email` → **Outputs**: `person_records`, `phones`
- **Platforms**: Web · **Tags**: `us-phone`, `reverse-lookup`, `cnam`, `free-lookup`
- **Overview**: Free US reverse phone, name, address, and email lookup tool with public CNAM/directory correlation.
- **Quick-Start / Tradecraft**: `Use Name Lookup mode (passive) at https://www.spydialer.com/; avoid Voicemail mode in covert cases (active call!).`

---

## WhatsApp Intelligence

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **B** | [**WhatsApp Direct & Business Metadata (`wa.me`)**](https://faq.whatsapp.com/) | Web Platform | Free | 🟢 Passive | 🔑 | `phone` → `social_profiles, metadata, geolocation` |

### [WhatsApp Direct & Business Metadata (`wa.me`)](https://faq.whatsapp.com/) `[B-Tier]`
- **ID**: `whatsapp-osint-check` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `phone` → **Outputs**: `social_profiles`, `metadata`, `geolocation`
- **Platforms**: Web · **Tags**: `whatsapp`, `business-profile`, `avatar-extraction`, `phone-pivot`
- **Overview**: WhatsApp Business & profile reconnaissance via `https://wa.me/<E164_digits>` and WhatsApp Web inside an isolated burner environment—revealing profile photos, status timestamps, and Business catalog/addresses.
- **Quick-Start / Tradecraft**: `Check WhatsApp registration first via Epieos, then inspect Business catalog/hours from a dedicated burner number with privacy settings locked.`

---

## VoIP & SIP Active Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**SIPVicious (svmap / svwar)**](https://github.com/EnableSecurity/sipvicious) ([GitHub](https://github.com/EnableSecurity/sipvicious)) | CLI | OSS / Free | 🔴 Active | ✅ | `ip, domain, phone` → `phones, open_ports, tech_stack` |

### [SIPVicious (svmap / svwar)](https://github.com/EnableSecurity/sipvicious) `[S-Tier]`
- **ID**: `sipvicious` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`EnableSecurity/sipvicious`](https://github.com/EnableSecurity/sipvicious)
- **Inputs**: `ip`, `domain`, `phone`, `asn` → **Outputs**: `phones`, `open_ports`, `tech_stack`, `metadata`
- **Platforms**: CLI, Linux, macOS, Python · **Tags**: `voip`, `sip`, `pbx`, `telecom-recon`, `active`
- **Overview**: Industry-standard active VoIP/SIP reconnaissance suite (svmap, svwar, svreport) for discovering SIP PBXs, user-agents, and valid telephone extension lines.
- **Quick-Start / Tradecraft**: `sipvicious_svmap 198.51.100.0/24`

---
[⬅️ Back to Master Index](../README.md) · [◀ 📧 Email Intelligence](./03-email-intelligence.md) · [🪪 People & Public Records ▶](./05-people-public-records.md)

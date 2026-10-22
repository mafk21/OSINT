[⬅️ Back to Master Index](../README.md) · [◀ 🏛️ Corporate, Finance & Sanctions](./14-corporate-financial-sanctions.md) · [🧅 Dark Web & Underground ▶](./16-darkweb-tor-underground.md)

# ⛓️ 15. Cryptocurrency, Blockchain Forensics, DeFi & On-Chain Attribution (`CRYPTOINT`)

> **Scope**: Multi-chain entity attribution platforms, visual transaction flow graphers, UTXO wallet clusterers, AML/OFAC risk screeners, smart-contract/rug analyzers, and ENS/Web3 identity resolvers.
>
> **OPSEC Advisory**: On-chain queries through public explorers are passive, but never connect a personal Web3 wallet (MetaMask/Phantom) to investigation pages or interact with suspect tokens/airdrops.

**Discipline Telemetry**: `27` Verified Tools · `10` S-Tier Flagships · `24` Passive · `17` Free/Open-Source

## Subcategories
- [Attribution & Entity Visualizers](#attribution-entity-visualizers) (3)
- [Scam & Threat Reporting](#scam-threat-reporting) (3)
- [Block Explorers](#block-explorers) (6)
- [Open-Source Chain Analytics](#open-source-chain-analytics) (4)
- [Web3 Identity Resolution](#web3-identity-resolution) (2)
- [DeFi & Insider Supply Visualization](#defi-insider-supply-visualization) (2)
- [AML & Exploit Tracing](#aml-exploit-tracing) (3)
- [Crypto Tradecraft Manuals](#crypto-tradecraft-manuals) (1)
- [Active EVM RPC & Contract Recon](#active-evm-rpc-contract-recon) (3)

---

## Attribution & Entity Visualizers

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Arkham Intelligence**](https://intel.arkm.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `crypto_address, company, person_name` → `tx_graph, entity_graph, person_records` |
| **S** | [**Breadcrumbs.app**](https://www.breadcrumbs.app/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `crypto_address` → `tx_graph, entity_graph` |
| **A** | [**DeBank**](https://debank.com/) | Web Platform | Free | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, social_profiles` |

### [Arkham Intelligence](https://intel.arkm.com/) `[S-Tier]`
- **ID**: `arkham-intelligence` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `crypto_address`, `company`, `person_name`, `username` → **Outputs**: `tx_graph`, `entity_graph`, `person_records`
- **Platforms**: Web · **Tags**: `wallet-attribution`, `300m-labels`, `visualizer`, `multi-chain`, `flagship`
- **Overview**: Leading public blockchain intelligence platform attributing 300M+ multi-chain wallet addresses to real-world exchanges, funds, hackers, and individuals with an interactive fund-flow Visualizer.
- **Quick-Start / Tradecraft**: `Paste any EVM/BTC/SOL/TRON address into https://intel.arkm.com/ and click 'Visualizer' to filter counterparty CEX deposit hops.`

### [Breadcrumbs.app](https://www.breadcrumbs.app/) `[S-Tier]`
- **ID**: `breadcrumbs` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `entity_graph`
- **Platforms**: Web · **Tags**: `fund-tracing`, `visual-flowchart`, `exchange-attribution`, `nft-scams`
- **Overview**: Intuitive visual blockchain investigation workbench mapping multi-hop BTC, ETH, Polygon, Solana, Arbitrum, Base, and TRON fund flows with entity risk tags and shareable case charts.
- **Quick-Start / Tradecraft**: `Use Pathfinder on https://www.breadcrumbs.app/ to auto-discover shortest transaction hops between a suspect wallet and known CEX.`

### [DeBank](https://debank.com/) `[A-Tier]`
- **ID**: `debank` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `social_profiles`
- **Platforms**: Web · **Tags**: `evm-portfolio`, `35-chains`, `defi-positions`, `wallet-profiling`
- **Overview**: Multi-EVM portfolio tracker enumerating every DeFi lending position, LP pool, NFT, social Web3 badge, and chronological activity feed across 35+ EVM chains for any `0x` address.
- **Quick-Start / Tradecraft**: `Open `https://debank.com/profile/<0x_address>` for an instant 35-chain net-worth and protocol interaction snapshot.`

---

## Scam & Threat Reporting

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Chainabuse (by TRM Labs)**](https://www.chainabuse.com/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `crypto_address, domain, url` → `malware_iocs, breach_records` |
| **B** | [**BitcoinAbuse / BitcoinWho'sWho**](https://www.bitcoinwhoswho.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, urls` |
| **B** | [**GoPlus Security & RugCheck.xyz**](https://gopluslabs.io/) ([GitHub](https://github.com/GoPlusSecurity/goplus-sdk-python)) | API / Service | Free | 🟢 Passive | ✅ | `crypto_address, url` → `malware_iocs, tx_graph` |

### [Chainabuse (by TRM Labs)](https://www.chainabuse.com/) `[S-Tier]`
- **ID**: `chainabuse` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address`, `domain`, `url` → **Outputs**: `malware_iocs`, `breach_records`
- **Platforms**: Web · **Tags**: `trm-labs`, `scam-wallets`, `ransomware-addresses`, `victim-reports`, `flagship`
- **Overview**: Free community-driven multi-chain cybercrime reporting database (operated by TRM Labs) indexing hundreds of thousands of victim-reported ransomware, sextortion, drainer, and pig-butchering addresses.
- **Quick-Start / Tradecraft**: `Query suspect wallet addresses or fake exchange domains at https://www.chainabuse.com/ before deep-diving hop graphs.`

### [BitcoinAbuse / BitcoinWho'sWho](https://www.bitcoinwhoswho.com/) `[B-Tier]`
- **ID**: `bitcoinwhoswho` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `urls`
- **Platforms**: Web · **Tags**: `bitcoin-lookup`, `website-appearances`, `scam-tags`
- **Overview**: Searchable directory of public website appearances, forum signatures, scam reports, and user tags tied to Bitcoin addresses.
- **Quick-Start / Tradecraft**: `Check whether a legacy `1...` or `bc1...` BTC address was scraped on clearnet donation or extortion pages.`

### [GoPlus Security & RugCheck.xyz](https://gopluslabs.io/) `[B-Tier]`
- **ID**: `rugcheck-goplus` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`GoPlusSecurity/goplus-sdk-python`](https://github.com/GoPlusSecurity/goplus-sdk-python)
- **Inputs**: `crypto_address`, `url` → **Outputs**: `malware_iocs`, `tx_graph`
- **Platforms**: Web, Python · **Tags**: `honeypot-detector`, `drainer-check`, `solana-rugcheck`, `smart-contract-audit`
- **Overview**: Automated Web3 token, NFT, approval-phishing, and smart-contract honeypot scanner across Solana (`rugcheck.xyz`) and EVM chains (`gopluslabs.io`).
- **Quick-Start / Tradecraft**: `Audit suspect token mints or drainer URLs via GoPlus free security APIs and https://rugcheck.xyz/.`

---

## Block Explorers

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Etherscan**](https://etherscan.io/) | Search Engine | Freemium | 🟢 Passive | ✅ | `crypto_address, keyword` → `tx_graph, metadata` |
| **S** | [**mempool.space**](https://mempool.space/) ([GitHub](https://github.com/mempool/mempool)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `crypto_address, keyword` → `tx_graph, metadata` |
| **S** | [**TRONSCAN**](https://tronscan.org/) | Search Engine | Free | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, sanctions_hits` |
| **A** | [**Blockchair**](https://blockchair.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `crypto_address, keyword` → `tx_graph, metadata` |
| **A** | [**Blockscout**](https://www.blockscout.com/) ([GitHub](https://github.com/blockscout/blockscout)) | Search Engine | OSS / Free | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, metadata` |
| **A** | [**Solscan**](https://solscan.io/) | Search Engine | Freemium | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, metadata` |

### [Etherscan](https://etherscan.io/) `[S-Tier]`
- **ID**: `etherscan` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address`, `keyword` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: Web · **Tags**: `ethereum`, `evm`, `smart-contracts`, `internal-txns`, `flagship`
- **Overview**: Canonical Ethereum explorer providing verified smart-contract Solidity source code, internal EVM call traces, ERC-20/721 transfers, Token Approval checker, public name tags, and comments.
- **Quick-Start / Tradecraft**: `Always check the very FIRST inbound ETH funding transaction of a fresh wallet on Etherscan—it often exposes the owner's CEX or main wallet!`

### [mempool.space](https://mempool.space/) `[S-Tier]`
- **ID**: `mempool-space` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mempool/mempool`](https://github.com/mempool/mempool)
- **Inputs**: `crypto_address`, `keyword` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: Web, Docker, Linux · **Tags**: `bitcoin`, `utxo-graph`, `lightning-network`, `open-source`, `flagship`
- **Overview**: Open-source Bitcoin & Lightning Network explorer featuring interactive UTXO input/output flow diagrams, fee-rate telemetry, mining pool attribution, and self-hostable Tor `.onion` support.
- **Quick-Start / Tradecraft**: `Expand the interactive transaction tree on https://mempool.space/ to spot peel-chain change outputs and CoinJoin rounds.`

### [TRONSCAN](https://tronscan.org/) `[S-Tier]`
- **ID**: `tronscan` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `tron`, `trc20-usdt`, `tether-freezes`, `ransomware-payments`
- **Overview**: Official TRON blockchain explorer—indispensable in modern cybercrime, ransomware, pig-butchering, and sanctions OSINT because `TRC-20 USDT` is a dominant underground settlement rail.
- **Quick-Start / Tradecraft**: `Filter transfers to `USDT` (`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`) and check Tether blacklist freeze events on TRONSCAN.`

### [Blockchair](https://blockchair.com/) `[A-Tier]`
- **ID**: `blockchair` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address`, `keyword` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: Web · **Tags**: `40-blockchains`, `cross-chain-search`, `op-return-text`, `privacy-preserving`
- **Overview**: Privacy-respecting multi-chain SQL-style search engine spanning 40+ blockchains (BTC, ETH, LTC, BCH, DOGE, XMR, ZEC, TON, XRP, ADA, SOL) with PDF transaction receipts and cross-chain address lookup.
- **Quick-Start / Tradecraft**: `Paste any ambiguous string or address into https://blockchair.com/ to check across 40+ chains at once; search `OP_RETURN` ASCII text!`

### [Blockscout](https://www.blockscout.com/) `[A-Tier]`
- **ID**: `blockscout` · **Type**: `Search Engine` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`blockscout/blockscout`](https://github.com/blockscout/blockscout)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: Web, Docker · **Tags**: `open-source-explorer`, `l2-rollups`, `rest-api`, `evm`
- **Overview**: Open-source EVM block explorer powering 1,000+ L1/L2/Rollup networks (Base, Optimism, Gnosis, Rootstock, zkSync) with open REST/GraphQL APIs and smart-contract verification.
- **Quick-Start / Tradecraft**: `Query keyless Blockscout v2 REST APIs (`/api/v2/addresses/<0x>/transactions`) without rate-limited API keys!`

### [Solscan](https://solscan.io/) `[A-Tier]`
- **ID**: `solscan` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: Web · **Tags**: `solana`, `spl-tokens`, `deployer-tracing`, `defi-swaps`
- **Overview**: Leading Solana block explorer parsing SPL token transfers, DeFi swaps, program instructions, fee-payer relationships, and meme-coin deployer funding trees.
- **Quick-Start / Tradecraft**: `Use Solscan's 'SPL Transfers' and 'Defi Activities' tabs + Fee Payer links to connect burner Solana wallets.`

---

## Open-Source Chain Analytics

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GraphSense**](https://graphsense.org/) ([GitHub](https://github.com/graphsense/graphsense-dashboard)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, entity_graph` |
| **A** | [**Dune**](https://dune.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `crypto_address, keyword` → `tx_graph, entity_graph` |
| **B** | [**BitInfoCharts**](https://bitinfocharts.com/) | Web Platform | Free | 🟢 Passive | ✅ | `crypto_address` → `tx_graph` |
| **B** | [**WalletExplorer.com**](https://www.walletexplorer.com/) | Web Platform | Free | 🟢 Passive | ✅ | `crypto_address` → `tx_graph, entity_graph` |

### [GraphSense](https://graphsense.org/) `[S-Tier]`
- **ID**: `graphsense` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`graphsense/graphsense-dashboard`](https://github.com/graphsense/graphsense-dashboard)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `entity_graph`
- **Platforms**: Docker, Linux, Python, Web · **Tags**: `open-source-chainalysis`, `utxo-clustering`, `btc-eth-tron`, `self-hosted`, `flagship`
- **Overview**: Premier open-source, self-hostable cryptoasset analytics platform (AIT / Iknaio) providing UTXO co-spend clustering, account-model tracing, attribution tags, and full data sovereignty across BTC, ETH, LTC, ZEC, and TRON.
- **Quick-Start / Tradecraft**: `Explore docs and GraphSense Maltego transforms at https://graphsense.org/ for reproducible evidentiary crypto graphs.`

### [Dune](https://dune.com/) `[A-Tier]`
- **ID**: `dune-analytics` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `crypto_address`, `keyword` → **Outputs**: `tx_graph`, `entity_graph`
- **Platforms**: Web · **Tags**: `dune-sql`, `blockchain-sql`, `bridge-analytics`, `custom-queries`
- **Overview**: Community SQL analytics engine over decoded tables for Ethereum, Solana, Bitcoin, Base, Arbitrum, and 15+ chains—allowing custom SQL queries over millions of contract events and bridge transfers.
- **Quick-Start / Tradecraft**: `Write custom Trino/DuneSQL queries over `ethereum.transactions` or fork community exploit-tracker dashboards.`

### [BitInfoCharts](https://bitinfocharts.com/) `[B-Tier]`
- **ID**: `bitinfocharts` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`
- **Platforms**: Web · **Tags**: `whale-wallets`, `utxo-clusters`, `dormant-btc`, `cold-wallets`
- **Overview**: Tracks multi-year UTXO rich-lists, dormant whale wallet awakenings, exchange cold-wallet clusters, and historical USD balance charts across BTC, LTC, BCH, DOGE, and DASH.
- **Quick-Start / Tradecraft**: `Check whether a large BTC address belongs to a known exchange cold-storage cluster on https://bitinfocharts.com/.`

### [WalletExplorer.com](https://www.walletexplorer.com/) `[B-Tier]`
- **ID**: `walletexplorer` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `entity_graph`
- **Platforms**: Web · **Tags**: `bitcoin-clustering`, `co-spend-heuristic`, `wallet-grouping`
- **Overview**: Classic automatic Bitcoin common-input-ownership (co-spend) heuristic explorer grouping separate BTC addresses controlled by the same underlying wallet cluster.
- **Quick-Start / Tradecraft**: `Paste any legacy/SegWit BTC address into https://www.walletexplorer.com/ to list sibling co-spent addresses in seconds.`

---

## Web3 Identity Resolution

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Web3.bio Identity Graph**](https://web3.bio/) ([GitHub](https://github.com/web3bio/web3bio)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `crypto_address, username, domain` → `social_profiles, entity_graph, usernames` |
| **A** | [**ENS Manager (`app.ens.domains`)**](https://app.ens.domains/) ([GitHub](https://github.com/ensdomains/ens-contracts)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `username, domain, crypto_address` → `social_profiles, emails, tx_graph` |

### [Web3.bio Identity Graph](https://web3.bio/) `[S-Tier]`
- **ID**: `web3-bio` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`web3bio/web3bio`](https://github.com/web3bio/web3bio)
- **Inputs**: `crypto_address`, `username`, `domain` → **Outputs**: `social_profiles`, `entity_graph`, `usernames`
- **Platforms**: Web · **Tags**: `ens-lookup`, `farcaster`, `lens-protocol`, `wallet-to-twitter`, `keyless-api`, `flagship`
- **Overview**: Open-source Web3 identity resolver and free API bridging `0x` / Solana addresses with ENS (`.eth`), Basenames, Farcaster, Lens, Unstoppable Domains, GitHub, and X handles!
- **Quick-Start / Tradecraft**: `curl -s 'https://api.web3.bio/profile/vitalik.eth' | jq  # Instant wallet <-> Farcaster/X/GitHub identity bridge!`

### [ENS Manager (`app.ens.domains`)](https://app.ens.domains/) `[A-Tier]`
- **ID**: `ens-domains` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ensdomains/ens-contracts`](https://github.com/ensdomains/ens-contracts)
- **Inputs**: `username`, `domain`, `crypto_address` → **Outputs**: `social_profiles`, `emails`, `tx_graph`
- **Platforms**: Web · **Tags**: `ens-eth`, `text-records`, `ipfs-websites`, `wallet-attribution`
- **Overview**: Official Ethereum Name Service registry lookup revealing `.eth` owner/registrant wallets, expiry dates, linked BTC/SOL/DOGE multi-coin addresses, IPFS content hashes, and Twitter/GitHub/email text records.
- **Quick-Start / Tradecraft**: `Inspect the 'Records -> Text' tab of any `.eth` name on https://app.ens.domains/ for linked `com.twitter`, `com.github`, and `email` strings!`

---

## DeFi & Insider Supply Visualization

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Bubblemaps**](https://bubblemaps.io/) | Web Platform | Freemium | 🟢 Passive | ✅ | `crypto_address` → `entity_graph, tx_graph` |
| **A** | [**DEX Screener**](https://dexscreener.com/) | Web Platform | Free | 🟢 Passive | ✅ | `crypto_address, keyword` → `tx_graph, metadata` |

### [Bubblemaps](https://bubblemaps.io/) `[A-Tier]`
- **ID**: `bubblemaps` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address` → **Outputs**: `entity_graph`, `tx_graph`
- **Platforms**: Web · **Tags**: `token-supply`, `insider-clustering`, `rugpull-detection`, `visual-bubbles`
- **Overview**: Visualizes ERC-20 and SPL token holder concentration as interactive connected bubbles—instantly exposing cabals, wash-trading rings, and insider dev wallets splitting token supply.
- **Quick-Start / Tradecraft**: `Paste any token contract address into https://bubblemaps.io/ to expose linked top-holder wallet clusters.`

### [DEX Screener](https://dexscreener.com/) `[A-Tier]`
- **ID**: `dexscreener` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `crypto_address`, `keyword` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: Web · **Tags**: `dex-liquidity`, `rugpull-investigation`, `top-traders`, `80-chains`
- **Overview**: Real-time decentralized exchange liquidity-pool, deployer wallet, top-trader PnL, and liquidity-lock tracker across 80+ EVM, Solana, TON, Sui, and Base chains.
- **Quick-Start / Tradecraft**: `Click the 'Top Traders' and 'Holders' tabs on https://dexscreener.com/ to spot sniper wallets funded by the token deployer.`

---

## AML & Exploit Tracing

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Chainalysis Free Sanctions Screening Oracle**](https://public.chainalysis.com/) ([GitHub](https://github.com/Chainalysis/sanctions-oracle)) | API / Service | OSS / Free | 🟢 Passive | ✅ | `crypto_address` → `sanctions_hits` |
| **A** | [**MetaSleuth (BlockSec)**](https://metasleuth.io/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `crypto_address` → `tx_graph, entity_graph` |
| **A** | [**MistTrack (SlowMist)**](https://misttrack.io/) ([GitHub](https://github.com/slowmist/Blockchain-dark-forest-selfguard-handbook)) | Web Platform | Freemium | 🟢 Passive | 🔑 | `crypto_address` → `tx_graph, sanctions_hits, malware_iocs` |

### [Chainalysis Free Sanctions Screening Oracle](https://public.chainalysis.com/) `[A-Tier]`
- **ID**: `chainalysis-sanctions-oracle` · **Type**: `API / Service` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Chainalysis/sanctions-oracle`](https://github.com/Chainalysis/sanctions-oracle)
- **Inputs**: `crypto_address` → **Outputs**: `sanctions_hits`
- **Platforms**: Web, CLI · **Tags**: `ofac-crypto-check`, `on-chain-oracle`, `chainalysis`, `free-screening`
- **Overview**: Free on-chain smart contract (`0x40C57923924B5c5c5455c48D93317139ADDaC8fb`) and REST API maintained by Chainalysis to check whether a crypto address is listed on OFAC sanctions designations.
- **Quick-Start / Tradecraft**: `Query `isSanctioned(address)` directly on Ethereum/Base/Arbitrum RPCs with zero account registration!`

### [MetaSleuth (BlockSec)](https://metasleuth.io/) `[A-Tier]`
- **ID**: `metasleuth` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `entity_graph`
- **Platforms**: Web · **Tags**: `blocksec`, `defi-exploits`, `cross-chain-bridges`, `visual-tracing`
- **Overview**: BlockSec's automated cross-chain fund-tracking canvas visualizing DeFi exploit drains, Tornado/bridge hops, and cash-out paths across 15+ chains.
- **Quick-Start / Tradecraft**: `Enter an exploit transaction hash or drainer address on https://metasleuth.io/ to auto-render cross-chain fund movement.`

### [MistTrack (SlowMist)](https://misttrack.io/) `[A-Tier]`
- **ID**: `misttrack` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`slowmist/Blockchain-dark-forest-selfguard-handbook`](https://github.com/slowmist/Blockchain-dark-forest-selfguard-handbook)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `sanctions_hits`, `malware_iocs`
- **Platforms**: Web · **Tags**: `slowmist`, `400m-labels`, `aml-risk`, `crypto-hacks`, `tron-usdt`
- **Overview**: SlowMist's AML and crypto-hack investigation platform packing 400M+ address labels across 19+ chains, mixer/bridge risk scoring, OFAC sanctions flags, and stolen-fund monitoring.
- **Quick-Start / Tradecraft**: `Particularly strong on TRON (`TRC-20 USDT`) OTC desk and Southeast Asian scam/laundering cluster attribution!`

---

## Crypto Tradecraft Manuals

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**On-Chain Investigations Tools List (OfficerCIA)**](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List) ([GitHub](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `crypto_address, keyword` → `tx_graph` |

### [On-Chain Investigations Tools List (OfficerCIA)](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List) `[A-Tier]`
- **ID**: `onchain-investigations-list` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`OffcierCia/On-Chain-Investigations-Tools-List`](https://github.com/OffcierCia/On-Chain-Investigations-Tools-List)
- **Inputs**: `crypto_address`, `keyword` → **Outputs**: `tx_graph`
- **Platforms**: Web · **Tags**: `crypto-tradecraft`, `bridge-tracing`, `mixer-heuristics`, `methodology`
- **Overview**: Comprehensive practitioner-maintained methodology and tool index for crypto hack post-mortems, mixer heuristics, Tornado Cash timing correlation, and cross-chain bridge tracing.
- **Quick-Start / Tradecraft**: `Reference when tracing funds across THORChain, Mayan, Across, Stargate, or non-EVM swap services.`

---

## Active EVM RPC & Contract Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Foundry Cast (`cast`)**](https://github.com/foundry-rs/foundry) ([GitHub](https://github.com/foundry-rs/foundry)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `crypto_address, domain` → `tx_graph, metadata, secrets` |
| **S** | [**Slither (Trail of Bits)**](https://github.com/crytic/slither) ([GitHub](https://github.com/crytic/slither)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `crypto_address, repo_code` → `metadata, entity_graph, malware_iocs` |
| **A** | [**Cryo (Paradigm)**](https://github.com/paradigmxyz/cryo) ([GitHub](https://github.com/paradigmxyz/cryo)) | CLI | OSS / Free | 🔴 Active | ✅ | `crypto_address` → `tx_graph, metadata` |

### [Foundry Cast (`cast`)](https://github.com/foundry-rs/foundry) `[S-Tier]`
- **ID**: `foundry-cast` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`foundry-rs/foundry`](https://github.com/foundry-rs/foundry)
- **Inputs**: `crypto_address`, `domain` → **Outputs**: `tx_graph`, `metadata`, `secrets`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Rust · **Tags**: `evm`, `rpc`, `storage-slots`, `ens`, `smart-contracts`
- **Overview**: Fast Rust EVM command-line Swiss-army knife querying live RPC nodes, reading private storage slots, resolving ENS, decompiling bytecode, and tracing txs.
- **Quick-Start / Tradecraft**: `cast storage 0xContractAddress 0 --rpc-url https://eth.llamarpc.com`

### [Slither (Trail of Bits)](https://github.com/crytic/slither) `[S-Tier]`
- **ID**: `slither-analyzer` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`crytic/slither`](https://github.com/crytic/slither)
- **Inputs**: `crypto_address`, `repo_code` → **Outputs**: `metadata`, `entity_graph`, `malware_iocs`
- **Platforms**: CLI, Linux, macOS, Windows, Docker, Python · **Tags**: `solidity`, `smart-contract-osint`, `trailofbits`, `rugpull-analysis`
- **Overview**: Static analysis framework pulling live verified Solidity/Vyper contracts directly by chain address to map admin privileges, upgrade proxies, and drainers.
- **Quick-Start / Tradecraft**: `slither 0xdAC17F958D2ee523a2206206994597C13D831ec7 --print human-summary`

### [Cryo (Paradigm)](https://github.com/paradigmxyz/cryo) `[A-Tier]`
- **ID**: `paradigm-cryo` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`paradigmxyz/cryo`](https://github.com/paradigmxyz/cryo)
- **Inputs**: `crypto_address` → **Outputs**: `tx_graph`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Rust · **Tags**: `evm-rpc`, `parquet`, `blockchain-forensics`, `paradigm`, `active`
- **Overview**: High-throughput Rust EVM data extractor pulling blocks, internal traces, ERC-20 transfers, and contract logs directly from live RPC endpoints into Parquet/JSON.
- **Quick-Start / Tradecraft**: `cryo logs --contract 0xAddress --rpc https://eth.llamarpc.com`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🏛️ Corporate, Finance & Sanctions](./14-corporate-financial-sanctions.md) · [🧅 Dark Web & Underground ▶](./16-darkweb-tor-underground.md)

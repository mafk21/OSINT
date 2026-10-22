[⬅️ Back to Master Index](../README.md) · [◀ 🗄️ Archiving, Evidence & Docs](./18-archiving-evidence-docs.md) · [🤖 AI Agents, MCP & OPSEC ▶](./20-ai-agents-mcp-opsec.md)

# 📻 19. Signals Intelligence (SIGINT), Wi-Fi/BLE/Cellular Geolocation, SDR & Orbital Space Tracking (`SIGINT`)

> **Scope**: Global BSSID/Wi-Fi/Bluetooth/Cell-tower geolocation databases, browser-accessible HF/VHF Software-Defined Radios (KiwiSDR/WebSDR), orbital TLE satellite trackers, and amateur ground-station networks.
>
> **OPSEC Advisory**: Querying WiGLE, OpenCelliD, CelesTrak, and KiwiSDR receivers online is passive. Local RF collection with SDR hardware is passive receive-only, but must comply with local telecommunications laws.

**Discipline Telemetry**: `30` Verified Tools · `15` S-Tier Flagships · `25` Passive · `28` Free/Open-Source

## Subcategories
- [Wi-Fi, Bluetooth & Cell Geolocation](#wi-fi,-bluetooth-cell-geolocation) (5)
- [Orbital & Satellite Tracking](#orbital-satellite-tracking) (4)
- [RF & Infrastructure Maps](#rf-infrastructure-maps) (6)
- [Browser Software-Defined Radio (SDR)](#browser-software-defined-radio-sdr) (2)
- [SDR & Local RF Suites](#sdr-local-rf-suites) (4)
- [Wi-Fi, BLE & Wireless Recon](#wi-fi,-ble-wireless-recon) (4)
- [Packet Crafting & Active Probing](#packet-crafting-active-probing) (1)
- [SDR Aviation & Maritime RF](#sdr-aviation-maritime-rf) (2)
- [Software Defined Radio](#software-defined-radio) (2)

---

## Wi-Fi, Bluetooth & Cell Geolocation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Apple WPS BSSID Geolocation (`bssid-geolocator`)**](https://github.com/acheong08/apple-corelocation-experiments) ([GitHub](https://github.com/acheong08/apple-corelocation-experiments)) | CLI | OSS / Free | 🟢 Passive | ✅ | `mac_bssid` → `geolocation` |
| **S** | [**OpenCelliD & Unwired Labs**](https://opencellid.org/) | Dataset / Registry | Free | 🟢 Passive | 🔑 | `keyword, coordinates` → `geolocation, signal_telemetry` |
| **S** | [**WiGLE (Wireless Geographic Logging Engine)**](https://wigle.net/) | Search Engine | Freemium | 🟢 Passive | 🔑 | `mac_bssid, keyword, coordinates` → `geolocation, signal_telemetry` |
| **A** | [**CellMapper**](https://www.cellmapper.net/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation, signal_telemetry` |
| **A** | [**Wireshark IEEE MAC OUI Vendor Lookup**](https://www.wireshark.org/tools/oui-lookup.html) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `mac_bssid, keyword` → `metadata, corporate_records` |

### [Apple WPS BSSID Geolocation (`bssid-geolocator`)](https://github.com/acheong08/apple-corelocation-experiments) `[S-Tier]`
- **ID**: `apple-bssid-wps` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`acheong08/apple-corelocation-experiments`](https://github.com/acheong08/apple-corelocation-experiments)
- **Inputs**: `mac_bssid` → **Outputs**: `geolocation`
- **Platforms**: Linux, macOS, Windows, Go, Python · **Tags**: `apple-wps`, `bssid-to-gps`, `keyless-triangulation`, `router-mac`, `flagship`
- **Overview**: Queries Apple's public unauthenticated CoreLocation Wi-Fi Positioning System protobuf endpoint (`gs-loc.apple.com`) to resolve any router MAC/BSSID to fresh iPhone-crowdsourced GPS coordinates!
- **Quick-Start / Tradecraft**: `Resolves live Wi-Fi router MAC/BSSID addresses to street-level GPS coordinates even when WiGLE has never wardriven the street!`

### [OpenCelliD & Unwired Labs](https://opencellid.org/) `[S-Tier]`
- **ID**: `opencellid` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `keyword`, `coordinates` → **Outputs**: `geolocation`, `signal_telemetry`
- **Platforms**: Web, Python · **Tags**: `cell-tower-geolocation`, `mcc-mnc-lac-cid`, `lte-5g-towers`, `open-csv`
- **Overview**: World's largest open database of 40M+ GSM/UMTS/LTE/5G cellular base stations, resolving `MCC + MNC + LAC/TAC + CellID` tuples from telecom logs or field modems to physical tower GPS coordinates.
- **Quick-Start / Tradecraft**: `Download country CSV tower dumps or query `MCC/MNC/LAC/CID` on https://opencellid.org/ to triangulate cellular tower sectors.`

### [WiGLE (Wireless Geographic Logging Engine)](https://wigle.net/) `[S-Tier]`
- **ID**: `wigle` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `mac_bssid`, `keyword`, `coordinates` → **Outputs**: `geolocation`, `signal_telemetry`
- **Platforms**: Web, Python · **Tags**: `bssid-geolocation`, `ssid-search`, `bluetooth-mac`, `wardriving`, `router-tracking`, `flagship`
- **Overview**: World's largest wardriving database indexing 1.4+ billion Wi-Fi networks (SSID/BSSID), Bluetooth beacons, and cell towers mapped to exact GPS coordinates since 2001.
- **Quick-Start / Tradecraft**: `Extract router BSSID from device logs/photos or search unique SSID names on https://wigle.net/ to pinpoint physical buildings!`

### [CellMapper](https://www.cellmapper.net/) `[A-Tier]`
- **ID**: `cellmapper` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `enodeb-gnodeb`, `sector-azimuth`, `5g-lte-coverage`, `telecom-osint`
- **Overview**: Crowdsourced cellular tower sector-polygon, frequency band, PCI, and eNodeB/gNodeB directional azimuth coverage map across global mobile carriers.
- **Quick-Start / Tradecraft**: `Select Carrier (MCC/MNC) + Radio (4G LTE / 5G NR) on https://www.cellmapper.net/ to view exact tower antenna sector cones.`

### [Wireshark IEEE MAC OUI Vendor Lookup](https://www.wireshark.org/tools/oui-lookup.html) `[A-Tier]`
- **ID**: `wireshark-oui-lookup` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `mac_bssid`, `keyword` → **Outputs**: `metadata`, `corporate_records`
- **Platforms**: Web · **Tags**: `mac-vendor`, `ieee-oui`, `hikvision-dji-starlink`, `hardware-attribution`
- **Overview**: Client-side IEEE Organizationally Unique Identifier lookup mapping the first 24/28/36 bits of any Ethernet, Wi-Fi BSSID, or Bluetooth MAC address to exact hardware manufacturer (e.g., DJI, Hikvision, Starlink, Cisco).
- **Quick-Start / Tradecraft**: `Look up OUI prefixes (`00:60:19`, `60:60:1F` = DJI drones!) locally at https://www.wireshark.org/tools/oui-lookup.html.`

---

## Orbital & Satellite Tracking

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**CelesTrak**](https://celestrak.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `keyword, coordinates` → `signal_telemetry, geolocation` |
| **S** | [**SatNOGS (Open Source Satellite Ground Station Network)**](https://network.satnogs.org/) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `rf_frequency, keyword` → `signal_telemetry` |
| **A** | [**Ground Station**](https://github.com/sgoudelis/ground-station) ([GitHub](https://github.com/sgoudelis/ground-station)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `rf_frequency, coordinates` → `signal_telemetry, geolocation` |
| **A** | [**N2YO Real-Time Satellite Tracking**](https://www.n2yo.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `coordinates, keyword` → `signal_telemetry, geolocation` |

### [CelesTrak](https://celestrak.org/) `[S-Tier]`
- **ID**: `celestrak` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `coordinates` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Web, Python · **Tags**: `tle-elements`, `satcat`, `recon-satellites`, `orbital-mechanics`, `flagship`
- **Overview**: Dr. T.S. Kelso's authoritative public astrodynamics portal publishing Two-Line Element (TLE) / GP orbital catalogs, SATCAT metadata, conjunction alerts, and live 3D Cesium orbit visualizations.
- **Quick-Start / Tradecraft**: `curl -s 'https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=json' | jq '.[0]'`

### [SatNOGS (Open Source Satellite Ground Station Network)](https://network.satnogs.org/) `[S-Tier]`
- **ID**: `satnogs` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `rf_frequency`, `keyword` → **Outputs**: `signal_telemetry`
- **Platforms**: Web, Linux, Python · **Tags**: `satellite-downlinks`, `waterfall-archives`, `telemetry-decoding`, `ground-stations`
- **Overview**: Libre Space Foundation's global network of automated open-source VHF/UHF/L/S-band ground stations recording live satellite waterfall spectrograms, telemetry frames, and transmitter downlink frequencies.
- **Quick-Start / Tradecraft**: `Query `https://db.satnogs.org/` by NORAD ID to look up exact satellite downlink MHz frequencies and decoded telemetry.`

### [Ground Station](https://github.com/sgoudelis/ground-station) `[A-Tier]`
- **ID**: `ground-station` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`sgoudelis/ground-station`](https://github.com/sgoudelis/ground-station)
- **Inputs**: `rf_frequency`, `coordinates` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Linux, macOS, Docker, Web · **Tags**: `orbital-tracking`, `sdr-waterfall`, `satnogs-enrichment`, `open-source`
- **Overview**: Modern browser-based open-source satellite tracking, CelesTrak/SatNOGS pass scheduling, SDR waterfall analysis, and telemetry decoding suite.
- **Quick-Start / Tradecraft**: `git clone https://github.com/sgoudelis/ground-station && docker compose up`

### [N2YO Real-Time Satellite Tracking](https://www.n2yo.com/) `[A-Tier]`
- **ID**: `n2yo` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Web · **Tags**: `overpass-predictions`, `spy-satellites`, `norad-id`, `pass-alerts`
- **Overview**: Tracks 29,000+ orbiting objects in real time—enabling analysts to check exact minute-by-minute overhead pass schedules of Sentinel, Landsat, WorldView, Gaofen, or military reconnaissance satellites over a site.
- **Quick-Start / Tradecraft**: `Check 10-day pass predictions on https://www.n2yo.com/ to calculate when the next optical/SAR satellite will image a target.`

---

## RF & Infrastructure Maps

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**FCC Universal Licensing System (ULS) & FCCID.io**](https://fccid.io/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, keyword, rf_frequency` → `signal_telemetry, corporate_records, documents` |
| **S** | [**TeleGeography Submarine Cable Map**](https://www.submarinecablemap.com/) ([GitHub](https://github.com/telegeography/www.submarinecablemap.com)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `coordinates, company, keyword` → `geolocation, corporate_records` |
| **A** | [**OpenMHz & Broadcastify**](https://openmhz.com/) ([GitHub](https://github.com/lukerobot/trunk-recorder)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword` → `signal_telemetry, archived_pages` |
| **B** | [**aprs.fi (Live Amateur Radio & Weather Telemetry)**](https://aprs.fi/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation, signal_telemetry` |
| **B** | [**Data Center Map & PeeringDB Facilities**](https://www.datacentermap.com/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `company, coordinates, keyword` → `geolocation, corporate_records` |
| **B** | [**PSKReporter & WSPRnet**](https://pskreporter.info/pskmap.html) | Web Platform | Free | 🟢 Passive | ✅ | `rf_frequency, coordinates, keyword` → `signal_telemetry, geolocation` |

### [FCC Universal Licensing System (ULS) & FCCID.io](https://fccid.io/) `[S-Tier]`
- **ID**: `fcc-uls-search` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword`, `rf_frequency`, `coordinates` → **Outputs**: `signal_telemetry`, `corporate_records`, `documents`, `geolocation`
- **Platforms**: Web · **Tags**: `hardware-teardowns`, `fcc-id`, `internal-photos`, `corporate-radio-frequencies`, `flagship`
- **Overview**: Searches US Federal Communications Commission RF emitter licenses (exact corporate radio frequencies & tower coordinates!) AND internal hardware teardown photos/schematics/manuals filed for every wireless device (`fccid.io`)!
- **Quick-Start / Tradecraft**: `Look up any router/drone/IoT `FCC ID` on https://fccid.io/ for unredacted internal PCB photos, frequencies, and unreleased product manuals!`

### [TeleGeography Submarine Cable Map](https://www.submarinecablemap.com/) `[S-Tier]`
- **ID**: `submarine-cable-map` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`telegeography/www.submarinecablemap.com`](https://github.com/telegeography/www.submarinecablemap.com)
- **Inputs**: `coordinates`, `company`, `keyword` → **Outputs**: `geolocation`, `corporate_records`
- **Platforms**: Web · **Tags**: `undersea-cables`, `landing-stations`, `critical-infrastructure`, `subsea-sabotage`, `flagship`
- **Overview**: Authoritative interactive map and open GeoJSON dataset of every active and planned undersea fiber-optic telecommunications cable, landing station, consortium owner, and RFS year worldwide.
- **Quick-Start / Tradecraft**: `Correlate AIS ship loitering / anchor-drag tracks from Global Fishing Watch against cable GeoJSON from TeleGeography!`

### [OpenMHz & Broadcastify](https://openmhz.com/) `[A-Tier]`
- **ID**: `openmhz-broadcastify` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`lukerobot/trunk-recorder`](https://github.com/lukerobot/trunk-recorder)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `signal_telemetry`, `archived_pages`
- **Platforms**: Web, Linux · **Tags**: `p25-trunked-radio`, `emergency-dispatch`, `incident-verification`, `sdr`
- **Overview**: Public archive of trunked municipal P25 police, fire, EMS, and public-works radio talkgroup transmissions (`openmhz.com`) powered by open-source SDR `trunk-recorder` nodes.
- **Quick-Start / Tradecraft**: `Replay timestamped fire/EMS dispatch talkgroups on https://openmhz.com/ to verify breaking municipal emergencies.`

### [aprs.fi (Live Amateur Radio & Weather Telemetry)](https://aprs.fi/) `[B-Tier]`
- **ID**: `aprs-fi` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `aprs`, `radio-beacons`, `high-altitude-balloons`, `weather-stations`
- **Overview**: Real-time global Automatic Packet Reporting System map tracking APRS radio beacons, high-altitude balloons, AIS coastal relays, and citizen weather stations.
- **Quick-Start / Tradecraft**: `Search amateur callsigns or inspect regional RF packet telemetry on https://aprs.fi/.`

### [Data Center Map & PeeringDB Facilities](https://www.datacentermap.com/) `[B-Tier]`
- **ID**: `datacenter-map` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `coordinates`, `keyword` → **Outputs**: `geolocation`, `corporate_records`
- **Platforms**: Web · **Tags**: `colocation-facilities`, `physical-cloud-infra`, `carrier-hotels`
- **Overview**: Global directory mapping 5,500+ physical colocation data centers, carrier hotels, IXPs, and cloud availability regions across 140+ countries.
- **Quick-Start / Tradecraft**: `Cross-reference ASN PeeringDB facility records with https://www.datacentermap.com/ street addresses.`

### [PSKReporter & WSPRnet](https://pskreporter.info/pskmap.html) `[B-Tier]`
- **ID**: `pskreporter-wsprnet` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `rf_frequency`, `coordinates`, `keyword` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Web · **Tags**: `hf-propagation`, `maidenhead-grid`, `ionosphere-telemetry`
- **Overview**: Real-time global HF/VHF ionospheric radio propagation maps logging millions of digital amateur radio reception spots (`FT8`/`WSPR`) with grid-square coordinates.
- **Quick-Start / Tradecraft**: `Verify whether a claimed shortwave HF intercept was physically propagatable between two regions at a given UTC hour!`

---

## Browser Software-Defined Radio (SDR)

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**KiwiSDR Global Public Receiver Network**](http://kiwisdr.com/public/) ([GitHub](https://github.com/jks-prv/Beagle_SDR_GPS)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `rf_frequency, coordinates` → `signal_telemetry, geolocation` |
| **S** | [**WebSDR.org**](http://www.websdr.org/) | Web Platform | Free | 🟢 Passive | ✅ | `rf_frequency` → `signal_telemetry` |

### [KiwiSDR Global Public Receiver Network](http://kiwisdr.com/public/) `[S-Tier]`
- **ID**: `kiwisdr` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`jks-prv/Beagle_SDR_GPS`](https://github.com/jks-prv/Beagle_SDR_GPS)
- **Inputs**: `rf_frequency`, `coordinates` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Web · **Tags**: `hf-radio`, `tdoa-triangulation`, `shortwave-sigint`, `military-hf`, `numbers-stations`, `flagship`
- **Overview**: Global grid of 600+ volunteer-hosted wideband 0–30 MHz HF Software-Defined Radios tunable live in any browser—supporting TDoA (Time Difference of Arrival) direction-finding triangulation of unknown transmitters!
- **Quick-Start / Tradecraft**: `Open 3–4 geographically separated KiwiSDR nodes -> Extension -> TDoA to geolocate an unknown HF radio transmitter across continents!`

### [WebSDR.org](http://www.websdr.org/) `[S-Tier]`
- **ID**: `websdr` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `rf_frequency` → **Outputs**: `signal_telemetry`
- **Platforms**: Web · **Tags**: `twente-websdr`, `hf-vhf-uhf`, `qo100-satellite`, `live-waterfall`
- **Overview**: University of Twente & worldwide directory of browser-accessible multi-user SDR receivers spanning HF, VHF, UHF, amateur bands, marine VHF, and geostationary QO-100 satellite transponders.
- **Quick-Start / Tradecraft**: `Tune University of Twente wideband 0–29 MHz WebSDR (`websdr.ewi.utwente.nl:8901`) in SSB/CW/AM directly in browser.`

---

## SDR & Local RF Suites

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**iNTERCEPT**](https://github.com/smittix/intercept) ([GitHub](https://github.com/smittix/intercept)) | Framework | OSS / Free | 🟢 Passive | ✅ | `rf_frequency` → `signal_telemetry, flight_tracks, vessel_tracks` |
| **A** | [**rtl_433 (ISM Band Telemetry Decoder)**](https://github.com/merbanan/rtl_433) ([GitHub](https://github.com/merbanan/rtl_433)) | CLI | OSS / Free | 🟢 Passive | ✅ | `rf_frequency` → `signal_telemetry` |
| **A** | [**SatDump**](https://www.satdump.org/) ([GitHub](https://github.com/SatDump/SatDump)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `rf_frequency` → `satellite_imagery, signal_telemetry` |
| **B** | [**WireTapper**](https://github.com/h9zdev/WireTapper) ([GitHub](https://github.com/h9zdev/WireTapper)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `mac_bssid, rf_frequency` → `signal_telemetry, geolocation` |

### [iNTERCEPT](https://github.com/smittix/intercept) `[A-Tier]`
- **ID**: `intercept-sigint` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`smittix/intercept`](https://github.com/smittix/intercept)
- **Inputs**: `rf_frequency` → **Outputs**: `signal_telemetry`, `flight_tracks`, `vessel_tracks`
- **Platforms**: Linux, Docker · **Tags**: `rtl-sdr`, `satdump`, `ais-adsb`, `acars`, `sigint-suite`
- **Overview**: Open-source unified SIGINT workbench integrating RTL-SDR, `rtl_433`, `dump1090` (ADS-B), `AIS-catcher` (maritime), `acarsdec`, `SatDump` (weather sats), and KiwiSDR monitoring into one interface.
- **Quick-Start / Tradecraft**: `Deploy on Linux with an RTL-SDR v3/v4 dongle for local passive ADS-B, AIS, ACARS, and NOAA APT reception.`

### [rtl_433 (ISM Band Telemetry Decoder)](https://github.com/merbanan/rtl_433) `[A-Tier]`
- **ID**: `rtl-433` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`merbanan/rtl_433`](https://github.com/merbanan/rtl_433)
- **Inputs**: `rf_frequency` → **Outputs**: `signal_telemetry`
- **Platforms**: Linux, macOS, Windows, Docker · **Tags**: `ism-433mhz`, `tpms-ids`, `iot-rf-decoding`, `rtl-sdr`
- **Overview**: Decodes 250+ unencrypted 315/433/868/915 MHz ISM radio protocols—automotive tire-pressure (TPMS) unique IDs, weather sensors, utility meters, and industrial telemetry using an RTL-SDR.
- **Quick-Start / Tradecraft**: `rtl_433 -F json  # Passively decode local 433.92 MHz / 915 MHz sensor packets to JSON`

### [SatDump](https://www.satdump.org/) `[A-Tier]`
- **ID**: `satdump` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`SatDump/SatDump`](https://github.com/SatDump/SatDump)
- **Inputs**: `rf_frequency` → **Outputs**: `satellite_imagery`, `signal_telemetry`
- **Platforms**: Linux, Windows, macOS · **Tags**: `satellite-downlink-decoder`, `inmarsat-stdc`, `meteor-noaa`, `sdr-geoint`
- **Overview**: All-in-one open-source C++ satellite signal decoding software demodulating live weather/Earth-observation downlinks (NOAA, Meteor-M, GOES, FengYun, MetOp, Inmarsat Aero/STD-C!) from cheap SDRs.
- **Quick-Start / Tradecraft**: `Decode live L-band Inmarsat EGC Maritime Safety Notices & direct-broadcast satellite imagery locally with SatDump!`

### [WireTapper](https://github.com/h9zdev/WireTapper) `[B-Tier]`
- **ID**: `wiretapper` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`h9zdev/WireTapper`](https://github.com/h9zdev/WireTapper)
- **Inputs**: `mac_bssid`, `rf_frequency` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Linux · **Tags**: `passive-ble-wifi`, `local-rf-situational-awareness`, `oui-classification`
- **Overview**: Passive wireless situational-intelligence mapper detecting and classifying nearby Wi-Fi APs, BLE beacons, vehicles, cameras, IoT devices, and cell towers locally without transmitting.
- **Quick-Start / Tradecraft**: `Use passively in authorized physical-security assessments to catalog nearby wireless/BLE emitters.`

---

## Wi-Fi, BLE & Wireless Recon

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Kismet Wireless**](https://github.com/kismetwireless/kismet) ([GitHub](https://github.com/kismetwireless/kismet)) | Framework | OSS / Free | 🟡 Hybrid | ✅ | `mac_bssid, rf_frequency, coordinates` → `signal_telemetry, geolocation, metadata` |
| **S** | [**bettercap**](https://github.com/bettercap/bettercap) ([GitHub](https://github.com/bettercap/bettercap)) | Framework | OSS / Free | 🔴 Active | ✅ | `mac_bssid, ip` → `signal_telemetry, ip_addresses, metadata` |
| **S** | [**Aircrack-ng Suite (airodump-ng)**](https://github.com/aircrack-ng/aircrack-ng) ([GitHub](https://github.com/aircrack-ng/aircrack-ng)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `mac_bssid` → `signal_telemetry, geolocation, metadata` |
| **A** | [**Project Ubertooth**](https://github.com/greatscottgadgets/ubertooth) ([GitHub](https://github.com/greatscottgadgets/ubertooth)) | CLI | OSS / Free | 🟡 Hybrid | ✅ | `mac_bssid, rf_frequency` → `signal_telemetry, metadata` |

### [Kismet Wireless](https://github.com/kismetwireless/kismet) `[S-Tier]`
- **ID**: `kismet` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`kismetwireless/kismet`](https://github.com/kismetwireless/kismet)
- **Inputs**: `mac_bssid`, `rf_frequency`, `coordinates` → **Outputs**: `signal_telemetry`, `geolocation`, `metadata`
- **Platforms**: Web, CLI, Linux, macOS, Docker · **Tags**: `wifi`, `wardriving`, `ble`, `zigbee`, `sigint`
- **Overview**: Flagship wireless network and device detector, sniffer, wardriving logger, and WIDS supporting 802.11 Wi-Fi, Bluetooth/BLE, Zigbee, ADS-B, and RTL-SDR.
- **Quick-Start / Tradecraft**: `sudo kismet -c wlan0`

### [bettercap](https://github.com/bettercap/bettercap) `[S-Tier]`
- **ID**: `bettercap` · **Type**: `Framework` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`bettercap/bettercap`](https://github.com/bettercap/bettercap)
- **Inputs**: `mac_bssid`, `ip` → **Outputs**: `signal_telemetry`, `ip_addresses`, `metadata`
- **Platforms**: Web, CLI, Linux, macOS, Windows, Docker, Go · **Tags**: `ble-recon`, `wifi-recon`, `lan-discovery`, `active`, `go`
- **Overview**: Swiss-army active reconnaissance framework in Go for 802.11 Wi-Fi access points/clients, Bluetooth Low Energy (BLE) GATT characteristics, 2.4GHz HID, and LANs.
- **Quick-Start / Tradecraft**: `sudo bettercap -eval 'ble.recon on; wifi.recon on'`

### [Aircrack-ng Suite (airodump-ng)](https://github.com/aircrack-ng/aircrack-ng) `[S-Tier]`
- **ID**: `aircrack-ng` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`aircrack-ng/aircrack-ng`](https://github.com/aircrack-ng/aircrack-ng)
- **Inputs**: `mac_bssid` → **Outputs**: `signal_telemetry`, `geolocation`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows · **Tags**: `80211`, `airodump-ng`, `bssid`, `probe-requests`, `sigint`
- **Overview**: Complete 802.11 wireless assessment suite featuring `airodump-ng` for live BSSID, ESSID, client MAC probe-request, channel, and GPS wardriving capture.
- **Quick-Start / Tradecraft**: `sudo airodump-ng wlan0mon --write capture`

### [Project Ubertooth](https://github.com/greatscottgadgets/ubertooth) `[A-Tier]`
- **ID**: `ubertooth` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟡 Hybrid · **Auth**: None (Keyless / Direct) · **GitHub**: [`greatscottgadgets/ubertooth`](https://github.com/greatscottgadgets/ubertooth)
- **Inputs**: `mac_bssid`, `rf_frequency` → **Outputs**: `signal_telemetry`, `metadata`
- **Platforms**: CLI, Linux, macOS · **Tags**: `bluetooth`, `ble`, `2.4ghz`, `greatscottgadgets`, `sigint`
- **Overview**: Open-source 2.4 GHz wireless platform and CLI tools (`ubertooth-rx`, `ubertooth-btle`) monitoring Bluetooth Basic Rate (LAP/UAP) and BLE traffic.
- **Quick-Start / Tradecraft**: `ubertooth-btle -f`

---

## Packet Crafting & Active Probing

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Scapy**](https://github.com/secdev/scapy) ([GitHub](https://github.com/secdev/scapy)) | Library | OSS / Free | 🔴 Active | ✅ | `ip, domain, mac_bssid` → `open_ports, signal_telemetry, ip_addresses` |

### [Scapy](https://github.com/secdev/scapy) `[S-Tier]`
- **ID**: `scapy` · **Type**: `Library` · **Pricing**: `Free / Open Source` · **OPSEC**: 🔴 Active · **Auth**: None (Keyless / Direct) · **GitHub**: [`secdev/scapy`](https://github.com/secdev/scapy)
- **Inputs**: `ip`, `domain`, `mac_bssid` → **Outputs**: `open_ports`, `signal_telemetry`, `ip_addresses`, `metadata`
- **Platforms**: CLI, Linux, macOS, Windows, Python · **Tags**: `packet-crafting`, `traceroute`, `80211`, `active-probing`
- **Overview**: Interactive Python packet manipulation program and library forging, transmitting, sniffing, tracerouting, and decoding custom Layer-2/3/4/802.11 frames.
- **Quick-Start / Tradecraft**: `sudo scapy`

---

## SDR Aviation & Maritime RF

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**readsb (1090 MHz ADS-B Decoder)**](https://github.com/wiedehopf/readsb) ([GitHub](https://github.com/wiedehopf/readsb)) | CLI | OSS / Free | 🟢 Passive | ✅ | `rf_frequency, aircraft_hex` → `flight_tracks, signal_telemetry, geolocation` |
| **S** | [**AIS-catcher**](https://github.com/jvde-github/AIS-catcher) ([GitHub](https://github.com/jvde-github/AIS-catcher)) | CLI | OSS / Free | 🟢 Passive | ✅ | `rf_frequency, vessel_imo` → `vessel_tracks, signal_telemetry, geolocation` |

### [readsb (1090 MHz ADS-B Decoder)](https://github.com/wiedehopf/readsb) `[S-Tier]`
- **ID**: `readsb` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`wiedehopf/readsb`](https://github.com/wiedehopf/readsb)
- **Inputs**: `rf_frequency`, `aircraft_hex` → **Outputs**: `flight_tracks`, `signal_telemetry`, `geolocation`
- **Platforms**: Web, CLI, Linux, Docker · **Tags**: `adsb`, `1090mhz`, `mode-s`, `rtl-sdr`, `aviation-sigint`
- **Overview**: Actively maintained Mode-S / ADS-B / TIS-B 1090 MHz SDR receiver and decoder powering modern airplanes.live and ADS-B Exchange feeder stations.
- **Quick-Start / Tradecraft**: `readsb --device-type rtlsdr --net`

### [AIS-catcher](https://github.com/jvde-github/AIS-catcher) `[S-Tier]`
- **ID**: `ais-catcher` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`jvde-github/AIS-catcher`](https://github.com/jvde-github/AIS-catcher)
- **Inputs**: `rf_frequency`, `vessel_imo` → **Outputs**: `vessel_tracks`, `signal_telemetry`, `geolocation`
- **Platforms**: Web, CLI, Linux, macOS, Windows, Docker · **Tags**: `ais`, `vhf-maritime`, `rtl-sdr`, `vessels`, `sigint`
- **Overview**: High-sensitivity VHF maritime Automatic Identification System (161.975 / 162.025 MHz) SDR decoder with built-in live vessel map web UI and JSON output.
- **Quick-Start / Tradecraft**: `AIS-catcher -N 8100`

---

## Software Defined Radio

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Gqrx SDR**](https://github.com/gqrx-sdr/gqrx) ([GitHub](https://github.com/gqrx-sdr/gqrx)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `rf_frequency` → `signal_telemetry` |
| **A** | [**SigDigger**](https://github.com/BatchDrake/SigDigger) ([GitHub](https://github.com/BatchDrake/SigDigger)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `rf_frequency, audio` → `signal_telemetry, metadata` |

### [Gqrx SDR](https://github.com/gqrx-sdr/gqrx) `[A-Tier]`
- **ID**: `gqrx` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`gqrx-sdr/gqrx`](https://github.com/gqrx-sdr/gqrx)
- **Inputs**: `rf_frequency` → **Outputs**: `signal_telemetry`
- **Platforms**: Linux, macOS · **Tags**: `sdr`, `waterfall`, `gnuradio`, `hackrf`, `rtlsdr`
- **Overview**: Open-source GNU Radio-powered software defined radio receiver with waterfall spectrum analyzer supporting RTL-SDR, Airspy, HackRF, BladeRF, and USRP.
- **Quick-Start / Tradecraft**: `gqrx # Launch SDR waterfall & receiver`

### [SigDigger](https://github.com/BatchDrake/SigDigger) `[A-Tier]`
- **ID**: `sigdigger` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`BatchDrake/SigDigger`](https://github.com/BatchDrake/SigDigger)
- **Inputs**: `rf_frequency`, `audio` → **Outputs**: `signal_telemetry`, `metadata`
- **Platforms**: Linux, macOS, Windows · **Tags**: `rf-analysis`, `demodulation`, `sdr`, `sigint`
- **Overview**: Qt digital signal analyzer for blind unknown RF protocol reverse-engineering, FSK/PSK/ASK demodulation, and satellite/telemetry inspection.
- **Quick-Start / Tradecraft**: `SigDigger`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🗄️ Archiving, Evidence & Docs](./18-archiving-evidence-docs.md) · [🤖 AI Agents, MCP & OPSEC ▶](./20-ai-agents-mcp-opsec.md)

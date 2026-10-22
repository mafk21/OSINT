[⬅️ Back to Master Index](../README.md) · [◀ 🔬 Image, Video & Media Forensics](./12-image-video-media-forensics.md) · [🏛️ Corporate, Finance & Sanctions ▶](./14-corporate-financial-sanctions.md)

# ✈️ 13. Aviation, Maritime, Rail, Supply Chain & Vehicle/VIN Intelligence (`TRANSINT`)

> **Scope**: Uncensored ADS-B/MLAT flight trackers, AIS vessel & dark-fleet monitors, GNSS/GPS jamming maps, maritime ownership & port-state control registries, bills-of-lading customs databases, and VIN/plate tools.
>
> **OPSEC Advisory**: Prefer unfiltered ADS-B networks (`ADS-B Exchange`, `airplanes.live`) when tracking state, military, or LADD-blocked private aircraft censored on commercial flight apps.

**Discipline Telemetry**: `26` Verified Tools · `8` S-Tier Flagships · `26` Passive · `19` Free/Open-Source

## Subcategories
- [Uncensored Aviation Tracking](#uncensored-aviation-tracking) (3)
- [Maritime Ownership & PSC](#maritime-ownership-psc) (4)
- [Commercial Aviation & Fleet Data](#commercial-aviation-fleet-data) (2)
- [Maritime AIS & Shadow Fleet](#maritime-ais-shadow-fleet) (5)
- [Electronic Warfare & Aviation RF](#electronic-warfare-aviation-rf) (1)
- [Customs, Cargo & Supply Chain](#customs,-cargo-supply-chain) (4)
- [Aviation Registries & Datalinks](#aviation-registries-datalinks) (4)
- [Vehicles, VINs & Rail](#vehicles,-vins-rail) (3)

---

## Uncensored Aviation Tracking

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ADS-B Exchange**](https://globe.adsbexchange.com/) | Web Platform | Free | 🟢 Passive | ✅ | `aircraft_hex, coordinates, keyword` → `flight_tracks, geolocation` |
| **S** | [**airplanes.live**](https://globe.airplanes.live/) | Web Platform | Free | 🟢 Passive | ✅ | `aircraft_hex, coordinates` → `flight_tracks, geolocation` |
| **A** | [**The OpenSky Network**](https://opensky-network.org/) ([GitHub](https://github.com/openskynetwork/opensky-api)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `aircraft_hex, coordinates` → `flight_tracks, signal_telemetry` |

### [ADS-B Exchange](https://globe.adsbexchange.com/) `[S-Tier]`
- **ID**: `ads-b-exchange` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `aircraft_hex`, `coordinates`, `keyword` → **Outputs**: `flight_tracks`, `geolocation`
- **Platforms**: Web · **Tags**: `ads-b`, `mlat`, `uncensored-flights`, `military-aircraft`, `ladd-bypass`, `flagship`
- **Overview**: World's largest unfiltered public ADS-B and MLAT aircraft tracking map—refusing FAA LADD/PIA censorship blocks so investigators can track military transports, state VIP jets, and private tail numbers.
- **Quick-Start / Tradecraft**: `Press `U` on https://globe.adsbexchange.com/ to filter strictly to Military aircraft, or click History to replay UTC dates!`

### [airplanes.live](https://globe.airplanes.live/) `[S-Tier]`
- **ID**: `airplanes-live` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `aircraft_hex`, `coordinates` → **Outputs**: `flight_tracks`, `geolocation`
- **Platforms**: Web · **Tags**: `ads-b`, `community-feeder`, `uncensored`, `military-jets`, `flagship`
- **Overview**: Community-owned, non-commercial, completely uncensored global ADS-B/MLAT flight tracker built by feeder volunteers displaying military, government, LADD, and private jets for free.
- **Quick-Start / Tradecraft**: `Query ICAO 24-bit hex (`?icao=ae01d5`) on https://globe.airplanes.live/ and cross-compare feeder coverage with ADS-B Exchange.`

### [The OpenSky Network](https://opensky-network.org/) `[A-Tier]`
- **ID**: `opensky-network` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`openskynetwork/opensky-api`](https://github.com/openskynetwork/opensky-api)
- **Inputs**: `aircraft_hex`, `coordinates` → **Outputs**: `flight_tracks`, `signal_telemetry`
- **Platforms**: Web, Python · **Tags**: `academic-adsb`, `historical-sql`, `raw-transponder`, `rest-api`
- **Overview**: Swiss non-profit academic air-traffic sensor network offering free REST APIs and multi-year Trino/Impala SQL access to raw historical Mode-S, ADS-B, and FLARM transponder frames.
- **Quick-Start / Tradecraft**: `curl -s 'https://opensky-network.org/api/states/all?lamin=45.8&lomin=5.9&lamax=47.8&lomax=10.5' | jq`

---

## Maritime Ownership & PSC

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Equasis**](https://www.equasis.org/) | Dataset / Registry | Free | 🟢 Passive | 🔑 | `vessel_imo, company` → `corporate_records, vessel_tracks, sanctions_hits` |
| **A** | [**Paris MoU & Tokyo MoU Port State Control Databases**](https://www.parismou.org/inspection-search/inspection-search) | Dataset / Registry | Free | 🟢 Passive | ✅ | `vessel_imo, company` → `corporate_records, vessel_tracks, documents` |
| **B** | [**ArcNautical Vessel Sanctions Screen**](https://arcnautical.com/) | Web Platform | Free | 🟢 Passive | ✅ | `vessel_imo` → `sanctions_hits, vessel_tracks` |
| **B** | [**ITU MARS (Maritime Mobile Access & Retrieval System)**](https://www.itu.int/en/ITU-R/terrestrial/mars/Pages/MARS.aspx) | Dataset / Registry | Free | 🟢 Passive | ✅ | `vessel_imo, keyword` → `corporate_records, signal_telemetry` |

### [Equasis](https://www.equasis.org/) `[S-Tier]`
- **ID**: `equasis` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `vessel_imo`, `company` → **Outputs**: `corporate_records`, `vessel_tracks`, `sanctions_hits`
- **Platforms**: Web · **Tags**: `imo-lookup`, `ship-ownership`, `p-and-i-insurer`, `flag-hopping`, `psc-detentions`, `flagship`
- **Overview**: International public-safety maritime database (founded by EC & French Maritime Admin) providing free historical Registered Owner, Commercial Operator, ISM Manager, Flag, Class, P&I Club, and PSC inspection records by IMO!
- **Quick-Start / Tradecraft**: `Free registration at https://www.equasis.org/—the single best free source for historical tanker/cargo management & insurer chains!`

### [Paris MoU & Tokyo MoU Port State Control Databases](https://www.parismou.org/inspection-search/inspection-search) `[A-Tier]`
- **ID**: `tokyo-paris-mou` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo`, `company` → **Outputs**: `corporate_records`, `vessel_tracks`, `documents`
- **Platforms**: Web · **Tags**: `port-state-control`, `ship-detentions`, `shadow-fleet-safety`, `ism-manager`
- **Overview**: Official European (`parismou.org`) and Asia-Pacific (`apcis.tmou.org`) Port State Control inspection databases exposing vessel safety deficiencies, detentions, certificates, and ISM technical managers!
- **Quick-Start / Tradecraft**: `Query any IMO number in Paris MoU / Tokyo MoU APCIS to uncover substandard maintenance and certificate issuers.`

### [ArcNautical Vessel Sanctions Screen](https://arcnautical.com/) `[B-Tier]`
- **ID**: `arcnautical` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo` → **Outputs**: `sanctions_hits`, `vessel_tracks`
- **Platforms**: Web · **Tags**: `imo-sanctions`, `keyless-json`, `maritime-compliance`
- **Overview**: Keyless, accountless IMO vessel sanctions screener cross-checking ships against OFAC, EU, UK, and UN maritime designations with a free JSON endpoint.
- **Quick-Start / Tradecraft**: `Screen IMO numbers rapidly and cross-verify positive matches in OpenSanctions and official OFAC SDN.`

### [ITU MARS (Maritime Mobile Access & Retrieval System)](https://www.itu.int/en/ITU-R/terrestrial/mars/Pages/MARS.aspx) `[B-Tier]`
- **ID**: `itu-mars` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo`, `keyword` → **Outputs**: `corporate_records`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `mmsi-lookup`, `radio-callsign`, `itu`, `official-telecom`
- **Overview**: Official International Telecommunication Union ship-station radio license database mapping MMSI numbers, radio callsigns, EPIRB hex IDs, and registered ship owners.
- **Quick-Start / Tradecraft**: `Resolve unknown MMSI numbers or marine VHF callsigns via ITU MARS.`

---

## Commercial Aviation & Fleet Data

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Flightradar24**](https://www.flightradar24.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `aircraft_hex, keyword, coordinates` → `flight_tracks, geolocation` |
| **A** | [**FlightAware**](https://www.flightaware.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `aircraft_hex, keyword` → `flight_tracks, corporate_records` |

### [Flightradar24](https://www.flightradar24.com/) `[S-Tier]`
- **ID**: `flightradar24` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `aircraft_hex`, `keyword`, `coordinates` → **Outputs**: `flight_tracks`, `geolocation`
- **Platforms**: Web · **Tags**: `commercial-aviation`, `airport-movements`, `flight-playback`, `satellite-adsb`
- **Overview**: Highest-density global commercial ADS-B, satellite ADS-B, and FLARM flight tracker offering 3D cockpit replay, weather overlays, airport ground movement, and granular fleet histories.
- **Quick-Start / Tradecraft**: `Use Playback on https://www.flightradar24.com/ for commercial diversions and ground taxi timelines (note: honors FAA LADD blocks).`

### [FlightAware](https://www.flightaware.com/) `[A-Tier]`
- **ID**: `flightaware` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `aircraft_hex`, `keyword` → **Outputs**: `flight_tracks`, `corporate_records`
- **Platforms**: Web · **Tags**: `ifr-flight-plans`, `fbo-logs`, `tail-numbers`, `aviation-osint`
- **Overview**: Authoritative IFR flight-plan filing, FBO arrival/departure log, and historical route database covering global airlines and North American/European general aviation.
- **Quick-Start / Tradecraft**: `Check filed IFR route strings and FBO destination handlers on https://www.flightaware.com/.`

---

## Maritime AIS & Shadow Fleet

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Global Fishing Watch Map**](https://globalfishingwatch.org/map) ([GitHub](https://github.com/GlobalFishingWatch/gfwr)) | Web Platform | OSS / Free | 🟢 Passive | 🔑 | `vessel_imo, coordinates, company` → `vessel_tracks, satellite_imagery, geolocation` |
| **S** | [**MarineTraffic**](https://www.marinetraffic.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `vessel_imo, coordinates, keyword` → `vessel_tracks, geolocation, metadata` |
| **A** | [**MyShipTracking**](https://www.myshiptracking.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `vessel_imo, coordinates, keyword` → `vessel_tracks, geolocation` |
| **A** | [**VesselFinder**](https://www.vesselfinder.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `vessel_imo, keyword, coordinates` → `vessel_tracks, geolocation` |
| **B** | [**CruiseMapper & Port Webcams**](https://www.cruisemapper.com/) | Web Platform | Free | 🟢 Passive | ✅ | `vessel_imo, coordinates, keyword` → `vessel_tracks, geolocation` |

### [Global Fishing Watch Map](https://globalfishingwatch.org/map) `[S-Tier]`
- **ID**: `global-fishing-watch` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`GlobalFishingWatch/gfwr`](https://github.com/GlobalFishingWatch/gfwr)
- **Inputs**: `vessel_imo`, `coordinates`, `company` → **Outputs**: `vessel_tracks`, `satellite_imagery`, `geolocation`
- **Platforms**: Web, Python · **Tags**: `dark-vessels`, `sar-ship-detection`, `ship-to-ship-transfers`, `ais-history`, `flagship`
- **Overview**: Open-access maritime transparency platform fusing commercial satellite AIS, VMS, Sentinel-1 SAR dark-vessel detections, Sentinel-2 optical imagery, loitering events, and ship-to-ship (STS) encounters!
- **Quick-Start / Tradecraft**: `Create a free account on https://globalfishingwatch.org/map and enable 'SAR Vessel Detections' + 'Encounter Events' layers!`

### [MarineTraffic](https://www.marinetraffic.com/) `[S-Tier]`
- **ID**: `marinetraffic` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo`, `coordinates`, `keyword` → **Outputs**: `vessel_tracks`, `geolocation`, `metadata`
- **Platforms**: Web · **Tags**: `ais-tracking`, `port-calls`, `draught-changes`, `hull-photos`, `flagship`
- **Overview**: Global coastal and satellite AIS ship-tracking standard displaying live vessel positions, reported draught changes, destination strings, port arrivals, and crowdsourced hull photography.
- **Quick-Start / Tradecraft**: `Check reported Draught changes before/after an offshore loitering gap to confirm covert cargo offloading!`

### [MyShipTracking](https://www.myshiptracking.com/) `[A-Tier]`
- **ID**: `myshiptracking` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo`, `coordinates`, `keyword` → **Outputs**: `vessel_tracks`, `geolocation`
- **Platforms**: Web · **Tags**: `free-ais-tracks`, `speed-graphs`, `port-history`
- **Overview**: Generous free real-time AIS ship map offering multi-day historical vessel tracks, port call logs, speed graphs, and fleet groupings without aggressive paywalls.
- **Quick-Start / Tradecraft**: `Check multi-day past track & speed curves on https://www.myshiptracking.com/ when MarineTraffic truncates free history.`

### [VesselFinder](https://www.vesselfinder.com/) `[A-Tier]`
- **ID**: `vesselfinder` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo`, `keyword`, `coordinates` → **Outputs**: `vessel_tracks`, `geolocation`
- **Platforms**: Web · **Tags**: `ais`, `imo-mmsi`, `recent-port-calls`, `ship-tracker`
- **Overview**: Fast real-time AIS ship position tracker, port call log, and IMO/MMSI vessel specification lookup with clean unauthenticated search.
- **Quick-Start / Tradecraft**: `Cross-check live terrestrial AIS hits between VesselFinder, MarineTraffic, and MyShipTracking.`

### [CruiseMapper & Port Webcams](https://www.cruisemapper.com/) `[B-Tier]`
- **ID**: `cruisemapper` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vessel_imo`, `coordinates`, `keyword` → **Outputs**: `vessel_tracks`, `geolocation`
- **Platforms**: Web · **Tags**: `ship-bridge-webcams`, `harbor-verification`, `ferry-ais`, `port-osint`
- **Overview**: Tracks global passenger cruise ships, ferries, and icebreakers in real time—critically indexing live bow/bridge deck webcams that inadvertently capture surrounding naval/port harbor activity!
- **Quick-Start / Tradecraft**: `Check which cruise ship was docked in a port on an incident date to pull live harbor weather/visibility from its bridge cam!`

---

## Electronic Warfare & Aviation RF

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**GPSJAM**](https://gpsjam.org/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `signal_telemetry, geolocation` |

### [GPSJAM](https://gpsjam.org/) `[S-Tier]`
- **ID**: `gpsjam` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `signal_telemetry`, `geolocation`
- **Platforms**: Web · **Tags**: `gnss-jamming`, `electronic-warfare`, `gps-spoofing`, `conflict-osint`, `flagship`
- **Overview**: Daily global H3 hexagonal map created by John Wiseman deriving real-world GPS/GNSS electronic-warfare jamming and spoofing zones from aircraft ADS-B navigation-accuracy (`NACp`) drops!
- **Quick-Start / Tradecraft**: `Inspect red H3 hexagons on https://gpsjam.org/ across Baltic, Black Sea, Eastern Med, and Red Sea corridors by date.`

---

## Customs, Cargo & Supply Chain

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ImportYeti**](https://www.importyeti.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `company, keyword` → `corporate_records, entity_graph, vessel_tracks` |
| **A** | [**BIC Container Prefix & Check-Digit Registry**](https://www.bic-code.org/bic-codes/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `keyword` → `corporate_records` |
| **A** | [**S&P Panjiva & ImportGenius**](https://panjiva.com/) | Web Platform | Paid | 🟢 Passive | 🔑 | `company, keyword, vessel_imo` → `corporate_records, vessel_tracks, entity_graph` |
| **A** | [**Track-Trace (Multi-Carrier Container & Air Waybill)**](https://www.track-trace.com/) | Web Platform | Free | 🟢 Passive | ✅ | `keyword` → `vessel_tracks, flight_tracks` |

### [ImportYeti](https://www.importyeti.com/) `[S-Tier]`
- **ID**: `importyeti` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `company`, `keyword` → **Outputs**: `corporate_records`, `entity_graph`, `vessel_tracks`
- **Platforms**: Web · **Tags**: `bills-of-lading`, `supply-chain-osint`, `customs-records`, `supplier-graph`, `flagship`
- **Overview**: Free search engine over 100M+ US Customs (CBP Automated Manifest System) sea bills of lading—exposing overseas factory suppliers, US buyers, HS codes, container weights, and shipment frequencies.
- **Quick-Start / Tradecraft**: `Search any brand or overseas manufacturer on https://www.importyeti.com/ to map its physical supply chain for free.`

### [BIC Container Prefix & Check-Digit Registry](https://www.bic-code.org/bic-codes/) `[A-Tier]`
- **ID**: `bic-containers` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `corporate_records`
- **Platforms**: Web · **Tags**: `iso-6346`, `shipping-containers`, `cargo-osint`, `photo-verification`
- **Overview**: Official Bureau International des Containers lookup resolving 4-letter ISO 6346 shipping container owner prefixes (e.g., `MSCU`, `MAEU`, `OOLU`) spotted in port/rail photos or videos.
- **Quick-Start / Tradecraft**: `Read the 4-letter container owner code + 7 digits from cargo imagery, verify check-digit, and resolve owner via BIC + Track-Trace.`

### [S&P Panjiva & ImportGenius](https://panjiva.com/) `[A-Tier]`
- **ID**: `panjiva-importgenius` · **Type**: `Web Platform` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `company`, `keyword`, `vessel_imo` → **Outputs**: `corporate_records`, `vessel_tracks`, `entity_graph`
- **Platforms**: Web · **Tags**: `global-customs`, `latin-america-india-trade`, `sanctions-evasion`, `supply-chain`
- **Overview**: Enterprise multi-country customs manifest databases covering US, Latin America (Mexico, Brazil, Colombia, Peru, Chile), India, Vietnam, and Pakistan import/export shipment records.
- **Quick-Start / Tradecraft**: `Journalists can apply for investigative access via GIJN/ImportGenius; use ImportYeti first for free US sea manifest coverage.`

### [Track-Trace (Multi-Carrier Container & Air Waybill)](https://www.track-trace.com/) `[A-Tier]`
- **ID**: `track-trace` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword` → **Outputs**: `vessel_tracks`, `flight_tracks`
- **Platforms**: Web · **Tags**: `container-tracking`, `air-waybill`, `bill-of-lading`, `logistics-osint`
- **Overview**: Unified multi-carrier tracking portal tracing ISO shipping containers, Bills of Lading, and 3-digit IATA Air Waybills (`AWB`) across dozens of ocean lines and air cargo carriers.
- **Quick-Start / Tradecraft**: `Enter a container ID (e.g. `MSCU1234567`) on https://www.track-trace.com/container to trace port-of-loading and vessel Voyages.`

---

## Aviation Registries & Datalinks

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Airframes.io (ACARS / VDL2 Datalink)**](https://app.airframes.io/) ([GitHub](https://github.com/airframesio/acars-bridge)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `aircraft_hex, keyword` → `signal_telemetry, flight_tracks` |
| **A** | [**FAA Aircraft Registry (N-Number Inquiry)**](https://registry.faa.gov/aircraftinquiry/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `aircraft_hex, company, person_name` → `corporate_records, person_records, flight_tracks` |
| **A** | [**LiveATC.net**](https://www.liveatc.net/) | Web Platform | Free | 🟢 Passive | ✅ | `keyword, coordinates` → `signal_telemetry, archived_pages` |
| **A** | [**Planespotters.net**](https://www.planespotters.net/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `aircraft_hex, keyword, image` → `flight_tracks, corporate_records, metadata` |

### [Airframes.io (ACARS / VDL2 Datalink)](https://app.airframes.io/) `[A-Tier]`
- **ID**: `airframes-io` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`airframesio/acars-bridge`](https://github.com/airframesio/acars-bridge)
- **Inputs**: `aircraft_hex`, `keyword` → **Outputs**: `signal_telemetry`, `flight_tracks`
- **Platforms**: Web · **Tags**: `acars`, `vdl2`, `hfdl`, `cockpit-datalink`, `aviation-sigint`
- **Overview**: Aggregates live VHF/HF/Satcom ACARS, VDL2, and HFDL plain-text cockpit datalink messages worldwide—often exposing flight numbers, maintenance faults, and dispatch texts from military/bizjets.
- **Quick-Start / Tradecraft**: `Filter by tail number or ICAO hex on https://app.airframes.io/ to read decoded ACARS text dispatches.`

### [FAA Aircraft Registry (N-Number Inquiry)](https://registry.faa.gov/aircraftinquiry/) `[A-Tier]`
- **ID**: `faa-n-number-inquiry` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `aircraft_hex`, `company`, `person_name` → **Outputs**: `corporate_records`, `person_records`, `flight_tracks`
- **Platforms**: Web · **Tags**: `tail-number`, `mode-s-hex`, `trust-ownership`, `official-us-gov`
- **Overview**: Official US Federal Aviation Administration registry mapping `N-` tail numbers to Mode-S 8-digit octal / 6-char hex codes, airframe serials, registered LLC/bank-trust owners, and downloadable CSV master dumps.
- **Quick-Start / Tradecraft**: `When an N-number is held by Wilmington Trust / TVPX Trust, request FAA Aircraft Registration FOIA trust-agreement PDFs!`

### [LiveATC.net](https://www.liveatc.net/) `[A-Tier]`
- **ID**: `liveatc` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `keyword`, `coordinates` → **Outputs**: `signal_telemetry`, `archived_pages`
- **Platforms**: Web · **Tags**: `atc-audio`, `aviation-osint`, `callsigns`, `utc-archives`
- **Overview**: Streams live VHF air traffic control tower/approach/center frequencies worldwide and stores 30-day downloadable 30-minute MP3 audio archives keyed by ICAO airport code and UTC block.
- **Quick-Start / Tradecraft**: `Pull 30-day ATC MP3 archives at https://www.liveatc.net/archive.php using airport ICAO code + exact UTC half-hour.`

### [Planespotters.net](https://www.planespotters.net/) `[A-Tier]`
- **ID**: `planespotters-net` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `aircraft_hex`, `keyword`, `image` → **Outputs**: `flight_tracks`, `corporate_records`, `metadata`
- **Platforms**: Web · **Tags**: `msn-serial`, `livery-identification`, `fleet-history`, `visual-aircraft-id`
- **Overview**: Global aviation photography and airframe production-list database tracking aircraft MSN serial numbers across every historical airline/government re-registration and paint livery change.
- **Quick-Start / Tradecraft**: `Trace an airframe's Manufacturers Serial Number (MSN) on Planespotters to link shell charter operators.`

---

## Vehicles, VINs & Rail

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Bidfax / Stat.vin Salvage Auction VIN Archives**](https://en.bidfax.info/) | Search Engine | Free | 🟢 Passive | ✅ | `vin` → `metadata, geolocation, urls` |
| **A** | [**NHTSA vPIC VIN Decoder & API**](https://vpic.nhtsa.dot.gov/decoder/) | API / Service | Free | 🟢 Passive | ✅ | `vin` → `metadata, corporate_records` |
| **A** | [**OpenRailwayMap**](https://www.openrailwaymap.org/) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `geolocation` |

### [Bidfax / Stat.vin Salvage Auction VIN Archives](https://en.bidfax.info/) `[A-Tier]`
- **ID**: `bidfax-salvage-vin` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vin` → **Outputs**: `metadata`, `geolocation`, `urls`
- **Platforms**: Web · **Tags**: `vin-osint`, `copart-iaai`, `exported-vehicles`, `auction-photos`, `bellingcat-trick`
- **Overview**: Indexes millions of historical US/Canadian Copart & IAAI insurance-auction lots by 17-char VIN—preserving 10+ high-res interior/odometer/damage photos of vehicles later exported to Eurasia, MENA, or West Africa!
- **Quick-Start / Tradecraft**: `Search any North American 17-digit VIN spotted on a foreign/conflict vehicle on https://en.bidfax.info/ to view its US auction history!`

### [NHTSA vPIC VIN Decoder & API](https://vpic.nhtsa.dot.gov/decoder/) `[A-Tier]`
- **ID**: `nhtsa-vin-decoder` · **Type**: `API / Service` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `vin` → **Outputs**: `metadata`, `corporate_records`
- **Platforms**: Web, Python · **Tags**: `vin-decoder`, `automotive-osint`, `keyless-api`, `assembly-plant`
- **Overview**: Official US DOT National Highway Traffic Safety Administration 17-character VIN decoder and completely free keyless REST/JSON API returning make, model, assembly plant, engine, and WMI manufacturer.
- **Quick-Start / Tradecraft**: `curl -s 'https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/5YJSA1E26MF123456?format=json' | jq`

### [OpenRailwayMap](https://www.openrailwaymap.org/) `[A-Tier]`
- **ID**: `openrailwaymap` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `rail-osint`, `overhead-catenary`, `track-gauge`, `train-geolocation`
- **Overview**: Detailed global rail-infrastructure overlay built on OpenStreetMap showing track gauges, electrification voltages, max speeds, signaling systems, milestones, and industrial spurs—vital for train video geolocation!
- **Quick-Start / Tradecraft**: `Switch between Infrastructure, Max Speeds, and Electrification views on https://www.openrailwaymap.org/ when geolocating rail videos.`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🔬 Image, Video & Media Forensics](./12-image-video-media-forensics.md) · [🏛️ Corporate, Finance & Sanctions ▶](./14-corporate-financial-sanctions.md)

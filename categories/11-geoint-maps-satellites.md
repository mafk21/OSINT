[⬅️ Back to Master Index](../README.md) · [◀ 💻 Code, Secrets & Cloud OSINT](./10-code-cloud-dev-osint.md) · [🔬 Image, Video & Media Forensics ▶](./12-image-video-media-forensics.md)

# 🛰️ 11. Geospatial Intelligence (GEOINT), Satellite Imagery, Mapping & Chronolocation (`GEOINT`)

> **Scope**: Multispectral & SAR satellite imagery browsers, Overpass/OpenStreetMap feature query engines, street-level ground-truth archives, solar shadow calculators, terrain skyline matchers, and conflict maps.
>
> **OPSEC Advisory**: GEOINT platforms are purely passive against real-world targets, though commercial tasking orders on high-resolution constellations may appear in archive catalogs unless private tasking is purchased.

**Discipline Telemetry**: `38` Verified Tools · `16` S-Tier Flagships · `38` Passive · `32` Free/Open-Source

## Subcategories
- [Conflict & Infrastructure Maps](#conflict-infrastructure-maps) (5)
- [Vector Feature & Proximity Search](#vector-feature-proximity-search) (4)
- [Solar Shadow & Chronolocation](#solar-shadow-chronolocation) (4)
- [Satellite & Historical Imagery](#satellite-historical-imagery) (9)
- [AI Photo Geolocation](#ai-photo-geolocation) (2)
- [GIS Desktop Workstations](#gis-desktop-workstations) (2)
- [Street-Level Ground Truth](#street-level-ground-truth) (2)
- [Thermal & Environmental Satellites](#thermal-environmental-satellites) (4)
- [Regional Maps & Street View](#regional-maps-street-view) (2)
- [Visual Clue Encyclopedias](#visual-clue-encyclopedias) (2)
- [3D Globe & Spatial Fusion](#3d-globe-spatial-fusion) (1)
- [Terrain & Skyline Matching](#terrain-skyline-matching) (1)

---

## Conflict & Infrastructure Maps

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ACLED (Armed Conflict Location & Event Data)**](https://acleddata.com/) | Dataset / Registry | Free | 🟢 Passive | 🔑 | `coordinates, keyword` → `geolocation, signal_telemetry` |
| **A** | [**DeepStateMAP**](https://deepstatemap.live/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `geolocation, satellite_imagery` |
| **A** | [**Liveuamap**](https://liveuamap.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation, urls` |
| **A** | [**MapChecking (Crowd Size Estimator)**](https://www.mapchecking.com/) ([GitHub](https://github.com/paraboul/mapchecking)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `geolocation, metadata` |
| **A** | [**Wikimapia**](https://wikimapia.org/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation` |

### [ACLED (Armed Conflict Location & Event Data)](https://acleddata.com/) `[S-Tier]`
- **ID**: `acled` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`, `signal_telemetry`
- **Platforms**: Web, Python · **Tags**: `conflict-dataset`, `protests`, `geopolitical-intel`, `research-api`
- **Overview**: Gold-standard empirical dataset coding exact dates, coordinates, actors, event types (battles, drone strikes, protests, riots), and source citations for political violence globally.
- **Quick-Start / Tradecraft**: `Register a free ACLED Access Portal key to export CSV/GeoJSON conflict events for QGIS mapping.`

### [DeepStateMAP](https://deepstatemap.live/) `[A-Tier]`
- **ID**: `deepstatemap` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `satellite_imagery`
- **Platforms**: Web · **Tags**: `conflict-mapping`, `daily-frontlines`, `firms-overlay`, `chronological-slider`
- **Overview**: Geolocated open-source conflict control-line map featuring historical daily timeline sliders, ruler/azimuth tools, FIRMS fire overlays, and verified incident citations.
- **Quick-Start / Tradecraft**: `Scrub the calendar control on https://deepstatemap.live/ to verify territorial status on any historical date.`

### [Liveuamap](https://liveuamap.com/) `[A-Tier]`
- **ID**: `liveuamap` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`, `urls`
- **Platforms**: Web · **Tags**: `live-conflict-map`, `historical-playback`, `crisis-monitoring`
- **Overview**: Near-real-time geolocated conflict, disaster, and security-incident map across 30+ regional theaters with historical date-picker playback back to 2014.
- **Quick-Start / Tradecraft**: `Use the top-bar calendar widget on https://liveuamap.com/ to reconstruct chronological incident timelines on a specific date.`

### [MapChecking (Crowd Size Estimator)](https://www.mapchecking.com/) `[A-Tier]`
- **ID**: `mapchecking` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`paraboul/mapchecking`](https://github.com/paraboul/mapchecking)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `metadata`
- **Platforms**: Web · **Tags**: `crowd-counting`, `protest-verification`, `fact-checking`, `polygon-area`
- **Overview**: Fact-checking calculator estimating realistic protest, rally, or stadium crowd headcounts by drawing the occupied street polygon and testing density sliders (0.5 to 4 people/m²).
- **Quick-Start / Tradecraft**: `Draw the crowd boundary observed in aerial/rooftop photos on https://www.mapchecking.com/ to debunk inflated attendance claims.`

### [Wikimapia](https://wikimapia.org/) `[A-Tier]`
- **ID**: `wikimapia` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `facility-polygons`, `military-bases`, `industrial-sites`, `crowdsourced`
- **Overview**: 20-year crowdsourced polygon annotation layer naming obscure industrial complexes, military depots, training ranges, mines, compounds, and local neighborhoods worldwide.
- **Quick-Start / Tradecraft**: `Inspect polygon revision history and multilingual comments on https://wikimapia.org/ to identify unnamed facilities.`

---

## Vector Feature & Proximity Search

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Bellingcat OpenStreetMap Search**](https://osm-search.bellingcat.com/) ([GitHub](https://github.com/bellingcat/osm-search)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation` |
| **S** | [**Overpass Turbo (OpenStreetMap Query Engine)**](https://overpass-turbo.eu/) ([GitHub](https://github.com/tyrasd/overpass-turbo)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation, entity_graph` |
| **A** | [**Overpass Ultra**](https://overpass-ultra.us/) ([GitHub](https://github.com/trailstash/ultra)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation` |
| **B** | [**Sightline (OSM Infrastructure Search)**](https://github.com/ni5arga/sightline) ([GitHub](https://github.com/ni5arga/sightline)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation` |

### [Bellingcat OpenStreetMap Search](https://osm-search.bellingcat.com/) `[S-Tier]`
- **ID**: `bellingcat-osm-search` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`bellingcat/osm-search`](https://github.com/bellingcat/osm-search)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `bellingcat`, `no-code-overpass`, `proximity-geolocation`, `osm`
- **Overview**: Point-and-click visual builder wrapping Overpass QL so investigators can select up to 5 visible features (e.g., power line, mosque, roundabout, river) and distance tolerances without writing code.
- **Quick-Start / Tradecraft**: `Select visible photo landmarks + max distance slider on https://osm-search.bellingcat.com/ and export matches to Google Earth.`

### [Overpass Turbo (OpenStreetMap Query Engine)](https://overpass-turbo.eu/) `[S-Tier]`
- **ID**: `overpass-turbo` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`tyrasd/overpass-turbo`](https://github.com/tyrasd/overpass-turbo)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`, `entity_graph`
- **Platforms**: Web · **Tags**: `openstreetmap`, `overpass-ql`, `photo-geolocation`, `spatial-constraints`, `flagship`
- **Overview**: The single most powerful deterministic photo-geolocation tool: executes spatial queries against OpenStreetMap's global vector database to find exact geometric arrangements of roads, towers, bridges, and shops.
- **Quick-Start / Tradecraft**: `Chain `around:100` filters in Overpass QL to find e.g. every school within 100m of both a water tower and railway line!`

### [Overpass Ultra](https://overpass-ultra.us/) `[A-Tier]`
- **ID**: `overpass-ultra` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`trailstash/ultra`](https://github.com/trailstash/ultra)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `maplibre`, `overpass-ql`, `webgl-gis`, `fast-rendering`
- **Overview**: Modern MapLibre GL vector-rendered successor to Overpass Turbo handling massive multi-thousand-feature spatial queries smoothly in browser WebGL.
- **Quick-Start / Tradecraft**: `Use https://overpass-ultra.us/ when standard Overpass Turbo chokes on country-scale OpenStreetMap result sets.`

### [Sightline (OSM Infrastructure Search)](https://github.com/ni5arga/sightline) `[B-Tier]`
- **ID**: `sightline` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`ni5arga/sightline`](https://github.com/ni5arga/sightline)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web, Node.js · **Tags**: `critical-infrastructure`, `osm-search`, `power-grids`, `geoint`
- **Overview**: Open-source OSINT search engine for mapping and querying real-world physical infrastructure (substations, telecom towers, pipelines, airfields, ports) extracted from OpenStreetMap.
- **Quick-Start / Tradecraft**: `Clone `ni5arga/sightline` for rapid critical-infrastructure geospatial filtering.`

---

## Solar Shadow & Chronolocation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Bellingcat ShadowFinder**](https://shadowfinder.bellingcat.com/) ([GitHub](https://github.com/bellingcat/ShadowFinder)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `image, keyword` → `geolocation` |
| **S** | [**SunCalc**](https://www.suncalc.org/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `geolocation, metadata` |
| **S** | [**Wolfram\|Alpha Historical Weather & Astronomy**](https://www.wolframalpha.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `coordinates, keyword` → `metadata, geolocation` |
| **A** | [**Shadowmap**](https://app.shadowmap.org/) | Web Platform | Freemium | 🟢 Passive | ✅ | `coordinates` → `geolocation` |

### [Bellingcat ShadowFinder](https://shadowfinder.bellingcat.com/) `[S-Tier]`
- **ID**: `bellingcat-shadowfinder` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`bellingcat/ShadowFinder`](https://github.com/bellingcat/ShadowFinder)
- **Inputs**: `image`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web, Python · **Tags**: `bellingcat`, `shadow-length`, `chronolocation`, `solar-geometry`
- **Overview**: Inverts SunCalc math: given a known UTC timestamp plus the ratio of an object's height to its shadow length, plots the exact curved band of Earth where that shadow length is physically possible.
- **Quick-Start / Tradecraft**: `Measure vertical pole pixel height vs shadow pixel length and run on https://shadowfinder.bellingcat.com/.`

### [SunCalc](https://www.suncalc.org/) `[S-Tier]`
- **ID**: `suncalc` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `metadata`
- **Platforms**: Web · **Tags**: `chronolocation`, `shadow-azimuth`, `solar-angles`, `verification`, `flagship`
- **Overview**: Computes solar azimuth, altitude angle, shadow length ratios, dawn/dusk twilight phases, and sun trajectory arcs for any coordinate and date/time on Earth.
- **Quick-Start / Tradecraft**: `Enter object height in SunCalc's top-left panel and match the orange shadow-direction vector against shadows in a photo.`

### [Wolfram|Alpha Historical Weather & Astronomy](https://www.wolframalpha.com/) `[S-Tier]`
- **ID**: `wolfram-alpha` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `metadata`, `geolocation`
- **Platforms**: Web · **Tags**: `historical-weather`, `metar-archives`, `moon-phase`, `chronolocation`, `flagship`
- **Overview**: Queries historical airport METAR weather stations worldwide for exact temperature, cloud cover, wind speed, precipitation, moon phase, and twilight at any city and historic date/hour!
- **Quick-Start / Tradecraft**: `Query `weather in Kyiv on March 14, 2025 at 14:00` on https://www.wolframalpha.com/ to verify rain/snow/cloud claims in videos!`

### [Shadowmap](https://app.shadowmap.org/) `[A-Tier]`
- **ID**: `shadowmap` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `3d-shadows`, `urban-chronolocation`, `terrain-shadows`, `visual-verification`
- **Overview**: Interactive global 3D building and terrain sunlight/shadow simulator rendering real-world cast shadows across urban canyons and mountains for any date and minute of the year.
- **Quick-Start / Tradecraft**: `Scrub the time slider on https://app.shadowmap.org/ to match building facade shadows in urban videos.`

---

## Satellite & Historical Imagery

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Copernicus Data Space Browser**](https://browser.dataspace.copernicus.eu/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |
| **S** | [**Esri World Imagery Wayback**](https://livingatlas.arcgis.com/wayback/) ([GitHub](https://github.com/vannizhang/wayback)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |
| **S** | [**Google Earth Pro**](https://www.google.com/earth/about/versions/) | Desktop App | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `satellite_imagery, geolocation` |
| **S** | [**NASA Worldview**](https://worldview.earthdata.nasa.gov/) ([GitHub](https://github.com/nasa-gibs/worldview)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |
| **A** | [**Maxar Open Data Program**](https://www.maxar.com/open-data) | Dataset / Registry | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `satellite_imagery` |
| **A** | [**OpenAerialMap**](https://map.openaerialmap.org/) ([GitHub](https://github.com/hotosm/OpenAerialMap)) | Dataset / Registry | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |
| **A** | [**Satellites.pro**](https://satellites.pro/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |
| **A** | [**SkyFi**](https://www.skyfi.com/) | Web Platform | Freemium | 🟢 Passive | 🔑 | `coordinates` → `satellite_imagery` |
| **A** | [**USGS EarthExplorer**](https://earthexplorer.usgs.gov/) | Dataset / Registry | Free | 🟢 Passive | 🔑 | `coordinates` → `satellite_imagery, geolocation` |

### [Copernicus Data Space Browser](https://browser.dataspace.copernicus.eu/) `[S-Tier]`
- **ID**: `copernicus-browser` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `sentinel-2`, `sentinel-1-sar`, `esa-copernicus`, `swir-fires`, `time-lapse`, `flagship`
- **Overview**: Official ESA portal (replacing retired Sentinel Hub EO Browser) providing free global Sentinel-1 SAR (cloud-penetrating radar!) and 10m Sentinel-2 optical/SWIR/NDVI imagery every ~5 days.
- **Quick-Start / Tradecraft**: `Switch to Sentinel-2 L2A False Color / SWIR for burn scars & fires, or Sentinel-1 SAR for ships/military radar interference!`

### [Esri World Imagery Wayback](https://livingatlas.arcgis.com/wayback/) `[S-Tier]`
- **ID**: `esri-wayback` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`vannizhang/wayback`](https://github.com/vannizhang/wayback)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `high-res-archive`, `maxar-basemaps`, `swipe-compare`, `change-detection`
- **Overview**: Digital archive of 150+ historical global high-resolution satellite basemap releases from Maxar/Earthstar since 2014 with swipe comparison and local-change filtering.
- **Quick-Start / Tradecraft**: `Check 'Only versions with local changes' on https://livingatlas.arcgis.com/wayback/ to step through every capture at a site.`

### [Google Earth Pro](https://www.google.com/earth/about/versions/) `[S-Tier]`
- **ID**: `google-earth-pro` · **Type**: `Desktop App` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Windows, macOS, Linux, Web · **Tags**: `historical-imagery`, `3d-terrain`, `viewshed`, `kml`, `flagship`
- **Overview**: Indispensable desktop 3D globe offering multi-decade Historical Imagery time-sliders, 3D terrain skyline simulation, sun-lighting previews, viewshed analysis, and KML/KMZ case overlays.
- **Quick-Start / Tradecraft**: `Use the Historical Imagery clock icon in Google Earth Pro Desktop to pinpoint exact construction/demolition dates.`

### [NASA Worldview](https://worldview.earthdata.nasa.gov/) `[S-Tier]`
- **ID**: `nasa-worldview` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`nasa-gibs/worldview`](https://github.com/nasa-gibs/worldview)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `daily-satellite`, `night-lights`, `weather-verification`, `nasa-gibs`
- **Overview**: Interactive browser over 1,200+ daily global NASA satellite imagery layers—many updated within 3 hours of overpass—for smoke plumes, cloud cover verification, floods, and night-lights blackouts.
- **Quick-Start / Tradecraft**: `Compare historical cloud cover on NASA Worldview to verify whether a claimed outdoor photo matches that day's sky!`

### [Maxar Open Data Program](https://www.maxar.com/open-data) `[A-Tier]`
- **ID**: `maxar-open-data` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `satellite_imagery`
- **Platforms**: Web · **Tags**: `30cm-imagery`, `disaster-response`, `geotiff`, `stac-catalog`
- **Overview**: Publishes free 30cm–50cm ultra-high-resolution pre- and post-event commercial satellite GeoTIFFs under Creative Commons for major earthquakes, floods, wildfires, and humanitarian crises.
- **Quick-Start / Tradecraft**: `Browse Maxar's public AWS S3 STAC catalog via QGIS or Leafmap (`aws s3 ls s3://maxar-opendata/ --no-sign-request`).`

### [OpenAerialMap](https://map.openaerialmap.org/) `[A-Tier]`
- **ID**: `openaerialmap` · **Type**: `Dataset / Registry` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`hotosm/OpenAerialMap`](https://github.com/hotosm/OpenAerialMap)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `drone-orthomosaics`, `5cm-uav`, `humanitarian-osm`, `geotiff`
- **Overview**: Open Humanitarian OpenStreetMap Team repository of centimeter-resolution openly licensed drone/UAV orthomosaics and post-disaster aerial captures worldwide.
- **Quick-Start / Tradecraft**: `Check https://map.openaerialmap.org/ for ultra-sharp UAV imagery over disaster/urban zones.`

### [Satellites.pro](https://satellites.pro/) `[A-Tier]`
- **ID**: `satellites-pro` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `apple-maps-satellite`, `basemap-comparison`, `no-login`, `fast-switcher`
- **Overview**: Instant one-click basemap switcher comparing Apple Maps Satellite (often sharper & fresher than Google in Europe/MENA!), Google, Esri, Yandex, Mapbox, and OpenStreetMap at identical coordinates.
- **Quick-Start / Tradecraft**: `Always check the 'Apple Satellite' layer on https://satellites.pro/—Apple often captures different months/angles than Google!`

### [SkyFi](https://www.skyfi.com/) `[A-Tier]`
- **ID**: `skyfi` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`
- **Platforms**: Web · **Tags**: `on-demand-tasking`, `commercial-sar`, `high-res-optical`, `archive-search`
- **Overview**: Self-serve commercial satellite marketplace allowing individual researchers to buy archive scenes or task new 15cm–50cm optical, SAR, and thermal captures on demand without enterprise contracts.
- **Quick-Start / Tradecraft**: `Use SkyFi Explore & free low-res previews to check exact commercial satellite pass dates over an AOI.`

### [USGS EarthExplorer](https://earthexplorer.usgs.gov/) `[A-Tier]`
- **ID**: `usgs-earthexplorer` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `landsat`, `declassified-corona`, `srtm-dem`, `aerial-archives`, `usgs`
- **Overview**: US Geological Survey archive granting free downloads of 50+ years of Landsat multispectral scenes, NAIP aerial photography, SRTM digital elevation models, and declassified Cold War CORONA/KH-9 spy-sat photos.
- **Quick-Start / Tradecraft**: `Draw a polygon on https://earthexplorer.usgs.gov/ to pull Landsat 8/9 scenes or declassified KH-9 Hexagon imagery.`

---

## AI Photo Geolocation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**geo-sleuth**](https://github.com/Oldcircle/geo-sleuth) ([GitHub](https://github.com/Oldcircle/geo-sleuth)) | AI / MCP | OSS / Free | 🟢 Passive | ✅ | `image` → `geolocation, satellite_imagery` |
| **A** | [**Picarta.ai**](https://picarta.ai/) ([GitHub](https://github.com/Picarta/picarta-py)) | Web Platform | Freemium | 🟢 Passive | 🔑 | `image` → `geolocation` |

### [geo-sleuth](https://github.com/Oldcircle/geo-sleuth) `[S-Tier]`
- **ID**: `geo-sleuth` · **Type**: `AI / MCP` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Oldcircle/geo-sleuth`](https://github.com/Oldcircle/geo-sleuth)
- **Inputs**: `image` → **Outputs**: `geolocation`, `satellite_imagery`
- **Platforms**: Linux, macOS, Python · **Tags**: `ai-geolocation`, `agent-skill`, `explainable-geoint`, `osm-geometry`
- **Overview**: Open-source autonomous geolocation agent skill combining OpenStreetMap road/building geometry, elevation skyline matching, satellite imagery, and Street View to geolocate photos with explainable evidence.
- **Quick-Start / Tradecraft**: `Install `Oldcircle/geo-sleuth` skill in Claude Code / Codex / Cursor to run multi-step verifiable photo geolocation.`

### [Picarta.ai](https://picarta.ai/) `[A-Tier]`
- **ID**: `picarta` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key) · **GitHub**: [`Picarta/picarta-py`](https://github.com/Picarta/picarta-py)
- **Inputs**: `image` → **Outputs**: `geolocation`
- **Platforms**: Web, Python · **Tags**: `ai-geolocator`, `no-exif`, `geospy-alternative`, `visual-recognition`
- **Overview**: Deep-learning visual photo geolocation platform and Python SDK predicting top GPS coordinate candidates worldwide from architecture, flora, soil, and signage when EXIF is stripped.
- **Quick-Start / Tradecraft**: `Upload cropped exterior scenery (masking faces) to https://picarta.ai/ to generate regional candidate pins, then verify in OSM/Earth.`

---

## GIS Desktop Workstations

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Map Switcher (Browser Extension)**](https://chromewebstore.google.com/detail/map-switcher/fanpjcbgemkfjgpkefdbcdbeebbibhbp) ([GitHub](https://github.com/autonome/map-switcher)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `coordinates, url` → `geolocation` |
| **S** | [**QGIS**](https://qgis.org/) ([GitHub](https://github.com/qgis/QGIS)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `coordinates, document` → `geolocation, satellite_imagery` |

### [Map Switcher (Browser Extension)](https://chromewebstore.google.com/detail/map-switcher/fanpjcbgemkfjgpkefdbcdbeebbibhbp) `[S-Tier]`
- **ID**: `map-switcher-ext` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`autonome/map-switcher`](https://github.com/autonome/map-switcher)
- **Inputs**: `coordinates`, `url` → **Outputs**: `geolocation`
- **Platforms**: Chrome, Firefox · **Tags**: `coordinate-jumping`, `25-maps`, `geoint-accelerator`, `open-source`
- **Overview**: One-click browser extension jumping your current map viewport (exact lat, lon, zoom) instantly between Google Maps, OSM, Overpass Turbo, Mapillary, Bing, Yandex, Sentinel/Copernicus, and Wikimapia!
- **Quick-Start / Tradecraft**: `Pin Map Switcher in your toolbar so you never manually copy-paste coordinates between Google Maps, Overpass, and SunCalc again!`

### [QGIS](https://qgis.org/) `[S-Tier]`
- **ID**: `qgis` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`qgis/QGIS`](https://github.com/qgis/QGIS)
- **Inputs**: `coordinates`, `document` → **Outputs**: `geolocation`, `satellite_imagery`
- **Platforms**: Windows, macOS, Linux · **Tags**: `gis`, `geotiff`, `viewshed`, `raster-analysis`, `cartography`, `flagship`
- **Overview**: World's flagship open-source Geographic Information System desktop workstation for fusing Sentinel/Maxar GeoTIFF rasters, Overpass GeoJSON layers, AIS/ADS-B tracks, and visibility viewsheds.
- **Quick-Start / Tradecraft**: `Install QuickMapServices + QuickOSM + Lat Lon Tools plugins in QGIS for rapid OSINT basemap and vector fusion.`

---

## Street-Level Ground Truth

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Mapillary**](https://www.mapillary.com/app/) ([GitHub](https://github.com/mapillary/mapillary_tools)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `geolocation` |
| **A** | [**KartaView**](https://kartaview.org/) ([GitHub](https://github.com/kartaview/openstreetcam.org)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `geolocation` |

### [Mapillary](https://www.mapillary.com/app/) `[S-Tier]`
- **ID**: `mapillary` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`mapillary/mapillary_tools`](https://github.com/mapillary/mapillary_tools)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`
- **Platforms**: Web, Python · **Tags**: `street-level-imagery`, `crowdsourced`, `ground-truth`, `dashcam`
- **Overview**: Over 2 billion crowdsourced street-level dashcam and walking images worldwide, offering coverage in countries, conflict zones, and rural roads where Google Street View has never driven.
- **Quick-Start / Tradecraft**: `Toggle time-filter and traffic-sign detection layers on https://www.mapillary.com/app/.`

### [KartaView](https://kartaview.org/) `[A-Tier]`
- **ID**: `kartaview` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`kartaview/openstreetcam.org`](https://github.com/kartaview/openstreetcam.org)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `street-view-alternative`, `southeast-asia`, `open-data`, `ground-truth`
- **Overview**: Open-licensed crowdsourced street-level photo platform (maintained by Grab/OSM community) providing dense ground-level street sequences especially across Southeast Asia, Eastern Europe, and Latin America.
- **Quick-Start / Tradecraft**: `Check https://kartaview.org/ alongside Mapillary, Yandex Panorama, and Baidu Street View when Google coverage is blank.`

---

## Thermal & Environmental Satellites

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**NASA FIRMS (Fire Information for Resource Management System)**](https://firms.modaps.eosdis.nasa.gov/map/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation, signal_telemetry` |
| **A** | [**earth.nullschool.net (Global Wind, Ocean & Smoke)**](https://earth.nullschool.net/) ([GitHub](https://github.com/cambecc/earth)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `geolocation, signal_telemetry` |
| **A** | [**Global Forest Watch**](https://www.globalforestwatch.org/map/) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |
| **A** | [**Zoom Earth**](https://zoom.earth/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates` → `satellite_imagery, geolocation` |

### [NASA FIRMS (Fire Information for Resource Management System)](https://firms.modaps.eosdis.nasa.gov/map/) `[S-Tier]`
- **ID**: `nasa-firms` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `thermal-anomalies`, `viirs-375m`, `conflict-osint`, `wildfires`, `nasa`, `flagship`
- **Overview**: Near-real-time global thermal anomaly map from MODIS and VIIRS polar-orbiting satellites (375m resolution)—routinely used in OSINT to detect wildfires, refinery strikes, gas flaring, and artillery barrages.
- **Quick-Start / Tradecraft**: `Enable VIIRS S-NPP / NOAA-20 / NOAA-21 375m layers + Time-Based color coding on https://firms.modaps.eosdis.nasa.gov/map/.`

### [earth.nullschool.net (Global Wind, Ocean & Smoke)](https://earth.nullschool.net/) `[A-Tier]`
- **ID**: `nullschool-earth` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`cambecc/earth`](https://github.com/cambecc/earth)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `signal_telemetry`
- **Platforms**: Web · **Tags**: `wind-direction`, `smoke-plume-azimuth`, `particulates`, `historical-weather`
- **Overview**: Interactive 3D globe visualizing historical and live global GFS wind vectors, ocean currents, particulate smoke (`PM2.5`/`SO2`/`CO`), and wave heights—vital for verifying smoke drift direction in strike videos!
- **Quick-Start / Tradecraft**: `Click 'earth' bottom-left -> adjust UTC date/hour -> compare wind vector azimuth against smoke plume direction in video!`

### [Global Forest Watch](https://www.globalforestwatch.org/map/) `[A-Tier]`
- **ID**: `global-forest-watch` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `illegal-mining`, `clandestine-airstrips`, `deforestation-radar`, `environmental-crime`
- **Overview**: World Resources Institute satellite monitoring platform offering weekly radar/optical deforestation alerts (`GLAD`/`RADD`)—used in OSINT to spot illegal mining airstrips, logging roads, and jungle camps.
- **Quick-Start / Tradecraft**: `Enable Sentinel-1 RADD radar disturbance alerts on Global Forest Watch to detect new clearings under tropical cloud cover!`

### [Zoom Earth](https://zoom.earth/) `[A-Tier]`
- **ID**: `zoom-earth` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates` → **Outputs**: `satellite_imagery`, `geolocation`
- **Platforms**: Web · **Tags**: `10min-geostationary`, `cloud-verification`, `smoke-plumes`, `weather-osint`
- **Overview**: Near-real-time geostationary weather satellite imagery (GOES/Himawari/Meteosat every 10–15 minutes!), active wildfire hotspots, storm tracks, and historical cloud-cover playback.
- **Quick-Start / Tradecraft**: `Verify exact cloud formations and smoke plume wind drift at 15-minute intervals on https://zoom.earth/!`

---

## Regional Maps & Street View

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Yandex Maps & Street Panoramas**](https://yandex.com/maps/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation, satellite_imagery` |
| **A** | [**Baidu Maps & Total View**](https://map.baidu.com/) | Web Platform | Free | 🟢 Passive | ✅ | `coordinates, keyword` → `geolocation` |

### [Yandex Maps & Street Panoramas](https://yandex.com/maps/) `[S-Tier]`
- **ID**: `yandex-maps` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`, `satellite_imagery`
- **Platforms**: Web · **Tags**: `eastern-europe`, `central-asia`, `street-panoramas`, `uncensored-blurring`
- **Overview**: Essential satellite, business directory, and street-level panorama map covering Russia, Ukraine, Central Asia, Caucasus, Turkey, and MENA—often featuring higher-res local aerials than Google.
- **Quick-Start / Tradecraft**: `Compare Yandex satellite & Mirror/Panorama layers when Google blurs or outdatedly renders Eurasian/MENA sites.`

### [Baidu Maps & Total View](https://map.baidu.com/) `[A-Tier]`
- **ID**: `baidu-maps` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `china-geoint`, `bd09-offset`, `street-view`, `poi-search`
- **Overview**: Primary street-view ('Total View'), 3D building footprint, and POI directory for mainland China—note China uses GCJ-02 / BD-09 coordinate offsets relative to WGS-84 GPS!
- **Quick-Start / Tradecraft**: `Convert BD-09 coordinates back to WGS-84 before plotting Baidu Map pins into Google Earth or QGIS!`

---

## Visual Clue Encyclopedias

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**GeoHints**](https://geohints.com/) | Web Platform | Free | 🟢 Passive | ✅ | `image, keyword` → `geolocation` |
| **A** | [**Plonk It Guide**](https://www.plonkit.net/guide) | Web Platform | Free | 🟢 Passive | ✅ | `image, keyword` → `geolocation` |

### [GeoHints](https://geohints.com/) `[A-Tier]`
- **ID**: `geohints` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `bollards`, `utility-poles`, `road-markings`, `license-plates`, `country-id`
- **Overview**: Visual reference encyclopedia cataloging country-specific roadside bollards, utility poles, guardrails, road markings, pedestrian signs, mailboxes, and license plates.
- **Quick-Start / Tradecraft**: `Match unknown roadside bollards, chevrons, or utility poles on https://geohints.com/ to narrow down the country in seconds.`

### [Plonk It Guide](https://www.plonkit.net/guide) `[A-Tier]`
- **ID**: `plonk-it` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `keyword` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `regional-clues`, `architecture`, `flora-soil`, `geoguessr-osint`
- **Overview**: Deep country-by-country and sub-regional visual recognition manual detailing regional architecture, phone area codes, vegetation, soil color, and camera-generation clues across 130+ countries.
- **Quick-Start / Tradecraft**: `Use Plonk It's sub-regional maps (e.g., Brazil, Russia, Indonesia, Mexico state clues) after identifying the country.`

---

## 3D Globe & Spatial Fusion

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**God's Eye View**](https://github.com/bilawalsidhu/gods-eye-view) ([GitHub](https://github.com/bilawalsidhu/gods-eye-view)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `coordinates` → `geolocation, flight_tracks, signal_telemetry` |

### [God's Eye View](https://github.com/bilawalsidhu/gods-eye-view) `[A-Tier]`
- **ID**: `gods-eye-view` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`bilawalsidhu/gods-eye-view`](https://github.com/bilawalsidhu/gods-eye-view)
- **Inputs**: `coordinates` → **Outputs**: `geolocation`, `flight_tracks`, `signal_telemetry`
- **Platforms**: Web, Node.js · **Tags**: `3d-globe`, `cesium`, `spatial-intelligence`, `live-telemetry`
- **Overview**: Open-source photorealistic 3D browser spatial-intelligence globe fusing live ADS-B aircraft, CelesTrak orbital satellites, traffic cameras, and Cesium 3D tiles into one real-time tactical view.
- **Quick-Start / Tradecraft**: `Clone `bilawalsidhu/gods-eye-view`, configure Cesium/Google 3D Tiles key, and launch local spatial fusion view.`

---

## Terrain & Skyline Matching

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**PeakVisor / PeakFinder**](https://www.peakfinder.com/) | Web Platform | Freemium | 🟢 Passive | ✅ | `coordinates, image` → `geolocation` |

### [PeakVisor / PeakFinder](https://www.peakfinder.com/) `[A-Tier]`
- **ID**: `peakvisor` · **Type**: `Web Platform` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `coordinates`, `image` → **Outputs**: `geolocation`
- **Platforms**: Web · **Tags**: `horizon-matching`, `mountain-skylines`, `dem-terrain`, `rural-geolocation`
- **Overview**: Generates synthetic 360-degree mountain horizon skylines from global digital elevation models (DEMs) at any coordinate and elevation—allowing investigators to triangulate rural photos from distant ridgelines.
- **Quick-Start / Tradecraft**: `Match distant mountain silhouettes on https://www.peakfinder.com/ to lock down exact camera azimuth and valley position.`

---
[⬅️ Back to Master Index](../README.md) · [◀ 💻 Code, Secrets & Cloud OSINT](./10-code-cloud-dev-osint.md) · [🔬 Image, Video & Media Forensics ▶](./12-image-video-media-forensics.md)

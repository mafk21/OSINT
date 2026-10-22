[⬅️ Back to Master Index](../README.md) · [◀ 🛰️ GEOINT, Maps & Satellites](./11-geoint-maps-satellites.md) · [✈️ Aviation, Maritime & Transport ▶](./13-aviation-maritime-transport.md)

# 🔬 12. Image, Video, Facial Recognition, Audio & Digital Media Forensics (IMINT) (`IMINT`)

> **Scope**: Reverse image and facial recognition search engines, EXIF/XMP metadata extractors, Error Level Analysis (ELA) & clone-detection labs, video keyframe verifiers, deepfake detectors, and bioacoustic/audio analyzers.
>
> **OPSEC Advisory**: Uploading sensitive or unreleased investigation photos to cloud reverse-image or face-search engines (Yandex, PimEyes, VirusTotal-style sandboxes) can cache or index the image; strip borders/EXIF and crop carefully.

**Discipline Telemetry**: `25` Verified Tools · `10` S-Tier Flagships · `25` Passive · `21` Free/Open-Source

## Subcategories
- [Metadata & Container Forensics](#metadata-container-forensics) (3)
- [Media Preservation & Frame Tools](#media-preservation-frame-tools) (3)
- [Video & Manipulation Verification](#video-manipulation-verification) (3)
- [Reverse Image & Visual Search](#reverse-image-visual-search) (7)
- [Facial Recognition Search](#facial-recognition-search) (3)
- [Bioacoustic & Audio Forensics](#bioacoustic-audio-forensics) (2)
- [Conflict & Remnant Verification](#conflict-remnant-verification) (1)
- [AI & Deepfake Detection](#ai-deepfake-detection) (2)
- [Document & Image De-obfuscation](#document-image-de-obfuscation) (1)

---

## Metadata & Container Forensics

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**ExifTool**](https://exiftool.org/) ([GitHub](https://github.com/exiftool/exiftool)) | CLI | OSS / Free | 🟢 Passive | ✅ | `image, video, audio` → `metadata, geolocation, person_records` |
| **B** | [**Aperi'Solve**](https://www.aperisolve.com/) ([GitHub](https://github.com/Zeecka/AperiSolve)) | Web Platform | OSS / Free | 🟢 Passive | ✅ | `image` → `metadata, secrets` |
| **B** | [**Jimpl Online EXIF & GPS Viewer**](https://jimpl.com/) | Web Platform | Free | 🟢 Passive | ✅ | `image` → `metadata, geolocation` |

### [ExifTool](https://exiftool.org/) `[S-Tier]`
- **ID**: `exiftool` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`exiftool/exiftool`](https://github.com/exiftool/exiftool)
- **Inputs**: `image`, `video`, `audio`, `document` → **Outputs**: `metadata`, `geolocation`, `person_records`
- **Platforms**: Linux, macOS, Windows, Docker · **Tags**: `metadata`, `exif-gps`, `pdf-forensics`, `quicktime-atoms`, `flagship`
- **Overview**: Phil Harvey's legendary Perl CLI/library reading, writing, and auditing EXIF, GPS, XMP, IPTC, ICC, QuickTime atoms, PDF producer tags, and Office revision metadata across 400+ file formats.
- **Quick-Start / Tradecraft**: `exiftool -a -u -g1 -ee -c '%.6f' suspect_media.mp4  # -ee extracts embedded GPS tracks from action-cam/drone videos!`

### [Aperi'Solve](https://www.aperisolve.com/) `[B-Tier]`
- **ID**: `aperisolve` · **Type**: `Web Platform` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`Zeecka/AperiSolve`](https://github.com/Zeecka/AperiSolve)
- **Inputs**: `image` → **Outputs**: `metadata`, `secrets`
- **Platforms**: Web, Docker, Python · **Tags**: `bit-planes`, `binwalk`, `hidden-payloads`, `ctf-forensics`
- **Overview**: Open-source multi-layer image inspection platform running ExifTool, `zsteg`, `steghide`, `outguess`, `binwalk`, `foremost`, `strings`, and RGB bit-plane decomposition in one view.
- **Quick-Start / Tradecraft**: `Self-host via Docker for sensitive images or inspect non-sensitive files on https://www.aperisolve.com/.`

### [Jimpl Online EXIF & GPS Viewer](https://jimpl.com/) `[B-Tier]`
- **ID**: `jimpl-exif` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image` → **Outputs**: `metadata`, `geolocation`
- **Platforms**: Web · **Tags**: `quick-exif`, `gps-plotter`, `beginner-friendly`
- **Overview**: Clean, no-install web EXIF/IPTC/XMP metadata inspector plotting embedded GPS coordinates on a map (use local `exiftool` or `Forensically` instead if the image is confidential!).
- **Quick-Start / Tradecraft**: `Use only on already-public images; for confidential evidence always run `exiftool` locally.`

---

## Media Preservation & Frame Tools

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**FFmpeg**](https://ffmpeg.org/) ([GitHub](https://github.com/FFmpeg/FFmpeg)) | CLI | OSS / Free | 🟢 Passive | ✅ | `video, audio` → `metadata` |
| **S** | [**yt-dlp**](https://github.com/yt-dlp/yt-dlp) ([GitHub](https://github.com/yt-dlp/yt-dlp)) | CLI | OSS / Free | 🟢 Passive | ✅ | `url` → `archived_pages, metadata` |
| **A** | [**Hugin Panorama Stitcher**](https://hugin.sourceforge.io/) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `image, video` → `geolocation` |

### [FFmpeg](https://ffmpeg.org/) `[S-Tier]`
- **ID**: `ffmpeg` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`FFmpeg/FFmpeg`](https://github.com/FFmpeg/FFmpeg)
- **Inputs**: `video`, `audio` → **Outputs**: `metadata`
- **Platforms**: Linux, macOS, Windows, Docker · **Tags**: `keyframe-extraction`, `video-stabilization`, `ffprobe`, `audio-isolation`
- **Overview**: Universal open-source audio/video Swiss-army knife used in OSINT to dump lossless keyframes, stabilize shaky eyewitness clips (`vidstab`), isolate background audio, and inspect stream headers (`ffprobe`).
- **Quick-Start / Tradecraft**: `ffmpeg -i clip.mp4 -vf "select='eq(pict_type,PICT_TYPE_I)'" -vsync vfr frame_%04d.png`

### [yt-dlp](https://github.com/yt-dlp/yt-dlp) `[S-Tier]`
- **ID**: `yt-dlp` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`yt-dlp/yt-dlp`](https://github.com/yt-dlp/yt-dlp)
- **Inputs**: `url` → **Outputs**: `archived_pages`, `metadata`
- **Platforms**: Linux, macOS, Windows, Docker, Python · **Tags**: `video-preservation`, `1800-extractors`, `info-json`, `subtitles`, `flagship`
- **Overview**: De facto open-source media archiver supporting 1,800+ video/social platforms (YouTube, X, TikTok, Rumble, Telegram,VK, news sites) with `--write-info-json` forensic metadata sidecars.
- **Quick-Start / Tradecraft**: `yt-dlp --write-info-json --write-subs --write-thumbnail -o '%(extractor)s_%(id)s.%(ext)s' '<URL>'`

### [Hugin Panorama Stitcher](https://hugin.sourceforge.io/) `[A-Tier]`
- **ID**: `hugin` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `video` → **Outputs**: `geolocation`
- **Platforms**: Windows, macOS, Linux · **Tags**: `video-panorama`, `frame-stitching`, `photogrammetry`, `geolocation-prep`
- **Overview**: Open-source photogrammetry stitcher used by Bellingcat and visual-investigations teams to stitch panning handheld video frames into one wide-angle composite panorama for architectural geolocation.
- **Quick-Start / Tradecraft**: `Extract 10–20 overlapping frames from a panning video with FFmpeg, then stitch into a single streetscape in Hugin.`

---

## Video & Manipulation Verification

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Forensically (29a.ch)**](https://29a.ch/photo-forensics/) | Web Platform | Free | 🟢 Passive | ✅ | `image` → `metadata` |
| **S** | [**InVID / WeVerify Verification Plugin**](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) ([GitHub](https://github.com/AFP-Medialab/verification-plugin)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `image, video, url` → `metadata, urls` |
| **B** | [**FotoForensics**](https://fotoforensics.com/) | Web Platform | Free | 🟢 Passive | ✅ | `image, url` → `metadata` |

### [Forensically (29a.ch)](https://29a.ch/photo-forensics/) `[S-Tier]`
- **ID**: `forensically` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image` → **Outputs**: `metadata`
- **Platforms**: Web · **Tags**: `client-side-privacy`, `clone-detection`, `ela`, `jpeg-ghosts`, `embedded-thumbnails`
- **Overview**: Client-side HTML5 digital photo forensics laboratory offering Clone Detection (copy-move), Error Level Analysis (ELA), Noise Analysis, PCA, JPEG Ghost detection, and hidden thumbnail extraction.
- **Quick-Start / Tradecraft**: `Runs 100% locally in browser RAM (images are never uploaded!); always check the 'Meta Data -> Thumbnail' tab for uncropped originals!`

### [InVID / WeVerify Verification Plugin](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) `[S-Tier]`
- **ID**: `invid-weverify` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`AFP-Medialab/verification-plugin`](https://github.com/AFP-Medialab/verification-plugin)
- **Inputs**: `image`, `video`, `url` → **Outputs**: `metadata`, `urls`
- **Platforms**: Chrome, Firefox · **Tags**: `video-verification`, `keyframes`, `ela-forensics`, `fact-checking`, `afp`, `flagship`
- **Overview**: AFP Medialab / vera.ai browser workbench extracting video keyframes, running multi-engine reverse image searches, inspecting optical magnifiers, and running ELA/Ghost/Block forensic splicing filters.
- **Quick-Start / Tradecraft**: `Open the InVID Toolbox tab -> Keyframes -> paste a video URL -> right-click extracted scene frames to search Yandex/Lens/TinEye.`

### [FotoForensics](https://fotoforensics.com/) `[B-Tier]`
- **ID**: `fotoforensics` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `metadata`
- **Platforms**: Web · **Tags**: `ela-analysis`, `quantization-tables`, `camera-fingerprinting`
- **Overview**: Dr. Neal Krawetz's pioneering Error Level Analysis (ELA), JPEG quantization-table camera-model fingerprinting, and metadata tutorial & analysis portal (note: uploads become public URLs!).
- **Quick-Start / Tradecraft**: `Use FotoForensics only on public URLs; use client-side `29a.ch` Forensically for sensitive/unpublished photos!`

---

## Reverse Image & Visual Search

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**Google Lens**](https://lens.google.com/) | Search Engine | Free | 🟢 Passive | ✅ | `image, url` → `urls, geolocation, metadata` |
| **S** | [**Search by Image (Browser Extension)**](https://github.com/dessant/search-by-image) ([GitHub](https://github.com/dessant/search-by-image)) | Browser Extension | OSS / Free | 🟢 Passive | ✅ | `image, url` → `urls` |
| **S** | [**TinEye**](https://tineye.com/) | Search Engine | Freemium | 🟢 Passive | ✅ | `image, url` → `urls, archived_pages` |
| **S** | [**Yandex Reverse Image Search**](https://yandex.com/images/) | Search Engine | Free | 🟢 Passive | ✅ | `image, url` → `urls, geolocation, social_profiles` |
| **A** | [**Baidu Image Search (`image.baidu.com`)**](https://image.baidu.com/) | Search Engine | Free | 🟢 Passive | ✅ | `image, url` → `urls, corporate_records` |
| **A** | [**Bing Visual Search**](https://www.bing.com/visualsearch) | Search Engine | Free | 🟢 Passive | ✅ | `image, url` → `urls, geolocation` |
| **A** | [**SauceNAO**](https://saucenao.com/) | Search Engine | Free | 🟢 Passive | ✅ | `image, url` → `urls, social_profiles` |

### [Google Lens](https://lens.google.com/) `[S-Tier]`
- **ID**: `google-lens` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `urls`, `geolocation`, `metadata`
- **Platforms**: Web, Chrome · **Tags**: `exact-matches`, `product-identification`, `ocr-translate`, `visual-search`, `flagship`
- **Overview**: Multimodal visual recognition engine excelling at Exact Source ('Find image source') discovery, commercial product/clothing/weapon identification, sign OCR translation, and plant/species matching.
- **Quick-Start / Tradecraft**: `Click 'Exact matches' tab in Google Lens to locate the earliest dated appearance of a recycled crisis photo.`

### [Search by Image (Browser Extension)](https://github.com/dessant/search-by-image) `[S-Tier]`
- **ID**: `search-by-image` · **Type**: `Browser Extension` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`dessant/search-by-image`](https://github.com/dessant/search-by-image)
- **Inputs**: `image`, `url` → **Outputs**: `urls`
- **Platforms**: Chrome, Firefox · **Tags**: `30-engines`, `context-menu`, `baidu-sogou`, `workflow-accelerator`
- **Overview**: Open-source browser extension launching right-click reverse image lookups simultaneously across 30+ engines (Google Lens, Yandex, Bing, TinEye, Baidu, Sogou, SauceNAO, KarmaDecay, Alamy).
- **Quick-Start / Tradecraft**: `Right-click any image or select screen region -> Search by Image -> All Engines.`

### [TinEye](https://tineye.com/) `[S-Tier]`
- **ID**: `tineye` · **Type**: `Search Engine` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `urls`, `archived_pages`
- **Platforms**: Web, Chrome, Firefox · **Tags**: `oldest-match`, `debunking`, `stock-photo-detection`, `perceptual-hash`
- **Overview**: Dedicated perceptual-hash reverse image search indexing 70B+ web images with 'Oldest' sort ordering—the gold standard for debunking old stock/conflict photos reposted as breaking news.
- **Quick-Start / Tradecraft**: `Sort TinEye results by 'Oldest' to immediately prove whether an image predates the claimed event.`

### [Yandex Reverse Image Search](https://yandex.com/images/) `[S-Tier]`
- **ID**: `yandex-images` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `urls`, `geolocation`, `social_profiles`
- **Platforms**: Web · **Tags**: `reverse-image`, `landmark-matching`, `crop-selection`, `visual-osint`, `flagship`
- **Overview**: Consistently outperforms Western visual search engines on architectural landmarks, background scenery cropping, Cyrillic/Eurasian web sources, and same-person visual similarity matching.
- **Quick-Start / Tradecraft**: `Use Yandex's interactive crop box around a single building, bridge, or uniform patch while excluding foreground people!`

### [Baidu Image Search (`image.baidu.com`)](https://image.baidu.com/) `[A-Tier]`
- **ID**: `baidu-images` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `urls`, `corporate_records`
- **Platforms**: Web · **Tags**: `china-osint`, `weibo-wechat`, `manufacturing-sourcing`, `reverse-image`
- **Overview**: Mandatory reverse image engine when tracing images originating on Chinese platforms (Weibo, WeChat articles, Xiaohongshu/RED, Bilibili, Douyin, Taobao/1688 manufacturing catalogs).
- **Quick-Start / Tradecraft**: `Click the camera icon on https://image.baidu.com/ to match hardware/equipment photos directly to Chinese OEM catalogs!`

### [Bing Visual Search](https://www.bing.com/visualsearch) `[A-Tier]`
- **ID**: `bing-visual-search` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `urls`, `geolocation`
- **Platforms**: Web · **Tags**: `object-crop`, `visual-search`, `complementary-index`
- **Overview**: Microsoft's visual object-crop and reverse image search engine—frequently surfaces distinct corporate PDFs, Pinterest boards, and news wire matches missed by Google Lens.
- **Quick-Start / Tradecraft**: `Always run Google Lens + Yandex + Bing Visual Search + TinEye as a mandatory 4-engine quad check.`

### [SauceNAO](https://saucenao.com/) `[A-Tier]`
- **ID**: `saucenao` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `url` → **Outputs**: `urls`, `social_profiles`
- **Platforms**: Web · **Tags**: `avatar-attribution`, `artwork-source`, `pixiv-artstation`, `persona-osint`
- **Overview**: Specialized reverse image search indexing billions of digital illustrations, anime/manga avatars, Pixiv/DeviantArt/ArtStation/FurAffinity/Twitter artworks—crucial for attributing custom online avatars!
- **Quick-Start / Tradecraft**: `When a threat actor uses a drawn/stylized avatar, run it on https://saucenao.com/—sometimes the actor commissioned or drew it themselves!`

---

## Facial Recognition Search

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **S** | [**PimEyes**](https://pimeyes.com/) | Search Engine | Paid | 🟢 Passive | 🔑 | `image` → `urls, person_records` |
| **A** | [**FaceCheck.ID**](https://facecheck.id/) | Search Engine | Paid | 🟢 Passive | ✅ | `image` → `social_profiles, urls, person_records` |
| **A** | [**Search4Faces**](https://search4faces.com/) | Search Engine | Free | 🟢 Passive | ✅ | `image` → `social_profiles, person_records` |

### [PimEyes](https://pimeyes.com/) `[S-Tier]`
- **ID**: `pimeyes` · **Type**: `Search Engine` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `image` → **Outputs**: `urls`, `person_records`
- **Platforms**: Web · **Tags**: `facial-recognition`, `biometric-osint`, `person-identification`, `high-recall`
- **Overview**: High-recall commercial reverse facial-recognition engine indexing faces across news sites, blogs, company rosters, event galleries, and public web media (excludes major walled social networks).
- **Quick-Start / Tradecraft**: `Use clear, front-facing, well-lit crops; review legal/GDPR rules in your jurisdiction before running biometric searches.`

### [FaceCheck.ID](https://facecheck.id/) `[A-Tier]`
- **ID**: `facecheck-id` · **Type**: `Search Engine` · **Pricing**: `Paid` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image` → **Outputs**: `social_profiles`, `urls`, `person_records`
- **Platforms**: Web · **Tags**: `face-search`, `social-avatars`, `scam-investigations`
- **Overview**: Investigative facial-recognition search engine indexing social media avatars, mugshots, news videos, podcasts, and scammer warnings.
- **Quick-Start / Tradecraft**: `Test multiple angles of a subject's face to cross-match avatars across video and social platforms.`

### [Search4Faces](https://search4faces.com/) `[A-Tier]`
- **ID**: `search4faces` · **Type**: `Search Engine` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image` → **Outputs**: `social_profiles`, `person_records`
- **Platforms**: Web · **Tags**: `free-face-search`, `vkontakte`, `tiktok-avatars`, `cis-osint`
- **Overview**: Free facial-recognition search engine indexing over 1+ billion avatars across VKontakte, Odnoklassniki, TikTok, and Clubhouse profiles.
- **Quick-Start / Tradecraft**: `Select the VK or TikTok avatar index on https://search4faces.com/ and optionally filter by age/city.`

---

## Bioacoustic & Audio Forensics

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**BirdNET Analyzer**](https://birdnet.cornell.edu/) ([GitHub](https://github.com/kahst/BirdNET-Analyzer)) | CLI | OSS / Free | 🟢 Passive | ✅ | `audio, video` → `geolocation, metadata` |
| **A** | [**Sonic Visualiser / Audacity Spectrogram Forensics**](https://www.sonicvisualiser.org/) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `audio` → `metadata, geolocation` |

### [BirdNET Analyzer](https://birdnet.cornell.edu/) `[A-Tier]`
- **ID**: `birdnet` · **Type**: `CLI` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`kahst/BirdNET-Analyzer`](https://github.com/kahst/BirdNET-Analyzer)
- **Inputs**: `audio`, `video` → **Outputs**: `geolocation`, `metadata`
- **Platforms**: Web, Linux, macOS, Windows, Python · **Tags**: `bioacoustics`, `bird-species`, `audio-geolocation`, `season-verification`
- **Overview**: Cornell Lab of Ornithology neural classifier identifying 6,000+ global bird species from faint background chirps in outdoor videos—narrowing down continent, biome, and migratory season!
- **Quick-Start / Tradecraft**: `Extract background audio (`ffmpeg -i video.mp4 -vn audio.wav`) and analyze species range maps via BirdNET!`

### [Sonic Visualiser / Audacity Spectrogram Forensics](https://www.sonicvisualiser.org/) `[A-Tier]`
- **ID**: `audacity-spectrogram` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `audio` → **Outputs**: `metadata`, `geolocation`
- **Platforms**: Windows, macOS, Linux · **Tags**: `gunshot-acoustics`, `enf-50hz-60hz`, `audio-splicing`, `spectrogram`, `bellingcat`
- **Overview**: Open-source precision audio spectrogram and waveform inspection workstation for analyzing gunshot acoustics (muzzle blast vs supersonic crack distance!), audio splice cuts, and 50Hz/60Hz mains hum (ENF).
- **Quick-Start / Tradecraft**: `Inspect 50 Hz (Europe/Asia/Africa) vs 60 Hz (Americas/parts of Japan/Korea) electrical mains hum and acoustic lag in Sonic Visualiser!`

---

## Conflict & Remnant Verification

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Open Source Munitions Portal & ARES**](https://munitionsportal.org/) | Dataset / Registry | Free | 🟢 Passive | ✅ | `image, keyword` → `metadata` |

### [Open Source Munitions Portal & ARES](https://munitionsportal.org/) `[A-Tier]`
- **ID**: `munitions-portal` · **Type**: `Dataset / Registry` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct)
- **Inputs**: `image`, `keyword` → **Outputs**: `metadata`
- **Platforms**: Web · **Tags**: `ordnance-identification`, `bellingcat`, `conflict-accountability`, `lot-numbers`
- **Overview**: Bellingcat & Fenix Insight visual identification catalog of military ordnance, cluster submunitions, tailfins, fuzes, stencil markings, and factory lot codes documented in open-source imagery.
- **Quick-Start / Tradecraft**: `Match stenciled Cyrillic/Latin lot codes, fin geometries, and color bands safely via https://munitionsportal.org/.`

---

## AI & Deepfake Detection

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**TrueMedia.org Deepfake Detector**](https://www.truemedia.org/) | Web Platform | Free | 🟢 Passive | 🔑 | `image, video, audio` → `metadata` |
| **B** | [**Hiya AI Voice & Audio Deepfake Detector**](https://www.hiya.com/products/deepfake-voice-detector) | Browser Extension | Freemium | 🟢 Passive | 🔑 | `audio, video, url` → `metadata` |

### [TrueMedia.org Deepfake Detector](https://www.truemedia.org/) `[A-Tier]`
- **ID**: `truemedia-org` · **Type**: `Web Platform` · **Pricing**: `Free` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `image`, `video`, `audio`, `url` → **Outputs**: `metadata`
- **Platforms**: Web · **Tags**: `deepfake-detection`, `voice-cloning`, `gan-diffusion`, `media-verification`
- **Overview**: Non-partisan ensemble AI media-authentication platform testing suspect political/news videos, audio clips, and portraits across multiple academic synthetic-media detectors simultaneously.
- **Quick-Start / Tradecraft**: `Always pair automated AI detector scores with provenance checks (TinEye/Wayback) and physical lighting/shadow geometry.`

### [Hiya AI Voice & Audio Deepfake Detector](https://www.hiya.com/products/deepfake-voice-detector) `[B-Tier]`
- **ID**: `hiya-deepfake-voice` · **Type**: `Browser Extension` · **Pricing**: `Freemium` · **OPSEC**: 🟢 Passive · **Auth**: Required (Account / API Key)
- **Inputs**: `audio`, `video`, `url` → **Outputs**: `metadata`
- **Platforms**: Chrome, Web · **Tags**: `voice-cloning-detection`, `audio-forensics`, `synthetic-speech`, `disinformation`
- **Overview**: Browser extension and audio authenticity verifier analyzing live web audio/video speeches, voicemails, and leaked recordings for ElevenLabs/TTS synthetic voice-cloning artifacts.
- **Quick-Start / Tradecraft**: `Sample clean 10+ second speech segments free of heavy background music for accurate synthetic-voice scoring.`

---

## Document & Image De-obfuscation

| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **A** | [**Unredacter (Bishop Fox)**](https://github.com/BishopFox/unredacter) ([GitHub](https://github.com/BishopFox/unredacter)) | Desktop App | OSS / Free | 🟢 Passive | ✅ | `image` → `metadata, secrets` |

### [Unredacter (Bishop Fox)](https://github.com/BishopFox/unredacter) `[A-Tier]`
- **ID**: `unredacter` · **Type**: `Desktop App` · **Pricing**: `Free / Open Source` · **OPSEC**: 🟢 Passive · **Auth**: None (Keyless / Direct) · **GitHub**: [`BishopFox/unredacter`](https://github.com/BishopFox/unredacter)
- **Inputs**: `image` → **Outputs**: `metadata`, `secrets`
- **Platforms**: Linux, macOS, Windows, Node.js · **Tags**: `depixelation`, `redaction-forensics`, `bishopfox`, `imint`
- **Overview**: Forensic image analysis tool demonstrating deterministic recovery of sensitive text hidden behind mosaic pixelation filters in screenshots and documents.
- **Quick-Start / Tradecraft**: `npm start # Load cropped pixelated text block in Unredacter`

---
[⬅️ Back to Master Index](../README.md) · [◀ 🛰️ GEOINT, Maps & Satellites](./11-geoint-maps-satellites.md) · [✈️ Aviation, Maritime & Transport ▶](./13-aviation-maritime-transport.md)

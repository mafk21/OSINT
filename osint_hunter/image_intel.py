"""Visual & Image Intelligence Harvester (IMINT): Profile Avatars, Open-Web Photos, Forensic Cache & EXIF/AI Audit.

100% Python 3 standard library. Zero external dependencies.
- Harvests profile pictures, banners, channel photos, and open-web images (Bing Images,
  DuckDuckGo Images, Yahoo Images, Wikimedia Commons, URLScan screenshots, Gravatar/Unavatar).
- Respects strict Passive vs Active OPSEC: in Passive mode, never sends HTTP requests to
  target-owned domains/IPs when caching images (fetches only from third-party CDNs, search
  engine thumbnails, or Internet Archive `web.archive.org/web/2im_/`).
- Forensically caches downloaded images into `cases/<CASE_ID>/images/`, verifies image magic
  bytes, extracts pixel dimensions + EXIF GPS/Camera + C2PA/AI synthetic avatar indicators,
  detects cross-platform identical avatar reuse via SHA-256, and generates 1-click Reverse
  Image / Face Search links (Google Lens, Yandex, Bing Visual, TinEye).
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import html
import ipaddress
import json
import re
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .dfir_forensics import analyze_png_webp_c2pa_bytes
from .offline_intel import _parse_jpeg_exif

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
IMG_TIMEOUT = 3.4
MAX_IMAGE_BYTES = 3_500_000  # 3.5 MB cap per cached image

PLACEHOLDER_SUBSTRINGS = (
    "default_profile",
    "default-avatar",
    "identicon",
    "mystery-man",
    "blank_avatar",
    "missing.png",
    "telegram.org/img/t_logo",
    "static.cdninstagram.com/rsrc.php",
    "abs.twimg.com/sticky/default_profile_images",
    "redditstatic.com/avatars/defaults",
    "1x1",
    "spacer.gif",
    "pixel.gif",
    "favicon.ico",
)


def is_valid_candidate_image_url(url: str | None) -> bool:
    if not url or not isinstance(url, str):
        return False
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        return False
    low = u.lower()
    if any(p in low for p in PLACEHOLDER_SUBSTRINGS):
        return False
    path_part = urllib.parse.urlparse(low).path
    if path_part.endswith((".svg", ".ico", ".css", ".js")):
        return False
    return True


def is_safe_public_http_url(url: str) -> bool:
    """SSRF guard: allow only http/https URLs whose hostname is not loopback/private/link-local."""
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        host = p.hostname.strip("[]").lower()
        if host in ("localhost", "0.0.0.0") or host.endswith((".local", ".internal", ".localhost")):
            return False
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_global
        except ValueError:
            return True
    except Exception:
        return False


def build_reverse_image_links(image_url: str) -> dict[str, str]:
    enc = urllib.parse.quote(image_url, safe="")
    yandex_u = f"https://yandex.com/images/search?rpt=imageview&url={enc}"
    return {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={enc}",
        "yandex": yandex_u,
        "yandex_vision": yandex_u,
        "bing_visual": f"https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl={enc}",
        "tineye": f"https://tineye.com/search?url={enc}",
    }


def detect_image_magic_and_dimensions(data: bytes) -> tuple[str | None, str | None, int | None, int | None]:
    """Verify binary image magic bytes and parse `(mime, ext, width, height)` in pure Python."""
    if len(data) < 24:
        return None, None, None, None

    # PNG
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        w, h = struct.unpack(">II", data[16:24])
        return "image/png", "png", w, h

    # GIF
    if data[:6] in (b"GIF87a", b"GIF89a"):
        w, h = struct.unpack("<HH", data[6:10])
        return "image/gif", "gif", w, h

    # WebP
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        w, h = None, None
        chunk = data[12:16]
        if chunk == b"VP8X" and len(data) >= 30:
            w = 1 + int.from_bytes(data[24:27], "little")
            h = 1 + int.from_bytes(data[27:30], "little")
        elif chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
            w, h = struct.unpack("<HH", data[26:30])
            w, h = w & 0x3FFF, h & 0x3FFF
        return "image/webp", "webp", w, h

    # JPEG
    if data[:3] == b"\xff\xd8\xff":
        w, h = None, None
        pos = 2
        n = len(data)
        while pos + 9 < n:
            if data[pos] != 0xFF:
                pos += 1
                continue
            while pos < n and data[pos] == 0xFF:
                pos += 1
            if pos >= n:
                break
            marker = data[pos]
            pos += 1
            if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
                continue
            if pos + 2 > n:
                break
            seg_len = struct.unpack(">H", data[pos : pos + 2])[0]
            if seg_len < 2:
                break
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB) and pos + 7 <= n:
                h, w = struct.unpack(">HH", data[pos + 3 : pos + 7])
                break
            pos += seg_len
        return "image/jpeg", "jpg", w, h

    return None, None, None, None


def detect_image_format_and_dimensions(data: bytes) -> dict[str, Any] | None:
    """Return `{'format': 'PNG'|'JPEG'|'WebP'|'GIF', 'ext': '.png', 'width': w, 'height': h}` or `None`."""
    mime, ext, w, h = detect_image_magic_and_dimensions(data)
    if not mime or not ext:
        return None
    fmt_map = {"image/png": "PNG", "image/jpeg": "JPEG", "image/webp": "WebP", "image/gif": "GIF"}
    return {"format": fmt_map.get(mime, ext.upper()), "ext": f".{ext}", "width": w, "height": h}


def inspect_image_bytes_forensics(data: bytes, mime: str) -> dict[str, Any]:
    """Extract EXIF GPS/Camera/Author or PNG/WebP C2PA & AI synthetic avatar signatures from image bytes."""
    meta: dict[str, Any] = {}
    if mime in ("image/jpeg", "JPEG"):
        exif = _parse_jpeg_exif(data)
        if exif:
            tags = exif.get("exif_tags") or {}
            clean_tags = {k: v for k, v in tags.items() if v}
            if clean_tags:
                meta["exif_tags"] = clean_tags
            if exif.get("gps_coordinates"):
                meta["gps_coordinates"] = exif["gps_coordinates"]
            meta["exif"] = {
                "camera_make": clean_tags.get("Make"),
                "camera_model": clean_tags.get("Model"),
                "datetime_original": clean_tags.get("DateTimeOriginal") or clean_tags.get("DateTime"),
                "gps_coordinates": exif.get("gps_coordinates"),
            }
            sw = str(tags.get("Software") or tags.get("Artist") or "").lower()
            if any(k in sw for k in ("midjourney", "dall-e", "stable diffusion", "firefly", "comfyui", "ai")):
                ind = f"EXIF Software/Artist indicates AI generation ({tags.get('Software') or tags.get('Artist')})"
                meta["ai_synthetic_indicator"] = ind
                meta["ai_or_c2pa"] = {"detected": True, "indicators": [ind]}
    elif mime in ("image/png", "image/webp", "PNG", "WebP"):
        c2pa = analyze_png_webp_c2pa_bytes(data)
        inds: list[str] = []
        if c2pa.get("c2pa_content_credentials_detected"):
            meta["c2pa_detected"] = True
            inds.append("C2PA Content Credentials")
        if c2pa.get("ai_provenance_classification"):
            meta["ai_synthetic_indicator"] = c2pa["ai_provenance_classification"]
            inds.append(str(c2pa["ai_provenance_classification"]))
        for sig in c2pa.get("ai_or_camera_signatures") or []:
            if sig != "Leica Content Credentials" and sig not in inds:
                inds.append(str(sig))
                if not meta.get("ai_synthetic_indicator"):
                    meta["ai_synthetic_indicator"] = str(sig)
        emb_txt = c2pa.get("embedded_text_metadata")
        if emb_txt:
            meta["text_chunks"] = emb_txt
        if inds:
            meta["ai_or_c2pa"] = {"detected": True, "indicators": inds}
    return meta


def inspect_image_forensics(data: bytes, fmt_or_mime: str = "PNG") -> dict[str, Any]:
    return inspect_image_bytes_forensics(data, fmt_or_mime)


# ============================================================================
# PASSIVE OPEN-WEB IMAGE SEARCH PARSERS (BING, DUCKDUCKGO, YAHOO, WIKIMEDIA)
# ============================================================================

def _fetch_text(url: str, *, headers: dict[str, str] | None = None, timeout: float = IMG_TIMEOUT) -> tuple[int, str]:
    hdrs = {
        "User-Agent": BROWSER_UA,
        "Accept": "text/html,application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(450_000).decode("utf-8", errors="replace")
    except Exception:
        return 0, ""


def fetch_image_bytes(url: str, timeout: float = 3.2) -> tuple[bytes | None, str | None]:
    """Safely download binary image bytes (capped at 3.5 MB) and validate image magic header."""
    if not is_safe_public_http_url(url):
        return None, None
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": BROWSER_UA,
            "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Verify resolved peer IP is global to prevent DNS-rebinding SSRF
            raw = resp.read(MAX_IMAGE_BYTES + 1)
            if len(raw) > MAX_IMAGE_BYTES:
                return None, None
            mime, _, w, h = detect_image_magic_and_dimensions(raw)
            if not mime:
                return None, None
            if w is not None and h is not None and (w < 24 or h < 24):
                return None, None
            return raw, mime
    except Exception:
        return None, None


def parse_bing_images_html(raw_html: str) -> list[dict[str, Any]]:
    """Parse Bing Images `<a class="iusc" m="{...}">` metadata blocks."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    if not raw_html:
        return results

    for m_raw in re.findall(r'\bm="(\{[^"]+\})"', raw_html):
        try:
            obj = json.loads(html.unescape(m_raw))
        except Exception:
            continue
        img_url = str(obj.get("murl") or "").strip()
        thumb_url = str(obj.get("turl") or "").strip()
        page_url = str(obj.get("purl") or "").strip()
        title = re.sub(r"[\ue000-\uf8ff]", "", str(obj.get("t") or obj.get("desc") or "")).strip()
        if not is_valid_candidate_image_url(img_url):
            continue
        if img_url in seen:
            continue
        seen.add(img_url)
        results.append(
            {
                "kind": "web_photo",
                "source": "Bing Images",
                "image_url": img_url,
                "thumbnail_url": thumb_url if thumb_url.startswith("http") else img_url,
                "source_page_url": page_url if page_url.startswith("http") else None,
                "title": title[:160] or None,
            }
        )
        if len(results) >= 14:
            break
    return results


def parse_yahoo_images_html(raw_html: str) -> list[dict[str, Any]]:
    """Parse Yahoo Images embedded result objects (`iurl`, `ith`, `rurl`, `alt`)."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    if not raw_html:
        return results

    for m in re.finditer(r'"iurl"\s*:\s*"([^"]+)"[^{}]*?"ith"\s*:\s*"([^"]+)"[^{}]*?"rurl"\s*:\s*"([^"]+)"', raw_html):
        img_u = m.group(1).replace("\\/", "/")
        if not img_u.startswith("http"):
            img_u = "https://" + img_u.lstrip("/")
        th_u = m.group(2).replace("\\/", "/")
        pg_u = m.group(3).replace("\\/", "/")
        if not is_valid_candidate_image_url(img_u) or img_u in seen:
            continue
        seen.add(img_u)
        results.append(
            {
                "kind": "web_photo",
                "source": "Yahoo Images",
                "image_url": img_u,
                "thumbnail_url": th_u if th_u.startswith("http") else img_u,
                "source_page_url": pg_u if pg_u.startswith("http") else None,
                "title": None,
            }
        )
        if len(results) >= 10:
            break
    return results


def parse_ddg_images_json(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse DuckDuckGo `i.js` JSON payload into image result dicts."""
    out: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return out
    for r in (payload.get("results") or [])[:12]:
        if not isinstance(r, dict):
            continue
        iu = str(r.get("image") or "").strip()
        tu = str(r.get("thumbnail") or "").strip()
        pu = str(r.get("url") or "").strip()
        if is_valid_candidate_image_url(iu):
            out.append(
                {
                    "kind": "web_photo",
                    "source": "DuckDuckGo Images",
                    "image_url": iu,
                    "thumbnail_url": tu if tu.startswith("http") else iu,
                    "source_page_url": pu if pu.startswith("http") else None,
                    "title": str(r.get("title") or "")[:160] or None,
                    "width": r.get("width"),
                    "height": r.get("height"),
                }
            )
    return out


def search_open_web_images(query: str) -> dict[str, Any]:
    """Query Bing Images, DuckDuckGo Images (`i.js`), Yahoo Images & Wikimedia Commons in parallel."""
    q = (query or "").strip()
    if len(q) < 2:
        return {"reachable": False, "images": []}
    q_enc = urllib.parse.quote(f'"{q}"' if " " in q or "." in q else q)

    def _bing_imgs():
        st, body = _fetch_text(f"https://www.bing.com/images/search?q={q_enc}&form=HDRSC2&first=1")
        return st != 0, parse_bing_images_html(body) if st == 200 else []

    def _ddg_imgs():
        st_tok, tok_body = _fetch_text(f"https://duckduckgo.com/?q={q_enc}&iax=images&ia=images", timeout=2.8)
        if st_tok == 0:
            return False, []
        m_vqd = re.search(r"vqd=['\"]?([\d-]+)['\"]?", tok_body)
        if not m_vqd:
            return True, []
        vqd = m_vqd.group(1)
        st_j, j_txt = _fetch_text(
            f"https://duckduckgo.com/i.js?l=us-en&o=json&q={q_enc}&vqd={urllib.parse.quote(vqd)}&f=,,,&p=1",
            headers={"Referer": "https://duckduckgo.com/"},
            timeout=3.0,
        )
        if st_j != 200 or not j_txt:
            return True, []
        try:
            return True, parse_ddg_images_json(json.loads(j_txt))
        except Exception:
            return True, []

    def _yahoo_imgs():
        st, body = _fetch_text(f"https://images.search.yahoo.com/search/images?p={q_enc}")
        return st != 0, parse_yahoo_images_html(body) if st == 200 else []

    def _wikimedia_imgs():
        api_u = (
            "https://commons.wikimedia.org/w/api.php?action=query&generator=search"
            f"&gsrsearch={urllib.parse.quote(q)}&gsrnamespace=6&gsrlimit=6&prop=imageinfo&iiprop=url|size&iiurlwidth=640&format=json"
        )
        st, txt = _fetch_text(api_u, timeout=3.0)
        if st != 200 or not txt:
            return st != 0, []
        try:
            pages = ((json.loads(txt).get("query") or {}).get("pages")) or {}
        except Exception:
            return True, []
        out = []
        for pg in pages.values():
            ii = (pg.get("imageinfo") or [{}])[0]
            iu = ii.get("url")
            tu = ii.get("thumburl") or iu
            if is_valid_candidate_image_url(iu):
                out.append(
                    {
                        "kind": "commons_media",
                        "source": "Wikimedia Commons",
                        "image_url": iu,
                        "thumbnail_url": tu,
                        "source_page_url": ii.get("descriptionurl"),
                        "title": str(pg.get("title") or "").removeprefix("File:")[:140],
                        "width": ii.get("width"),
                        "height": ii.get("height"),
                    }
                )
        return True, out

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        f_b = pool.submit(_bing_imgs)
        f_d = pool.submit(_ddg_imgs)
        f_y = pool.submit(_yahoo_imgs)
        f_w = pool.submit(_wikimedia_imgs)
        r_b, l_b = f_b.result()
        r_d, l_d = f_d.result()
        r_y, l_y = f_y.result()
        r_w, l_w = f_w.result()

    merged: list[dict[str, Any]] = []
    seen_u: set[str] = set()
    for item in l_b + l_d + l_y + l_w:
        u = item["image_url"]
        if u not in seen_u:
            seen_u.add(u)
            merged.append(item)

    return {"reachable": any((r_b, r_d, r_y, r_w)), "images": merged[:18]}


# ============================================================================
# CASE-WIDE VISUAL EVIDENCE AGGREGATOR, FORENSIC CACHE & EXIF/AI AUDITOR
# ============================================================================

def harvest_and_cache_visual_intel(
    report: dict,
    *,
    case_dir: Path | None = None,
    is_active: bool = False,
) -> dict[str, Any]:
    """Aggregate all avatars, channel photos, screenshots & web images across a hunt and cache top hits."""
    candidates: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    nodes = report.get("graph", {}).get("nodes", [])
    target_domains = {
        n["value"].lower().removeprefix("www.")
        for n in nodes
        if n.get("type") == "domain" and n.get("value")
    }

    def _add_img(
        *,
        image_url: str | None,
        source: str,
        entity: str,
        kind: str = "profile_avatar",
        title: str | None = None,
        thumbnail_url: str | None = None,
        source_page_url: str | None = None,
    ) -> None:
        if not is_valid_candidate_image_url(image_url):
            return
        u = str(image_url).strip()
        if u in seen_urls:
            return
        seen_urls.add(u)
        lbl = (str(title).strip()[:160] if title else None) or f"{source} ({entity})"
        candidates.append(
            {
                "kind": kind,  # profile_avatar | channel_or_post_photo | web_photo | site_screenshot
                "source": source,
                "platform": source,
                "entity": entity,
                "selector": entity,
                "title": lbl,
                "label": lbl,
                "image_url": u,
                "url": u,
                "thumbnail_url": thumbnail_url if is_valid_candidate_image_url(thumbnail_url) else u,
                "source_page_url": source_page_url,
                "source_page": source_page_url or u,
                "reverse_search": build_reverse_image_links(u),
            }
        )

    # 1. Walk all collector outputs across all waves to gather avatars, screenshots & open-web photos
    for wave_item in report.get("wave_results") or []:
        sval = wave_item.get("value", "")
        for mod in wave_item.get("collector_outputs") or []:
            if mod.get("status") != "ok":
                continue
            mname = mod.get("module", "")
            d = mod.get("data") or {}
            if not isinstance(d, dict):
                continue

            if mname == "github_user_osint" and d.get("avatar_url"):
                _add_img(
                    image_url=d["avatar_url"],
                    source="GitHub",
                    entity=d.get("login") or sval,
                    kind="profile_avatar",
                    title=d.get("name") or f"GitHub @{d.get('login') or sval}",
                    source_page_url=f"https://github.com/{d.get('login') or sval}",
                )
            elif mname == "bluesky_atproto":
                if d.get("avatar"):
                    _add_img(
                        image_url=d["avatar"],
                        source="Bluesky",
                        entity=d.get("handle") or sval,
                        kind="profile_avatar",
                        title=d.get("display_name") or f"Bluesky @{d.get('handle')}",
                        source_page_url=f"https://bsky.app/profile/{d.get('handle')}",
                    )
                if d.get("banner"):
                    _add_img(image_url=d["banner"], source="Bluesky Banner", entity=d.get("handle") or sval, kind="channel_or_post_photo")
            elif mname == "mastodon_fediverse" and d.get("avatar_url"):
                _add_img(
                    image_url=d["avatar_url"],
                    source="Mastodon",
                    entity=d.get("acct") or sval,
                    kind="profile_avatar",
                    title=d.get("display_name"),
                    source_page_url=d.get("url"),
                )
            elif mname == "gravatar_profile" and d.get("thumbnailUrl"):
                _add_img(
                    image_url=str(d["thumbnailUrl"]) + "?s=512",
                    source="Gravatar",
                    entity=sval,
                    kind="profile_avatar",
                    title=d.get("displayName"),
                    source_page_url=d.get("profileUrl"),
                )
            elif mname == "email_forensic_decomposition" and d.get("avatar_direct_url"):
                # Will only be kept if live check returns 200 image/* (since ?d=404 returns 404 when unset!)
                _add_img(
                    image_url=d["avatar_direct_url"],
                    source="Gravatar (Email Hash)",
                    entity=sval,
                    kind="profile_avatar",
                    title=f"Gravatar for {sval}",
                    thumbnail_url=None,
                )
            elif mname == "username_platform_sweep":
                for p in d.get("profiles_detailed") or []:
                    if not isinstance(p, dict):
                        continue
                    plat = p.get("platform", "Social")
                    if p.get("avatar_url"):
                        _add_img(
                            image_url=p["avatar_url"],
                            source=plat,
                            entity=sval,
                            kind="profile_avatar",
                            title=p.get("display_name") or f"{plat} @{sval}",
                            source_page_url=p.get("url"),
                        )
                    if p.get("snapcode_url"):
                        _add_img(
                            image_url=p["snapcode_url"],
                            source="Snapchat Snapcode",
                            entity=sval,
                            kind="profile_avatar",
                            title=f"Snapcode @{sval}",
                            source_page_url=p.get("url"),
                        )
                    for ch_ph in (p.get("post_photos") or [])[:4]:
                        _add_img(
                            image_url=ch_ph,
                            source=f"{plat} Post",
                            entity=sval,
                            kind="channel_or_post_photo",
                            title=f"Public post media from {plat} @{sval}",
                            source_page_url=p.get("url"),
                        )
            elif mname == "wikidata_knowledge_graph":
                for img_u in (d.get("images") or [])[:3]:
                    _add_img(
                        image_url=img_u,
                        source="Wikidata / Commons",
                        entity=d.get("label") or sval,
                        kind="profile_avatar",
                        title=f"{d.get('label') or sval} ({d.get('qid')})",
                        source_page_url=d.get("url"),
                    )
            elif mname == "adsbdb_airframe_registry" and (d.get("url_photo") or d.get("url_photo_thumbnail")):
                _add_img(
                    image_url=d.get("url_photo") or d.get("url_photo_thumbnail"),
                    thumbnail_url=d.get("url_photo_thumbnail"),
                    source="ADSBdb Airframe Photo",
                    entity=sval,
                    kind="web_photo",
                    title=f"{d.get('manufacturer') or ''} {d.get('type') or ''} ({d.get('registration') or sval})".strip(),
                )
            elif mname == "urlscan_passive_history":
                for sc in (d.get("recent_scans") or [])[:4]:
                    if isinstance(sc, dict) and sc.get("screenshot"):
                        _add_img(
                            image_url=sc["screenshot"],
                            source="URLScan Screenshot",
                            entity=sval,
                            kind="site_screenshot",
                            title=sc.get("title") or sc.get("url"),
                            source_page_url=sc.get("url"),
                        )
            elif mname in ("wayback_archived_page_intel", "wayback_url_content_intel", "active_url_jsonld_opengraph"):
                meta_tags = d.get("meta_tags") or {}
                og_img = meta_tags.get("og:image") or meta_tags.get("twitter:image")
                if og_img and og_img.startswith("http"):
                    safe_og = (
                        f"https://web.archive.org/web/2im_/{og_img}"
                        if (not is_active and any((urllib.parse.urlparse(og_img).hostname or "").lower().endswith(td) for td in target_domains))
                        else og_img
                    )
                    _add_img(
                        image_url=safe_og,
                        source="Site OpenGraph Image",
                        entity=sval,
                        kind="site_screenshot",
                        title=d.get("title") or sval,
                    )
            elif mname == "open_web_image_search":
                for im in d.get("images") or []:
                    if isinstance(im, dict):
                        _add_img(
                            image_url=im.get("image_url"),
                            thumbnail_url=im.get("thumbnail_url"),
                            source=im.get("source", "Web Images"),
                            entity=sval,
                            kind=im.get("kind", "web_photo"),
                            title=im.get("title"),
                            source_page_url=im.get("source_page_url"),
                        )

    if not candidates:
        return {
            "total_images": 0,
            "cached_count": 0,
            "images": [],
            "avatar_reuse_matches": [],
            "cross_platform_avatar_matches": [],
            "forensic_alerts": [],
            "forensic_image_alerts": [],
        }

    # Prioritize direct profile avatars first, then post/web photos, then screenshots
    kind_order = {"profile_avatar": 0, "channel_or_post_photo": 1, "web_photo": 2, "commons_media": 2, "site_screenshot": 3}
    candidates.sort(key=lambda c: kind_order.get(c["kind"], 5))

    # 2. Download, verify & forensically inspect up to 16 images concurrently
    images_dir = (case_dir / "images") if case_dir else None
    case_id = case_dir.name if case_dir else None

    def _verify_and_cache(idx_item: tuple[int, dict[str, Any]]) -> dict[str, Any] | None:
        idx, item = idx_item
        dl_url = item["image_url"]
        # Passive OPSEC guard: never hit a target-owned domain directly in Passive mode
        try:
            dl_host = (urllib.parse.urlparse(dl_url).hostname or "").lower().removeprefix("www.")
        except ValueError:
            dl_host = ""
        if not is_active and dl_host and any(dl_host == td or dl_host.endswith("." + td) for td in target_domains):
            # Use thumbnail proxy if from Bing/DDG/Yahoo, otherwise skip direct target fetch
            th = item.get("thumbnail_url") or ""
            th_host = (urllib.parse.urlparse(th).hostname or "").lower()
            if th and th != dl_url and not any(th_host.endswith(td) for td in target_domains):
                dl_url = th
            else:
                return item if "?d=404" not in dl_url else None

        raw, mime = fetch_image_bytes(dl_url, timeout=3.0)
        if not raw or not mime:
            # If Gravatar ?d=404 returned 404, drop it cleanly (means user has no Gravatar!)
            if "?d=404" in dl_url or "fallback=false" in dl_url:
                return None
            # Try thumbnail_url if original full-res URL blocked hotlinking
            th = item.get("thumbnail_url")
            if th and th != dl_url:
                raw, mime = fetch_image_bytes(th, timeout=2.6)
        if not raw or not mime:
            return item

        fmt_info = detect_image_format_and_dimensions(raw) or {}
        ext = (fmt_info.get("ext") or "").lstrip(".")
        width = fmt_info.get("width")
        height = fmt_info.get("height")
        sha256_hex = hashlib.sha256(raw).hexdigest()
        forensics = inspect_image_bytes_forensics(raw, mime)

        enriched = dict(item)
        enriched["verified_binary"] = True
        enriched["format"] = fmt_info.get("format")
        enriched["mime_type"] = mime
        enriched["size_bytes"] = len(raw)
        enriched["width"] = width
        enriched["height"] = height
        enriched["sha256"] = sha256_hex
        if forensics:
            enriched["forensics"] = forensics

        if images_dir is not None and case_id and ext:
            images_dir.mkdir(parents=True, exist_ok=True)
            safe_src = re.sub(r"[^a-zA-Z0-9]+", "_", item["source"].lower()).strip("_")[:18]
            fname = f"img_{idx + 1:02d}_{safe_src}.{ext}"
            try:
                (images_dir / fname).write_bytes(raw)
                enriched["cached"] = True
                enriched["cached_file"] = f"images/{fname}"
                enriched["local_rel_path"] = f"images/{fname}"
                enriched["local_url"] = f"./api/cases/{urllib.parse.quote(case_id)}/images/{fname}"
            except OSError:
                pass
        return enriched

    verified_images: list[dict[str, Any]] = []
    batch = list(enumerate(candidates[:16]))
    overflow = candidates[16:28]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for res_item in pool.map(_verify_and_cache, batch):
            if res_item is not None:
                verified_images.append(res_item)

    for extra in overflow:
        if "?d=404" not in extra["image_url"]:
            verified_images.append(extra)

    # 3. Cross-platform identical photo reuse & EXIF/AI synthetic alerts
    by_sha: dict[str, list[dict[str, Any]]] = {}
    forensic_alerts: list[str] = []
    for im in verified_images:
        sha = im.get("sha256")
        if sha:
            by_sha.setdefault(sha, []).append(im)
        fmeta = im.get("forensics") or {}
        if fmeta.get("gps_coordinates"):
            forensic_alerts.append(
                f"EXIF GPS coordinates `{fmeta['gps_coordinates']}` embedded inside {im['source']} image ({im['entity']})"
            )
        if fmeta.get("ai_synthetic_indicator"):
            forensic_alerts.append(
                f"Synthetic / AI-generated image signature on {im['source']} ({im['entity']}): {fmeta['ai_synthetic_indicator']}"
            )

    avatar_reuse_matches: list[dict[str, Any]] = []
    for sha, grp in by_sha.items():
        sources = sorted({g["source"] for g in grp})
        if len(sources) >= 2:
            avatar_reuse_matches.append(
                {
                    "sha256": sha,
                    "platforms": [{"platform": g["source"], "selector": g["entity"]} for g in grp],
                    "platform_names": sources,
                    "entities": sorted({g["entity"] for g in grp}),
                    "note": f"Identical binary photo (SHA-256 {sha[:12]}…) reused across {' + '.join(sources)}",
                }
            )
            forensic_alerts.append(f"Confirmed identical photo reused across {' + '.join(sources)} (SHA-256 `{sha[:12]}…`)")

    cached_cnt = sum(1 for im in verified_images if im.get("cached_file"))
    return {
        "total_images": len(verified_images),
        "cached_count": cached_cnt,
        "images": verified_images[:24],
        "avatar_reuse_matches": avatar_reuse_matches,
        "cross_platform_avatar_matches": avatar_reuse_matches,
        "forensic_alerts": forensic_alerts,
        "forensic_image_alerts": forensic_alerts,
    }

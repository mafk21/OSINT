"""Keyless Open-Web Search, Webpage Intelligence Carver, Phone/Email Breach & Knowledge Graph Collectors.

100% Python 3 standard library. Zero API keys required.
Strictly Passive by default: queries only third-party search engines, web archives,
breach/infostealer databases, academic/corporate/map registries, and DNS-over-HTTPS —
never sending packets directly to target-owned domains or IP addresses.
"""

from __future__ import annotations

import concurrent.futures
import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any
from xml.etree import ElementTree as ET

from .bilingual_mena import generate_bilingual_pivots
from .classify import DOMAIN_RE, EMAIL_RE, NOISE_DOMAINS, extract_selectors
from .image_intel import search_open_web_images

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
API_UA = "OSINT-Monster-Hunter/2026.10 (+https://github.com/mafk21/OSINT)"
SEARCH_TIMEOUT = 3.6

HTML_TAG_RE = re.compile(r"<[^>]+>")
EMAIL_FALSE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff", ".woff2", ".ico")
EMAIL_NOISE_HOSTS = {
    "sentry.io", "sentry.wixpress.com", "sentry-next.wixpress.com", "wixpress.com",
    "example.com", "example.org", "domain.com", "email.com", "yoursite.com",
}

PLATFORM_AND_DIRECTORY_HOSTS = {
    "instagram.com", "tiktok.com", "snapchat.com", "x.com", "twitter.com", "linkedin.com",
    "facebook.com", "threads.net", "threads.com", "youtube.com", "youtu.be", "t.me",
    "telegram.org", "telegram.me", "wa.me", "whatsapp.com", "linktr.ee", "taplink.cc",
    "beacons.ai", "bio.link", "solo.to", "carrd.co", "bento.me", "pinterest.com",
    "soundcloud.com", "medium.com", "substack.com", "patreon.com", "behance.net",
    "dribbble.com", "vimeo.com", "twitch.tv", "reddit.com", "quora.com", "amazon.com",
    "wikipedia.org", "wikidata.org", "truecaller.com", "sync.me", "crunchbase.com",
    "zoominfo.com", "rocketreach.co", "apollo.io", "yelp.com", "trustpilot.com",
    "haraj.com.sa", "opensooq.com", "maroof.sa", "vezeeta.com", "altibbi.com",
    "practo.com", "researchgate.net", "academia.edu", "orcid.org", "ncbi.nlm.nih.gov",
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "github.com", "gitlab.com",
}

SOCIAL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Instagram",
        re.compile(r"https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]{2,35})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "TikTok",
        re.compile(r"https?://(?:www\.|vm\.)?tiktok\.com/@([A-Za-z0-9_.]{2,35})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Snapchat",
        re.compile(r"https?://(?:www\.|story\.)?snapchat\.com/(?:add/|@)([A-Za-z0-9_.-]{2,35})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "X/Twitter",
        re.compile(r"https?://(?:www\.|mobile\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{2,20})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Telegram",
        re.compile(r"https?://(?:www\.)?(?:t|telegram)\.me/(?:s/)?([A-Za-z0-9_]{4,35})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "YouTube",
        re.compile(r"https?://(?:www\.|m\.)?youtube\.com/@([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Threads",
        re.compile(r"https?://(?:www\.)?threads\.(?:net|com)/@([A-Za-z0-9_.]{2,35})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "LinkedIn Person",
        re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/in/([A-Za-z0-9_%-]{2,70})/?(?:[?#]|$)", re.I),
        "url",
    ),
    (
        "LinkedIn Company",
        re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/company/([A-Za-z0-9_%-]{2,70})/?(?:[?#]|$)", re.I),
        "url",
    ),
    (
        "Facebook",
        re.compile(r"https?://(?:www\.|m\.|ar-ar\.)?facebook\.com/([A-Za-z0-9.]{3,50})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Linktree",
        re.compile(r"https?://(?:www\.)?linktr\.ee/([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Taplink",
        re.compile(r"https?://(?:www\.)?taplink\.cc/([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Beacons",
        re.compile(r"https?://(?:www\.)?beacons\.ai/([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Bio.link",
        re.compile(r"https?://(?:www\.)?bio\.link/([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Solo.to",
        re.compile(r"https?://(?:www\.)?solo\.to/([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "GitHub",
        re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9-]{2,39})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Pinterest",
        re.compile(r"https?://(?:[a-z]{2}\.|www\.)?pinterest\.com/([A-Za-z0-9_]{2,35})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "SoundCloud",
        re.compile(r"https?://(?:www\.|m\.)?soundcloud\.com/([A-Za-z0-9_-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
    (
        "Medium",
        re.compile(r"https?://(?:www\.)?medium\.com/@([A-Za-z0-9_.-]{2,40})/?(?:[?#]|$)", re.I),
        "username",
    ),
]

SOCIAL_RESERVED_SLUGS = {
    "p", "reel", "reels", "stories", "explore", "accounts", "about", "legal", "privacy", "terms",
    "help", "login", "signup", "share", "sharer", "sharer.php", "intent", "home", "search",
    "hashtag", "i", "status", "watch", "channel", "results", "feed", "shorts", "playlist",
    "groups", "events", "pages", "marketplace", "gaming", "public", "profile.php", "s", "joinchat",
    "iv", "addstickers", "proxy", "blog", "pricing", "features", "admin", "register", "discover",
    "tag", "music", "trending", "live", "settings", "messages", "notifications",
}

WHATSAPP_URL_RE = re.compile(
    r"https?://(?:wa\.me/|api\.whatsapp\.com/send/?\?(?:[^\"'\s>]*&)?phone=)\+?(\d{8,15})",
    re.I,
)


def _res(module: str, status: str, summary: str, data: dict | list, pivots: list[dict] | None = None) -> dict:
    clean_pivots = []
    seen = set()
    for p in pivots or []:
        t, v = p.get("type"), str(p.get("value") or "").strip()
        if t and v and (t, v.lower()) not in seen:
            seen.add((t, v.lower()))
            clean_pivots.append({"type": t, "value": v})
    return {
        "module": module,
        "status": status,
        "summary": summary,
        "data": data,
        "pivots": clean_pivots,
    }


def _http_fetch(
    url: str,
    *,
    method: str = "GET",
    data_bytes: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = SEARCH_TIMEOUT,
    browser_ua: bool = False,
    max_bytes: int = 450_000,
) -> tuple[int, str, str | None]:
    hdrs = {
        "User-Agent": BROWSER_UA if browser_ua else API_UA,
        "Accept": "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data_bytes, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes).decode("utf-8", errors="replace")
            return resp.status, body, None
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(40_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return exc.code, body, f"HTTP {exc.code}"
    except Exception as exc:
        return 0, "", str(exc)


def _http_json(
    url: str,
    *,
    method: str = "GET",
    data_bytes: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = SEARCH_TIMEOUT,
) -> tuple[int, Any, str | None]:
    h = {"Accept": "application/json", **(headers or {})}
    st, txt, err = _http_fetch(url, method=method, data_bytes=data_bytes, headers=h, timeout=timeout)
    if st == 200 and txt:
        try:
            return st, json.loads(txt), None
        except Exception as exc:
            return st, None, f"Invalid JSON ({exc})"
    return st, None, err


def _strip_html(raw: str) -> str:
    if not raw:
        return ""
    cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.I | re.S)
    cleaned = HTML_TAG_RE.sub(" ", cleaned)
    return re.sub(r"\s+", " ", html.unescape(cleaned)).strip()


def classify_social_profile_url(url: str, title: str = "", snippet: str = "") -> dict[str, str] | None:
    """Identify social media / bio-link / WhatsApp URLs and extract the canonical handle or phone."""
    u = (url or "").strip()
    if not u.startswith(("http://", "https://")):
        return None

    wa_m = WHATSAPP_URL_RE.search(u)
    if wa_m:
        e164 = f"+{wa_m.group(1)}"
        return {
            "platform": "WhatsApp",
            "handle": e164,
            "pivot_type": "phone",
            "pivot_value": e164,
            "url": u,
            "title": title[:140],
            "snippet": snippet[:220],
        }

    for platform, pat, piv_type in SOCIAL_PATTERNS:
        m = pat.match(u)
        if not m:
            continue
        slug = urllib.parse.unquote(m.group(1)).strip().strip("/")
        if not slug or slug.lower() in SOCIAL_RESERVED_SLUGS:
            return None
        return {
            "platform": platform,
            "handle": slug,
            "pivot_type": piv_type,
            "pivot_value": u if piv_type == "url" else slug,
            "url": u.split("?")[0].rstrip("/"),
            "title": title[:140],
            "snippet": snippet[:220],
        }
    return None


# ============================================================================
# SHARED WEBPAGE CONTACT, SOCIAL, SCHEMA.ORG & TRACKING CARVER
# ============================================================================

class _RichPageParser(HTMLParser):
    def __init__(self, base_url: str = "") -> None:
        super().__init__()
        self.base_url = base_url
        self.title_parts: list[str] = []
        self._in_title = False
        self._in_ld = False
        self._ld_buf: list[str] = []
        self.meta: dict[str, str] = {}
        self.links: list[tuple[str, str]] = []
        self._cur_href: str | None = None
        self._cur_link_txt: list[str] = []
        self.jsonld_raw: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tl = tag.lower()
        ad = {k.lower(): (v or "") for k, v in attrs if k}
        if tl == "title":
            self._in_title = True
        elif tl == "meta":
            k = (ad.get("property") or ad.get("name") or "").lower().strip()
            v = ad.get("content", "").strip()
            if k and v and k not in self.meta:
                self.meta[k] = v[:350]
        elif tl == "a" and ad.get("href"):
            self._cur_href = ad["href"].strip()
            self._cur_link_txt = []
        elif tl == "script" and "ld+json" in ad.get("type", "").lower():
            self._in_ld = True
            self._ld_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._cur_href is not None:
            self._cur_link_txt.append(data)
        if self._in_ld:
            self._ld_buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        tl = tag.lower()
        if tl == "title":
            self._in_title = False
        elif tl == "a" and self._cur_href is not None:
            txt = re.sub(r"\s+", " ", "".join(self._cur_link_txt)).strip()[:120]
            self.links.append((self._cur_href, txt))
            self._cur_href = None
            self._cur_link_txt = []
        elif tl == "script" and self._in_ld:
            self._in_ld = False
            self.jsonld_raw.append("".join(self._ld_buf))


def _clean_emails_from_text(text: str) -> list[str]:
    found: set[str] = set()
    # De-obfuscate common "name [at] domain [dot] com"
    deobf = re.sub(r"\s*\[\s*at\s*\]\s*|\s*\(\s*at\s*\)\s*", "@", text, flags=re.I)
    deobf = re.sub(r"\s*\[\s*dot\s*\]\s*|\s*\(\s*dot\s*\)\s*", ".", deobf, flags=re.I)
    for raw_em in EMAIL_RE.findall(deobf):
        em = raw_em.strip().strip(".,;:()[]\"'").lower()
        if any(em.endswith(ext) for ext in EMAIL_FALSE_EXTS):
            continue
        if "@" not in em:
            continue
        dom = em.split("@", 1)[1]
        if dom in EMAIL_NOISE_HOSTS or dom in NOISE_DOMAINS or "2x." in dom:
            continue
        found.add(em)
    return sorted(found)[:25]


def carve_webpage_intelligence(raw_html: str, base_url: str = "") -> dict[str, Any]:
    """Extract emails, phones, WhatsApp links, social handles, schema.org entities & tracking IDs from HTML."""
    parser = _RichPageParser(base_url)
    try:
        parser.feed(raw_html)
    except Exception:
        pass

    title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()[:180]
    description = (
        parser.meta.get("og:description")
        or parser.meta.get("description")
        or parser.meta.get("twitter:description")
        or ""
    )

    emails: set[str] = set(_clean_emails_from_text(raw_html))
    phones: set[str] = set()
    social_map: dict[str, dict[str, str]] = {}
    contact_subpages: list[str] = []
    pivots: list[dict[str, str]] = []

    base_host = ""
    if base_url:
        try:
            base_host = (urllib.parse.urlparse(base_url).hostname or "").lower().removeprefix("www.")
        except ValueError:
            base_host = ""

    # 1. Inspect all <a href="..."> links
    for href, anchor_txt in parser.links:
        hl = href.lower()
        if hl.startswith("mailto:"):
            em_part = urllib.parse.unquote(href[7:].split("?", 1)[0]).strip().lower()
            for clean_em in _clean_emails_from_text(em_part):
                emails.add(clean_em)
            continue
        if hl.startswith(("tel:", "callto:")):
            raw_tel = urllib.parse.unquote(href.split(":", 1)[1].split("?", 1)[0])
            for s in extract_selectors(raw_tel, check_local_file=False):
                if s["type"] == "phone":
                    phones.add(s["value"])
            # Local Saudi/GCC 05xxxxxxxx -> +9665xxxxxxxx when page is .sa or Arabic
            digits_only = re.sub(r"\D", "", raw_tel)
            if len(digits_only) == 10 and digits_only.startswith("05") and base_host.endswith(".sa"):
                phones.add(f"+966{digits_only[1:]}")
            continue

        resolved = urllib.parse.urljoin(base_url, href) if base_url else href
        soc = classify_social_profile_url(resolved, title=anchor_txt)
        if soc:
            key = f"{soc['platform']}:{soc['handle'].lower()}"
            if key not in social_map:
                social_map[key] = soc
            if soc["pivot_type"] == "phone":
                phones.add(soc["pivot_value"])
            else:
                pivots.append({"type": soc["pivot_type"], "value": soc["pivot_value"]})
            continue

        # Same-host contact/about/team pages for active spidering
        if base_host and resolved.startswith(("http://", "https://")):
            try:
                p_sub = urllib.parse.urlparse(resolved)
                sub_host = (p_sub.hostname or "").lower().removeprefix("www.")
                sub_path = (p_sub.path or "").lower()
            except ValueError:
                sub_host, sub_path = "", ""
            if sub_host == base_host and any(
                kw in sub_path or kw in anchor_txt.lower()
                for kw in ("contact", "about", "team", "doctor", "staff", "leadership", "clinic", "اتصل", "تواصل", "من-نحن", "الاطباء", "الأطباء")
            ):
                clean_sub = f"{p_sub.scheme}://{p_sub.netloc}{p_sub.path}"
                if clean_sub not in contact_subpages and clean_sub.rstrip("/") != base_url.rstrip("/"):
                    contact_subpages.append(clean_sub)

    # 2. Scan visible text + WhatsApp links in raw HTML
    for wm in WHATSAPP_URL_RE.finditer(raw_html):
        e164_wa = f"+{wm.group(1)}"
        phones.add(e164_wa)
        social_map.setdefault(
            f"WhatsApp:{e164_wa}",
            {"platform": "WhatsApp", "handle": e164_wa, "pivot_type": "phone", "pivot_value": e164_wa, "url": wm.group(0), "title": "WhatsApp Direct", "snippet": ""},
        )

    visible_txt = _strip_html(raw_html)[:45_000]
    for s in extract_selectors(visible_txt, check_local_file=False):
        if s["type"] == "phone":
            phones.add(s["value"])
        elif s["type"] == "email":
            for clean_em in _clean_emails_from_text(s["value"]):
                emails.add(clean_em)

    # 3. Parse JSON-LD structured schema.org entities (MedicalClinic, Organization, Person, LocalBusiness)
    schema_entities: list[dict[str, Any]] = []
    same_as_links: list[str] = []

    def _walk_ld(node: Any) -> None:
        if isinstance(node, list):
            for it in node:
                _walk_ld(it)
            return
        if not isinstance(node, dict):
            return
        if isinstance(node.get("@graph"), list):
            _walk_ld(node["@graph"])
        ntype = node.get("@type")
        if ntype:
            rec: dict[str, Any] = {"type": ntype if isinstance(ntype, str) else ",".join(str(x) for x in ntype)}
            for fld in ("name", "legalName", "alternateName", "jobTitle", "telephone", "email", "url", "taxID", "vatID"):
                if node.get(fld) and isinstance(node[fld], (str, int, float)):
                    rec[fld] = str(node[fld]).strip()[:140]
            if rec.get("email"):
                for em in _clean_emails_from_text(rec["email"]):
                    emails.add(em)
            if rec.get("telephone"):
                for s in extract_selectors(rec["telephone"], check_local_file=False):
                    if s["type"] == "phone":
                        phones.add(s["value"])
            addr = node.get("address")
            if isinstance(addr, dict):
                parts = [
                    str(addr.get(k) or "").strip()
                    for k in ("streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry")
                ]
                addr_str = ", ".join(p for p in parts if p)
                if addr_str:
                    rec["address"] = addr_str
            geo = node.get("geo")
            if isinstance(geo, dict) and geo.get("latitude") and geo.get("longitude"):
                try:
                    lat = float(geo["latitude"])
                    lon = float(geo["longitude"])
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        coord_s = f"{lat:.6f},{lon:.6f}"
                        rec["coordinates"] = coord_s
                        pivots.append({"type": "coordinates", "value": coord_s})
                except (ValueError, TypeError):
                    pass
            sa = node.get("sameAs")
            if sa:
                sa_list = sa if isinstance(sa, list) else [sa]
                for u in sa_list:
                    if isinstance(u, str) and u.startswith("http"):
                        same_as_links.append(u)
                        soc = classify_social_profile_url(u)
                        if soc:
                            social_map.setdefault(f"{soc['platform']}:{soc['handle'].lower()}", soc)
                            pivots.append({"type": soc["pivot_type"], "value": soc["pivot_value"]})
                        else:
                            pivots.append({"type": "url", "value": u})
            # Extract human/org names from JSON-LD
            t_low = str(rec["type"]).lower()
            nm = rec.get("name") or rec.get("legalName")
            if nm and 2 <= len(nm.split()) <= 6:
                if any(x in t_low for x in ("person", "physician", "author")):
                    pivots.append({"type": "person_name", "value": nm})
                elif any(x in t_low for x in ("organization", "corporation", "clinic", "hospital", "business", "medical", "store")):
                    pivots.append({"type": "company", "value": nm})
            for rel_key in ("founder", "founders", "employee", "employees", "member", "members", "author"):
                rel_v = node.get(rel_key)
                rel_items = rel_v if isinstance(rel_v, list) else ([rel_v] if rel_v else [])
                for rv in rel_items[:8]:
                    if isinstance(rv, dict) and rv.get("name"):
                        pivots.append({"type": "person_name", "value": str(rv["name"]).strip()})
            if len(rec) > 1:
                schema_entities.append(rec)

    for blk in parser.jsonld_raw[:10]:
        try:
            _walk_ld(json.loads(blk))
        except Exception:
            pass

    # 4. Analytics, AdSense & Pixel Fingerprints (link sibling sites owned by same operator!)
    tracking_ids: dict[str, list[str]] = {}
    for key_t, rx in (
        ("ga4_ids", r"\bG-[A-Z0-9]{8,12}\b"),
        ("gtm_ids", r"\bGTM-[A-Z0-9]{5,10}\b"),
        ("ua_ids", r"\bUA-\d{4,10}-\d{1,4}\b"),
        ("adsense_ids", r"\bpub-\d{14,18}\b"),
        ("meta_pixels", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{12,18})['\"]"),
        ("tiktok_pixels", r"ttq\.load\(\s*['\"]([A-Z0-9]{14,24})['\"]"),
        ("snap_pixels", r"snaptr\(\s*['\"]init['\"]\s*,\s*['\"]([a-f0-9-]{32,36})['\"]"),
    ):
        matches = sorted(set(re.findall(rx, raw_html)))
        if matches:
            tracking_ids[key_t] = matches[:10]

    for em in sorted(emails)[:12]:
        pivots.append({"type": "email", "value": em})
    for ph in sorted(phones)[:12]:
        pivots.append({"type": "phone", "value": ph})

    return {
        "title": title or parser.meta.get("og:title"),
        "description": description[:300] if description else None,
        "meta_tags": {k: v for k, v in parser.meta.items() if k.startswith(("og:", "twitter:", "author", "generator"))},
        "emails": sorted(emails)[:20],
        "phones": sorted(phones)[:20],
        "social_profiles": list(social_map.values())[:30],
        "schema_same_as_links": sorted(set(same_as_links))[:25],
        "schema_entities": schema_entities[:12],
        "tracking_ids": tracking_ids,
        "contact_subpages": contact_subpages[:5],
        "pivots": pivots,
    }


# ============================================================================
# MULTI-ENGINE KEYLESS PASSIVE WEB & NEWS SEARCH
# ============================================================================

def _unwrap_ddg_url(href: str) -> str:
    if "uddg=" in href:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        if qs.get("uddg"):
            return qs["uddg"][0]
    if href.startswith("//"):
        return "https:" + href
    return href


def parse_duckduckgo_html(raw_html: str) -> list[dict[str, str]]:
    """Parse DuckDuckGo `/html/` or `/lite/` organic results into `{title, url, snippet, engine}`."""
    results: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    # Standard /html/ blocks
    for blk in re.findall(r'<div[^>]+class="[^"]*results_links[^"]*"[^>]*>(.*?)</div>\s*</div>', raw_html, flags=re.I | re.S):
        m_a = re.search(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', blk, flags=re.I | re.S)
        if not m_a:
            continue
        url = _unwrap_ddg_url(html.unescape(m_a.group(1)))
        if not url.startswith(("http://", "https://")) or "duckduckgo.com" in url:
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        title = _strip_html(m_a.group(2))
        m_snip = re.search(r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div|span)>', blk, flags=re.I | re.S)
        snippet = _strip_html(m_snip.group(1)) if m_snip else ""
        results.append({"title": title[:180], "url": url, "snippet": snippet[:320], "engine": "DuckDuckGo"})

    # Fallback pattern if DDG slightly varies wrapper divs
    if not results:
        links = re.findall(r'<a[^>]+class="[^"]*(?:result__a|result-link)[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', raw_html, flags=re.I | re.S)
        snips = re.findall(r'class="[^"]*(?:result__snippet|result-snippet)[^"]*"[^>]*>(.*?)</(?:a|td|div|span)>', raw_html, flags=re.I | re.S)
        for idx, (href, t_raw) in enumerate(links):
            url = _unwrap_ddg_url(html.unescape(href))
            if not url.startswith(("http://", "https://")) or "duckduckgo.com" in url or url in seen_urls:
                continue
            seen_urls.add(url)
            snip = _strip_html(snips[idx]) if idx < len(snips) else ""
            results.append({"title": _strip_html(t_raw)[:180], "url": url, "snippet": snip[:320], "engine": "DuckDuckGo"})

    return results[:20]


def parse_yahoo_search_html(raw_html: str) -> list[dict[str, str]]:
    """Parse Yahoo Web Search HTML (`search.yahoo.com/search`) results and unwrap `/RU=.../RK=` URLs."""
    results: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    for blk in re.findall(r'<div[^>]+class="[^"]*\balgo\b[^"]*"[^>]*>(.*?)</li>', raw_html, flags=re.I | re.S):
        m_a = re.search(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', blk, flags=re.I | re.S)
        if not m_a:
            continue
        raw_u = html.unescape(m_a.group(1))
        ru_m = re.search(r"/RU=([^/]+)/RK=", raw_u)
        url = urllib.parse.unquote(ru_m.group(1)) if ru_m else raw_u
        if not url.startswith(("http://", "https://")) or "yahoo.com" in urllib.parse.urlparse(url).netloc or "bing.com/aclick" in url:
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        title = re.sub(r"^.*?\bhttp[^\s]+\s*", "", _strip_html(m_a.group(2))).strip()
        m_snip = re.search(r'<div[^>]+class="[^"]*compText[^"]*"[^>]*>(.*?)</div>', blk, flags=re.I | re.S)
        snippet = _strip_html(m_snip.group(1)) if m_snip else ""
        results.append({"title": title[:180], "url": url, "snippet": snippet[:320], "engine": "Yahoo"})

    return results[:15]


def parse_rss_search_xml(raw_xml: str, engine_name: str) -> list[dict[str, str]]:
    """Parse Bing Search RSS (`format=rss`) or Google News RSS XML into `{title, url, snippet, date, engine}`."""
    results: list[dict[str, str]] = []
    if not raw_xml or "<item>" not in raw_xml:
        return results
    try:
        root = ET.fromstring(raw_xml)
    except Exception:
        return results

    for item in root.findall(".//item")[:15]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        desc = _strip_html(item.findtext("description") or "")
        pub_date = (item.findtext("pubDate") or "").strip()
        if not link.startswith(("http://", "https://")):
            continue
        rec = {"title": title[:180], "url": link, "snippet": desc[:320], "engine": engine_name}
        if pub_date:
            rec["published"] = pub_date
        results.append(rec)
    return results


def _search_ddg(query: str) -> tuple[bool, list[dict[str, str]]]:
    form = urllib.parse.urlencode({"q": query, "kl": ""}).encode("utf-8")
    st, html_txt, _ = _http_fetch(
        "https://html.duckduckgo.com/html/",
        method="POST",
        data_bytes=form,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": "https://html.duckduckgo.com/"},
        browser_ua=True,
        timeout=3.4,
    )
    if st == 0:
        return False, []
    if st in (200, 202) and html_txt and "anomaly-modal" not in html_txt:
        parsed = parse_duckduckgo_html(html_txt)
        if parsed:
            return True, parsed
    st2, lite_txt, _ = _http_fetch(
        "https://lite.duckduckgo.com/lite/",
        method="POST",
        data_bytes=urllib.parse.urlencode({"q": query}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": "https://lite.duckduckgo.com/"},
        browser_ua=True,
        timeout=3.0,
    )
    if st2 == 200 and lite_txt:
        return True, parse_duckduckgo_html(lite_txt)
    return True, []


def _search_yahoo(query: str) -> tuple[bool, list[dict[str, str]]]:
    url = f"https://search.yahoo.com/search?p={urllib.parse.quote(query)}&n=12&ei=UTF-8"
    st, html_txt, _ = _http_fetch(url, browser_ua=True)
    if st == 200 and html_txt:
        return True, parse_yahoo_search_html(html_txt)
    return st != 0, []


def _search_bing_rss(query: str) -> tuple[bool, list[dict[str, str]]]:
    url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}&format=rss&count=12"
    st, xml_txt, _ = _http_fetch(url, browser_ua=True)
    if st == 200 and xml_txt:
        parsed = parse_rss_search_xml(xml_txt, "Bing")
        if parsed:
            return True, parsed
    return st != 0, []


def _search_google_news_rss(query: str) -> tuple[bool, list[dict[str, str]]]:
    has_arabic = bool(re.search(r"[\u0600-\u06FF]", query))
    hl_params = "hl=ar&gl=SA&ceid=SA:ar" if has_arabic else "hl=en-US&gl=US&ceid=US:en"
    url = f"https://news.google.com/rss/search?q={urllib.parse.quote(query)}&{hl_params}"
    st, xml_txt, _ = _http_fetch(url, browser_ua=True)
    if st == 200 and xml_txt:
        return True, parse_rss_search_xml(xml_txt, "GoogleNews")
    return st != 0, []


def run_multi_engine_web_search(queries: list[str], *, include_news: bool = True) -> dict[str, Any]:
    """Execute queries concurrently across DuckDuckGo, Yahoo, Bing RSS & Google News RSS and carve OSINT leads."""
    clean_queries = [q.strip() for q in queries if q and q.strip()][:2]
    if not clean_queries:
        return {"reachable": False, "results": [], "social_hits": [], "emails": [], "phones": [], "pivots": []}

    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for idx, q in enumerate(clean_queries):
            tasks.append(pool.submit(_search_ddg, q))
            tasks.append(pool.submit(_search_yahoo, q))
            if idx == 0:
                tasks.append(pool.submit(_search_bing_rss, q))
                if include_news:
                    tasks.append(pool.submit(_search_google_news_rss, q))

        any_reachable = False
        merged_results: list[dict[str, str]] = []
        seen_urls: set[str] = set()
        for fut in tasks:
            try:
                ok_reach, rows = fut.result()
                if ok_reach:
                    any_reachable = True
                for r in rows:
                    u_norm = r["url"].rstrip("/")
                    if u_norm not in seen_urls:
                        seen_urls.add(u_norm)
                        merged_results.append(r)
            except Exception:
                continue

    social_hits: dict[str, dict[str, str]] = {}
    emails: set[str] = set()
    phones: set[str] = set()
    domains: set[str] = set()
    pivots: list[dict[str, str]] = []

    for r in merged_results[:30]:
        u = r["url"]
        title = r.get("title", "")
        snip = r.get("snippet", "")
        soc = classify_social_profile_url(u, title=title, snippet=snip)
        if soc:
            skey = f"{soc['platform']}:{soc['handle'].lower()}"
            if skey not in social_hits:
                social_hits[skey] = soc
            pivots.append({"type": soc["pivot_type"], "value": soc["pivot_value"]})
        elif r.get("engine") != "GoogleNews":
            try:
                host = (urllib.parse.urlparse(u).hostname or "").lower().removeprefix("www.")
                if (
                    host
                    and host not in NOISE_DOMAINS
                    and host not in PLATFORM_AND_DIRECTORY_HOSTS
                    and not any(host.endswith("." + ph) for ph in PLATFORM_AND_DIRECTORY_HOSTS)
                ):
                    domains.add(host)
            except ValueError:
                pass

        blob = f"{title} — {snip}"
        for em in _clean_emails_from_text(blob):
            emails.add(em)
            pivots.append({"type": "email", "value": em})
        for sel in extract_selectors(blob, check_local_file=False):
            if sel["type"] == "phone":
                phones.add(sel["value"])
                pivots.append({"type": "phone", "value": sel["value"]})

    for dom in sorted(domains)[:6]:
        pivots.append({"type": "domain", "value": dom})

    return {
        "reachable": any_reachable,
        "queries_executed": clean_queries,
        "results": merged_results[:25],
        "social_hits": list(social_hits.values())[:20],
        "emails": sorted(emails)[:15],
        "phones": sorted(phones)[:15],
        "related_domains": sorted(domains)[:12],
        "pivots": pivots,
    }


# ============================================================================
# DEEP PHONE OSINT COLLECTOR (FORMATS + WEB + WHATSAPP + GITHUB + OSM)
# ============================================================================

def generate_phone_search_variants(e164: str) -> dict[str, Any]:
    """Generate international, trunk-0 local, and spaced representations for real-world OSINT phone search."""
    digits = re.sub(r"\D", "", e164)
    full_e164 = f"+{digits}"
    variants = [full_e164, digits]
    local_formats: list[str] = []

    # GCC / MENA / Europe 3-digit & 2-digit country codes with trunk '0'
    for cc in ("966", "971", "965", "974", "973", "968", "962", "961", "964", "970", "972", "212", "213", "216"):
        if digits.startswith(cc) and len(digits) >= len(cc) + 8:
            nat = digits[len(cc):]
            if cc in ("966", "971", "962", "970", "972", "212", "213"):
                local_0 = f"0{nat}"
                local_formats.append(local_0)
                if len(local_0) == 10:
                    local_formats.append(f"{local_0[:3]} {local_0[3:6]} {local_0[6:]}")
                    local_formats.append(f"+{cc} {nat[:2]} {nat[2:5]} {nat[5:]}")
            else:
                local_formats.append(nat)
            break
    else:
        for cc2 in ("20", "44", "33", "49", "90", "91", "92"):
            if digits.startswith(cc2) and len(digits) >= len(cc2) + 9:
                nat = digits[len(cc2):]
                local_formats.append(f"0{nat}")
                break
        if digits.startswith("1") and len(digits) == 11:
            area, exch, line = digits[1:4], digits[4:7], digits[7:]
            local_formats.extend([f"{area}-{exch}-{line}", f"({area}) {exch}-{line}", digits[1:]])

    for lf in local_formats:
        if lf not in variants:
            variants.append(lf)

    return {
        "e164": full_e164,
        "digits": digits,
        "local_formats": local_formats,
        "all_variants": variants,
        "whatsapp_direct_url": f"https://wa.me/{digits}",
        "whatsapp_api_url": f"https://api.whatsapp.com/send/?phone={digits}",
    }


def collect_phone_deep_osint(e164_phone: str) -> list[dict]:
    """Run live open-web, WhatsApp share metadata, GitHub code/repo, and OpenStreetMap POI lookups for a phone."""
    fmt = generate_phone_search_variants(e164_phone)
    digits = fmt["digits"]
    local0 = fmt["local_formats"][0] if fmt["local_formats"] else ""

    q1_terms = [f'"{fmt["e164"]}"', f'"{digits}"']
    if local0:
        q1_terms.insert(0, f'"{local0}"')
    if len(fmt["local_formats"]) >= 2:
        q1_terms.append(f'"{fmt["local_formats"][1]}"')
    queries = [
        " OR ".join(q1_terms[:3]),
        f'({" OR ".join(q1_terms[:2])}) (instagram OR snapchat OR tiktok OR linktr.ee OR taplink OR x.com OR whatsapp)',
    ]

    out: list[dict] = []

    def _web_task():
        return run_multi_engine_web_search(queries, include_news=False)

    def _wa_task():
        st, body, err = _http_fetch(fmt["whatsapp_api_url"], browser_ua=True, timeout=4.2)
        if st != 200 or not body:
            return None, err
        m_og = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        m_h3 = re.search(r'<h3[^>]*class="[^"]*_9vd5[^"]*"[^>]*>(.*?)</h3>', body, re.I | re.S)
        raw_title = html.unescape(m_h3.group(1) if m_h3 else (m_og.group(1) if m_og else "")).strip()
        raw_title = _strip_html(raw_title)
        generic = {"share on whatsapp", "whatsapp", "send message on whatsapp", ""}
        exposed_name = raw_title if raw_title.lower() not in generic and digits not in raw_title else None
        return {"reachable": True, "whatsapp_url": fmt["whatsapp_direct_url"], "business_or_display_title": exposed_name}, None

    def _gh_task():
        search_tok = local0 or digits
        q = urllib.parse.quote(f'"{digits}" OR "{search_tok}"' if local0 else f'"{digits}"')
        st, obj, _ = _http_json(f"https://api.github.com/search/repositories?q={q}&per_page=5")
        if st == 200 and isinstance(obj, dict) and obj.get("items"):
            repos = [
                {"full_name": it.get("full_name"), "description": (it.get("description") or "")[:140], "homepage": it.get("homepage")}
                for it in obj["items"][:5]
            ]
            return repos
        return []

    def _osm_task():
        st, arr, _ = _http_json(
            f"https://nominatim.openstreetmap.org/search?q={urllib.parse.quote(fmt['e164'])}&format=jsonv2&addressdetails=1&extratags=1&limit=5"
        )
        if st == 200 and isinstance(arr, list) and arr:
            return arr[:5]
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        f_web = pool.submit(_web_task)
        f_wa = pool.submit(_wa_task)
        f_gh = pool.submit(_gh_task)
        f_osm = pool.submit(_osm_task)
        f_img = pool.submit(search_open_web_images, f'"{fmt["e164"]}"' + (f' OR "{local0}"' if local0 else ""))
        web_res = f_web.result()
        wa_res, _ = f_wa.result()
        gh_repos = f_gh.result()
        osm_places = f_osm.result()
        img_res = f_img.result()

    # 1. Phone formats + WhatsApp verification link card (always useful)
    wa_pivots = []
    if wa_res and wa_res.get("business_or_display_title"):
        wa_pivots.append({"type": "company", "value": wa_res["business_or_display_title"]})
    out.append(
        _res(
            "phone_formats_and_whatsapp",
            "ok",
            f"Generated {len(fmt['all_variants'])} search format(s) ({', '.join(fmt['all_variants'][:4])}) · WhatsApp: {fmt['whatsapp_direct_url']}"
            + (f" · Exposed WA Title: '{wa_res['business_or_display_title']}'" if (wa_res and wa_res.get("business_or_display_title")) else ""),
            {**fmt, "whatsapp_page_probe": wa_res},
            wa_pivots,
        )
    )

    # 2. Open-Web Mentions & Social Bio Links
    if web_res["results"]:
        out.append(
            _res(
                "phone_open_web_mentions",
                "ok",
                f"Found {len(web_res['results'])} web mention(s) & {len(web_res['social_hits'])} linked social profile(s) for {fmt['e164']}",
                {
                    "queries": web_res["queries_executed"],
                    "social_profiles": web_res["social_hits"],
                    "web_results": web_res["results"][:15],
                    "extracted_emails": web_res["emails"],
                    "related_domains": web_res["related_domains"],
                },
                web_res["pivots"],
            )
        )
    elif not web_res["reachable"]:
        out.append(_res("phone_open_web_mentions", "restricted_or_offline", "External search engines unreachable in restricted network", {"queries": queries}))
    else:
        out.append(_res("phone_open_web_mentions", "not_found", f"0 indexed public web pages matched {fmt['e164']} / {local0 or digits}", {"queries": queries}))

    if img_res and img_res.get("images"):
        out.append(
            _res(
                "open_web_image_search",
                "ok",
                f"Discovered {len(img_res['images'])} public photo(s) / flyer(s) mentioning {fmt['e164']}",
                {"images": img_res["images"]},
            )
        )

    # 3. GitHub Public Repos mentioning Phone
    if gh_repos:
        gh_pivots = [{"type": "repo_code", "value": r["full_name"]} for r in gh_repos if r.get("full_name")]
        out.append(
            _res(
                "github_phone_footprints",
                "ok",
                f"Phone number found in {len(gh_repos)} public GitHub repository description(s)",
                {"repositories": gh_repos},
                gh_pivots,
            )
        )

    # 4. OpenStreetMap Registered Clinic/Business POI
    if osm_places:
        osm_pivots = []
        places_clean = []
        for pl in osm_places:
            tags = pl.get("extratags") or {}
            places_clean.append(
                {
                    "name": pl.get("name") or pl.get("display_name"),
                    "category": pl.get("type"),
                    "address": pl.get("display_name"),
                    "lat": pl.get("lat"),
                    "lon": pl.get("lon"),
                    "website": tags.get("website") or tags.get("contact:website"),
                }
            )
            if pl.get("lat") and pl.get("lon"):
                osm_pivots.append({"type": "coordinates", "value": f"{float(pl['lat']):.6f},{float(pl['lon']):.6f}"})
            web_u = tags.get("website") or tags.get("contact:website")
            if web_u and web_u.startswith("http"):
                osm_pivots.append({"type": "url", "value": web_u})
        out.append(
            _res(
                "osm_phone_business_lookup",
                "ok",
                f"Matched {len(places_clean)} OpenStreetMap business/clinic listing(s)",
                {"places": places_clean},
                osm_pivots,
            )
        )

    return out


# ============================================================================
# DEEP EMAIL BREACH, INFOSTEALER, REPUTATION, CLOUD & PGP COLLECTORS
# ============================================================================

def collect_email_deep_intel(email: str) -> list[dict]:
    """Run keyless XposedOrNot breaches, HudsonRock stealer check, EmailRep, PGP VKS, M365/Live & Open-Web search."""
    em = email.strip().lower()
    domain = em.split("@", 1)[1]

    def _xposed():
        st, obj, err = _http_json(f"https://api.xposedornot.com/v1/breach-analytics?email={urllib.parse.quote(em)}")
        if st == 200 and isinstance(obj, dict):
            exposed = ((obj.get("ExposedBreaches") or {}).get("breaches_details")) or []
            if exposed:
                breaches = [
                    {
                        "breach": b.get("breach"),
                        "domain": b.get("domain"),
                        "date": b.get("xposed_date"),
                        "exposed_data": b.get("xposed_data"),
                        "industry": b.get("industry"),
                    }
                    for b in exposed[:25]
                ]
                return _res(
                    "xposedornot_breach_intelligence",
                    "ok",
                    f"ALERT: Email found in {len(exposed)} public data breach(es): {', '.join(b['breach'] for b in breaches[:5] if b.get('breach'))}",
                    {"breach_count": len(exposed), "breaches": breaches},
                )
            return _res("xposedornot_breach_intelligence", "not_found", "0 public breaches matched in XposedOrNot dataset", {"breach_count": 0})
        if st == 404:
            return _res("xposedornot_breach_intelligence", "not_found", "0 public breaches matched in XposedOrNot dataset", {"breach_count": 0})
        return _res("xposedornot_breach_intelligence", "restricted_or_offline", f"XposedOrNot unreachable ({err})", {})

    def _hudsonrock():
        st, obj, err = _http_json(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={urllib.parse.quote(em)}"
        )
        if st == 200 and isinstance(obj, dict):
            stealers = obj.get("stealers") or []
            if stealers:
                return _res(
                    "hudsonrock_infostealer_check",
                    "ok",
                    f"CRITICAL: Email compromised in {len(stealers)} infostealer malware log(s)!",
                    {"stealer_count": len(stealers), "stealers": stealers[:10]},
                )
            return _res("hudsonrock_infostealer_check", "not_found", "No infostealer malware infections recorded in HudsonRock", {"stealer_count": 0})
        return _res("hudsonrock_infostealer_check", "restricted_or_offline", f"HudsonRock API unreachable ({err})", {})

    def _emailrep():
        st, obj, err = _http_json(f"https://emailrep.io/{urllib.parse.quote(em)}")
        if st == 200 and isinstance(obj, dict) and obj.get("email"):
            details = obj.get("details") or {}
            profiles = details.get("profiles") or []
            return _res(
                "emailrep_reputation_and_profiles",
                "ok",
                f"Reputation: {obj.get('reputation')} · Breached={details.get('data_breach')} · Linked Platforms: {profiles or ['none']}",
                {
                    "reputation": obj.get("reputation"),
                    "suspicious": obj.get("suspicious"),
                    "references": obj.get("references"),
                    "profiles": profiles,
                    "credentials_leaked": details.get("credentials_leaked"),
                    "data_breach": details.get("data_breach"),
                    "first_seen": details.get("first_seen"),
                    "last_seen": details.get("last_seen"),
                },
            )
        return _res("emailrep_reputation_and_profiles", "restricted_or_offline", f"EmailRep unavailable ({err})", {})

    def _pgp_vks():
        st, txt, err = _http_fetch(
            f"https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search={urllib.parse.quote(em)}"
        )
        if st == 200 and "uid:" in txt:
            uids = []
            pivots = []
            for ln in txt.splitlines():
                if ln.startswith("uid:"):
                    raw_uid = urllib.parse.unquote(ln.split(":", 2)[1])
                    uids.append(raw_uid)
                    m_nm = re.match(r"^([^<(]{3,50})\s*<", raw_uid)
                    if m_nm and " " in m_nm.group(1).strip():
                        pivots.append({"type": "person_name", "value": m_nm.group(1).strip()})
                    for extra_em in _clean_emails_from_text(raw_uid):
                        if extra_em != em:
                            pivots.append({"type": "email", "value": extra_em})
            if uids:
                return _res("openpgp_keyserver_uids", "ok", f"PGP keyserver returned {len(uids)} identity UID(s): {uids[:3]}", {"uids": uids[:10]}, pivots)
        if st == 0:
            return _res("openpgp_keyserver_uids", "restricted_or_offline", f"Keyserver unreachable ({err})", {})
        return _res("openpgp_keyserver_uids", "not_found", "No PGP key indexed on Ubuntu HKP", {})

    def _ms_account():
        payload = json.dumps({"Username": em, "isOtherIdpSupported": True}).encode("utf-8")
        st, obj, err = _http_json(
            "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
            method="POST",
            data_bytes=payload,
            headers={"Content-Type": "application/json"},
        )
        if st == 200 and isinstance(obj, dict):
            exists_code = obj.get("IfExistsResult")
            # 0 = exists, 1 = does not exist, 5/6 = exists in another/federated IDP
            exists = exists_code in (0, 5, 6)
            fed_url = ((obj.get("Credentials") or {}).get("FederationRedirectUrl")) or None
            return _res(
                "microsoft_cloud_identity_check",
                "ok" if exists else "not_found",
                f"Microsoft / M365 / Live / Skype account exists={exists} (IfExistsResult={exists_code})",
                {"account_exists": exists, "if_exists_code": exists_code, "throttle_status": obj.get("ThrottleStatus"), "federation_redirect_url": fed_url},
            )
        return _res("microsoft_cloud_identity_check", "restricted_or_offline", f"Microsoft endpoint unreachable ({err})", {})

    def _duolingo_email():
        st, obj, _ = _http_json(f"https://www.duolingo.com/2017-06-30/users?email={urllib.parse.quote(em)}")
        users = (obj.get("users") or []) if (st == 200 and isinstance(obj, dict)) else []
        if users and isinstance(users[0], dict):
            u0 = users[0]
            pivs = []
            if u0.get("username"):
                pivs.append({"type": "username", "value": u0["username"]})
            if u0.get("name") and " " in str(u0["name"]).strip():
                pivs.append({"type": "person_name", "value": str(u0["name"]).strip()})
            return _res(
                "duolingo_email_attribution",
                "ok",
                f"Matched Duolingo account @{u0.get('username')} ({u0.get('name') or 'no name'})",
                {"username": u0.get("username"), "name": u0.get("name"), "creation_date": u0.get("creationDate"), "streak": u0.get("streak")},
                pivs,
            )
        return None

    def _mx_provider():
        st_mx, mx_obj, _ = _http_json(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=MX",
            headers={"Accept": "application/dns-json"},
        )
        st_dmarc, dm_obj, _ = _http_json(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote('_dmarc.' + domain)}&type=TXT",
            headers={"Accept": "application/dns-json"},
        )
        if st_mx != 200 or not isinstance(mx_obj, dict):
            return None
        mx_rows = [str(a.get("data") or "").lower().rstrip(".") for a in (mx_obj.get("Answer") or []) if a.get("data")]
        dmarc_rows = [str(a.get("data") or "").strip('"') for a in ((dm_obj or {}).get("Answer") or []) if isinstance(dm_obj, dict) and a.get("data")]
        mx_blob = " ".join(mx_rows)
        provider = "Custom / Self-Hosted Mail"
        for marker, label in (
            ("google.com", "Google Workspace / Gmail"),
            ("googlemail.com", "Google Workspace / Gmail"),
            ("protection.outlook.com", "Microsoft 365 / Exchange Online"),
            ("outlook.com", "Microsoft Outlook / Live"),
            ("protonmail.ch", "Proton Mail"),
            ("zoho.", "Zoho Mail"),
            ("icloud.com", "Apple iCloud Mail"),
            ("messagingengine.com", "Fastmail"),
            ("mimecast.com", "Mimecast Secure Email Gateway"),
            ("pphosted.com", "Proofpoint Email Security"),
            ("yahoodns.net", "Yahoo Mail"),
        ):
            if marker in mx_blob:
                provider = label
                break
        return _res(
            "email_mx_and_dmarc_posture",
            "ok" if mx_rows else "not_found",
            f"Mail Provider: {provider} · {len(mx_rows)} MX record(s) · DMARC={'present' if dmarc_rows else 'missing'}",
            {"mail_provider": provider, "mx_records": mx_rows[:10], "dmarc_records": dmarc_rows[:4]},
        )

    def _web_email():
        return run_multi_engine_web_search([f'"{em}"'], include_news=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        f_xp = pool.submit(_xposed)
        f_hr = pool.submit(_hudsonrock)
        f_er = pool.submit(_emailrep)
        f_pgp = pool.submit(_pgp_vks)
        f_ms = pool.submit(_ms_account)
        f_duo = pool.submit(_duolingo_email)
        f_mx = pool.submit(_mx_provider)
        f_wb = pool.submit(_web_email)

        results = [f_xp.result(), f_hr.result(), f_er.result(), f_pgp.result(), f_ms.result()]
        duo_r = f_duo.result()
        if duo_r:
            results.append(duo_r)
        mx_r = f_mx.result()
        if mx_r:
            results.append(mx_r)
        wb_r = f_wb.result()
        if wb_r["results"]:
            results.append(
                _res(
                    "email_open_web_mentions",
                    "ok",
                    f"Found {len(wb_r['results'])} public web page(s) mentioning '{em}'",
                    {"web_results": wb_r["results"][:12], "social_profiles": wb_r["social_hits"]},
                    wb_r["pivots"],
                )
            )
    return results


# ============================================================================
# EXTENDED PASSIVE DOMAIN & ARCHIVED WEBPAGE CONTENT COLLECTORS
# ============================================================================

def collect_domain_deep_passive(domain: str) -> list[dict]:
    """Supplement domain OSINT with URLScan.io, Multi-Feed Subdomains, Wayback HTML Carver, HudsonRock & Web Search."""
    d = domain.strip().lower().removeprefix("www.")

    def _urlscan():
        st, obj, err = _http_json(f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(d)}&size=20")
        if st != 200 or not isinstance(obj, dict):
            return _res("urlscan_passive_history", "restricted_or_offline", f"URLScan search unreachable ({err})", {})
        rows = obj.get("results") or []
        if not rows:
            return _res("urlscan_passive_history", "not_found", f"0 historical URLScan captures for '{d}'", {"total": 0})
        ips: set[str] = set()
        servers: set[str] = set()
        scans = []
        for r in rows[:15]:
            page = r.get("page") or {}
            task = r.get("task") or {}
            if page.get("ip"):
                ips.add(page["ip"])
            if page.get("server"):
                servers.add(page["server"])
            scans.append(
                {
                    "url": page.get("url") or task.get("url"),
                    "title": (page.get("title") or "")[:120],
                    "ip": page.get("ip"),
                    "asn": page.get("asn"),
                    "asnname": page.get("asnname"),
                    "server": page.get("server"),
                    "scanned_at": task.get("time"),
                    "screenshot": r.get("screenshot"),
                }
            )
        pivs = [{"type": "ip", "value": ip} for ip in sorted(ips)[:5]]
        return _res(
            "urlscan_passive_history",
            "ok",
            f"URLScan indexed {obj.get('total', len(rows))} historical scan(s) · Servers: {sorted(servers)[:4]} · IPs: {sorted(ips)[:4]}",
            {"total": obj.get("total", len(rows)), "servers": sorted(servers), "ips": sorted(ips), "recent_scans": scans[:10]},
            pivs,
        )

    def _multi_subdomains():
        subs: set[str] = set()
        otx_ips: set[str] = set()
        sources_hit: list[str] = []

        def _f_ht():
            return _http_fetch(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(d)}", timeout=3.8)

        def _f_anubis():
            return _http_json(f"https://jldc.me/anubis/subdomains/{urllib.parse.quote(d)}", timeout=3.8)

        def _f_cs():
            return _http_json(
                f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(d)}&include_subdomains=true&expand=dns_names",
                timeout=3.8,
            )

        def _f_otx():
            return _http_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(d)}/passive_dns", timeout=3.8)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as sub_pool:
            r_ht = sub_pool.submit(_f_ht)
            r_an = sub_pool.submit(_f_anubis)
            r_cs = sub_pool.submit(_f_cs)
            r_ox = sub_pool.submit(_f_otx)
            st1, txt1, _ = r_ht.result()
            st2, arr2, _ = r_an.result()
            st3, arr3, _ = r_cs.result()
            st4, obj4, _ = r_ox.result()

        if st1 == 200 and txt1 and "API count exceeded" not in txt1 and "," in txt1:
            sources_hit.append("HackerTarget")
            for ln in txt1.splitlines():
                host_part = ln.split(",", 1)[0].strip().lower()
                if host_part.endswith(d) and DOMAIN_RE.fullmatch(host_part):
                    subs.add(host_part)

        if st2 == 200 and isinstance(arr2, list):
            sources_hit.append("AnubisDB")
            for h in arr2[:300]:
                if isinstance(h, str) and h.lower().endswith(d) and DOMAIN_RE.fullmatch(h.lower()):
                    subs.add(h.lower())

        if st3 == 200 and isinstance(arr3, list):
            sources_hit.append("CertSpotter")
            for it in arr3[:150]:
                for dns_n in (it.get("dns_names") or []) if isinstance(it, dict) else []:
                    clean_n = str(dns_n).lower().removeprefix("*.")
                    if clean_n.endswith(d) and DOMAIN_RE.fullmatch(clean_n):
                        subs.add(clean_n)

        if st4 == 200 and isinstance(obj4, dict):
            sources_hit.append("AlienVaultOTX")
            for row in (obj4.get("passive_dns") or [])[:200]:
                if not isinstance(row, dict):
                    continue
                hn = str(row.get("hostname") or "").lower().removeprefix("*.")
                if hn.endswith(d) and DOMAIN_RE.fullmatch(hn):
                    subs.add(hn)
                addr = str(row.get("address") or "")
                if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", addr):
                    otx_ips.add(addr)

        if not sources_hit:
            return _res("passive_dns_subdomain_feeds", "restricted_or_offline", "External passive DNS feeds unreachable", {})
        pivs = [{"type": "domain", "value": s} for s in sorted(subs) if s != d][:12] + [{"type": "ip", "value": ip} for ip in sorted(otx_ips)[:4]]
        return _res(
            "passive_dns_subdomain_feeds",
            "ok" if (subs or otx_ips) else "not_found",
            f"Aggregated {len(subs)} subdomain(s) & {len(otx_ips)} historical IP(s) via {', '.join(sources_hit)}",
            {"sources": sources_hit, "subdomains": sorted(subs)[:80], "historical_ips": sorted(otx_ips)[:25]},
            pivs,
        )

    def _wayback_homepage_carve():
        # Fetch archived HTML from web.archive.org ONLY (zero packets to target domain!)
        wb_url = f"https://web.archive.org/web/2id_/https://{d}/"
        st, raw_html, err = _http_fetch(wb_url, timeout=5.5, max_bytes=350_000)
        if st != 200 or not raw_html:
            return _res("wayback_archived_page_intel", "not_found" if st == 404 else "restricted_or_offline", f"No archived homepage body carved ({err or st})", {})
        carved = carve_webpage_intelligence(raw_html, base_url=f"https://{d}/")
        pivs = [p for p in carved.pop("pivots", []) if not (p["type"] == "domain" and p["value"] == d)]
        return _res(
            "wayback_archived_page_intel",
            "ok",
            f"Archived site intel: Title='{(carved.get('title') or 'n/a')[:60]}' · {len(carved['emails'])} email(s) · {len(carved['phones'])} phone(s) · {len(carved['social_profiles'])} social link(s)",
            carved,
            pivs,
        )

    def _hudsonrock_dom():
        st, obj, err = _http_json(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={urllib.parse.quote(d)}"
        )
        if st == 200 and isinstance(obj, dict):
            emp = obj.get("employees") or 0
            users = obj.get("users") or 0
            third = obj.get("third_parties") or 0
            if emp or users or third:
                return _res(
                    "hudsonrock_domain_exposure",
                    "ok",
                    f"HudsonRock stealer telemetry: {emp} compromised employee(s), {users} user(s), {third} third-party credential(s)",
                    {"employees": emp, "users": users, "third_parties": third, "stealer_families": obj.get("stealerFamilies")},
                )
            return _res("hudsonrock_domain_exposure", "not_found", "0 compromised domain credentials in HudsonRock", {})
        return _res("hudsonrock_domain_exposure", "restricted_or_offline", f"HudsonRock unreachable ({err})", {})

    def _web_dom():
        return run_multi_engine_web_search([f'"{d}" -site:{d}'], include_news=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        f1 = pool.submit(_urlscan)
        f2 = pool.submit(_multi_subdomains)
        f3 = pool.submit(_wayback_homepage_carve)
        f4 = pool.submit(_hudsonrock_dom)
        f5 = pool.submit(_web_dom)
        out = [f1.result(), f2.result(), f3.result(), f4.result()]
        wb = f5.result()
        if wb["results"]:
            out.append(
                _res(
                    "domain_external_mentions_and_profiles",
                    "ok",
                    f"Found {len(wb['results'])} external web/news mention(s) & {len(wb['social_hits'])} social profile(s) for '{d}'",
                    {"social_profiles": wb["social_hits"], "web_results": wb["results"][:15], "emails": wb["emails"], "phones": wb["phones"]},
                    [p for p in wb["pivots"] if not (p["type"] == "domain" and p["value"] == d)],
                )
            )
    return out


# ============================================================================
# PERSON, DOCTOR, ACADEMIC, CLINIC & COMPANY KNOWLEDGE COLLECTORS
# ============================================================================

def collect_entity_deep_osint(sel_type: str, value: str) -> list[dict]:
    """Deep open-web, Wikidata, ORCID/OpenAlex/PubMed medical & academic, and OpenStreetMap POI hunter."""
    q_clean = value.strip()
    q_enc = urllib.parse.quote(q_clean)
    bilingual = generate_bilingual_pivots(q_clean)

    def _web_entity():
        alt_script = bilingual["latin_queries"] if bilingual["has_arabic"] else bilingual["arabic_queries"]
        if alt_script:
            queries = [f'"{q_clean}"', f'"{alt_script[0]}"']
        else:
            queries = [
                f'"{q_clean}"',
                f'"{q_clean}" (instagram OR linkedin OR tiktok OR snapchat OR x.com OR linktr.ee OR clinic OR company)',
            ]
        return run_multi_engine_web_search(queries, include_news=True)

    def _wikidata():
        wd_lang = "ar" if bilingual["has_arabic"] else "en"
        st, obj, err = _http_json(
            f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={q_enc}&language={wd_lang}&format=json&limit=3"
        )
        if st != 200 or not isinstance(obj, dict):
            return None
        hits = obj.get("search") or []
        if not hits:
            return None
        qid = hits[0].get("id")
        label = hits[0].get("label")
        desc = hits[0].get("description")
        pivs: list[dict[str, str]] = []
        props_summary: dict[str, Any] = {"qid": qid, "label": label, "description": desc, "url": f"https://www.wikidata.org/wiki/{qid}"}

        if qid:
            st_e, ent_obj, _ = _http_json(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json")
            claims = (((ent_obj or {}).get("entities") or {}).get(qid) or {}).get("claims") or {} if (st_e == 200 and isinstance(ent_obj, dict)) else {}
            prop_map = {
                "P856": ("official_website", "url"),
                "P2002": ("twitter_x", "username"),
                "P2003": ("instagram", "username"),
                "P2397": ("youtube_channel", None),
                "P3789": ("telegram", "username"),
                "P2037": ("github", "username"),
                "P496": ("orcid", None),
            }
            for pid, (pname, ptype) in prop_map.items():
                arr = claims.get(pid) or []
                vals = []
                for c in arr[:3]:
                    dv = (((c.get("mainsnak") or {}).get("datavalue") or {}).get("value"))
                    if isinstance(dv, str) and dv:
                        vals.append(dv)
                        if ptype:
                            pivs.append({"type": ptype, "value": dv})
                if vals:
                    props_summary[pname] = vals
            # P18 (image) & P154 (logo image) -> Wikimedia Commons Special:FilePath URLs!
            wd_images = []
            for img_pid in ("P18", "P154"):
                for c in (claims.get(img_pid) or [])[:2]:
                    fn = (((c.get("mainsnak") or {}).get("datavalue") or {}).get("value"))
                    if isinstance(fn, str) and fn:
                        wd_images.append(f"https://commons.wikimedia.org/wiki/Special:FilePath/{urllib.parse.quote(fn.replace(' ', '_'))}?width=800")
            if wd_images:
                props_summary["images"] = wd_images
        return _res(
            "wikidata_knowledge_graph",
            "ok",
            f"Wikidata {qid} ({label}): {desc or 'entity matched'}",
            props_summary,
            pivs,
        )

    def _academic_medical():
        # OpenAlex + ORCID for doctors, researchers, professors, hospitals & universities
        clean_person = re.sub(r"^(?:dr\.?|prof\.?|doctor|د\.|الدكتور|دكتور)\s+", "", q_clean, flags=re.I).strip()
        if len(clean_person) < 3:
            return None
        endpoint = "institutions" if sel_type == "company" else "authors"
        st, obj, _ = _http_json(f"https://api.openalex.org/{endpoint}?search={urllib.parse.quote(clean_person)}&per-page=5")
        if st != 200 or not isinstance(obj, dict) or not obj.get("results"):
            return None
        records = []
        pivs = []
        for r in obj["results"][:5]:
            if endpoint == "authors":
                affs = [
                    ((a.get("institution") or {}).get("display_name"))
                    for a in (r.get("affiliations") or [])[:4]
                    if isinstance(a, dict) and (a.get("institution") or {}).get("display_name")
                ]
                records.append(
                    {
                        "display_name": r.get("display_name"),
                        "orcid": r.get("orcid"),
                        "works_count": r.get("works_count"),
                        "cited_by_count": r.get("cited_by_count"),
                        "affiliations": affs,
                    }
                )
                for af in affs[:2]:
                    pivs.append({"type": "company", "value": af})
            else:
                records.append(
                    {
                        "display_name": r.get("display_name"),
                        "country_code": r.get("country_code"),
                        "type": r.get("type"),
                        "homepage_url": r.get("homepage_url"),
                        "works_count": r.get("works_count"),
                    }
                )
                if r.get("homepage_url"):
                    pivs.append({"type": "url", "value": r["homepage_url"]})
        return _res(
            "openalex_academic_and_medical_registry",
            "ok",
            f"Matched {len(records)} {endpoint} record(s) in OpenAlex / ORCID scientific & medical index",
            {"records": records},
            pivs,
        )

    def _osm_poi():
        st, arr, _ = _http_json(
            f"https://nominatim.openstreetmap.org/search?q={q_enc}&format=jsonv2&addressdetails=1&extratags=1&limit=5"
        )
        if st != 200 or not isinstance(arr, list) or not arr:
            return None
        places = []
        pivs = []
        for pl in arr[:5]:
            tags = pl.get("extratags") or {}
            ph = tags.get("phone") or tags.get("contact:phone")
            wb = tags.get("website") or tags.get("contact:website")
            em = tags.get("email") or tags.get("contact:email")
            places.append(
                {
                    "name": pl.get("name") or pl.get("display_name"),
                    "category": f"{pl.get('category')}/{pl.get('type')}",
                    "address": pl.get("display_name"),
                    "phone": ph,
                    "website": wb,
                    "email": em,
                    "opening_hours": tags.get("opening_hours"),
                    "lat": pl.get("lat"),
                    "lon": pl.get("lon"),
                }
            )
            if ph:
                for s in extract_selectors(ph, check_local_file=False):
                    if s["type"] == "phone":
                        pivs.append({"type": "phone", "value": s["value"]})
            if wb and wb.startswith("http"):
                pivs.append({"type": "url", "value": wb})
            if em and "@" in em:
                pivs.append({"type": "email", "value": em.strip().lower()})
            if pl.get("lat") and pl.get("lon"):
                pivs.append({"type": "coordinates", "value": f"{float(pl['lat']):.6f},{float(pl['lon']):.6f}"})
        return _res(
            "osm_business_and_location_directory",
            "ok",
            f"Found {len(places)} physical location/business listing(s) on OpenStreetMap",
            {"places": places},
            pivs,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        f_web = pool.submit(_web_entity)
        f_wd = pool.submit(_wikidata)
        f_ac = pool.submit(_academic_medical)
        f_osm = pool.submit(_osm_poi)
        f_img = pool.submit(search_open_web_images, q_clean)
        web_r = f_web.result()
        wd_r = f_wd.result()
        ac_r = f_ac.result()
        osm_r = f_osm.result()
        img_r = f_img.result()

    out: list[dict] = []
    if bilingual["arabic_queries"] or bilingual["latin_queries"] or bilingual["handle_candidates"]:
        bi_pivs: list[dict[str, str]] = []
        for lq in bilingual["latin_queries"][:1]:
            bi_pivs.append({"type": sel_type, "value": lq})
        for aq in bilingual["arabic_queries"][:1]:
            bi_pivs.append({"type": sel_type, "value": aq})
        for hc in bilingual["handle_candidates"][:2]:
            bi_pivs.append({"type": "username", "value": hc})
        out.append(
            _res(
                "bilingual_arabic_arabizi_transliteration",
                "ok",
                f"Generated bilingual Arabic/Latin pivot(s) for '{q_clean}': "
                + ", ".join((bilingual["arabic_queries"] + bilingual["latin_queries"] + bilingual["handle_candidates"])[:4]),
                bilingual,
                bi_pivs,
            )
        )

    if web_r["results"]:
        out.append(
            _res(
                "entity_open_web_and_news_search",
                "ok",
                f"Found {len(web_r['results'])} web/news result(s), {len(web_r['social_hits'])} social profile(s), {len(web_r['phones'])} phone(s), {len(web_r['emails'])} email(s)",
                {
                    "queries": web_r["queries_executed"],
                    "social_profiles": web_r["social_hits"],
                    "web_results": web_r["results"][:18],
                    "phones": web_r["phones"],
                    "emails": web_r["emails"],
                    "related_domains": web_r["related_domains"],
                },
                web_r["pivots"],
            )
        )
    elif not web_r["reachable"]:
        out.append(_res("entity_open_web_and_news_search", "restricted_or_offline", "External search engines unreachable in restricted network", {"query": q_clean}))

    if img_r["images"]:
        img_pivs = []
        for im in img_r["images"]:
            if im.get("source_page_url"):
                soc = classify_social_profile_url(im["source_page_url"], title=im.get("title") or "")
                if soc:
                    img_pivs.append({"type": soc["pivot_type"], "value": soc["pivot_value"]})
        out.append(
            _res(
                "open_web_image_search",
                "ok",
                f"Discovered {len(img_r['images'])} public photo(s) / visual media for '{q_clean}'",
                {"images": img_r["images"]},
                img_pivs,
            )
        )

    for extra_mod in (wd_r, ac_r, osm_r):
        if extra_mod:
            out.append(extra_mod)

    # Smart handle candidate seeding when searching an alias-style name (e.g. "Dr. Abo 3tab")
    ascii_tokens = re.findall(r"[a-zA-Z0-9]+", q_clean.lower())
    if 2 <= len(ascii_tokens) <= 3 and any(any(c.isdigit() for c in t) or t in ("dr", "abo", "abu", "mr", "official", "real") for t in ascii_tokens):
        joined_dot = ".".join(ascii_tokens)
        joined_und = "_".join(ascii_tokens)
        joined_flat = "".join(ascii_tokens)
        cand_pivs = [{"type": "username", "value": h} for h in (joined_dot, joined_und, joined_flat) if 4 <= len(h) <= 30]
        if cand_pivs:
            out.append(
                _res(
                    "entity_handle_permutation_seeds",
                    "ok",
                    f"Generated {len(cand_pivs)} high-probability social handle candidate(s): {[p['value'] for p in cand_pivs]}",
                    {"candidate_handles": [p["value"] for p in cand_pivs]},
                    cand_pivs,
                )
            )

    return out

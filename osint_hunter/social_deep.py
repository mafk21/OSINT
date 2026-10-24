"""Deep 30+ Platform Social, Bio-Link, Messaging & Creator Profile Intelligence Extractor.

Replaces shallow HTTP 200 checks with structured profile parsing (display names, bios,
follower counts, regions, verified external links, crypto proofs, WhatsApp numbers,
emails, and public channel posts) plus open-web social handle discovery.
"""

from __future__ import annotations

import concurrent.futures
import html
import json
import re
import urllib.parse
from typing import Any
from xml.etree import ElementTree as ET

from .classify import DOMAIN_RE, NOISE_DOMAINS, extract_selectors
from .web_search_intel import (
    _clean_emails_from_text,
    _http_fetch,
    _http_json,
    _res,
    _strip_html,
    carve_webpage_intelligence,
    classify_social_profile_url,
    run_multi_engine_web_search,
)

NEXT_DATA_RE = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.I | re.S)
TIKTOK_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__UNIVERSAL_DATA_FOR_REHYDRATION__["\'][^>]*>(.*?)</script>',
    re.I | re.S,
)


def _add_profile_pivots(
    pivots: list[dict[str, str]],
    *,
    display_name: str | None = None,
    bio: str | None = None,
    external_urls: list[str] | None = None,
    extra_handles: list[str] | None = None,
    extra_domains: list[str] | None = None,
    extra_emails: list[str] | None = None,
    extra_phones: list[str] | None = None,
    src_username: str = "",
) -> None:
    if display_name:
        dn = re.sub(r"\s+", " ", display_name).strip(" -|•·@\"'()")
        if 2 <= len(dn.split()) <= 5 and len(dn) <= 55 and dn.lower() != src_username.lower():
            if not any(c.isdigit() for c in dn) and "@" not in dn and "http" not in dn.lower():
                pivots.append({"type": "person_name", "value": dn})

    if bio:
        for em in _clean_emails_from_text(bio):
            pivots.append({"type": "email", "value": em})
        for s in extract_selectors(bio, check_local_file=False):
            if s["type"] in ("phone", "domain", "email", "crypto_address"):
                pivots.append({"type": s["type"], "value": s["value"]})
            elif s["type"] == "url":
                soc = classify_social_profile_url(s["value"])
                if soc:
                    pivots.append({"type": soc["pivot_type"], "value": soc["pivot_value"]})
                else:
                    pivots.append({"type": "url", "value": s["value"]})
        # Extract @mentions in bios (e.g. "Clinic: @myclinic")
        for m_at in re.findall(r"(?<![A-Za-z0-9._%+-])@([A-Za-z0-9_.]{3,30})", bio):
            h_cand = m_at.strip(".")
            if h_cand and h_cand.lower() != src_username.lower() and "." not in h_cand[-3:]:
                pivots.append({"type": "username", "value": h_cand})

    for u in external_urls or []:
        if not isinstance(u, str) or not u.startswith(("http://", "https://")):
            continue
        soc = classify_social_profile_url(u)
        if soc:
            pivots.append({"type": soc["pivot_type"], "value": soc["pivot_value"]})
        else:
            pivots.append({"type": "url", "value": u})
            try:
                host = (urllib.parse.urlparse(u).hostname or "").lower().removeprefix("www.")
                if host and host not in NOISE_DOMAINS and DOMAIN_RE.fullmatch(host):
                    pivots.append({"type": "domain", "value": host})
            except ValueError:
                pass

    for h in extra_handles or []:
        if h and h.lower() != src_username.lower():
            pivots.append({"type": "username", "value": h.lstrip("@")})
    for d in extra_domains or []:
        d_clean = d.lower().removeprefix("www.")
        if d_clean and d_clean not in NOISE_DOMAINS and DOMAIN_RE.fullmatch(d_clean):
            pivots.append({"type": "domain", "value": d_clean})
    for em in extra_emails or []:
        for clean_em in _clean_emails_from_text(em):
            pivots.append({"type": "email", "value": clean_em})
    for ph in extra_phones or []:
        for s in extract_selectors(str(ph), check_local_file=False):
            if s["type"] == "phone":
                pivots.append({"type": "phone", "value": s["value"]})


# ============================================================================
# INDIVIDUAL DEEP PLATFORM PARSERS (PUBLIC HTML / JSON)
# ============================================================================

def parse_linktree_html(raw_html: str, username: str) -> dict[str, Any] | None:
    if not raw_html or '"statusCode":404' in raw_html or "The page you’re looking for doesn’t exist" in raw_html:
        return None
    m = NEXT_DATA_RE.search(raw_html)
    links_out: list[dict[str, str]] = []
    display_name = None
    bio = None
    if m:
        try:
            nd = json.loads(m.group(1))
            acct = ((nd.get("props") or {}).get("pageProps") or {}).get("account") or {}
            if not acct:
                return None
            display_name = acct.get("pageTitle") or acct.get("username")
            bio = acct.get("description")
            for lk in acct.get("links") or []:
                if isinstance(lk, dict) and lk.get("url"):
                    links_out.append({"title": str(lk.get("title") or "")[:100], "url": str(lk["url"])})
            for sl in acct.get("socialLinks") or []:
                if isinstance(sl, dict) and sl.get("url"):
                    links_out.append({"title": str(sl.get("type") or "Social"), "url": str(sl["url"])})
        except Exception:
            return None
    else:
        carved = carve_webpage_intelligence(raw_html, base_url=f"https://linktr.ee/{username}")
        if not carved["social_profiles"] and not carved["phones"]:
            return None
        display_name = carved.get("title")
        bio = carved.get("description")
        links_out = [{"title": s["platform"], "url": s["url"]} for s in carved["social_profiles"]]

    return {
        "platform": "Linktree",
        "category": "Bio-Links",
        "url": f"https://linktr.ee/{username}",
        "display_name": display_name,
        "bio": bio,
        "external_links": links_out[:30],
    }


def parse_telegram_html(raw_html: str, username: str, channel_html: str = "") -> dict[str, Any] | None:
    if not raw_html or "tgme_page_title" not in raw_html:
        return None
    m_title = re.search(r'<div[^>]+class="[^"]*tgme_page_title[^"]*"[^>]*>(.*?)</div>', raw_html, re.I | re.S)
    m_extra = re.search(r'<div[^>]+class="[^"]*tgme_page_extra[^"]*"[^>]*>(.*?)</div>', raw_html, re.I | re.S)
    m_desc = re.search(r'<div[^>]+class="[^"]*tgme_page_description[^"]*"[^>]*>(.*?)</div>', raw_html, re.I | re.S)
    title = _strip_html(m_title.group(1)) if m_title else None
    if not title or f"Telegram: Contact @{username}".lower() == title.lower():
        return None
    extra = _strip_html(m_extra.group(1)) if m_extra else None
    desc_raw = m_desc.group(1) if m_desc else ""
    bio = _strip_html(desc_raw)
    ext_urls = re.findall(r'href=["\'](https?://[^"\'>\s]+)["\']', desc_raw, re.I)
    ext_urls = [u for u in ext_urls if not u.startswith("https://telegram.org")]

    recent_posts: list[str] = []
    if channel_html and "tgme_widget_message_text" in channel_html:
        for pm in re.findall(r'<div[^>]+class="[^"]*tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', channel_html, re.I | re.S)[:5]:
            recent_posts.append(_strip_html(pm)[:260])
            for u in re.findall(r'href=["\'](https?://[^"\'>\s]+)["\']', pm, re.I):
                if "t.me/" not in u or f"t.me/{username.lower()}" not in u.lower():
                    ext_urls.append(u)

    return {
        "platform": "Telegram",
        "category": "Messaging",
        "url": f"https://t.me/{username}",
        "display_name": title,
        "subscribers_or_handle": extra,
        "bio": bio or None,
        "external_links": sorted(set(ext_urls))[:20],
        "recent_channel_posts": recent_posts,
    }


def parse_snapchat_html(raw_html: str, username: str) -> dict[str, Any] | None:
    if not raw_html:
        return None
    m = NEXT_DATA_RE.search(raw_html)
    if m:
        try:
            nd = json.loads(m.group(1))
            pp = (nd.get("props") or {}).get("pageProps") or {}
            up = pp.get("userProfile") or {}
            info = up.get("publicProfileInfo") or up.get("userInfo") or {}
            if info and (info.get("username") or info.get("title") or info.get("snapcodeImageUrl")):
                return {
                    "platform": "Snapchat",
                    "category": "Social",
                    "url": f"https://www.snapchat.com/add/{username}",
                    "display_name": info.get("title") or info.get("displayName"),
                    "bio": info.get("bio"),
                    "website": info.get("websiteUrl"),
                    "location": info.get("address"),
                    "subscribers": info.get("subscriberCount"),
                    "profile_category": info.get("categoryStringId") or info.get("subcategoryStringId"),
                }
        except Exception:
            pass
    # Fallback og:title check
    m_og = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', raw_html, re.I)
    if m_og:
        og_t = html.unescape(m_og.group(1)).strip()
        if username.lower() in og_t.lower() and "Snapchat" in og_t and "Share your favorite" not in og_t:
            disp = re.sub(r"\s*\(@?[^)]+\).*$|\s+on\s+Snapchat.*$", "", og_t, flags=re.I).strip()
            return {
                "platform": "Snapchat",
                "category": "Social",
                "url": f"https://www.snapchat.com/add/{username}",
                "display_name": disp if disp.lower() != username.lower() else None,
            }
    return None


def parse_tiktok_html(raw_html: str, username: str) -> dict[str, Any] | None:
    if not raw_html:
        return None
    m = TIKTOK_DATA_RE.search(raw_html)
    if m:
        try:
            obj = json.loads(m.group(1))
            ud = ((obj.get("__DEFAULT_SCOPE__") or {}).get("webapp.user-detail") or {}).get("userInfo") or {}
            user = ud.get("user") or {}
            stats = ud.get("stats") or {}
            if user.get("uniqueId") and str(user["uniqueId"]).lower() == username.lower():
                bio_link = ((user.get("bioLink") or {}).get("link")) or None
                return {
                    "platform": "TikTok",
                    "category": "Social/Video",
                    "url": f"https://www.tiktok.com/@{username}",
                    "display_name": user.get("nickname"),
                    "bio": user.get("signature") or None,
                    "website": bio_link,
                    "region": user.get("region"),
                    "verified": user.get("verified"),
                    "followers": stats.get("followerCount"),
                    "hearts": stats.get("heartCount"),
                    "videos": stats.get("videoCount"),
                }
        except Exception:
            pass
    return None


def parse_instagram_meta_html(raw_html: str, username: str) -> dict[str, Any] | None:
    if not raw_html:
        return None
    m_title = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', raw_html, re.I)
    m_desc = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', raw_html, re.I)
    if not m_title:
        return None
    og_t = html.unescape(m_title.group(1)).strip()
    if f"@{username.lower()}" not in og_t.lower():
        return None
    disp_m = re.match(r"^(.*?)\s*\(@", og_t)
    disp = disp_m.group(1).strip() if disp_m else None
    og_d = html.unescape(m_desc.group(1)).strip() if m_desc else None
    return {
        "platform": "Instagram",
        "category": "Social",
        "url": f"https://www.instagram.com/{username}/",
        "display_name": disp,
        "stats_and_bio_preview": og_d,
    }


def parse_youtube_html(raw_html: str, username: str) -> dict[str, Any] | None:
    if not raw_html or '"channelMetadataRenderer":' not in raw_html:
        return None
    m_meta = re.search(r'"channelMetadataRenderer":(\{"title":.*?\})\s*,\s*"', raw_html)
    title = None
    desc = None
    chan_id = None
    if m_meta:
        try:
            cm = json.loads(m_meta.group(1))
            title = cm.get("title")
            desc = cm.get("description")
            chan_id = cm.get("externalId")
        except Exception:
            pass
    if not title:
        m_og = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', raw_html, re.I)
        title = html.unescape(m_og.group(1)).strip() if m_og else None
    if not title or title == "YouTube":
        return None
    return {
        "platform": "YouTube",
        "category": "Video",
        "url": f"https://www.youtube.com/@{username}",
        "display_name": title,
        "bio": (desc or "")[:350] or None,
        "channel_id": chan_id,
    }


# ============================================================================
# ORCHESTRATED DEEP SOCIAL, BIO-LINK & MESSAGING SWEEP
# ============================================================================

def collect_deep_social_footprint(username: str) -> list[dict]:
    """Deeply probe & parse 28+ social, messaging, creator & bio-link platforms + open-web social search."""
    u = username.strip().lstrip("@")
    if not u or " " in u or "/" in u:
        return []
    u_enc = urllib.parse.quote(u)

    profiles_found: list[dict[str, Any]] = []
    pivots: list[dict[str, str]] = []
    offline_count = 0

    def _p_telegram():
        st, body, _ = _http_fetch(f"https://t.me/{u_enc}", browser_ua=True, timeout=4.2)
        if st == 0:
            return "offline", None
        if st == 200 and "tgme_page_title" in body:
            ch_body = ""
            if "subscribers" in body.lower() or "members" in body.lower():
                _, ch_body, _ = _http_fetch(f"https://t.me/s/{u_enc}", browser_ua=True, timeout=4.0)
            rec = parse_telegram_html(body, u, ch_body)
            return ("hit", rec) if rec else ("miss", None)
        return "miss", None

    def _p_linktree():
        st, body, _ = _http_fetch(f"https://linktr.ee/{u_enc}", browser_ua=True, timeout=4.5)
        if st == 0:
            return "offline", None
        rec = parse_linktree_html(body, u) if st == 200 else None
        return ("hit", rec) if rec else ("miss", None)

    def _p_biohubs():
        hubs = [
            ("Taplink", f"https://taplink.cc/{u_enc}"),
            ("Beacons", f"https://beacons.ai/{u_enc}"),
            ("Bio.link", f"https://bio.link/{u_enc}"),
            ("Solo.to", f"https://solo.to/{u_enc}"),
        ]
        found_hubs = []
        any_reach = False
        for name, url in hubs:
            st, body, _ = _http_fetch(url, browser_ua=True, timeout=3.8, max_bytes=220_000)
            if st == 0:
                continue
            any_reach = True
            if st != 200 or not body:
                continue
            low = body.lower()
            if any(miss in low for miss in ("page not found", '"statuscode":404', "claim your link", "doesn't exist", "404 not found")):
                continue
            carved = carve_webpage_intelligence(body, base_url=url)
            if carved["social_profiles"] or carved["phones"] or carved["emails"]:
                found_hubs.append(
                    {
                        "platform": name,
                        "category": "Bio-Links",
                        "url": url,
                        "display_name": carved.get("title"),
                        "bio": carved.get("description"),
                        "external_links": [{"title": s["platform"], "url": s["url"]} for s in carved["social_profiles"]],
                        "phones": carved["phones"],
                        "emails": carved["emails"],
                    }
                )
        if not any_reach:
            return "offline", None
        return ("hit_list", found_hubs) if found_hubs else ("miss", None)

    def _p_snapchat():
        st, body, _ = _http_fetch(f"https://www.snapchat.com/add/{u_enc}", browser_ua=True, timeout=4.5)
        if st == 0:
            return "offline", None
        rec = parse_snapchat_html(body, u) if st == 200 else None
        return ("hit", rec) if rec else ("miss", None)

    def _p_tiktok():
        st, body, _ = _http_fetch(f"https://www.tiktok.com/@{u_enc}", browser_ua=True, timeout=4.5)
        if st == 0:
            return "offline", None
        rec = parse_tiktok_html(body, u) if st == 200 else None
        return ("hit", rec) if rec else ("miss", None)

    def _p_instagram():
        st, body, _ = _http_fetch(f"https://www.instagram.com/{u_enc}/", browser_ua=True, timeout=4.2)
        if st == 0:
            return "offline", None
        rec = parse_instagram_meta_html(body, u) if st == 200 else None
        return ("hit", rec) if rec else ("miss", None)

    def _p_x_twitter():
        st, arr, _ = _http_json(
            f"https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names={u_enc}",
            timeout=4.0,
        )
        if st == 0:
            return "offline", None
        if st == 200 and isinstance(arr, list) and arr and isinstance(arr[0], dict):
            x0 = arr[0]
            return "hit", {
                "platform": "X/Twitter",
                "category": "Social",
                "url": f"https://x.com/{x0.get('screen_name') or u}",
                "display_name": x0.get("name"),
                "followers": x0.get("followers_count"),
                "user_id": x0.get("id"),
            }
        return "miss", None

    def _p_youtube():
        st, body, _ = _http_fetch(f"https://www.youtube.com/@{u_enc}", browser_ua=True, timeout=4.5)
        if st == 0:
            return "offline", None
        rec = parse_youtube_html(body, u) if st == 200 else None
        return ("hit", rec) if rec else ("miss", None)

    def _p_reddit():
        st, obj, _ = _http_json(f"https://www.reddit.com/user/{u_enc}/about.json", timeout=4.2)
        if st == 0:
            return "offline", None
        if st == 200 and isinstance(obj, dict) and isinstance(obj.get("data"), dict):
            d = obj["data"]
            if d.get("is_suspended"):
                return "hit", {"platform": "Reddit", "category": "Social", "url": f"https://www.reddit.com/user/{u}", "status_note": "Suspended account"}
            sub = d.get("subreddit") or {}
            return "hit", {
                "platform": "Reddit",
                "category": "Social",
                "url": f"https://www.reddit.com/user/{d.get('name') or u}",
                "display_name": sub.get("title") or None,
                "bio": sub.get("public_description") or None,
                "total_karma": d.get("total_karma"),
                "created_utc": d.get("created_utc"),
            }
        return "miss", None

    def _p_keybase():
        st, obj, _ = _http_json(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u_enc}", timeout=4.2)
        if st == 0:
            return "offline", None
        them = (obj.get("them") or []) if (st == 200 and isinstance(obj, dict)) else []
        if them and isinstance(them[0], dict):
            t0 = them[0]
            prof = t0.get("profile") or {}
            proofs = ((t0.get("proofs_summary") or {}).get("all")) or []
            verified_proofs = [
                {"service": p.get("proof_type"), "handle": p.get("nametag"), "url": p.get("service_url")}
                for p in proofs
                if isinstance(p, dict) and p.get("nametag")
            ]
            return "hit", {
                "platform": "Keybase",
                "category": "Crypto/Identity",
                "url": f"https://keybase.io/{u}",
                "display_name": prof.get("full_name"),
                "bio": prof.get("bio"),
                "location": prof.get("location"),
                "verified_proofs": verified_proofs,
            }
        return "miss", None

    def _p_gravatar():
        st, obj, _ = _http_json(f"https://en.gravatar.com/{u_enc}.json", timeout=4.0)
        if st == 0:
            return "offline", None
        entries = (obj.get("entry") or []) if (st == 200 and isinstance(obj, dict)) else []
        if entries and isinstance(entries[0], dict):
            e0 = entries[0]
            accts = [
                {"service": a.get("shortname"), "username": a.get("username"), "url": a.get("url")}
                for a in (e0.get("accounts") or [])
                if isinstance(a, dict)
            ]
            urls = [x.get("value") for x in (e0.get("urls") or []) if isinstance(x, dict) and x.get("value")]
            return "hit", {
                "platform": "Gravatar",
                "category": "Identity",
                "url": e0.get("profileUrl") or f"https://gravatar.com/{u}",
                "display_name": e0.get("displayName"),
                "bio": e0.get("aboutMe"),
                "location": e0.get("currentLocation"),
                "company": e0.get("company"),
                "job_title": e0.get("job_title"),
                "verified_accounts": accts,
                "external_links": urls,
            }
        return "miss", None

    def _p_gitlab():
        st, arr, _ = _http_json(f"https://gitlab.com/api/v4/users?username={u_enc}", timeout=4.2)
        if st == 0:
            return "offline", None
        if st == 200 and isinstance(arr, list) and arr and isinstance(arr[0], dict):
            g0 = arr[0]
            uid = g0.get("id")
            detail = g0
            if uid:
                st_d, d_obj, _ = _http_json(f"https://gitlab.com/api/v4/users/{uid}", timeout=3.8)
                if st_d == 200 and isinstance(d_obj, dict):
                    detail = d_obj
            return "hit", {
                "platform": "GitLab",
                "category": "Developer",
                "url": detail.get("web_url") or f"https://gitlab.com/{u}",
                "display_name": detail.get("name"),
                "bio": detail.get("bio") or None,
                "location": detail.get("location") or None,
                "company": detail.get("organization") or None,
                "job_title": detail.get("job_title") or None,
                "website": detail.get("website_url") or None,
                "public_email": detail.get("public_email") or None,
                "twitter": detail.get("twitter") or None,
                "linkedin": detail.get("linkedin") or None,
            }
        return "miss", None

    def _p_dev_creator_batch():
        found_batch = []
        any_reach = False
        # DEV.to
        st1, d1, _ = _http_json(f"https://dev.to/api/users/by_username?url={u_enc}", timeout=3.8)
        if st1 != 0:
            any_reach = True
        if st1 == 200 and isinstance(d1, dict) and d1.get("username"):
            found_batch.append(
                {
                    "platform": "DEV.to",
                    "category": "Developer",
                    "url": f"https://dev.to/{d1['username']}",
                    "display_name": d1.get("name"),
                    "bio": d1.get("summary"),
                    "location": d1.get("location"),
                    "website": d1.get("website_url"),
                    "twitter": d1.get("twitter_username"),
                    "github": d1.get("github_username"),
                }
            )
        # HackerNews
        st2, d2, _ = _http_json(f"https://hacker-news.firebaseio.com/v0/user/{u_enc}.json", timeout=3.8)
        if st2 != 0:
            any_reach = True
        if st2 == 200 and isinstance(d2, dict) and d2.get("id"):
            found_batch.append(
                {
                    "platform": "HackerNews",
                    "category": "Tech",
                    "url": f"https://news.ycombinator.com/user?id={d2['id']}",
                    "bio": _strip_html(d2.get("about") or "") or None,
                    "karma": d2.get("karma"),
                    "created_utc": d2.get("created"),
                }
            )
        # Medium RSS
        st3, xml3, _ = _http_fetch(f"https://medium.com/feed/@{u_enc}", timeout=3.8)
        if st3 != 0:
            any_reach = True
        if st3 == 200 and "<rss" in xml3:
            try:
                rt = ET.fromstring(xml3)
                ch_title = (rt.findtext("./channel/title") or "").replace("Stories by ", "").replace(" on Medium", "").strip()
                articles = [(it.findtext("title") or "").strip() for it in rt.findall("./channel/item")[:4]]
                found_batch.append(
                    {
                        "platform": "Medium",
                        "category": "Publishing",
                        "url": f"https://medium.com/@{u}",
                        "display_name": ch_title or None,
                        "recent_articles": articles,
                    }
                )
            except Exception:
                pass
        # Chess.com & Lichess & Duolingo
        st4, d4, _ = _http_json(f"https://api.chess.com/pub/player/{u_enc}", timeout=3.5)
        if st4 == 200 and isinstance(d4, dict) and d4.get("player_id"):
            any_reach = True
            found_batch.append(
                {
                    "platform": "Chess.com",
                    "category": "Gaming",
                    "url": d4.get("url") or f"https://www.chess.com/member/{u}",
                    "display_name": d4.get("name"),
                    "location": d4.get("location"),
                }
            )
        st5, d5, _ = _http_json(f"https://www.duolingo.com/2017-06-30/users?username={u_enc}", timeout=3.5)
        if st5 == 200 and isinstance(d5, dict) and d5.get("users"):
            any_reach = True
            du0 = d5["users"][0]
            found_batch.append(
                {
                    "platform": "Duolingo",
                    "category": "Education",
                    "url": f"https://www.duolingo.com/profile/{u}",
                    "display_name": du0.get("name"),
                    "streak": du0.get("streak"),
                }
            )
        if not any_reach:
            return "offline", None
        return ("hit_list", found_batch) if found_batch else ("miss", None)

    def _p_hudsonrock_user():
        st, obj, err = _http_json(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={u_enc}",
            timeout=4.2,
        )
        if st == 200 and isinstance(obj, dict) and obj.get("stealers"):
            return obj["stealers"][:8]
        return None

    def _p_social_web_search():
        queries = [
            f'"{u}"',
            f'"{u}" (site:instagram.com OR site:tiktok.com OR site:snapchat.com OR site:x.com OR site:linkedin.com OR site:linktr.ee OR site:taplink.cc)',
        ]
        return run_multi_engine_web_search(queries, include_news=False)

    probe_fns = [
        _p_telegram,
        _p_linktree,
        _p_biohubs,
        _p_snapchat,
        _p_tiktok,
        _p_instagram,
        _p_x_twitter,
        _p_youtube,
        _p_reddit,
        _p_keybase,
        _p_gravatar,
        _p_gitlab,
        _p_dev_creator_batch,
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        f_probes = [pool.submit(fn) for fn in probe_fns]
        f_hr = pool.submit(_p_hudsonrock_user)
        f_web = pool.submit(_p_social_web_search)

        for fut in f_probes:
            try:
                state, payload = fut.result()
                if state == "offline":
                    offline_count += 1
                elif state == "hit" and isinstance(payload, dict):
                    profiles_found.append(payload)
                elif state == "hit_list" and isinstance(payload, list):
                    profiles_found.extend(payload)
            except Exception:
                continue

        stealer_hits = f_hr.result()
        web_social = f_web.result()

    # Harvest pivots from every discovered profile!
    for prof in profiles_found:
        ext_links = []
        for lk in prof.get("external_links") or []:
            if isinstance(lk, dict) and lk.get("url"):
                ext_links.append(lk["url"])
            elif isinstance(lk, str):
                ext_links.append(lk)
        if prof.get("website"):
            ext_links.append(prof["website"])

        extra_handles = []
        extra_domains = []
        for k_h in ("twitter", "github"):
            if prof.get(k_h):
                extra_handles.append(str(prof[k_h]))
        for vp in prof.get("verified_proofs") or []:
            svc = str(vp.get("service") or "").lower()
            if svc in ("dns", "generic_web_site"):
                extra_domains.append(str(vp["handle"]))
            elif vp.get("handle"):
                extra_handles.append(str(vp["handle"]))
        for va in prof.get("verified_accounts") or []:
            if va.get("username"):
                extra_handles.append(str(va["username"]))
            if va.get("url"):
                ext_links.append(str(va["url"]))

        if prof.get("company") and len(str(prof["company"])) >= 3:
            pivots.append({"type": "company", "value": str(prof["company"]).lstrip("@")})

        _add_profile_pivots(
            pivots,
            display_name=prof.get("display_name"),
            bio=" ".join(
                str(x)
                for x in (
                    prof.get("bio"),
                    prof.get("stats_and_bio_preview"),
                    " ".join(prof.get("recent_channel_posts") or []),
                )
                if x
            ),
            external_urls=ext_links,
            extra_handles=extra_handles,
            extra_domains=extra_domains,
            extra_emails=([prof["public_email"]] if prof.get("public_email") else []) + (prof.get("emails") or []),
            extra_phones=prof.get("phones") or [],
            src_username=u,
        )

    out_modules: list[dict] = []

    # 1. Deep Social & Bio-Link Profile Sweep
    if profiles_found or offline_count < len(probe_fns):
        plat_names = [p["platform"] for p in profiles_found]
        summary = (
            f"Extracted {len(profiles_found)} rich profile(s) ({', '.join(plat_names)})"
            if profiles_found
            else f"0 direct profile hits across {len(probe_fns) - offline_count} reachable platforms"
        )
        if offline_count:
            summary += f" ({offline_count} external platform checks blocked by sandbox policy)"
        out_modules.append(
            _res(
                "username_platform_sweep",
                "ok" if profiles_found else ("restricted_or_offline" if offline_count == len(probe_fns) else "not_found"),
                summary,
                {
                    "hits": [
                        {
                            "site": p["platform"],
                            "category": p.get("category", "Social"),
                            "probe_url": p["url"],
                            "display_name": p.get("display_name"),
                            "bio": p.get("bio") or p.get("stats_and_bio_preview"),
                            "followers": p.get("followers") or p.get("subscribers") or p.get("subscribers_or_handle"),
                            "location": p.get("location") or p.get("region"),
                            "external_links": p.get("external_links") or ([p["website"]] if p.get("website") else []),
                            "verified_proofs": p.get("verified_proofs") or p.get("verified_accounts"),
                        }
                        for p in profiles_found
                    ],
                    "profiles_detailed": profiles_found,
                    "offline_skipped": offline_count,
                },
                pivots,
            )
        )
    else:
        out_modules.append(
            _res(
                "username_platform_sweep",
                "restricted_or_offline",
                f"0 reachable social endpoints ({offline_count} external sites blocked by sandbox network policy)",
                {"hits": [], "offline_skipped": offline_count},
            )
        )

    # 2. Open-Web Handle & Indexed Social Discovery (catches IG/TikTok/Snap/LinkedIn/X bios indexed in search!)
    if web_social["results"]:
        out_modules.append(
            _res(
                "username_open_web_and_social_index",
                "ok",
                f"Open-web search discovered {len(web_social['results'])} mention(s) & {len(web_social['social_hits'])} indexed social account(s) for '{u}'",
                {
                    "social_profiles": web_social["social_hits"],
                    "web_results": web_social["results"][:15],
                    "extracted_emails": web_social["emails"],
                    "extracted_phones": web_social["phones"],
                    "related_domains": web_social["related_domains"],
                },
                web_social["pivots"],
            )
        )

    # 3. HudsonRock Stealer Log Exposure for Username
    if stealer_hits:
        out_modules.append(
            _res(
                "hudsonrock_username_infostealer",
                "ok",
                f"CRITICAL: Username '{u}' appeared in {len(stealer_hits)} infostealer malware log(s)!",
                {"stealer_count": len(stealer_hits), "stealers": stealer_hits},
            )
        )

    return out_modules

"""Universal Zero-Prompt Selector Classifier & Multi-Entity Extractor.

Accepts raw selectors, natural-language agent prompts, URLs, or local file paths
and extracts normalized, typed OSINT selectors ready for autonomous hunting.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from .bilingual_mena import classify_arabic_seed, normalize_arabic_digits

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]{1,64}@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
URL_RE = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b|\b[a-z2-7]{16}\.onion\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
ASN_RE = re.compile(r"\bAS([1-9]\d{1,9})\b", re.IGNORECASE)
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
EVM_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
COORD_RE = re.compile(r"(?<![\d.])(-?(?:[1-8]?\d(?:\.\d{3,10})|90(?:\.0+)?))\s*,\s*(-?(?:1[0-7]\d(?:\.\d{3,10})|[1-9]?\d(?:\.\d{3,10})|180(?:\.0+)?))(?![\d.])")
VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
IMO_EXPLICIT_RE = re.compile(r"\b(?:IMO[\s:#-]*)(\d{7})\b", re.IGNORECASE)
MMSI_EXPLICIT_RE = re.compile(r"\b(?:MMSI[\s:#-]*)(\d{9})\b", re.IGNORECASE)
ICAO_EXPLICIT_RE = re.compile(r"\b(?:ICAO(?:24)?|HEX|MODE-?S|AIRCRAFT)[\s:#-]*([0-9A-Fa-f]{6})\b", re.IGNORECASE)
VIN_EXPLICIT_RE = re.compile(r"\bVIN[\s:#-]*([A-HJ-NPR-Z0-9]{17})\b", re.IGNORECASE)
PHONE_INTL_RE = re.compile(r"(?<!\w)\+[1-9]\d{6,14}\b")
PHONE_00_INTL_RE = re.compile(r"\b00([1-9]\d{6,14})\b")
PHONE_BARE_GCC_MENA_RE = re.compile(r"\b((?:9665\d|9715\d|965[569]|974[3567]|9733|968[79]|201[0125]\d)\d{7})\b")
PHONE_FMT_RE = re.compile(r"(?<!\w)\+[1-9][\d\s().-]{7,20}\d\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|co|ai|gov|edu|mil|int|app|dev|xyz|info|biz|me|tv|cc|sh|gg|ru|cn|de|uk|fr|nl|se|ch|jp|kr|in|br|au|ca|sa|ae|qa|kw|bh|om|il|ir|tr|ua|pl|es|it|eu|onion|cloud|tech|security|online|site|store|pro|finance|crypto|eth)\b",
    re.IGNORECASE,
)
HANDLE_AT_RE = re.compile(r"(?<![a-zA-Z0-9._%+-])@([a-zA-Z0-9_.-]{2,39})\b")
LABELED_HANDLE_RE = re.compile(
    r"\b(?:insta(?:gram)?|ig|tiktok|tt|snap(?:chat)?|x|twitter|telegram|tg|threads|youtube|yt|reddit|github|gh|gitlab|linkedin|linktree|username|handle)(?:\s+(?:username|handle|user|account|id|profile))?\s*(?:[:=]|(?<=\susername)\s+|(?<=\shandle)\s+)\s*@?([a-zA-Z0-9_.-]{2,39})\b",
    re.IGNORECASE,
)
WHATSAPP_URL_RE = re.compile(
    r"(?:https?://)?(?:wa\.me/|api\.whatsapp\.com/send\?(?:[^#\s]*&)?phone=)\+?([1-9]\d{6,14})\b",
    re.IGNORECASE,
)
OBFUSCATED_EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+-]{1,64})\s*(?:\[at\]|\(at\)|\sat\s)\s*([a-zA-Z0-9-]+(?:\s*(?:\.|\[dot\]|\(dot\))\s*[a-zA-Z0-9-]+)+)\b",
    re.IGNORECASE,
)

SOCIAL_PATH_PATTERNS = [
    (re.compile(r"^https?://(?:www\.)?github\.com/([a-zA-Z0-9-]{1,39})(?:/([a-zA-Z0-9._-]+))?/?$"), "github"),
    (re.compile(r"^https?://(?:www\.)?gitlab\.com/([a-zA-Z0-9_.-]{2,39})(?:/.*)?$"), "gitlab"),
    (re.compile(r"^https?://(?:www\.)?(?:x\.com|twitter\.com)/([a-zA-Z0-9_]{1,15})(?:/.*)?$"), "x"),
    (re.compile(r"^https?://(?:www\.)?(?:instagram\.com|instagr\.am)/([a-zA-Z0-9._]{2,30})(?:/.*)?$"), "instagram"),
    (re.compile(r"^https?://(?:www\.)?tiktok\.com/@([a-zA-Z0-9._]{2,30})(?:/.*)?$"), "tiktok"),
    (re.compile(r"^https?://(?:www\.)?snapchat\.com/(?:add|t)/([a-zA-Z0-9._-]{2,30})(?:/.*)?$"), "snapchat"),
    (re.compile(r"^https?://(?:www\.)?threads\.net/@([a-zA-Z0-9._]{2,30})(?:/.*)?$"), "threads"),
    (re.compile(r"^https?://(?:www\.)?youtube\.com/@([a-zA-Z0-9._-]{2,35})(?:/.*)?$"), "youtube"),
    (re.compile(r"^https?://(?:www\.)?reddit\.com/(?:user|u)/([a-zA-Z0-9_-]{2,25})(?:/.*)?$"), "reddit"),
    (re.compile(r"^https?://(?:www\.)?t\.me/(?:s/)?([a-zA-Z0-9_]{4,32})(?:/.*)?$"), "telegram"),
    (re.compile(r"^https?://(?:www\.)?linktr\.ee/([a-zA-Z0-9._-]{2,35})(?:/.*)?$"), "linktree"),
    (re.compile(r"^https?://(?:www\.)?(?:beacons\.ai|bio\.link|taplink\.cc)/([a-zA-Z0-9._-]{2,35})(?:/.*)?$"), "biolink"),
    (re.compile(r"^https?://(?:www\.)?medium\.com/@([a-zA-Z0-9._-]{2,35})(?:/.*)?$"), "medium"),
    (re.compile(r"^https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9_-]{2,60})(?:/.*)?$"), "linkedin"),
    (re.compile(r"^https?://(?:www\.)?npmjs\.com/~([a-zA-Z0-9._-]+)$"), "npm"),
    (re.compile(r"^https?://pypi\.org/user/([a-zA-Z0-9._-]+)/?$"), "pypi"),
    (re.compile(r"^https?://(?:www\.)?bsky\.app/profile/([a-zA-Z0-9_.-]{3,60})(?:/.*)?$"), "bluesky"),
    (re.compile(r"^https?://(?:www\.)?huggingface\.co/([a-zA-Z0-9_.-]{2,42})/?$"), "huggingface"),
]

SOCIAL_URL_RESERVED = {
    "orgs", "topics", "search", "explore", "settings", "login", "about", "p", "reel",
    "reels", "stories", "tv", "direct", "accounts", "share", "intent", "home", "hashtag",
    "channel", "watch", "playlist", "shorts", "joinchat", "addstickers",
}

NOISE_DOMAINS = {
    "github.com", "api.github.com", "raw.githubusercontent.com", "users.noreply.github.com",
    "gitlab.com", "x.com", "twitter.com", "reddit.com", "t.me", "linkedin.com", "instagram.com",
    "instagr.am", "tiktok.com", "snapchat.com", "threads.net", "linktr.ee", "beacons.ai",
    "bio.link", "taplink.cc", "wa.me", "api.whatsapp.com", "medium.com",
    "facebook.com", "youtube.com", "google.com", "npmjs.com", "pypi.org",
    "w3.org", "www.w3.org", "schema.org", "example.com", "localhost",
    "schemas.openxmlformats.org", "openxmlformats.org", "schemas.microsoft.com",
    "purl.org", "ns.adobe.com", "adobe.com", "iptc.org", "useplus.org", "ns.useplus.org",
    "c2pa.org", "xml.org", "oasis-open.org", "openoffice.org", "libreoffice.org",
    "iec.ch", "color.org", "xmp.org", "pdfa.org", "npes.org", "pkware.com",
}

PROMPT_STOPWORDS = {
    "osint", "hunt", "investigate", "search", "find", "everything", "about", "on", "target",
    "check", "scan", "recon", "whois", "lookup", "please", "do", "an", "for", "this", "guy",
    "person", "company", "domain", "email", "user", "username", "wallet", "ip", "address",
    "the", "and", "with", "from", "start", "now", "insta", "instagram", "tiktok", "snapchat",
    "telegram", "twitter", "handle", "account", "profile",
}


def generate_handle_variants(handle: str, max_variants: int = 4) -> list[str]:
    """Generate deterministic cross-platform username mutations (e.g. X/GitHub forbid '.' in handles)."""
    h = (handle or "").strip().lstrip("@")
    if len(h) < 3 or " " in h:
        return []
    seen = {h.lower()}
    variants: list[str] = []

    def _push(cand: str) -> None:
        c = cand.strip("._-")
        if 3 <= len(c) <= 39 and c.lower() not in seen and not c.isdigit():
            seen.add(c.lower())
            variants.append(c)

    if "." in h:
        _push(h.replace(".", "_"))
        _push(h.replace(".", "-"))
        _push(h.replace(".", ""))
    elif "_" in h:
        _push(h.replace("_", "."))
        _push(h.replace("_", "-"))
        _push(h.replace("_", ""))
    elif "-" in h:
        _push(h.replace("-", "_"))
        _push(h.replace("-", "."))
        _push(h.replace("-", ""))

    # Strip common professional/social prefixes/suffixes (e.g. dr.abo3tab -> abo3tab, official_foo -> foo)
    low = h.lower()
    for pfx in ("dr.", "dr_", "dr-", "eng.", "eng_", "prof.", "prof_", "official.", "official_", "real.", "real_", "its.", "its_", "iam.", "iam_"):
        if low.startswith(pfx) and len(h) - len(pfx) >= 4:
            _push(h[len(pfx):])
    for sfx in (".official", "_official", "-official", ".real", "_real"):
        if low.endswith(sfx) and len(h) - len(sfx) >= 4:
            _push(h[: -len(sfx)])

    return variants[:max_variants]


VIN_TRANSLITERATION = {
    **{str(i): i for i in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def is_valid_vin(candidate: str) -> bool:
    s = candidate.upper()
    if len(s) != 17 or any(ch in "IOQ" for ch in s):
        return False
    # Must mix letters and digits to avoid 17-char hex/words
    if s.isdigit() or s.isalpha():
        return False
    # North American check digit (position 9, index 8) or known WMI structure
    if not s[13:].isdigit():
        return False
    total = sum(VIN_TRANSLITERATION[ch] * VIN_WEIGHTS[i] for i, ch in enumerate(s))
    rem = total % 11
    expected = "X" if rem == 10 else str(rem)
    return s[8] == expected or s[:3] in {"WBA", "WDB", "WVW", "WAU", "WP0", "VF1", "VF3", "ZFF", "SAL", "SAJ", "YV1"}


def is_valid_imo(digits7: str) -> bool:
    if len(digits7) != 7 or not digits7.isdigit():
        return False
    checksum = sum(int(digits7[i]) * (7 - i) for i in range(6)) % 10
    return checksum == int(digits7[6])


def _add(results: list[dict], seen: set[tuple[str, str]], sel_type: str, value: str, confidence: float = 0.95, note: str = "") -> None:
    norm_val = value.strip()
    if not norm_val:
        return
    key = (sel_type, norm_val.lower())
    if key in seen:
        return
    seen.add(key)
    results.append(
        {
            "type": sel_type,
            "value": norm_val,
            "confidence": round(confidence, 2),
            "note": note,
        }
    )


def extract_selectors(raw_input: str, cwd: str | None = None, *, check_local_file: bool = True) -> list[dict]:
    """Extract and rank all OSINT selectors from an arbitrary string or prompt."""
    text = (raw_input or "").strip()
    if not text:
        return []

    results: list[dict] = []
    seen: set[tuple[str, str]] = set()

    # 1. Check if the input (or token) points to an existing local file for forensic extraction
    if check_local_file and "\n" not in text and len(text) < 400:
        base_dir = Path(cwd) if cwd else Path.cwd()
        candidate_path = Path(text)
        try:
            resolved = candidate_path if candidate_path.is_absolute() else (base_dir / candidate_path)
            if resolved.exists() and resolved.is_file():
                ext = resolved.suffix.lower()
                sub = "image" if ext in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".tiff", ".heic", ".bmp"} else "document"
                _add(results, seen, "local_file", str(resolved.resolve()), 1.0, f"Local {sub} file on disk")
                return results
        except OSError:
            pass

    # Normalize Eastern-Arabic & Persian digits (`٠-٩`, `۰-۹` -> `0-9`) so Arabic phones/IBANs parse natively
    text = normalize_arabic_digits(text)

    # 2. JWT tokens
    for m in JWT_RE.findall(text):
        _add(results, seen, "jwt_token", m, 0.99, "JSON Web Token")

    # 3. URLs (plus social handle & domain extraction from URLs)
    for url in URL_RE.findall(text):
        clean_url = url.rstrip(".,;:!?)")
        _add(results, seen, "url", clean_url, 0.98, "Direct URL")
        try:
            parsed = urlparse(clean_url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            host = ""
        if host.endswith(".onion"):
            _add(results, seen, "onion_url", host, 0.99, "Tor v3/v2 hidden service")
        elif host and host not in NOISE_DOMAINS:
            _add(results, seen, "domain", host.removeprefix("www."), 0.92, "Extracted from URL")

        for rx, platform in SOCIAL_PATH_PATTERNS:
            sm = rx.match(clean_url)
            if sm:
                handle = sm.group(1).rstrip("/")
                if handle.lower() not in SOCIAL_URL_RESERVED:
                    _add(results, seen, "username", handle, 0.96, f"Extracted from {platform} URL")
                if platform == "github" and sm.lastindex and sm.lastindex >= 2 and sm.group(2):
                    _add(results, seen, "repo_code", f"{handle}/{sm.group(2)}", 0.97, "GitHub owner/repo")

    # 3b. WhatsApp wa.me / api.whatsapp.com phone links
    for wa_digits in WHATSAPP_URL_RE.findall(text):
        _add(results, seen, "phone", f"+{wa_digits}", 0.98, "Phone extracted from WhatsApp link")

    # 4. Onion domains standalone
    for onion in ONION_RE.findall(text):
        _add(results, seen, "onion_url", onion.lower(), 0.99, "Tor hidden service")

    # 5. Emails (plus non-freemail corporate domain pivot)
    freemails = {
        "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
        "proton.me", "protonmail.com", "protonmail.ch", "tutanota.com", "tuta.io", "aol.com",
        "yandex.ru", "yandex.com", "mail.ru", "gmx.com", "gmx.de", "live.com", "msn.com",
        "users.noreply.github.com",
    }
    for em in EMAIL_RE.findall(text):
        _add(results, seen, "email", em.lower(), 0.99, "Email address")
        dom = em.split("@", 1)[1].lower()
        if dom not in freemails and dom not in NOISE_DOMAINS:
            _add(results, seen, "domain", dom, 0.88, "Corporate domain from email")
    for loc_part, dom_part in OBFUSCATED_EMAIL_RE.findall(text):
        norm_dom = re.sub(r"\s*(?:\[dot\]|\(dot\)|\.)\s*", ".", dom_part.strip(), flags=re.IGNORECASE).lower()
        if "." in norm_dom:
            obf_em = f"{loc_part.lower()}@{norm_dom}"
            _add(results, seen, "email", obf_em, 0.93, "De-obfuscated email address")
            if norm_dom not in freemails and norm_dom not in NOISE_DOMAINS:
                _add(results, seen, "domain", norm_dom, 0.86, "Corporate domain from obfuscated email")

    # 6. Crypto addresses (EVM, BTC, TRON)
    for evm in EVM_RE.findall(text):
        _add(results, seen, "crypto_address", evm, 0.99, "EVM / Ethereum 20-byte address")
    for btc in BTC_RE.findall(text):
        _add(results, seen, "crypto_address", btc, 0.97, "Bitcoin address")
    for trx in TRON_RE.findall(text):
        _add(results, seen, "crypto_address", trx, 0.94, "Tron Base58Check address")

    # 7. MAC / BSSID
    for mac in MAC_RE.findall(text):
        _add(results, seen, "mac_bssid", mac.upper().replace("-", ":"), 0.98, "IEEE 802 MAC / BSSID")

    # 8. Coordinates
    for lat_s, lon_s in COORD_RE.findall(text):
        _add(results, seen, "coordinates", f"{float(lat_s):.6f},{float(lon_s):.6f}", 0.96, "WGS84 GPS coordinates")

    # 9. IPv4 / IPv6
    for ip_cand in IPV4_RE.findall(text):
        try:
            ip_obj = ipaddress.ip_address(ip_cand)
            if not (ip_obj.is_loopback or ip_obj.is_unspecified):
                _add(results, seen, "ip", str(ip_obj), 0.98, "IPv4 address")
        except ValueError:
            pass
    for ip6_cand in re.findall(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])", text):
        if MAC_RE.fullmatch(ip6_cand):
            continue
        try:
            ip6 = ipaddress.IPv6Address(ip6_cand)
            if not (ip6.is_loopback or ip6.is_unspecified):
                _add(results, seen, "ip", str(ip6), 0.98, "IPv6 address")
        except ValueError:
            pass

    # 10. ASNs
    for asn_num in ASN_RE.findall(text):
        _add(results, seen, "asn", f"AS{asn_num}", 0.98, "Autonomous System Number")

    # 11. Explicit Maritime IMO / MMSI & Aircraft ICAO Hex
    for imo in IMO_EXPLICIT_RE.findall(text):
        _add(results, seen, "vessel_imo", f"IMO {imo}", 0.99 if is_valid_imo(imo) else 0.8, "Vessel IMO number")
    for mmsi in MMSI_EXPLICIT_RE.findall(text):
        _add(results, seen, "vessel_imo", f"MMSI {mmsi}", 0.99, "Vessel 9-digit MMSI")
    for hex6 in ICAO_EXPLICIT_RE.findall(text):
        _add(results, seen, "aircraft_hex", hex6.upper(), 0.99, "Aircraft 24-bit ICAO Mode-S hex")

    # Single-token 6-char hex (e.g. "AE01D5") or 7/9 digit maritime
    stripped = text.strip()
    if re.fullmatch(r"[0-9A-Fa-f]{6}", stripped) and not stripped.isalpha():
        _add(results, seen, "aircraft_hex", stripped.upper(), 0.88, "6-hex ICAO24 Mode-S candidate")
    elif re.fullmatch(r"\d{7}", stripped) and is_valid_imo(stripped):
        _add(results, seen, "vessel_imo", f"IMO {stripped}", 0.92, "Validated 7-digit IMO checksum")
    elif re.fullmatch(r"[2-7]\d{8}", stripped):
        _add(results, seen, "vessel_imo", f"MMSI {stripped}", 0.86, "9-digit MMSI candidate")

    # 12. File hashes (avoid matching EVM addresses already prefixed with 0x)
    text_no_evm = EVM_RE.sub(" ", text)
    for h64 in SHA256_RE.findall(text_no_evm):
        _add(results, seen, "file_hash", h64.lower(), 0.98, "SHA-256 hash")
    if not results:
        for h40 in SHA1_RE.findall(text_no_evm):
            _add(results, seen, "file_hash", h40.lower(), 0.95, "SHA-1 hash")
        for h32 in MD5_RE.findall(text_no_evm):
            _add(results, seen, "file_hash", h32.lower(), 0.94, "MD5 hash")

    # 13. VIN (17-character ISO 3779 — explicit VIN prefix or valid check-digit/known WMI)
    for vin_exp in VIN_EXPLICIT_RE.findall(text.upper()):
        if not any(ch in "IOQ" for ch in vin_exp):
            _add(results, seen, "vin", vin_exp, 0.98, "Explicit 17-character VIN")
    for vin_cand in VIN_RE.findall(text.upper()):
        if is_valid_vin(vin_cand):
            _add(results, seen, "vin", vin_cand, 0.96, "17-character Vehicle Identification Number")

    # 14. Phone numbers (E.164 international format, 00-prefixed, and unprefixed GCC/MENA mobile)
    for ph in PHONE_FMT_RE.findall(text):
        digits = "+" + re.sub(r"\D", "", ph)
        if 8 <= len(digits) <= 16:
            _add(results, seen, "phone", digits, 0.96, "E.164 international phone number")
    for ph in PHONE_INTL_RE.findall(text):
        _add(results, seen, "phone", ph, 0.97, "E.164 phone number")
    for ph00 in PHONE_00_INTL_RE.findall(text):
        _add(results, seen, "phone", f"+{ph00}", 0.95, "00-prefixed international phone number")
    for ph_gcc in PHONE_BARE_GCC_MENA_RE.findall(text):
        _add(results, seen, "phone", f"+{ph_gcc}", 0.94, "International mobile number")
    for m_sa05 in re.findall(r"(?<!\d)0(5\d[\s.-]?\d{3}[\s.-]?\d{4})(?!\d)", text):
        digs_05 = re.sub(r"\D", "", m_sa05)
        if len(digs_05) == 9:
            _add(results, seen, "phone", f"+966{digs_05}", 0.92, "Saudi local 05XXXXXXXX mobile normalized to E.164")

    # 15. Domains (not part of email addresses or noise social hosts)
    text_no_emails = EMAIL_RE.sub(" ", text)
    for dom in DOMAIN_RE.findall(text_no_emails):
        d_low = dom.lower().removeprefix("www.")
        if d_low.endswith(".eth"):
            _add(results, seen, "crypto_address", d_low, 0.95, "ENS .eth Web3 domain")
        elif d_low not in NOISE_DOMAINS:
            _add(results, seen, "domain", d_low, 0.94, "Domain / Hostname")

    # 16. @handles and platform-labeled handles (e.g. "insta username: dr.abo3tab", "tiktok: foo")
    for h in HANDLE_AT_RE.findall(text_no_emails):
        h_clean = h.strip(".,;:!?)")
        if h_clean.lower() not in PROMPT_STOPWORDS and not DOMAIN_RE.fullmatch(h_clean):
            _add(results, seen, "username", h_clean, 0.95, "Explicit @handle")
    for lh in LABELED_HANDLE_RE.findall(text_no_emails):
        lh_clean = lh.strip(".,;:!?)")
        if lh_clean.lower() not in PROMPT_STOPWORDS and not DOMAIN_RE.fullmatch(lh_clean):
            _add(results, seen, "username", lh_clean, 0.96, "Labeled platform username/handle")

    # 16b. Arabic multi-word Person / Company entities embedded alongside phones, handles, or emails
    for ar_span in re.findall(r"[\u0600-\u06FF.]+(?:\s+[\u0600-\u06FF.]+){1,5}", text):
        ar_cls_span = classify_arabic_seed(ar_span.strip())
        if ar_cls_span is not None:
            _add(results, seen, ar_cls_span[0], ar_cls_span[1], 0.91, f"Arabic {ar_cls_span[0]} entity")

    # 17. Fallback heuristics when the input is a bare handle, owner/repo, person name, or company!
    if not results:
        # Clean leading conversational verbs like "do osint on ..." or "hunt ..."
        cleaned = re.sub(
            r"^(?:please\s+)?(?:do\s+(?:an?\s+)?osint\s+(?:on|for)|hunt|investigate|recon|search(?:\s+for)?|find(?:\s+everything\s+on)?|check|lookup)\s+",
            "",
            stripped,
            flags=re.IGNORECASE,
        ).strip(" \"'`")

        if DOMAIN_RE.fullmatch(cleaned.removeprefix("www.")):
            _add(results, seen, "domain", cleaned.lower().removeprefix("www."), 0.96, "Explicit target domain")
        elif re.fullmatch(r"[a-zA-Z0-9-]{1,39}/[a-zA-Z0-9._-]{1,80}", cleaned):
            owner, _ = cleaned.split("/", 1)
            _add(results, seen, "repo_code", cleaned, 0.97, "owner/repo slug")
            _add(results, seen, "username", owner, 0.88, "Repository owner handle")
        elif re.fullmatch(r"05\d{8}", re.sub(r"[\s.-]", "", cleaned)):
            digs_sa = re.sub(r"\D", "", cleaned)
            _add(results, seen, "phone", f"+966{digs_sa[1:]}", 0.91, "Saudi local 05XXXXXXXX mobile normalized to E.164")
        elif re.fullmatch(r"[1-9]\d{9,14}", cleaned):
            _add(results, seen, "phone", f"+{cleaned}", 0.90, "Unprefixed international phone number")
        elif re.fullmatch(r"[a-zA-Z0-9_.-]{2,39}", cleaned) and " " not in cleaned:
            _add(results, seen, "username", cleaned, 0.92, "Single-token username / package handle")
        elif (ar_cls := classify_arabic_seed(cleaned)) is not None:
            _add(results, seen, ar_cls[0], ar_cls[1], 0.91, f"Arabic {ar_cls[0]} entity")
        elif 2 <= len(cleaned.split()) <= 5:
            corp_suffixes = {"inc", "inc.", "llc", "ltd", "ltd.", "corp", "corp.", "gmbh", "ag", "plc", "sa", "bv", "group", "technologies", "labs", "holdings", "bank", "capital"}
            tokens_low = {w.lower().strip(",.") for w in cleaned.split()}
            if tokens_low & corp_suffixes:
                _add(results, seen, "company", cleaned, 0.92, "Organization / Corporate entity")
            else:
                _add(results, seen, "person_name", cleaned, 0.82, "Person or Organization name")
                _add(results, seen, "company", cleaned, 0.78, "Organization / Brand candidate")
        else:
            _add(results, seen, "keyword", cleaned[:120], 0.70, "Free-text intelligence query")

    return results

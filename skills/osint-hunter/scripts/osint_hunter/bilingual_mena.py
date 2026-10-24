"""Arabic <-> English / Arabizi Bilingual Pivoting & MENA/GCC Regional OSINT Engine (Upgrade #4).

100% Python 3 standard library. Zero external dependencies.
- Normalizes Eastern-Arabic & Persian digits (`٠١٢٣٤٥٦٧٨٩` -> `0123456789`) across phones, IBANs, and handles.
- Classifies Arabic-script person names (`طارق المنصور`, `د. أبو عتاب`) and companies/clinics (`شركة ...`, `عيادات ...`).
- Bidirectionally transliterates:
    * Arabizi / Latin handles & names (`dr.abo3tab`, `7amad`, `5aled`, `Tariq Al-Mansoor`) -> Arabic script (`د. أبو عتاب`, `حمد`, `خالد`, `طارق المنصور`)
    * Arabic names & kunyas -> English / Latin variants & handle candidates (`Tariq Al-Mansoor`, `abo3tab`, `tariq_almansoor`)
- Builds MENA / GCC regional directory queries & 1-click Launchpad links (`Maroof`, `Saudi Business Center`, `SCFHS`, `Haraj`, `OpenSooq`).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

ARABIC_DIGITS_MAP = str.maketrans(
    "٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹",
    "01234567890123456789",
)
ARABIC_CHAR_RE = re.compile(r"[\u0600-\u06FF]")
ARABIC_DIACRITICS_RE = re.compile(r"[\u0640\u064B-\u065F\u0670]")
ARABIZI_TOKEN_RE = re.compile(r"(?:[a-zA-Z]+[2356789]'?[a-zA-Z]+|^[2356789]'?[a-zA-Z]{2,}|[a-zA-Z]{3,}[2356789]$)")

ARABIC_COMPANY_KEYWORDS: set[str] = {
    "شركة", "شركه", "مؤسسة", "موسسة", "موسسه", "مجموعة", "مجموعه", "مستشفى",
    "عيادة", "عياده", "عيادات", "مجمع", "مركز", "مكتب", "مصنع", "بنك", "مصرف",
    "جامعة", "جامعه", "كلية", "معهد", "جمعية", "هيئة", "وزارة", "وكالة",
    "قابضة", "القابضة", "للتجارة", "للمقاولات", "الطبية", "الطبي", "التخصصي",
    "للاستشارات", "العقارية", "التقنية", "المحدودة", "متجر",
}

ARABIC_HONORIFICS: dict[str, str] = {
    "د": "Dr",
    "د.": "Dr",
    "دكتور": "Dr",
    "الدكتور": "Dr",
    "دكتورة": "Dr",
    "الدكتورة": "Dr",
    "أ.د": "Prof",
    "م": "Eng",
    "م.": "Eng",
    "مهندس": "Eng",
    "المهندس": "Eng",
    "الشيخ": "Sheikh",
    "شيخ": "Sheikh",
}

# Bidirectional lexicon: Latin/Arabizi token -> primary Arabic rendering(s)
LATIN_TO_ARABIC_LEXICON: dict[str, list[str]] = {
    "dr": ["د.", "دكتور"],
    "doctor": ["دكتور"],
    "eng": ["مهندس"],
    "abo": ["أبو", "ابو"],
    "abu": ["أبو", "ابو"],
    "abou": ["أبو", "ابو"],
    "um": ["أم", "ام"],
    "umm": ["أم", "ام"],
    "bin": ["بن"],
    "ibn": ["بن", "ابن"],
    "bint": ["بنت"],
    "al": ["ال"],
    "el": ["ال"],
    "3tab": ["عتاب"],
    "atab": ["عتاب"],
    "attab": ["عتاب"],
    "ahmed": ["أحمد", "احمد"],
    "ahmad": ["أحمد", "احمد"],
    "a7mad": ["أحمد", "احمد"],
    "mohammed": ["محمد"],
    "mohamed": ["محمد"],
    "muhammad": ["محمد"],
    "m7md": ["محمد"],
    "ali": ["علي"],
    "3li": ["علي"],
    "3ali": ["علي"],
    "omar": ["عمر"],
    "3omar": ["عمر"],
    "3mr": ["عمر"],
    "khalid": ["خالد"],
    "khaled": ["خالد"],
    "5aled": ["خالد"],
    "5alid": ["خالد"],
    "fahad": ["فهد"],
    "fahd": ["فهد"],
    "faisal": ["فيصل"],
    "saud": ["سعود"],
    "s3oud": ["سعود"],
    "salman": ["سلمان"],
    "sultan": ["سلطان"],
    "abdullah": ["عبدالله", "عبد الله"],
    "3bdullah": ["عبدالله"],
    "abdulrahman": ["عبدالرحمن"],
    "abdulaziz": ["عبدالعزيز"],
    "3bdulaziz": ["عبدالعزيز"],
    "tariq": ["طارق"],
    "tarek": ["طارق"],
    "6ariq": ["طارق"],
    "hamad": ["حمد"],
    "7amad": ["حمد"],
    "7md": ["حمد"],
    "hassan": ["حسن"],
    "7assan": ["حسن"],
    "hussein": ["حسين"],
    "7ussein": ["حسين"],
    "saleh": ["صالح"],
    "9aleh": ["صالح"],
    "saad": ["سعد"],
    "s3d": ["سعد"],
    "saeed": ["سعيد"],
    "s3eed": ["سعيد"],
    "yasser": ["ياسر"],
    "yousef": ["يوسف"],
    "youssef": ["يوسف"],
    "ibrahim": ["إبراهيم", "ابراهيم"],
    "nasser": ["ناصر"],
    "nawaf": ["نواف"],
    "bandar": ["بندر"],
    "turki": ["تركي"],
    "waleed": ["وليد"],
    "walid": ["وليد"],
    "majed": ["ماجد"],
    "majid": ["ماجد"],
    "sami": ["سامي"],
    "rami": ["رامي"],
    "karim": ["كريم"],
    "adel": ["عادل"],
    "3adel": ["عادل"],
    "talal": ["طلال"],
    "6alal": ["طلال"],
    "badr": ["بدر"],
    "bader": ["بدر"],
    "osama": ["أسامة", "اسامه"],
    "anas": ["أنس", "انس"],
    "ziad": ["زياد"],
    "sara": ["سارة", "ساره"],
    "sarah": ["سارة", "ساره"],
    "fatima": ["فاطمة", "فاطمه"],
    "noura": ["نورة", "نوره"],
    "noor": ["نور"],
    "reem": ["ريم"],
    "amal": ["أمل", "امل"],
    # Common GCC family / tribal surnames
    "mansoor": ["منصور"],
    "mansour": ["منصور"],
    "almansoor": ["المنصور"],
    "almansour": ["المنصور"],
    "qahtani": ["القحطاني", "قحطاني"],
    "alqahtani": ["القحطاني"],
    "otaibi": ["العتيبي", "عتيبي"],
    "alotaibi": ["العتيبي"],
    "3taibi": ["العتيبي", "عتيبي"],
    "ghamdi": ["الغامدي", "غامدي"],
    "alghamdi": ["الغامدي"],
    "zahrani": ["الزهراني"],
    "alzahrani": ["الزهراني"],
    "harbi": ["الحربي"],
    "alharbi": ["الحربي"],
    "mutairi": ["المطيري"],
    "almutairi": ["المطيري"],
    "shamri": ["الشمري"],
    "alshamri": ["الشمري"],
    "shammari": ["الشمري"],
    "dosari": ["الدوسري"],
    "aldosari": ["الدوسري"],
    "dossari": ["الدوسري"],
    "subaei": ["السبيعي"],
    "alsubaei": ["السبيعي"],
    "anazi": ["العنزي"],
    "alanazi": ["العنزي"],
    "shehri": ["الشهري"],
    "alshehri": ["الشهري"],
    "malki": ["المالكي"],
    "almalki": ["المالكي"],
    "قرني": ["alqarni"],
    "qarni": ["القرني"],
    "alqarni": ["القرني"],
    "tamimi": ["التميمي"],
    "altamimi": ["التميمي"],
    "rajhi": ["الراجحي"],
    "alrajhi": ["الراجحي"],
    # Common clinic / business terms
    "clinic": ["عيادة", "عيادات"],
    "clinics": ["عيادات"],
    "medical": ["الطبي", "الطبية"],
    "hospital": ["مستشفى"],
    "dental": ["أسنان"],
    "derma": ["جلدية"],
}

# Build reverse Arabic -> Latin lookup automatically + explicit overrides
ARABIC_TO_LATIN_LEXICON: dict[str, list[str]] = {
    "أبو": ["Abo", "Abu"],
    "ابو": ["Abo", "Abu"],
    "أم": ["Um", "Umm"],
    "ام": ["Um", "Umm"],
    "عتاب": ["3tab", "Atab"],
    "طارق": ["Tariq", "Tarek"],
    "المنصور": ["Al-Mansoor", "Almansour"],
    "منصور": ["Mansoor", "Mansour"],
    "أحمد": ["Ahmed", "Ahmad"],
    "احمد": ["Ahmed", "Ahmad"],
    "محمد": ["Mohammed", "Mohamed"],
    "علي": ["Ali"],
    "عمر": ["Omar"],
    "خالد": ["Khalid", "Khaled"],
    "فهد": ["Fahad"],
    "فيصل": ["Faisal"],
    "سعود": ["Saud"],
    "سلمان": ["Salman"],
    "سلطان": ["Sultan"],
    "عبدالله": ["Abdullah"],
    "عبدالرحمن": ["Abdulrahman"],
    "عبدالعزيز": ["Abdulaziz"],
    "حمد": ["Hamad", "7amad"],
    "حسن": ["Hassan"],
    "حسين": ["Hussein"],
    "صالح": ["Saleh"],
    "سعد": ["Saad"],
    "سعيد": ["Saeed"],
    "ياسر": ["Yasser"],
    "يوسف": ["Yousef"],
    "إبراهيم": ["Ibrahim"],
    "ابراهيم": ["Ibrahim"],
    "ناصر": ["Nasser"],
    "نواف": ["Nawaf"],
    "بندر": ["Bandar"],
    "تركي": ["Turki"],
    "وليد": ["Waleed"],
    "ماجد": ["Majed"],
    "سارة": ["Sara", "Sarah"],
    "ساره": ["Sara", "Sarah"],
    "نورة": ["Noura"],
    "نور": ["Noor"],
    "ريم": ["Reem"],
    "القحطاني": ["Al-Qahtani", "Alqahtani"],
    "العتيبي": ["Al-Otaibi", "Alotaibi"],
    "الغامدي": ["Al-Ghamdi", "Alghamdi"],
    "الزهراني": ["Al-Zahrani", "Alzahrani"],
    "الحربي": ["Al-Harbi", "Alharbi"],
    "المطيري": ["Al-Mutairi", "Almutairi"],
    "الشمري": ["Al-Shammari", "Alshammari"],
    "الدوسري": ["Al-Dosari", "Aldosari"],
    "العنزي": ["Al-Anazi", "Alanazi"],
    "الشهري": ["Al-Shehri", "Alshehri"],
    "التميمي": ["Al-Tamimi", "Altamimi"],
    "الراجحي": ["Al-Rajhi", "Alrajhi"],
    "عيادة": ["Clinic"],
    "عيادات": ["Clinics"],
    "مستشفى": ["Hospital"],
    "شركة": ["Company"],
    "مركز": ["Center"],
}

ARABIC_CHAR_PHONETIC: dict[str, str] = {
    "ا": "a", "أ": "a", "إ": "i", "آ": "aa", "ى": "a",
    "ب": "b", "ت": "t", "ث": "th", "ج": "j", "ح": "h",
    "خ": "kh", "د": "d", "ذ": "dh", "ر": "r", "ز": "z",
    "س": "s", "ش": "sh", "ص": "s", "ض": "d", "ط": "t",
    "ظ": "z", "ع": "a", "غ": "gh", "ف": "f", "ق": "q",
    "ك": "k", "ل": "l", "م": "m", "ن": "n", "ه": "h",
    "ة": "a", "و": "w", "ؤ": "o", "ي": "y", "ئ": "y", "ء": "",
}


def normalize_arabic_digits(raw: str) -> str:
    """Convert Eastern-Arabic (`٠-٩`) and Persian (`۰-۹`) numerals to ASCII `0-9`."""
    return (raw or "").translate(ARABIC_DIGITS_MAP)


def strip_arabic_diacritics(raw: str) -> str:
    return ARABIC_DIACRITICS_RE.sub("", raw or "")


def classify_arabic_seed(raw: str) -> tuple[str, str] | None:
    """Detect whether an Arabic phrase is a `company` or `person_name`."""
    cleaned = re.sub(r"\s+", " ", strip_arabic_diacritics(normalize_arabic_digits(raw))).strip(" \t\r\n.,;:|\"'()")
    if not cleaned or not ARABIC_CHAR_RE.search(cleaned):
        return None
    # Skip if it contains URLs, emails, or > 7 words
    if "http" in cleaned.lower() or "@" in cleaned:
        return None
    words = cleaned.split()
    if len(words) < 2 or len(words) > 6:
        return None
    # Ensure words are predominantly Arabic letters
    ar_words = [w for w in words if ARABIC_CHAR_RE.search(w)]
    if len(ar_words) < 2:
        return None

    for w in words:
        w_bare = w.strip(".")
        if w_bare in ARABIC_COMPANY_KEYWORDS:
            return ("company", cleaned)

    return ("person_name", cleaned)


def _split_compound_handle_token(tok: str) -> list[str]:
    """Split glued prefixes like `abo3tab` -> `['abo', '3tab']` or `almansoor` -> `['al', 'mansoor']`."""
    tl = tok.lower()
    if tl in LATIN_TO_ARABIC_LEXICON:
        return [tl]
    for pref in ("abou", "abo", "abu", "umm", "al", "el"):
        if tl.startswith(pref) and len(tl) >= len(pref) + 3:
            rem = tl[len(pref) :]
            if rem in LATIN_TO_ARABIC_LEXICON or ARABIZI_TOKEN_RE.search(rem):
                return [pref, rem]
    return [tl]


def _arabizi_word_to_arabic(tok: str) -> str | None:
    """Phonetic + Arabizi fallback (`7amad` -> `حمد`, `3tab` -> `عتاب`, `5aled` -> `خالد`)."""
    t = tok.lower()
    if t in LATIN_TO_ARABIC_LEXICON:
        return LATIN_TO_ARABIC_LEXICON[t][0]
    if not ARABIZI_TOKEN_RE.search(t):
        return None

    # Multi-char digraphs first
    rep = (
        ("3'", "غ"), ("7'", "خ"), ("9'", "ض"), ("6'", "ظ"),
        ("sh", "ش"), ("kh", "خ"), ("gh", "غ"), ("th", "ث"), ("dh", "ذ"), ("ch", "تش"),
        ("oo", "و"), ("ou", "و"), ("ee", "ي"), ("aa", "ا"),
    )
    out = t
    for src, dst in rep:
        out = out.replace(src, dst)

    char_map = {
        "2": "أ", "3": "ع", "5": "خ", "6": "ط", "7": "ح", "8": "ق", "9": "ص",
        "a": "ا", "b": "ب", "c": "ك", "d": "د", "e": "", "f": "ف", "g": "ج",
        "h": "ه", "i": "ي", "j": "ج", "k": "ك", "l": "ل", "m": "م", "n": "ن",
        "o": "و", "p": "ب", "q": "ق", "r": "ر", "s": "س", "t": "ت", "u": "و",
        "v": "ف", "w": "و", "x": "كس", "y": "ي", "z": "ز",
    }
    res_chars: list[str] = []
    for idx, ch in enumerate(out):
        if ARABIC_CHAR_RE.match(ch):
            res_chars.append(ch)
        elif ch in char_map:
            # Drop short internal 'a' after consonants like '7amad' -> 'حمد' while keeping '3tab' -> 'عتاب'
            if ch == "a" and 0 < idx < len(out) - 1 and idx == 1 and t[0] in "2356789":
                continue
            res_chars.append(char_map[ch])
    ar = "".join(res_chars).strip()
    return ar if len(ar) >= 2 else None


def _arabic_word_to_latin(word: str) -> tuple[str, str]:
    """Return `(TitleLatin, ArabiziOrAlt)` for an Arabic word."""
    w = strip_arabic_diacritics(word).strip(".")
    if w in ARABIC_HONORIFICS:
        h = ARABIC_HONORIFICS[w]
        return h, h.lower()
    if w in ARABIC_TO_LATIN_LEXICON:
        opts = ARABIC_TO_LATIN_LEXICON[w]
        return opts[0], opts[-1]
    if w.startswith("ال") and len(w) >= 5:
        stem = w[2:]
        if stem in ARABIC_TO_LATIN_LEXICON:
            s0 = ARABIC_TO_LATIN_LEXICON[stem][0]
            return f"Al-{s0}", f"al{s0.lower()}"
        phon = "".join(ARABIC_CHAR_PHONETIC.get(c, c) for c in stem)
        return f"Al-{phon.capitalize()}", f"al{phon}"
    phon = "".join(ARABIC_CHAR_PHONETIC.get(c, c) for c in w)
    return phon.capitalize(), phon.lower()


def generate_bilingual_pivots(raw_value: str) -> dict[str, Any]:
    """Generate Arabic <-> English/Arabizi query equivalents & handle candidates."""
    s = normalize_arabic_digits((raw_value or "").strip()).lstrip("@")
    if not s:
        return {"has_arabic": False, "has_arabizi": False, "is_mena_relevant": False, "arabic_queries": [], "latin_queries": [], "handle_candidates": []}

    has_ar = bool(ARABIC_CHAR_RE.search(s))
    raw_tokens = [t for t in re.split(r"[\s._-]+", s) if t]
    has_arabizi = any(bool(ARABIZI_TOKEN_RE.search(t)) for t in raw_tokens)

    arabic_queries: list[str] = []
    latin_queries: list[str] = []
    handle_candidates: list[str] = []

    if has_ar:
        words = [strip_arabic_diacritics(w) for w in s.split() if w.strip()]
        primary_parts: list[str] = []
        alt_parts: list[str] = []
        for w in words:
            p0, p1 = _arabic_word_to_latin(w)
            if p0:
                primary_parts.append(p0)
            if p1:
                alt_parts.append(p1)
        if primary_parts:
            lat1 = " ".join(primary_parts)
            latin_queries.append(lat1)
            lat2 = " ".join(p.replace("Al-", "Al") for p in primary_parts)
            if lat2 not in latin_queries:
                latin_queries.append(lat2)
        # Build clean handle candidates (e.g. ד. أبو عتاب -> dr.abo3tab, abo3tab; طارق المنصور -> tariq_almansoor)
        slug_tokens = [re.sub(r"[^a-z0-9]", "", p.lower()) for p in alt_parts if re.sub(r"[^a-z0-9]", "", p.lower())]
        if slug_tokens:
            joined_dot = ".".join(slug_tokens)
            joined_und = "_".join(slug_tokens)
            joined_flat = "".join(slug_tokens)
            for hc in (joined_dot, joined_und, joined_flat):
                if 4 <= len(hc) <= 32 and hc not in handle_candidates:
                    handle_candidates.append(hc)
            if slug_tokens[0] in ("dr", "eng", "sheikh") and len(slug_tokens) >= 2:
                no_title = "".join(slug_tokens[1:])
                if 4 <= len(no_title) <= 30 and no_title not in handle_candidates:
                    handle_candidates.append(no_title)
    else:
        # Latin or Arabizi input -> check if transliterable to Arabic!
        expanded_tokens: list[str] = []
        for rt in raw_tokens:
            expanded_tokens.extend(_split_compound_handle_token(rt))

        ar_parts_primary: list[str] = []
        ar_parts_alt: list[str] = []
        matched_arabic_tokens = 0
        for tok in expanded_tokens:
            tl = tok.lower().strip(".")
            if tl in LATIN_TO_ARABIC_LEXICON:
                opts = LATIN_TO_ARABIC_LEXICON[tl]
                ar_parts_primary.append(opts[0])
                ar_parts_alt.append(opts[-1])
                matched_arabic_tokens += 1
            else:
                az = _arabizi_word_to_arabic(tl)
                if az:
                    ar_parts_primary.append(az)
                    ar_parts_alt.append(az)
                    matched_arabic_tokens += 1

        # Emit Arabic queries if all tokens (or >=2 meaningful MENA/Arabizi tokens) mapped cleanly
        if ar_parts_primary and (matched_arabic_tokens == len(expanded_tokens) or (has_arabizi and matched_arabic_tokens >= 1) or matched_arabic_tokens >= 2):
            # Join 'ال' prefix onto next word cleanly
            def _join_ar(parts: list[str]) -> str:
                out_w: list[str] = []
                i = 0
                while i < len(parts):
                    if parts[i] == "ال" and i + 1 < len(parts) and not parts[i + 1].startswith("ال"):
                        out_w.append("ال" + parts[i + 1])
                        i += 2
                    else:
                        out_w.append(parts[i])
                        i += 1
                return " ".join(out_w).strip()

            q1 = _join_ar(ar_parts_primary)
            q2 = _join_ar(ar_parts_alt)
            if q1:
                arabic_queries.append(q1)
            if q2 and q2 not in arabic_queries:
                arabic_queries.append(q2)
            # Also without honorific 'د.' if present so bare Arabic name searches hit too
            if len(ar_parts_primary) >= 2 and ar_parts_primary[0] in ("د.", "دكتور", "مهندس"):
                q_bare = _join_ar(ar_parts_primary[1:])
                if q_bare and q_bare not in arabic_queries:
                    arabic_queries.append(q_bare)

    is_mena = bool(has_ar or has_arabizi or arabic_queries)
    return {
        "has_arabic": has_ar,
        "has_arabizi": has_arabizi,
        "is_mena_relevant": is_mena,
        "arabic_queries": arabic_queries[:4],
        "latin_queries": latin_queries[:4],
        "handle_candidates": handle_candidates[:4],
    }


def build_mena_regional_launchpad(
    *,
    names: list[str],
    handles: list[str],
    phones: list[str],
    domains: list[str],
) -> list[dict[str, str]]:
    """Build 1-click MENA / GCC verification & marketplace OSINT links when target has GCC/Arabic signals."""
    links: list[dict[str, str]] = []
    gcc_phones = [p for p in phones if p.startswith(("+966", "+971", "+965", "+974", "+973", "+968", "+20", "+962"))]
    gcc_domains = [d for d in domains if d.endswith((".sa", ".ae", ".kw", ".qa", ".bh", ".om", ".eg", ".jo"))]

    all_text = " ".join(names + handles)
    bilingual = generate_bilingual_pivots(all_text) if all_text else {"is_mena_relevant": False, "arabic_queries": []}
    if not (gcc_phones or gcc_domains or bilingual["is_mena_relevant"]):
        return links

    primary_q = (
        (bilingual["arabic_queries"][0] if bilingual.get("arabic_queries") else "")
        or (names[0] if names else "")
        or (handles[0] if handles else "")
    )

    if gcc_phones:
        ph = gcc_phones[0]
        local_sa = "0" + ph[4:] if ph.startswith("+966") and len(ph) == 13 else ph.lstrip("+")
        q_haraj = f'site:haraj.com.sa "{local_sa}" OR "{ph}"'
        q_maroof_ph = f'site:maroof.sa "{local_sa}" OR "{ph}"'
        links.append(
            {
                "label": f"Haraj KSA ({local_sa})",
                "category": "MENA Regional",
                "url": f"https://www.google.com/search?q={urllib.parse.quote(q_haraj)}",
            }
        )
        links.append(
            {
                "label": f"Maroof Store Check ({local_sa})",
                "category": "MENA Regional",
                "url": f"https://www.google.com/search?q={urllib.parse.quote(q_maroof_ph)}",
            }
        )

    if primary_q:
        q_ksa_biz = f'(site:maroof.sa OR site:business.sa) "{primary_q}"'
        links.append(
            {
                "label": f"Maroof / KSA Business ({primary_q[:22]})",
                "category": "MENA Regional",
                "url": f"https://www.google.com/search?q={urllib.parse.quote(q_ksa_biz)}",
            }
        )
        low_all = all_text.lower()
        if any(med in low_all for med in ("dr", "doctor", "clinic", "د.", "دكتور", "عيادة", "عيادات", "طبي")):
            q_scfhs = f'(site:scfhs.org.sa OR site:altibbi.com OR site:vezeeta.com) "{primary_q}"'
            links.append(
                {
                    "label": f"SCFHS Practitioner / Medical ({primary_q[:20]})",
                    "category": "MENA Regional",
                    "url": f"https://www.google.com/search?q={urllib.parse.quote(q_scfhs)}",
                }
            )

    return links[:5]

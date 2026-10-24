"""Entity Disambiguation & Common-Username Collision Filter (Upgrade #1).

Prevents generic or common first-name / dictionary handles (e.g. `@ahmed`, `@alex`,
`@clinic`, `@vip`) from polluting multi-stage graph pivots with unrelated strangers'
bios, websites, and emails—while keeping distinctive handles (`@dr.abo3tab`,
`@torvalds`) at full multi-stage velocity and preserving uncorroborated hits
non-destructively under `possible_namesake_profiles`.
"""

from __future__ import annotations

import math
import re
import urllib.parse
from collections import Counter
from typing import Any

COMMON_GIVEN_NAMES: set[str] = {
    # MENA / Arabic transliterated given names
    "ahmed", "ahmad", "mohammed", "mohamed", "muhammad", "mohamad", "ali", "omar",
    "umar", "khalid", "khaled", "fahad", "fahd", "faisal", "saud", "salman", "sultan",
    "abdullah", "abdulrahman", "abdulaziz", "tariq", "tarek", "yasser", "yasir",
    "hassan", "hasan", "hussein", "hussain", "ibrahim", "ismail", "yousef", "youssef",
    "yusuf", "hamad", "hamza", "zaid", "zayd", "ziad", "ziyad", "majed", "majid",
    "nasser", "nasir", "nawaf", "bandar", "turki", "waleed", "walid", "adel", "amir",
    "ameer", "rami", "ramy", "sami", "samy", "karim", "kareem", "bilal", "mustafa",
    "mostafa", "osama", "usama", "anas", "ayman", "badr", "bader", "talal", "meshari",
    "mishari", "rayan", "rayyan", "saad", "saeed", "said", "saleh", "salih",
    "sara", "sarah", "fatima", "fatimah", "fatma", "aisha", "ayesha", "maryam",
    "mariam", "noor", "nour", "noura", "nora", "reem", "rima", "amal", "mona", "muna",
    "hana", "hanaa", "layla", "laila", "leila", "lina", "dana", "dina", "rana",
    "rania", "salma", "yasmin", "yasmine", "nada", "hind", "shahad", "raghad", "lama",
    # Global / English common given names
    "alex", "alexander", "john", "james", "robert", "michael", "mike", "william",
    "will", "david", "dave", "richard", "joseph", "joe", "thomas", "tom", "charles",
    "chris", "daniel", "dan", "matthew", "matt", "anthony", "tony", "mark", "donald",
    "steven", "steve", "paul", "andrew", "andy", "joshua", "josh", "kenneth", "kevin",
    "brian", "george", "timothy", "tim", "ronald", "edward", "jason", "jeffrey",
    "ryan", "jacob", "gary", "nicholas", "nick", "eric", "jonathan", "stephen",
    "larry", "justin", "scott", "brandon", "benjamin", "ben", "samuel", "sam",
    "gregory", "frank", "raymond", "patrick", "jack", "dennis", "jerry", "tyler",
    "aaron", "jose", "adam", "nathan", "henry", "douglas", "zachary", "peter", "kyle",
    "noah", "ethan", "jeremy", "walter", "christian", "keith", "roger", "terry",
    "austin", "sean", "gerald", "carl", "harold", "dylan", "arthur", "lawrence",
    "jordan", "jesse", "bryan", "billy", "bruce", "gabriel", "logan", "alan", "juan",
    "wayne", "elijah", "randy", "roy", "vincent", "ralph", "eugene", "russell",
    "bobby", "mason", "philip", "louis", "leo", "max", "lukas", "luca", "ivan",
    "carlos", "luis", "diego", "pedro", "marco", "jean", "pierre", "hans", "chen",
    "wang", "zhang", "liu", "yang", "kim", "park", "lee", "raj", "amit", "rahul",
    "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan",
    "jessica", "karen", "ashley", "emily", "amanda", "melissa", "deborah",
    "stephanie", "rebecca", "sharon", "laura", "cynthia", "kathleen", "amy", "angela",
    "shirley", "anna", "brenda", "pamela", "emma", "nicole", "helen", "samantha",
    "katherine", "kate", "christine", "debra", "rachel", "carolyn", "janet",
    "catherine", "maria", "heather", "diane", "ruth", "julie", "olivia", "joyce",
    "virginia", "victoria", "kelly", "lauren", "christina", "joan", "evelyn",
    "judith", "megan", "andrea", "cheryl", "hannah", "jacqueline", "martha",
    "gloria", "teresa", "ann", "madison", "frances", "kathryn", "janice",
    "abigail", "alice", "julia", "judy", "sophia", "grace", "denise", "amber",
    "doris", "marilyn", "danielle", "beverly", "isabella", "theresa", "diana",
    "natalie", "brittany", "charlotte", "marie", "kayla", "alexis", "lori", "claire",
    "chloe", "zoe", "lily", "mia", "ava", "ella", "aria", "luna", "mila", "elena",
}

GENERIC_ROLE_AND_DICT_HANDLES: set[str] = {
    "admin", "administrator", "root", "user", "guest", "test", "testing", "demo",
    "sample", "example", "support", "help", "helpdesk", "info", "contact", "sales",
    "marketing", "billing", "security", "sec", "privacy", "legal", "press", "media",
    "news", "official", "real", "original", "verified", "team", "staff", "office",
    "clinic", "doctor", "hospital", "medical", "dental", "health", "care", "pharma",
    "store", "shop", "market", "mart", "mall", "boutique", "fashion", "beauty",
    "salon", "spa", "fitness", "gym", "coach", "trainer", "food", "cafe", "coffee",
    "hotel", "travel", "tours", "cars", "auto", "motors", "realty", "homes",
    "tech", "technology", "digital", "cloud", "cyber", "data", "ai", "bot", "app",
    "web", "dev", "developer", "code", "coder", "hacker", "design", "designer",
    "art", "artist", "photo", "photography", "video", "music", "dj", "radio", "tv",
    "film", "studio", "agency", "creative", "group", "global", "world", "international",
    "crypto", "bitcoin", "btc", "eth", "ethereum", "nft", "defi", "web3", "forex",
    "trading", "trader", "invest", "finance", "money", "gold", "cash", "bank",
    "vip", "king", "queen", "prince", "princess", "boss", "ceo", "founder", "owner",
    "pro", "elite", "prime", "alpha", "omega", "shadow", "ghost", "ninja", "dragon",
    "wolf", "eagle", "lion", "tiger", "falcon", "hawk", "phoenix", "star", "moon",
    "sun", "sky", "fire", "ice", "storm", "dark", "light", "black", "white", "blue",
    "red", "green", "gold", "silver", "gamer", "gaming", "player", "play", "live",
    "stream", "meme", "memes", "funny", "love", "life", "peace", "free", "cool",
    "arab", "arabic", "saudi", "ksa", "riyadh", "jeddah", "khobar", "dammam", "makkah",
    "dubai", "uae", "abudhabi", "qatar", "doha", "kuwait", "bahrain", "oman", "cairo",
    "egypt", "london", "paris", "tokyo", "usa", "uk",
}

STOP_BIO_WORDS: set[str] = {
    "the", "and", "for", "with", "from", "this", "that", "your", "have", "more",
    "official", "account", "page", "profile", "follow", "welcome", "contact", "link",
    "below", "bio", "all", "rights", "reserved", "http", "https", "www", "com", "org",
    "net", "creator", "digital", "content", "founder", "ceo", "engineer", "developer",
    "student", "lover", "enthusiast", "based", "living", "working", "views", "own",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def score_handle_uniqueness(handle: str) -> dict[str, Any]:
    """Compute a deterministic 0.0..1.0 uniqueness score & collision risk for a username."""
    h = (handle or "").strip().lstrip("@").lower()
    if not h:
        return {"handle": "", "uniqueness_score": 0.0, "tier": "low_collision_prone", "is_collision_prone": True, "reasons": ["empty"]}

    alpha_only = re.sub(r"[^a-z]", "", h)
    digits = re.findall(r"\d+", h)
    has_sep = bool(re.search(r"[._-]", h))
    # Arabizi pattern: digit 2/3/5/6/7/8/9 embedded inside letters (e.g. abo3tab, 7amad, 5aled)
    has_arabizi = bool(re.search(r"[a-z][2356789][a-z]|^[2356789][a-z]{3,}", h))

    reasons: list[str] = []
    score = 0.50

    # Length contribution
    if len(h) <= 3:
        score -= 0.35
        reasons.append("very_short_handle_<=3")
    elif len(h) == 4:
        score -= 0.22
        reasons.append("short_handle_4_chars")
    elif len(h) == 5:
        score -= 0.08
    elif 8 <= len(h) <= 13:
        score += 0.14
    elif len(h) >= 14:
        score += 0.24
        reasons.append("long_compound_handle")

    # Separator & multi-segment contribution
    parts = [p for p in re.split(r"[._-]+", h) if p]
    if has_sep and len(parts) >= 2:
        score += 0.16
        reasons.append("multi_token_separator")

    # Arabizi / alphanumeric structure
    if has_arabizi:
        score += 0.22
        reasons.append("distinctive_arabizi_pattern")
    elif digits and alpha_only:
        tot_d = sum(len(d) for d in digits)
        if tot_d >= 3:
            score += 0.12
            reasons.append("alphanumeric_with_digits")
        else:
            score += 0.05

    # Entropy check
    ent = _shannon_entropy(h)
    if ent >= 3.1:
        score += 0.10
    elif ent < 2.0:
        score -= 0.12
        reasons.append("low_character_entropy")

    # Dictionary / common first-name collision penalties
    if h in COMMON_GIVEN_NAMES or h in GENERIC_ROLE_AND_DICT_HANDLES:
        score -= 0.38
        reasons.append("exact_common_name_or_generic_word")
    elif alpha_only in COMMON_GIVEN_NAMES and not has_sep and sum(len(d) for d in digits) <= 2:
        # e.g. "ahmed1", "alex99", "sarah2" -> still super collision-prone across platforms!
        score -= 0.26
        reasons.append("common_name_plus_short_suffix")
    elif alpha_only in GENERIC_ROLE_AND_DICT_HANDLES and not has_sep and sum(len(d) for d in digits) <= 2:
        score -= 0.26
        reasons.append("generic_word_plus_short_suffix")
    elif len(parts) == 2 and all(p in COMMON_GIVEN_NAMES or p in GENERIC_ROLE_AND_DICT_HANDLES for p in parts):
        # e.g. "dr_ahmed", "official_store", "ali_omar" -> moderate collision risk
        score -= 0.18
        reasons.append("compound_of_common_tokens")

    score = max(0.02, min(0.99, score))
    if score >= 0.68:
        tier = "high"
    elif score >= 0.52:
        tier = "medium"
    else:
        tier = "low_collision_prone"

    return {
        "handle": h,
        "uniqueness_score": round(score, 3),
        "tier": tier,
        "is_collision_prone": score < 0.52,
        "reasons": reasons or ["distinctive_identifier"],
    }


def _extract_profile_domains_and_tokens(prof: dict[str, Any]) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    tokens: set[str] = set()

    urls: list[str] = []
    if prof.get("website"):
        urls.append(str(prof["website"]))
    for lk in prof.get("external_links") or []:
        if isinstance(lk, dict) and lk.get("url"):
            urls.append(str(lk["url"]))
        elif isinstance(lk, str):
            urls.append(lk)
    for vp in (prof.get("verified_proofs") or []) + (prof.get("verified_accounts") or []):
        if isinstance(vp, dict) and vp.get("url"):
            urls.append(str(vp["url"]))

    for u in urls:
        if u.startswith(("http://", "https://")):
            try:
                host = (urllib.parse.urlparse(u).hostname or "").lower().removeprefix("www.")
                if host and host not in {
                    "instagram.com", "x.com", "twitter.com", "tiktok.com", "snapchat.com",
                    "youtube.com", "youtu.be", "t.me", "linktr.ee", "facebook.com",
                    "linkedin.com", "github.com", "gitlab.com", "reddit.com",
                }:
                    domains.add(host)
            except ValueError:
                pass

    text_blob = " ".join(
        str(prof.get(k) or "")
        for k in ("display_name", "bio", "stats_and_bio_preview", "company", "location", "region", "website")
    )
    # Also extract bare domains mentioned directly in bio/company/website text (e.g. "engineer at acme-cyber.sa")
    for bare_d in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,18}\b", text_blob):
        bd = bare_d.lower().removeprefix("www.")
        if bd not in {
            "instagram.com", "x.com", "twitter.com", "tiktok.com", "snapchat.com",
            "youtube.com", "youtu.be", "t.me", "linktr.ee", "facebook.com",
            "linkedin.com", "github.com", "gitlab.com", "reddit.com", "gmail.com",
            "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
        }:
            domains.add(bd)

    # Extract meaningful Latin & Arabic tokens (>= 4 chars)
    for tok in re.findall(r"[A-Za-z]{4,}|[\u0600-\u06FF]{3,}", text_blob):
        tl = tok.lower()
        if tl not in STOP_BIO_WORDS and tl not in COMMON_GIVEN_NAMES and tl not in GENERIC_ROLE_AND_DICT_HANDLES:
            tokens.add(tl)

    return domains, tokens


def build_anchor_context_from_nodes(
    seeds_or_nodes: list[dict[str, Any]],
    *,
    handle: str = "",
) -> dict[str, set[str]]:
    """Build anchor tokens, domains, emails, phones, and names from current case seeds/nodes."""
    domains: set[str] = set()
    emails: set[str] = set()
    phones_last8: set[str] = set()
    name_tokens: set[str] = set()

    h_low = handle.strip().lstrip("@").lower()
    for n in seeds_or_nodes:
        nt = n.get("type", "")
        nv = str(n.get("value") or "").strip()
        if not nv:
            continue
        if nt == "domain":
            domains.add(nv.lower().removeprefix("www."))
            stem = nv.lower().removeprefix("www.").split(".", 1)[0]
            if len(stem) >= 4 and stem != h_low:
                name_tokens.add(stem)
        elif nt == "email":
            emails.add(nv.lower())
            loc, _, dom = nv.lower().partition("@")
            if dom:
                domains.add(dom)
        elif nt == "phone":
            digs = re.sub(r"\D", "", nv)
            if len(digs) >= 8:
                phones_last8.add(digs[-8:])
        elif nt in ("person_name", "company"):
            for tok in re.findall(r"[A-Za-z]{3,}|[\u0600-\u06FF]{2,}", nv):
                tl = tok.lower()
                if tl not in STOP_BIO_WORDS and tl != h_low:
                    name_tokens.add(tl)

    return {
        "domains": domains,
        "emails": emails,
        "phones_last8": phones_last8,
        "name_tokens": name_tokens,
    }


def corroborate_social_profiles(
    handle: str,
    profiles: list[dict[str, Any]],
    *,
    anchor_context: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    """Classify social hits into `corroborated` vs `possible_namesake` to prevent false-positive pivots."""
    uniq = score_handle_uniqueness(handle)
    is_prone = uniq["is_collision_prone"]
    ctx = anchor_context or {"domains": set(), "emails": set(), "phones_last8": set(), "name_tokens": set()}

    # Compute cross-profile consensus across all discovered profiles for this handle
    prof_domains: list[set[str]] = []
    prof_tokens: list[set[str]] = []
    all_dom_counts: Counter[str] = Counter()
    all_tok_counts: Counter[str] = Counter()
    all_disp_counts: Counter[str] = Counter()

    for p in profiles:
        doms, toks = _extract_profile_domains_and_tokens(p)
        prof_domains.append(doms)
        prof_tokens.append(toks)
        for d in doms:
            all_dom_counts[d] += 1
        for t in toks:
            all_tok_counts[t] += 1
        dn = re.sub(r"\s+", " ", str(p.get("display_name") or "").strip().lower())
        if len(dn) >= 5 and " " in dn and dn != handle.lower():
            all_disp_counts[dn] += 1

    consensus_domains = {d for d, c in all_dom_counts.items() if c >= 2}
    consensus_tokens = {t for t, c in all_tok_counts.items() if c >= 2}
    consensus_disp = {d for d, c in all_disp_counts.items() if c >= 2}

    corroborated: list[dict[str, Any]] = []
    namesakes: list[dict[str, Any]] = []

    for idx, p in enumerate(profiles):
        doms = prof_domains[idx]
        toks = prof_tokens[idx]
        reasons: list[str] = []
        c_score = uniq["uniqueness_score"]

        # Check anchor matches (seed domains, phones, emails, rare name/company tokens)
        matched_anchor_doms = doms & ctx.get("domains", set())
        if matched_anchor_doms:
            c_score = max(c_score, 0.25) + 0.50
            reasons.append(f"shared_domain:{next(iter(matched_anchor_doms))}")

        blob_raw = " ".join(
            str(p.get(k) or "")
            for k in ("display_name", "bio", "stats_and_bio_preview", "public_email", "website", "location")
        ) + " " + " ".join(str(x) for x in (p.get("phones") or []) + (p.get("emails") or []))
        blob_low = blob_raw.lower()
        blob_digits = re.sub(r"\D", "", blob_raw)

        for em in ctx.get("emails", set()):
            if em and em in blob_low:
                c_score = max(c_score, 0.25) + 0.55
                reasons.append(f"shared_email:{em}")
                break

        for ph8 in ctx.get("phones_last8", set()):
            if ph8 and ph8 in blob_digits:
                c_score = max(c_score, 0.25) + 0.55
                reasons.append("shared_phone")
                break

        matched_name_toks = toks & ctx.get("name_tokens", set())
        if matched_name_toks:
            c_score = max(c_score, 0.20) + min(0.45, 0.25 * len(matched_name_toks))
            reasons.append(f"matched_anchor_terms:{','.join(sorted(matched_name_toks)[:3])}")

        # Cross-profile consensus matches
        shared_c_doms = doms & consensus_domains
        if shared_c_doms:
            c_score = max(c_score, 0.25) + 0.45
            reasons.append(f"cross_platform_domain:{next(iter(shared_c_doms))}")

        dn_norm = re.sub(r"\s+", " ", str(p.get("display_name") or "").strip().lower())
        if dn_norm in consensus_disp:
            c_score += 0.35
            reasons.append(f"cross_platform_full_name:{dn_norm}")

        shared_c_toks = toks & consensus_tokens
        if len(shared_c_toks) >= 2:
            c_score += 0.30
            reasons.append(f"cross_platform_bio_terms:{','.join(sorted(shared_c_toks)[:3])}")
        elif len(shared_c_toks) == 1 and not is_prone:
            c_score += 0.15

        # Cryptographic identity proofs (Keybase / Gravatar verified_accounts)
        if p.get("verified_proofs") or p.get("verified_accounts"):
            c_score += 0.18
            reasons.append("verified_linked_proof")

        c_score = round(min(0.99, c_score), 3)
        enriched = dict(p)
        enriched["attribution_confidence"] = c_score
        enriched["corroboration_reasons"] = reasons

        # Decision rule:
        # - Distinctive handle: corroborated unless score < 0.50
        # - Collision-prone handle (@ahmed, @alex, @clinic): MUST have at least one real corroborating signal (c_score >= 0.54 and reasons non-empty)
        if not is_prone:
            enriched["corroborated"] = True
            corroborated.append(enriched)
        else:
            if c_score >= 0.54 and reasons:
                enriched["corroborated"] = True
                corroborated.append(enriched)
            else:
                enriched["corroborated"] = False
                namesakes.append(enriched)

    return {
        "handle_uniqueness": uniq,
        "corroborated_profiles": corroborated,
        "possible_namesake_profiles": namesakes,
        "collision_guard_triggered": bool(is_prone and namesakes),
    }

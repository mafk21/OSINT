"""Exhaustive Post-Stage Intelligence Analyzer, Unstructured Lead Carver & Multi-Stage Dork Engine.

Implements the core iterative OSINT surface-expansion loop:
  Stage N (Exhaustive Collect) -> Analyze ALL Findings & Carve EVERY New Clue -> Stage N+1 (Hunt ALL New Clues) -> Converge.
"""

from __future__ import annotations

import re
from typing import Any

from .classify import DOMAIN_RE, NOISE_DOMAINS, extract_selectors, generate_handle_variants

# Selector execution priority (lower = higher priority when ordering within a stage,
# though ALL valid leads in a stage are hunted — never stopped after finding 1 clue!)
HUNTABLE_PRIORITY: dict[str, int] = {
    "email": 0,
    "phone": 1,
    "domain": 2,
    "username": 3,
    "url": 4,
    "onion_url": 5,
    "ip": 6,
    "person_name": 7,
    "company": 8,
    "repo_code": 9,
    "crypto_address": 10,
    "asn": 11,
    "coordinates": 12,
    "aircraft_hex": 13,
    "vessel_imo": 14,
    "vin": 15,
    "mac_bssid": 16,
    "file_hash": 17,
}

INFRA_NOISE_EXACT_DOMAINS = NOISE_DOMAINS | {
    "cloudflare.com", "cloudflare-dns.com", "one.one.one.one",
    "letsencrypt.org", "lencr.org", "digicert.com", "sectigo.com", "usertrust.com",
    "verisign.com", "globalsign.com", "entrust.net", "identrust.com", "pki.goog",
    "godaddy.com", "domaincontrol.com", "registrar-servers.com", "namecheap.com",
    "markmonitor.com", "cscdbs.com", "networksolutions.com", "tucows.com", "gandi.net",
    "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com",
    "doubleclick.net", "facebook.net", "fbcdn.net", "cdninstagram.com", "tiktokcdn.com",
    "twimg.com", "t.co", "youtu.be", "ytimg.com",
    "githubassets.com", "githubusercontent.com", "github.io",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "cloudflareinsights.com",
    "fastly.net", "akamai.net", "akamaiedge.net", "akam.net", "cloudfront.net",
    "amazonaws.com", "azurewebsites.net", "windows.net", "trafficmanager.net",
    "iana.org", "icann.org", "arin.net", "ripe.net", "apnic.net", "lacnic.net", "afrinic.net",
    "rdap.org", "crt.sh", "archive.org", "waybackmachine.org", "shodan.io", "censys.io",
    "circl.lu", "gleif.org", "gravatar.com", "wp.com", "wordpress.org", "shields.io",
    # Major social, messaging, bio-link & directory platforms (keep profile URLs/handles, never pivot onto platform infra!)
    "instagram.com", "tiktok.com", "snapchat.com", "x.com", "twitter.com", "linkedin.com",
    "facebook.com", "threads.net", "threads.com", "youtube.com", "t.me", "telegram.org",
    "telegram.me", "wa.me", "whatsapp.com", "linktr.ee", "taplink.cc", "beacons.ai",
    "bio.link", "solo.to", "carrd.co", "bento.me", "pinterest.com", "soundcloud.com",
    "medium.com", "substack.com", "patreon.com", "behance.net", "dribbble.com", "vimeo.com",
    "twitch.tv", "reddit.com", "quora.com", "discord.gg", "discord.com", "bsky.app",
    "mastodon.social", "keybase.io", "gitlab.com", "github.com", "huggingface.co",
    "truecaller.com", "sync.me", "crunchbase.com", "zoominfo.com", "rocketreach.co",
    "apollo.io", "yelp.com", "trustpilot.com", "haraj.com.sa", "opensooq.com", "maroof.sa",
    "vezeeta.com", "altibbi.com", "practo.com", "researchgate.net", "academia.edu",
    "orcid.org", "openalex.org", "wikipedia.org", "wikidata.org", "ncbi.nlm.nih.gov",
}

INFRA_NOISE_DOMAIN_SUFFIXES = (
    ".ns.cloudflare.com",
    ".domaincontrol.com",
    ".registrar-servers.com",
    ".awsdns-00.org",
    ".googledomains.com",
    ".gtld-servers.net",
    ".root-servers.net",
    ".in-addr.arpa",
    ".ip6.arpa",
)

GENERIC_NAME_STOP = {
    "not found", "unknown", "none", "null", "n/a", "redacted", "redacted for privacy",
    "data protected", "privacy service", "whois privacy", "domains by proxy",
    "contact privacy", "domain admin", "domain administrator", "hostmaster",
    "postmaster", "webmaster", "administrator", "admin", "support", "info",
    "github", "gitlab", "instagram", "tiktok", "twitter", "cloudflare",
}

NOISE_EMAIL_PREFIXES = (
    "abuse@", "domainabuse@", "registrar@", "whoisprivacy@", "privacy@",
    "dataprotection@", "noreply@", "no-reply@", "donotreply@", "hostmaster@cloudflare",
    "dns@cloudflare", "noc@",
)

LABELED_ENTITY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"(?:^|[\n|•·;])\s*(?:full\s+name|real\s+name|doctor\s+name|owner\s+name|founder|person)\s*[:=-]\s*([^\n|•·;]{3,60})",
            re.IGNORECASE,
        ),
        "person_name",
        "Labeled person name in evidence",
    ),
    (
        re.compile(
            r"(?:^|[\n|•·;])\s*(?:company|clinic|hospital|medical\s+center|organization|employer|brand|business)\s*[:=-]\s*([^\n|•·;]{3,70})",
            re.IGNORECASE,
        ),
        "company",
        "Labeled organization/clinic in evidence",
    ),
]


def is_infra_noise(sel_type: str, value: str) -> bool:
    """Return True if selector is generic third-party CDN/CA/registrar noise rather than target surface."""
    v = (value or "").strip().lower()
    if not v:
        return True

    if sel_type == "domain":
        v = v.rstrip(".").removeprefix("*.")
        if v in INFRA_NOISE_EXACT_DOMAINS:
            return True
        if any(v.endswith(sfx) for sfx in INFRA_NOISE_DOMAIN_SUFFIXES):
            return True
        if ".awsdns-" in v:
            return True
        if not DOMAIN_RE.fullmatch(v):
            return True
        return False

    if sel_type == "email":
        if any(v.startswith(pfx) for pfx in NOISE_EMAIL_PREFIXES):
            return True
        if "@" in v:
            dom = v.split("@", 1)[1]
            if dom in {"users.noreply.github.com", "cloudflare.com", "godaddy.com", "namecheap.com", "markmonitor.com"}:
                return True
        return False

    if sel_type == "url":
        for d in ("web.archive.org", "crt.sh", "rdap.org", "api.github.com", "registry.npmjs.org", "pypi.org/pypi", "gleif.org", "hashlookup.circl.lu"):
            if d in v:
                return True
        return False

    if sel_type in ("person_name", "company"):
        cleaned = re.sub(r"\s+", " ", v).strip(" .,;:-_|\"'()")
        if len(cleaned) < 3 or len(cleaned) > 75 or cleaned in GENERIC_NAME_STOP:
            return True
        if "privacy" in cleaned or "redacted" in cleaned or "whois" in cleaned:
            return True
        return False

    if sel_type == "username":
        if len(v) < 2 or len(v) > 39 or v in GENERIC_NAME_STOP:
            return True
        if " " in v or "/" in v:
            return True
        return False

    if sel_type == "ip":
        if v.startswith(("127.", "0.", "169.254.", "255.")):
            return True
        return False

    return False


def _clean_human_label(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    s = re.sub(r"\s+", " ", raw).strip(" \t\r\n.,;:|•·\"'()")
    return s


def _carve_from_collector_data(
    src_type: str,
    src_val: str,
    module_name: str,
    data: Any,
    emit_cb,
) -> None:
    """Inspect structured collector `data` dictionaries to carve every hidden lead."""
    if not isinstance(data, dict):
        return

    # 1. Profile / Registry Human Names
    for k in ("name", "display_name", "full_name", "author_name", "registrant_name"):
        val = _clean_human_label(data.get(k))
        if val and val.lower() != src_val.lower() and 2 <= len(val.split()) <= 5:
            if not any(ch.isdigit() for ch in val) and "@" not in val and "." not in val.replace("Dr.", "").replace("Prof.", ""):
                emit_cb("person_name", val, f"{module_name}:{k}")

    # 2. Company / Clinic / Organization fields
    for k in ("company", "organization", "org", "employer"):
        val = _clean_human_label(data.get(k))
        if not val:
            continue
        if val.startswith("@") and " " not in val and len(val) > 2:
            emit_cb("username", val.lstrip("@"), f"{module_name}:{k}")
        elif val.lower() != src_val.lower():
            emit_cb("company", val.lstrip("@").strip(), f"{module_name}:{k}")

    # 3. Website / Blog / Homepage / Bio URL fields
    for k in ("blog", "website", "homepage", "external_url", "bio_url"):
        val = _clean_human_label(data.get(k))
        if not val:
            continue
        if not val.startswith(("http://", "https://")) and DOMAIN_RE.fullmatch(val.lower().removeprefix("www.")):
            emit_cb("domain", val.lower().removeprefix("www."), f"{module_name}:{k}")
        else:
            for s in extract_selectors(val):
                emit_cb(s["type"], s["value"], f"{module_name}:{k}")

    # 4. Rich text fields (bios, descriptions, TXT/SPF/DMARC, security.txt, commit authors, OpenGraph)
    text_blobs: list[str] = []
    for k in ("bio", "description", "summary", "about", "notes", "security_txt", "humans_txt", "header_value"):
        v = data.get(k)
        if isinstance(v, str) and len(v) >= 4:
            text_blobs.append(v)
    for k in ("TXT", "MX", "emails", "commit_emails", "pgp_uids", "same_as_links", "mailto_contacts", "tel_contacts", "csp_hosts"):
        arr = data.get(k)
        if isinstance(arr, list):
            for entry in arr[:30]:
                if isinstance(entry, str) and entry:
                    text_blobs.append(entry)

    if text_blobs:
        combined = "\n".join(text_blobs)
        for s in extract_selectors(combined):
            emit_cb(s["type"], s["value"], f"{module_name}:deep_carve")


def analyze_stage_and_extract_leads(
    *,
    stage_num: int,
    stage_items: list[dict],
    visited: set[str],
    ingested_evidence: list[dict] | None = None,
    expand_handle_variants: bool = True,
) -> dict:
    """Analyze ALL outputs from Stage `stage_num` + any ingested text, returning EVERY new lead for Stage `stage_num + 1`."""
    discovered_map: dict[str, dict] = {}
    all_edges: list[dict] = []
    filtered_noise_count = 0
    handle_variants_added: list[str] = []

    def _register_lead(src_id: str, sel_type: str, raw_val: str, via: str) -> None:
        nonlocal filtered_noise_count
        val = str(raw_val or "").strip()
        if not val or sel_type not in HUNTABLE_PRIORITY:
            return
        if sel_type in ("domain", "email", "onion_url"):
            val = val.lower().removeprefix("www.") if sel_type == "domain" else val.lower()

        if is_infra_noise(sel_type, val):
            filtered_noise_count += 1
            return

        dst_id = f"{sel_type}:{val.lower()}"
        if dst_id != src_id:
            all_edges.append({"source": src_id, "target": dst_id, "via": via, "stage": stage_num})

        if dst_id in visited:
            return

        if dst_id not in discovered_map:
            discovered_map[dst_id] = {
                "id": dst_id,
                "type": sel_type,
                "value": val,
                "priority": HUNTABLE_PRIORITY.get(sel_type, 50),
                "source_id": src_id,
                "via": via,
                "discovered_in_stage": stage_num,
            }

    # A. Analyze every single collector output across every entity hunted in this stage
    for item in stage_items:
        stype = item["type"]
        sval = item["value"]
        src_id = f"{stype}:{sval.lower()}"

        # Deterministic handle mutation on Stage 1 usernames (or newly found dotted/underscored social handles)
        if expand_handle_variants and stype == "username" and stage_num == 1:
            for var in generate_handle_variants(sval, max_variants=4):
                before = len(discovered_map)
                _register_lead(src_id, "username", var, "stage_analyzer:handle_variant")
                if len(discovered_map) > before:
                    handle_variants_added.append(var)

        for mod_res in item.get("collector_outputs") or []:
            mod_name = mod_res.get("module", "collector")
            # 1. Explicit collector pivots (ALL of them — never stop at 1!)
            for piv in mod_res.get("pivots") or []:
                if isinstance(piv, dict) and piv.get("type") and piv.get("value"):
                    _register_lead(src_id, piv["type"], str(piv["value"]), mod_name)

            # 2. Deep structured & unstructured carving inside `mod_res["data"]`
            if mod_res.get("status") == "ok" and mod_res.get("data"):
                _carve_from_collector_data(
                    stype,
                    sval,
                    mod_name,
                    mod_res["data"],
                    lambda t, v, via, _sid=src_id: _register_lead(_sid, t, v, via),
                )

    # B. Carve any external unstructured evidence ingested in this stage (e.g. web_search / fetch_page / bio text)
    for ev in ingested_evidence or []:
        ev_src = ev.get("source_id") or f"evidence:stage_{stage_num}"
        ev_label = ev.get("label") or "ingested_evidence"
        raw_txt = ev.get("text") or ""
        if not raw_txt.strip():
            continue

        # Standard multi-entity extractor across full text + line-by-line
        for sel in extract_selectors(raw_txt):
            _register_lead(ev_src, sel["type"], sel["value"], f"{ev_label}:carver")
            if expand_handle_variants and sel["type"] == "username":
                for var in generate_handle_variants(sel["value"], max_variants=3):
                    _register_lead(f"username:{sel['value'].lower()}", "username", var, f"{ev_label}:handle_variant")

        # Labeled human/company lines (e.g. "Full Name: Dr. Ahmed ...", "Clinic: ...")
        for rx, ent_type, _note in LABELED_ENTITY_PATTERNS:
            for match_val in rx.findall(raw_txt):
                cleaned_ent = _clean_human_label(match_val)
                if cleaned_ent:
                    _register_lead(ev_src, ent_type, cleaned_ent, f"{ev_label}:labeled_{ent_type}")

    ordered_leads = sorted(discovered_map.values(), key=lambda d: (d["priority"], d["id"]))
    by_type_counts: dict[str, int] = {}
    for ld in ordered_leads:
        by_type_counts[ld["type"]] = by_type_counts.get(ld["type"], 0) + 1

    return {
        "stage_analyzed": stage_num,
        "entities_analyzed_in_stage": len(stage_items),
        "ingested_evidence_blocks": len(ingested_evidence or []),
        "new_leads_count": len(ordered_leads),
        "new_leads_by_type": by_type_counts,
        "handle_variants_generated": handle_variants_added,
        "filtered_infra_noise_count": filtered_noise_count,
        "leads": ordered_leads,
        "edges": all_edges,
    }


def forge_exhaustive_dorks_for_entities(
    entities: list[tuple[str, str]],
    catalog_dorks: list[dict],
    max_total: int = 60,
) -> list[dict]:
    """Generate exhaustive multi-platform passive search dorks for EVERY discovered selector."""
    forged: list[dict] = []
    seen_queries: set[str] = set()

    def _emit(engine: str, category: str, target_type: str, target_val: str, title: str, query: str, purpose: str) -> None:
        if len(forged) >= max_total or query in seen_queries:
            return
        seen_queries.add(query)
        forged.append(
            {
                "engine": engine,
                "category": category,
                "selector_type": target_type,
                "target": target_val,
                "title": title,
                "query": query,
                "purpose": purpose,
            }
        )

    for stype, sval in entities:
        if len(forged) >= max_total:
            break

        if stype == "username":
            _emit(
                "Google", "SOCMINT", stype, sval,
                f"Instagram Profile, Reels & Mentions ({sval})",
                f'site:instagram.com "{sval}"',
                "Surface indexed Instagram profile bio, reels, posts, and third-party caption mentions.",
            )
            _emit(
                "Google", "SOCMINT", stype, sval,
                f"Cross-Platform Social Footprint ({sval})",
                f'"{sval}" (site:tiktok.com OR site:snapchat.com OR site:x.com OR site:threads.net OR site:t.me OR site:youtube.com OR site:linkedin.com)',
                "Identify cross-platform accounts reusing the exact handle.",
            )
            _emit(
                "Google", "SOCMINT", stype, sval,
                f"Link-in-Bio & Contact Links ({sval})",
                f'"{sval}" (site:linktr.ee OR site:beacons.ai OR site:bio.link OR site:taplink.cc OR "wa.me" OR "whatsapp")',
                "Uncover Linktree/bio-link hubs and WhatsApp business numbers tied to the handle.",
            )
            _emit(
                "Google", "Contact & Directory Pivot", stype, sval,
                f"External Web, Clinic/Business & Email Mentions ({sval})",
                f'"{sval}" -site:instagram.com -site:tiktok.com',
                "Find external websites, directories, articles, bookings, or leaked contact info mentioning the handle.",
            )

        elif stype == "phone":
            digits = re.sub(r"\D", "", sval)
            _emit(
                "Google", "PHONEINT", stype, sval,
                f"Phone & WhatsApp Link Footprint ({sval})",
                f'"{sval}" OR "{digits}" OR "wa.me/{digits}"',
                "Locate public WhatsApp links, social bios, classifieds, and business pages listing this phone number.",
            )
            _emit(
                "Google", "PHONEINT", stype, sval,
                f"Social & Directory Phone Mentions ({sval})",
                f'("{sval}" OR "{digits}") (site:instagram.com OR site:facebook.com OR site:linkedin.com OR site:t.me)',
                "Correlate phone number against social media bios and Telegram channels.",
            )

        elif stype == "email":
            _emit(
                "Google", "EMAILINT", stype, sval,
                f"Public Web, Code & Document Exposure ({sval})",
                f'"{sval}" (site:github.com OR site:gitlab.com OR site:pastebin.com OR filetype:pdf OR filetype:xlsx OR filetype:csv)',
                "Check public repositories, pastes, and indexed office/PDF documents for this email.",
            )
            _emit(
                "Google", "EMAILINT", stype, sval,
                f"Identity & Social Bio Attribution ({sval})",
                f'"{sval}"',
                "Find websites, WHOIS archives, staff pages, and social bios publishing this email.",
            )

        elif stype in ("person_name", "company"):
            _emit(
                "Google", "HUMINT / FININT", stype, sval,
                f"Social & Professional Profiles ({sval})",
                f'"{sval}" (site:linkedin.com OR site:instagram.com OR site:x.com OR site:facebook.com)',
                "Map professional and social accounts associated with this name/organization.",
            )
            _emit(
                "Google", "HUMINT / FININT", stype, sval,
                f"Official Records, Directories & PDFs ({sval})",
                f'"{sval}" (filetype:pdf OR "license" OR "clinic" OR "director" OR "founder" OR "contact")',
                "Surface official registries, staff listings, publications, and PDF documents.",
            )

        elif stype == "domain":
            _emit(
                "Google", "DNSINT", stype, sval,
                f"Indexed Subdomains ({sval})",
                f"site:*.{sval} -site:www.{sval}",
                "Enumerate search-indexed subdomains without sending packets to the target.",
            )
            _emit(
                "Google", "ARCHINT", stype, sval,
                f"Exposed Documents & Metadata ({sval})",
                f"site:{sval} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)",
                "Locate public documents on the domain for author/EXIF metadata extraction.",
            )
            _emit(
                "Shodan", "NETINT", stype, sval,
                f"Shodan SSL Certificate & Hostname Pivot ({sval})",
                f'ssl.cert.subject.cn:"{sval}" OR hostname:"{sval}"',
                "Passively enumerate exposed services and origin IPs holding TLS certs for the domain.",
            )

        # Also pull matching specialized catalog dorks for primary domains/companies
        if stype in ("domain", "company"):
            for d in catalog_dorks:
                q = d["query"]
                replaced = (
                    q.replace("example.com", sval if stype == "domain" else q)
                    .replace("Target Corp", sval)
                    .replace("Target Company", sval)
                    .replace("target-company", sval)
                    .replace("target_company", sval)
                    .replace("target_org", sval)
                )
                if replaced != q and "example.com" not in replaced:
                    _emit(d["engine"], d["category"], stype, sval, f"{d['title']} ({sval})", replaced, d["purpose"])

    return forged

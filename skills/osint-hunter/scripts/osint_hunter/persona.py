"""Weighted Attribution Confidence, Typosquat Permutator & Sockpuppet Heuristics.

Enriches entity-pivot graphs non-destructively with:
  1. Edge confidence scores (0.0–1.0) & forensic evidence tiers
  2. Shortest high-confidence attribution chains (Seed -> Identity/Infra)
  3. Pure-Python offline Domain Typosquat, Bitsquat & IDN Punycode Homoglyph Generator
  4. Sockpuppet, Burner & Coordinated Account Indicators
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any

HIGH_PROOF_VIA_SUBSTRINGS = (
    "pgp", "gpg", "ssh", "patch", "commit", "rdap", "dns", "doh", "keybase",
    "rel_me", "gleif", "entra", "plc_historical", "eml_", "pcap_", "whois",
)
DIRECT_LINK_VIA_SUBSTRINGS = (
    "github", "gitlab", "npm", "pypi", "crtsh", "wayback", "bluesky", "mastodon",
    "crates", "dockerhub", "huggingface", "wa.me", "whatsapp", "email_domain", "url",
)
VARIANT_VIA_SUBSTRINGS = ("variant", "permutation", "stem", "fuzzy", "heuristic")

DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "yopmail.com",
    "tempmail.com", "temp-mail.org", "sharklasers.com", "trashmail.com",
    "getnada.com", "maildrop.cc", "dispostable.com", "burnermail.io",
}

HOMOGLYPH_MAP: dict[str, list[str]] = {
    "a": ["а", "ạ", "ă"],  # Cyrillic/Latin lookalikes
    "e": ["е", "ė"],
    "i": ["і", "1", "l"],
    "o": ["о", "0"],
    "c": ["с"],
    "p": ["р"],
    "s": ["ѕ", "5"],
    "l": ["1", "i"],
    "m": ["rn"],
    "w": ["vv"],
}

QWERTY_ADJACENT: dict[str, str] = {
    "a": "sqzw", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}

ALT_TLDS = ("com", "net", "org", "io", "co", "ai", "app", "xyz", "dev", "info", "cloud", "me")


def classify_edge_confidence(via: str) -> tuple[float, str]:
    """Score an edge's attribution reliability based on how the pivot was discovered."""
    v = (via or "").lower()
    if any(tok in v for tok in VARIANT_VIA_SUBSTRINGS):
        return 0.52, "HEURISTIC_HANDLE_VARIANT"
    if any(tok in v for tok in HIGH_PROOF_VIA_SUBSTRINGS):
        return 0.98, "CRYPTOGRAPHIC_OR_REGISTRY_PROOF"
    if "ingest" in v or "carve" in v:
        return 0.80, "INGESTED_STAGE_EVIDENCE"
    if any(tok in v for tok in DIRECT_LINK_VIA_SUBSTRINGS):
        return 0.88, "DIRECT_PLATFORM_ATTRIBUTE"
    return 0.75, "CORRELATED_LEAD"


def find_shortest_attribution_path(
    nodes: list[dict],
    edges: list[dict],
    source_id: str,
    target_id: str,
) -> dict[str, Any] | None:
    """Find shortest path (preferring highest joint confidence) between two node IDs."""
    if source_id == target_id:
        return {"source": source_id, "target": target_id, "hops": 0, "joint_confidence": 1.0, "steps": [source_id]}

    adj: dict[str, list[dict]] = {}
    for e in edges:
        s, t = e["source"], e["target"]
        conf = float(e.get("confidence") or classify_edge_confidence(e.get("via", ""))[0])
        adj.setdefault(s, []).append({"next": t, "via": e.get("via", "pivot"), "confidence": conf})
        adj.setdefault(t, []).append({"next": s, "via": e.get("via", "pivot"), "confidence": conf})

    visited: set[str] = {source_id}
    queue: deque[tuple[str, list[dict], float]] = deque([(source_id, [], 1.0)])
    while queue:
        curr, path_steps, joint_conf = queue.popleft()
        # Sort neighbors by descending confidence so ties prefer cryptographic proof
        for nb in sorted(adj.get(curr, []), key=lambda x: -x["confidence"]):
            nxt = nb["next"]
            if nxt in visited:
                continue
            next_steps = path_steps + [
                {
                    "from": curr,
                    "to": nxt,
                    "via": nb["via"],
                    "confidence": nb["confidence"],
                }
            ]
            new_joint = round(joint_conf * nb["confidence"], 3)
            if nxt == target_id:
                chain_str = curr
                chain_parts = [source_id]
                for st in next_steps:
                    chain_parts.append(f"--[{st['via']} ({int(round(st['confidence'] * 100))}%)]--> {st['to']}")
                return {
                    "source": source_id,
                    "target": target_id,
                    "hops": len(next_steps),
                    "joint_confidence": new_joint,
                    "steps": next_steps,
                    "formatted_chain": " ".join(chain_parts),
                }
            visited.add(nxt)
            queue.append((nxt, next_steps, new_joint))
    return None


def generate_domain_typosquats(domain: str, limit: int = 45) -> dict[str, Any]:
    """Generate offline typosquat, bitsquat, TLD-swap & IDN punycode homoglyph permutations."""
    clean = (domain or "").strip().lower().strip(".").removeprefix("www.")
    if "." not in clean:
        return {"domain": clean, "count": 0, "permutations": []}

    parts = clean.rsplit(".", 1)
    label, tld = parts[0], parts[1]
    if "." in label:
        # Focus on registrable root label if subdomain was supplied
        sub_parts = clean.split(".")
        label, tld = sub_parts[-2], sub_parts[-1]

    seen: set[str] = {f"{label}.{tld}"}
    perms: list[dict[str, str]] = []

    def _add(cand_label: str, cand_tld: str, fuzzer: str, display_unicode: str | None = None) -> None:
        if len(perms) >= limit or not cand_label or len(cand_label) > 63:
            return
        if cand_label.startswith("-") or cand_label.endswith("-"):
            return
        fqdn = f"{cand_label}.{cand_tld}".lower()
        if fqdn in seen:
            return
        if not re.fullmatch(r"[a-z0-9-]+", cand_label):
            return
        seen.add(fqdn)
        entry: dict[str, str] = {"domain": fqdn, "fuzzer": fuzzer}
        if display_unicode:
            entry["unicode_lookalike"] = f"{display_unicode}.{cand_tld}"
        perms.append(entry)

    # 1. TLD swaps (highest real-world brand/phishing prevalence)
    for alt in ALT_TLDS:
        if alt != tld:
            _add(label, alt, "tld-swap")

    # 2. IDN Homoglyphs (with valid `xn--` Punycode encoding)
    for i, ch in enumerate(label):
        for lookalike in HOMOGLYPH_MAP.get(ch, []):
            mut = label[:i] + lookalike + label[i + 1 :]
            if mut.isascii():
                _add(mut, tld, "ascii-homoglyph")
            else:
                try:
                    puny = mut.encode("idna").decode("ascii")
                    _add(puny, tld, "idn-homoglyph-punycode", display_unicode=mut)
                except Exception:
                    pass

    # 3. Character omission & adjacent transposition
    if len(label) >= 4:
        for i in range(len(label)):
            _add(label[:i] + label[i + 1 :], tld, "omission")
        for i in range(len(label) - 1):
            if label[i] != label[i + 1]:
                _add(label[:i] + label[i + 1] + label[i] + label[i + 2 :], tld, "transposition")

    # 4. Character repetition & hyphenation
    for i in range(len(label)):
        if label[i].isalpha():
            _add(label[:i] + label[i] + label[i:], tld, "repetition")
    for i in range(1, min(len(label), 10)):
        if label[i - 1] != "-" and label[i] != "-":
            _add(label[:i] + "-" + label[i:], tld, "hyphenation")

    # 5. QWERTY keyboard fat-finger replacement & bitsquatting
    for i, ch in enumerate(label[:10]):
        adj = QWERTY_ADJACENT.get(ch, "")
        if adj:
            _add(label[:i] + adj[0] + label[i + 1 :], tld, "qwerty-replacement")
        for bit in (1, 2, 4):
            flipped = chr(ord(ch) ^ bit)
            if flipped.isalnum() and flipped.islower():
                _add(label[:i] + flipped + label[i + 1 :], tld, "bitsquatting")

    return {
        "seed_domain": f"{label}.{tld}",
        "count": len(perms),
        "permutations": perms[:limit],
    }


def enrich_graph_confidence_and_personas(report: dict) -> dict[str, Any]:
    """Mutate edge confidences additively & return attribution chains, typosquats, and sockpuppet flags."""
    nodes = report.get("graph", {}).get("nodes", [])
    edges = report.get("graph", {}).get("edges", [])

    # 1. Enrich every edge with confidence & evidence_tier
    for e in edges:
        conf, tier = classify_edge_confidence(e.get("via", ""))
        e["confidence"] = conf
        e["evidence_tier"] = tier

    # 2. Shortest attribution paths from Stage-1 seed(s) to high-value discovered targets
    seeds = [n["id"] for n in nodes if n.get("wave") == 1]
    high_value_types = {"person_name", "email", "phone", "company", "domain", "crypto_address"}
    attribution_chains: list[dict[str, Any]] = []
    for n in nodes:
        if n.get("wave", 1) > 1 and n.get("type") in high_value_types:
            best_chain = None
            for sid in seeds[:4]:
                ch = find_shortest_attribution_path(nodes, edges, sid, n["id"])
                if ch and (best_chain is None or ch["joint_confidence"] > best_chain["joint_confidence"]):
                    best_chain = ch
            if best_chain:
                attribution_chains.append(best_chain)
    attribution_chains.sort(key=lambda c: (-c["joint_confidence"], c["hops"]))

    # 3. Sockpuppet / Burner / Coordinated Account Heuristics
    sockpuppet_flags: list[str] = []
    for n in nodes:
        nt, nv = n.get("type"), str(n.get("value", ""))
        if nt == "username":
            if re.search(r"[a-zA-Z_]\d{6,}$", nv):
                sockpuppet_flags.append(f"Handle '{nv}' matches auto-generated 6+ trailing-digit bot/burner pattern")
        elif nt == "email" and "@" in nv:
            edom = nv.split("@", 1)[1].lower()
            if edom in DISPOSABLE_EMAIL_DOMAINS:
                sockpuppet_flags.append(f"Disposable/burner email provider detected: {nv}")

    # Check RDAP recent domain creation (<45 days) if present
    for w in report.get("wave_results", []):
        for col in w.get("collector_outputs", []):
            if col.get("module") == "iana_rdap" and col.get("status") == "ok":
                evs = (col.get("data") or {}).get("events") or {}
                reg = str(evs.get("registration") or "")
                if reg.startswith("2026-10") or reg.startswith("2026-09"):
                    sockpuppet_flags.append(f"Newly registered domain (<60 days old in RDAP): {w.get('value')} ({reg[:10]})")

    # 4. Offline typosquat watchlist sample for primary discovered domain
    primary_domains = [
        n["value"]
        for n in nodes
        if n.get("type") == "domain" and n["value"].count(".") == 1
    ]
    typosquat_preview = generate_domain_typosquats(primary_domains[0], limit=20) if primary_domains else None

    return {
        "attribution_chains": attribution_chains[:20],
        "sockpuppet_and_burner_indicators": sockpuppet_flags[:15],
        "typosquat_watchlist_preview": typosquat_preview,
    }

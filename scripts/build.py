#!/usr/bin/env python3
"""Master build pipeline for the OSINT Monster Database.

Generates from `data/*.json`:
  - `data/tools.csv`, `data/tools.jsonl`, `data/osint.sqlite` (with FTS5 full-text search)
  - `categories/01-*.md` .. `categories/20-*.md`
  - `docs/PIVOT_MATRIX.md`, `docs/WORKFLOWS.md`, `docs/DORKS_ARSENAL.md`, `docs/GRAVEYARD_2026.md`
  - `web/data.js`
  - `README.md`
"""

from __future__ import annotations

import csv
import json
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CAT_DIR = ROOT / "categories"
DOCS_DIR = ROOT / "docs"
WEB_DIR = ROOT / "web"

SELECTOR_LABELS = {
    "username": ("Username / Handle", "`@johndoe`, gaming alias"),
    "email": ("Email Address", "`user@company.com`"),
    "phone": ("Phone Number", "E.164 `+14155552671`"),
    "person_name": ("Person Full Name", "Individual, executive, official"),
    "domain": ("Domain / Hostname", "`example.com`"),
    "ip": ("IPv4 / IPv6 Address", "`198.51.100.42`"),
    "asn": ("ASN / CIDR Netblock", "`AS13335`, `198.51.100.0/24`"),
    "url": ("Web URL / Post Link", "Webpage, social post, phishing URL"),
    "image": ("Image / Photograph", "JPEG/PNG, face crop, scenery"),
    "video": ("Video Clip", "MP4, livestream, social upload"),
    "audio": ("Audio Recording", "Voice clip, background birds/hum"),
    "coordinates": ("GPS Coordinates / AOI", "`lat, lon` bounding box"),
    "company": ("Company / Organization", "Corporate name, LEI, CAGE"),
    "crypto_address": ("Crypto Wallet / Tx", "`0x...`, `bc1...`, `.eth`, `T...`"),
    "file_hash": ("File / Cert / DOM Hash", "SHA-256, MD5, JARM, mmh3"),
    "keyword": ("Keyword / Phrase", "Project slug, quote, topic"),
    "vessel_imo": ("Vessel IMO / MMSI", "7-digit IMO or 9-digit MMSI"),
    "aircraft_hex": ("Aircraft ICAO Hex / Tail", "Mode-S `AE01D5`, `N123AB`"),
    "vin": ("Vehicle 17-Char VIN", "Automotive chassis number"),
    "mac_bssid": ("Wi-Fi BSSID / BLE MAC", "`00:11:22:33:44:55`"),
    "repo_code": ("Git Repo / Package", "GitHub org/repo, npm/PyPI pkg"),
    "onion_url": ("Tor `.onion` Address", "v3 hidden service URL"),
    "document": ("Document File", "PDF, DOCX, XLSX, PGP key"),
    "rf_frequency": ("RF Frequency (kHz/MHz)", "`8992 kHz` HFGCS, `433.92 MHz`"),
}

PRIMARY_DISCIPLINE_FOR_SELECTOR = {
    "username": "username-enumeration",
    "email": "email-intelligence",
    "phone": "phone-messaging-osint",
    "person_name": "people-public-records",
    "domain": "domain-dns-asm",
    "ip": "network-ip-iot-search",
    "asn": "network-ip-iot-search",
    "url": "archiving-evidence-docs",
    "image": "image-video-media-forensics",
    "video": "image-video-media-forensics",
    "audio": "image-video-media-forensics",
    "coordinates": "geoint-maps-satellites",
    "company": "corporate-financial-sanctions",
    "crypto_address": "crypto-blockchain-web3",
    "file_hash": "threat-intel-malware-cti",
    "vessel_imo": "aviation-maritime-transport",
    "aircraft_hex": "aviation-maritime-transport",
    "vin": "aviation-maritime-transport",
    "mac_bssid": "sigint-wireless-space-rf",
    "repo_code": "code-cloud-dev-osint",
    "onion_url": "darkweb-tor-underground",
    "document": "archiving-evidence-docs",
    "rf_frequency": "sigint-wireless-space-rf",
}


def pick_top_tools_for_selector(sel: str, matched: list[dict], count: int = 3) -> list[dict]:
    primary_cat = PRIMARY_DISCIPLINE_FOR_SELECTOR.get(sel)
    tier_rank = {"S": 0, "A": 1, "B": 2}
    passive_pool = [t for t in matched if t["opsec"] == "Passive"] or matched
    ranked = sorted(
        passive_pool,
        key=lambda t: (
            0 if t["category"] == primary_cat else (2 if t["category"] == "all-in-one-frameworks" else 1),
            tier_rank.get(t["tier"], 2),
            0 if not t["auth_required"] else 1,
            t["name"].lower(),
        ),
    )
    return ranked[:count]


def load_json(name: str):
    with (DATA_DIR / name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def opsec_badge(opsec: str) -> str:
    return {"Passive": "🟢 Passive", "Hybrid": "🟡 Hybrid", "Active": "🔴 Active"}[opsec]


def pricing_short(pricing: str) -> str:
    return {
        "Free / Open Source": "OSS / Free",
        "Free": "Free",
        "Freemium": "Freemium",
        "Paid": "Paid",
    }[pricing]


def build_exports(categories, tools, workflows, dorks, graveyard) -> None:
    # 1. CSV export
    csv_path = DATA_DIR / "tools.csv"
    fieldnames = [
        "id",
        "name",
        "tier",
        "category",
        "subcategory",
        "type",
        "pricing",
        "opsec",
        "auth_required",
        "url",
        "github",
        "inputs",
        "outputs",
        "platforms",
        "tags",
        "description",
        "quick_start",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for t in tools:
            writer.writerow(
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tier": t["tier"],
                    "category": t["category"],
                    "subcategory": t["subcategory"],
                    "type": t["type"],
                    "pricing": t["pricing"],
                    "opsec": t["opsec"],
                    "auth_required": t["auth_required"],
                    "url": t["url"],
                    "github": t["github"] or "",
                    "inputs": "|".join(t["inputs"]),
                    "outputs": "|".join(t["outputs"]),
                    "platforms": "|".join(t["platforms"]),
                    "tags": "|".join(t["tags"]),
                    "description": t["description"],
                    "quick_start": t["quick_start"],
                }
            )

    # 2. JSONL export
    jsonl_path = DATA_DIR / "tools.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for t in tools:
            fh.write(json.dumps(t, ensure_ascii=False) + "\n")

    # 3. SQLite 3 + FTS5 full-text database
    db_path = DATA_DIR / "osint.sqlite"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.executescript(
        """
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;

        CREATE TABLE categories (
            order_num INTEGER PRIMARY KEY,
            id TEXT UNIQUE NOT NULL,
            code TEXT NOT NULL,
            icon TEXT NOT NULL,
            title TEXT NOT NULL,
            short_title TEXT NOT NULL,
            description TEXT NOT NULL,
            opsec_notes TEXT NOT NULL
        );

        CREATE TABLE tools (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            github TEXT,
            category TEXT NOT NULL REFERENCES categories(id),
            subcategory TEXT NOT NULL,
            description TEXT NOT NULL,
            type TEXT NOT NULL,
            pricing TEXT NOT NULL,
            opsec TEXT NOT NULL,
            auth_required INTEGER NOT NULL,
            tier TEXT NOT NULL,
            quick_start TEXT NOT NULL,
            inputs_json TEXT NOT NULL,
            outputs_json TEXT NOT NULL,
            platforms_json TEXT NOT NULL,
            tags_json TEXT NOT NULL
        );

        CREATE TABLE tool_inputs (
            tool_id TEXT NOT NULL REFERENCES tools(id),
            selector TEXT NOT NULL,
            PRIMARY KEY (tool_id, selector)
        );

        CREATE TABLE tool_outputs (
            tool_id TEXT NOT NULL REFERENCES tools(id),
            output_type TEXT NOT NULL,
            PRIMARY KEY (tool_id, output_type)
        );

        CREATE TABLE tool_tags (
            tool_id TEXT NOT NULL REFERENCES tools(id),
            tag TEXT NOT NULL,
            PRIMARY KEY (tool_id, tag)
        );

        CREATE TABLE workflows (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            discipline TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            starting_selector TEXT NOT NULL,
            summary TEXT NOT NULL,
            steps_json TEXT NOT NULL
        );

        CREATE TABLE dorks (
            id TEXT PRIMARY KEY,
            engine TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            query TEXT NOT NULL,
            purpose TEXT NOT NULL
        );

        CREATE TABLE graveyard (
            dead_tool TEXT PRIMARY KEY,
            former_url TEXT NOT NULL,
            status TEXT NOT NULL,
            what_happened TEXT NOT NULL,
            replacements_json TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE tools_fts USING fts5(
            id UNINDEXED,
            name,
            category,
            subcategory,
            description,
            tags,
            inputs,
            outputs,
            quick_start
        );

        CREATE VIEW v_passive_free_tools AS
        SELECT id, name, tier, category, subcategory, type, pricing, url, github, description
        FROM tools
        WHERE opsec = 'Passive' AND pricing IN ('Free / Open Source', 'Free')
        ORDER BY CASE tier WHEN 'S' THEN 0 WHEN 'A' THEN 1 ELSE 2 END, name;

        CREATE VIEW v_selector_pivot_counts AS
        SELECT ti.selector,
               COUNT(*) AS total_tools,
               SUM(CASE WHEN t.opsec = 'Passive' THEN 1 ELSE 0 END) AS passive_tools,
               SUM(CASE WHEN t.pricing IN ('Free / Open Source', 'Free') THEN 1 ELSE 0 END) AS free_tools
        FROM tool_inputs ti
        JOIN tools t ON t.id = ti.tool_id
        GROUP BY ti.selector
        ORDER BY total_tools DESC;
        """
    )

    for c in categories:
        cur.execute(
            "INSERT INTO categories VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (c["order"], c["id"], c["code"], c["icon"], c["title"], c["short_title"], c["description"], c["opsec_notes"]),
        )

    for t in tools:
        cur.execute(
            "INSERT INTO tools VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                t["id"],
                t["name"],
                t["url"],
                t["github"],
                t["category"],
                t["subcategory"],
                t["description"],
                t["type"],
                t["pricing"],
                t["opsec"],
                1 if t["auth_required"] else 0,
                t["tier"],
                t["quick_start"],
                json.dumps(t["inputs"]),
                json.dumps(t["outputs"]),
                json.dumps(t["platforms"]),
                json.dumps(t["tags"]),
            ),
        )
        for inp in t["inputs"]:
            cur.execute("INSERT INTO tool_inputs VALUES (?, ?)", (t["id"], inp))
        for out in t["outputs"]:
            cur.execute("INSERT INTO tool_outputs VALUES (?, ?)", (t["id"], out))
        for tag in t["tags"]:
            cur.execute("INSERT INTO tool_tags VALUES (?, ?)", (t["id"], tag))
        cur.execute(
            "INSERT INTO tools_fts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                t["id"],
                t["name"],
                t["category"],
                t["subcategory"],
                t["description"],
                " ".join(t["tags"]),
                " ".join(t["inputs"]),
                " ".join(t["outputs"]),
                t["quick_start"],
            ),
        )

    for wf in workflows:
        cur.execute(
            "INSERT INTO workflows VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                wf["id"],
                wf["title"],
                wf["discipline"],
                wf["difficulty"],
                wf["starting_selector"],
                wf["summary"],
                json.dumps(wf["steps"]),
            ),
        )

    for d in dorks:
        cur.execute(
            "INSERT INTO dorks VALUES (?, ?, ?, ?, ?, ?)",
            (d["id"], d["engine"], d["category"], d["title"], d["query"], d["purpose"]),
        )

    for g in graveyard:
        cur.execute(
            "INSERT INTO graveyard VALUES (?, ?, ?, ?, ?)",
            (g["dead_tool"], g["former_url"], g["status"], g["what_happened"], json.dumps(g["replacements"])),
        )

    conn.commit()
    cur.execute("VACUUM")
    conn.close()

    # 4. Web UI Data Bundle (`web/data.js`)
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_on": "2026-10-22",
        "categories": categories,
        "tools": tools,
        "workflows": workflows,
        "dorks": dorks,
        "graveyard": graveyard,
        "selector_labels": {k: v[0] for k, v in SELECTOR_LABELS.items()},
    }
    with (WEB_DIR / "data.js").open("w", encoding="utf-8") as fh:
        fh.write("window.OSINT_DB = ")
        json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write(";\n")


def build_category_pages(categories, tools) -> None:
    CAT_DIR.mkdir(parents=True, exist_ok=True)
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        by_cat[t["category"]].append(t)

    for idx, cat in enumerate(categories):
        cat_tools = by_cat[cat["id"]]
        prev_cat = categories[idx - 1] if idx > 0 else None
        next_cat = categories[idx + 1] if idx + 1 < len(categories) else None

        subcats: dict[str, list[dict]] = defaultdict(list)
        for t in cat_tools:
            subcats[t["subcategory"]].append(t)

        lines: list[str] = []
        nav = ["[⬅️ Back to Master Index](../README.md)"]
        if prev_cat:
            nav.append(f"[◀ {prev_cat['icon']} {prev_cat['short_title']}](./{prev_cat['filename']})")
        if next_cat:
            nav.append(f"[{next_cat['icon']} {next_cat['short_title']} ▶](./{next_cat['filename']})")
        lines.append(" · ".join(nav))
        lines.append("")
        lines.append(f"# {cat['icon']} {cat['order']:02d}. {cat['title']} (`{cat['code']}`)")
        lines.append("")
        lines.append(f"> **Scope**: {cat['description']}")
        lines.append(">")
        lines.append(f"> **OPSEC Advisory**: {cat['opsec_notes']}")
        lines.append("")

        s_cnt = sum(1 for t in cat_tools if t["tier"] == "S")
        passive_cnt = sum(1 for t in cat_tools if t["opsec"] == "Passive")
        free_cnt = sum(1 for t in cat_tools if t["pricing"] in ("Free / Open Source", "Free"))
        lines.append(
            f"**Discipline Telemetry**: `{len(cat_tools)}` Verified Tools · "
            f"`{s_cnt}` S-Tier Flagships · `{passive_cnt}` Passive · `{free_cnt}` Free/Open-Source"
        )
        lines.append("")
        lines.append("## Subcategories")
        for sub_name, items in subcats.items():
            anchor = (
                sub_name.lower()
                .replace("&", "")
                .replace("/", "")
                .replace("(", "")
                .replace(")", "")
                .replace(".", "")
                .replace("'", "")
            )
            anchor = "-".join(anchor.split())
            lines.append(f"- [{sub_name}](#{anchor}) ({len(items)})")
        lines.append("")

        for sub_name, items in subcats.items():
            lines.append("---")
            lines.append("")
            lines.append(f"## {sub_name}")
            lines.append("")
            lines.append("| Tier | Tool | Type | Pricing | OPSEC | Auth | Inputs → Outputs |")
            lines.append("| :---: | :--- | :--- | :--- | :--- | :---: | :--- |")
            for t in items:
                gh_link = f" ([GitHub](https://github.com/{t['github']}))" if t["github"] else ""
                auth_str = "🔑" if t["auth_required"] else "✅"
                io_str = f"`{', '.join(t['inputs'][:3])}` → `{', '.join(t['outputs'][:3])}`"
                lines.append(
                    f"| **{t['tier']}** | [**{md_escape(t['name'])}**]({t['url']}){gh_link} | "
                    f"{t['type']} | {pricing_short(t['pricing'])} | {opsec_badge(t['opsec'])} | {auth_str} | {io_str} |"
                )
            lines.append("")

            for t in items:
                gh_badge = f" · **GitHub**: [`{t['github']}`](https://github.com/{t['github']})" if t["github"] else ""
                auth_txt = "Required (Account / API Key)" if t["auth_required"] else "None (Keyless / Direct)"
                lines.append(f"### [{t['name']}]({t['url']}) `[{t['tier']}-Tier]`")
                lines.append(f"- **ID**: `{t['id']}` · **Type**: `{t['type']}` · **Pricing**: `{t['pricing']}` · **OPSEC**: {opsec_badge(t['opsec'])} · **Auth**: {auth_txt}{gh_badge}")
                lines.append(f"- **Inputs**: {', '.join(f'`{i}`' for i in t['inputs'])} → **Outputs**: {', '.join(f'`{o}`' for o in t['outputs'])}")
                lines.append(f"- **Platforms**: {', '.join(t['platforms'])} · **Tags**: {', '.join(f'`{tg}`' for tg in t['tags'])}")
                lines.append(f"- **Overview**: {t['description']}")
                lines.append(f"- **Quick-Start / Tradecraft**: `{t['quick_start']}`")
                lines.append("")

        lines.append("---")
        lines.append(" · ".join(nav))
        (CAT_DIR / cat["filename"]).write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_docs(categories, tools, workflows, dorks, graveyard) -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    by_id = {t["id"]: t for t in tools}

    # 1. PIVOT_MATRIX.md
    by_input: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        for inp in t["inputs"]:
            by_input[inp].append(t)

    pm_lines = [
        "[⬅️ Back to Master Index](../README.md)",
        "",
        "# 🧭 OSINT Selector Pivot Matrix (`Input → Tools → Downstream Pivots`)",
        "",
        "Real-world investigations start from a **known selector** (an email, handle, phone number, domain, wallet, photo, IMO number, or BSSID) and pivot toward new selectors. Use this matrix—or run `python3 scripts/osint.py pivot <selector> --passive`—to pick your exact next move.",
        "",
        "## Summary Selector Index",
        "",
        "| Input Selector | Example Artifact | Total Tools | Passive Tools | Top S-Tier Starting Tools | Primary Downstream Outputs |",
        "| :--- | :--- | :---: | :---: | :--- | :--- |",
    ]

    ordered_selectors = sorted(by_input.keys(), key=lambda s: (-len(by_input[s]), s))
    for sel in ordered_selectors:
        matched = by_input[sel]
        passive_cnt = sum(1 for t in matched if t["opsec"] == "Passive")
        s_tools = pick_top_tools_for_selector(sel, matched, count=4)
        top_links = ", ".join(f"[{t['name']}]({t['url']})" for t in s_tools)
        out_counts = Counter(o for t in matched for o in t["outputs"])
        top_outs = ", ".join(f"`{k}`" for k, _ in out_counts.most_common(4))
        label, example = SELECTOR_LABELS.get(sel, (sel, ""))
        pm_lines.append(
            f"| [`{sel}`](#selector-{sel.replace('_', '-')}) ({label}) | {example} | **{len(matched)}** | {passive_cnt} | {top_links} | {top_outs} |"
        )
    pm_lines.append("")

    for sel in ordered_selectors:
        matched = by_input[sel]
        label, example = SELECTOR_LABELS.get(sel, (sel, ""))
        anchor_title = f"Selector: {sel}"
        pm_lines.append("---")
        pm_lines.append("")
        pm_lines.append(f"## {anchor_title}")
        pm_lines.append(f"**{label}** ({example}) — `{len(matched)}` tools (`python3 scripts/osint.py pivot {sel} --passive`)")
        pm_lines.append("")
        pm_lines.append("| Tier | Tool | Category | OPSEC | Pricing | Outputs Produced |")
        pm_lines.append("| :---: | :--- | :--- | :--- | :--- | :--- |")
        for t in matched:
            pm_lines.append(
                f"| **{t['tier']}** | [**{md_escape(t['name'])}**]({t['url']}) | `{t['category']}` | "
                f"{opsec_badge(t['opsec'])} | {pricing_short(t['pricing'])} | {', '.join(f'`{o}`' for o in t['outputs'][:4])} |"
            )
        pm_lines.append("")

    (DOCS_DIR / "PIVOT_MATRIX.md").write_text("\n".join(pm_lines) + "\n", encoding="utf-8")

    # 2. WORKFLOWS.md
    wf_lines = [
        "[⬅️ Back to Master Index](../README.md)",
        "",
        "# 🗺️ End-to-End OSINT Investigation Playbooks",
        "",
        "12 battle-tested operational workflows chaining multiple disciplines from initial seed selector to verified intelligence dossier. Query any playbook from the terminal via `python3 scripts/osint.py workflows <id>`.",
        "",
        "## Playbook Index",
        "",
    ]
    for idx, wf in enumerate(workflows, 1):
        wf_lines.append(f"{idx}. [**{wf['title']}**](#{wf['id']}) — `{wf['discipline']}` · Seed: `{wf['starting_selector']}` · *{wf['difficulty']}*")
    wf_lines.append("")

    for wf in workflows:
        wf_lines.append("---")
        wf_lines.append("")
        wf_lines.append(f"<a id=\"{wf['id']}\"></a>")
        wf_lines.append(f"## {wf['title']}")
        wf_lines.append(f"- **Playbook ID**: `{wf['id']}` · **Disciplines**: `{wf['discipline']}` · **Difficulty**: `{wf['difficulty']}` · **Seed Selector**: `{wf['starting_selector']}`")
        wf_lines.append(f"- **Objective**: {wf['summary']}")
        wf_lines.append("")
        for st in wf["steps"]:
            wf_lines.append(f"### Phase {st['step']}: {st['phase']}")
            wf_lines.append(f"{st['action']}")
            wf_lines.append("")
            for tid in st["recommended_tools"]:
                t = by_id[tid]
                wf_lines.append(
                    f"- **[`{t['tier']}`] [{t['name']}]({t['url']})** ({opsec_badge(t['opsec'])}, *{pricing_short(t['pricing'])}*) — {t['description']}"
                )
            wf_lines.append("")

    (DOCS_DIR / "WORKFLOWS.md").write_text("\n".join(wf_lines) + "\n", encoding="utf-8")

    # 3. DORKS_ARSENAL.md
    by_engine: dict[str, list[dict]] = defaultdict(list)
    for d in dorks:
        by_engine[d["engine"]].append(d)

    dk_lines = [
        "[⬅️ Back to Master Index](../README.md)",
        "",
        "# 🎯 OSINT Search & Cyberspace Dorks Arsenal",
        "",
        f"`{len(dorks)}` high-yield search operators across Google, Shodan, Censys, FOFA, ZoomEye, GitHub, URLScan.io, X, Wayback CDX, and `crt.sh` SQL.",
        "",
        "> **CLI Tip**: Auto-substitute your target domain across all dorks instantly with:",
        "> ```bash",
        "> python3 scripts/osint.py dorks --target acme.com",
        "> python3 scripts/osint.py dorks --engine Shodan --target acme.com",
        "> ```",
        "",
    ]
    for engine, items in by_engine.items():
        dk_lines.append(f"## {engine} ({len(items)} Dorks)")
        dk_lines.append("")
        for d in items:
            dk_lines.append(f"### {d['title']} (`{d['category']}`)")
            dk_lines.append(f"{d['purpose']}")
            dk_lines.append("```text")
            dk_lines.append(d["query"])
            dk_lines.append("```")
            dk_lines.append("")

    (DOCS_DIR / "DORKS_ARSENAL.md").write_text("\n".join(dk_lines) + "\n", encoding="utf-8")

    # 4. GRAVEYARD_2026.md
    gy_lines = [
        "[⬅️ Back to Master Index](../README.md)",
        "",
        "# 🪦 OSINT Graveyard & Verified 2026 Replacements",
        "",
        "Older OSINT blogs, courses, and unmaintained GitHub lists still recommend tools that have shut down, revoked public access, been seized, or **had their domains hijacked**. Consult this table whenever an older workflow breaks.",
        "",
        "| Legacy / Dead Tool | Status | What Happened | Verified 2026 Replacements |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for g in graveyard:
        rep_links = "<br>".join(
            f"• [**{r['name']}**]({by_id[r['id']]['url']}) — {md_escape(r['note'])}" for r in g["replacements"]
        )
        gy_lines.append(
            f"| **{md_escape(g['dead_tool'])}**<br>`{g['former_url']}` | `{g['status']}` | {md_escape(g['what_happened'])} | {rep_links} |"
        )
    gy_lines.append("")
    (DOCS_DIR / "GRAVEYARD_2026.md").write_text("\n".join(gy_lines) + "\n", encoding="utf-8")

    # 5. FULL_INDEX.md (Single-page Ctrl+F directory of all 540 tools, keeping README.md fast & concise)
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        by_cat[t["category"]].append(t)

    fi_lines = [
        "[⬅️ Back to Master README](../README.md)",
        "",
        f"# 🗂️ Complete {len(tools)}-Tool OSINT Master Directory",
        "",
        "Single-page `Ctrl+F` index of every verified tool in the database. For extended CLI `quick_start` snippets and `Input → Output` mappings, open the linked discipline manual.",
        "",
        "Legend: **`S`** = Gold Standard · **`A`** = Specialist · **`B`** = Tactical/Regional · `🟢 Passive` · `🟡 Hybrid` · `🔴 Active` · ✅ = No-Auth · 🔑 = Key/Login.",
        "",
    ]
    for c in categories:
        c_tools = by_cat[c["id"]]
        anchor = f"{c['order']:02d}-{c['id']}"
        fi_lines.append(f"<a id=\"{anchor}\"></a>")
        fi_lines.append(f"## {c['icon']} {c['order']:02d}. {c['title']} (`{c['code']}`) — [Extended Manual →](../categories/{c['filename']})")
        fi_lines.append("")
        fi_lines.append("| Tier | Tool | Subcategory | Type | Pricing | OPSEC | Auth | Description |")
        fi_lines.append("| :---: | :--- | :--- | :--- | :--- | :--- | :---: | :--- |")
        for t in c_tools:
            gh = f" · [GH](https://github.com/{t['github']})" if t["github"] else ""
            auth_icon = "🔑" if t["auth_required"] else "✅"
            fi_lines.append(
                f"| **{t['tier']}** | [**{md_escape(t['name'])}**]({t['url']}){gh} | {md_escape(t['subcategory'])} | "
                f"{t['type']} | {pricing_short(t['pricing'])} | {opsec_badge(t['opsec'])} | {auth_icon} | {md_escape(t['description'])} |"
            )
        fi_lines.append("")

    (DOCS_DIR / "FULL_INDEX.md").write_text("\n".join(fi_lines) + "\n", encoding="utf-8")


def build_readme(categories, tools, workflows, dorks, graveyard) -> None:
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        by_cat[t["category"]].append(t)

    by_input: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        for inp in t["inputs"]:
            by_input[inp].append(t)

    passive_cnt = sum(1 for t in tools if t["opsec"] == "Passive")
    oss_cnt = sum(1 for t in tools if t["github"])
    no_auth_cnt = sum(1 for t in tools if not t["auth_required"])

    lines: list[str] = [
        "<div align=\"center\">",
        "",
        "# 🛰️ OSINT MONSTER DATABASE",
        "",
        "**Autonomous OSINT Hunting Engine · 540-Tool Intelligence Arsenal · Native MCP Server · Field Playbooks**",
        "",
        f"![Verified Tools](https://img.shields.io/badge/Verified_Tools-{len(tools)}-00e5ff?style=for-the-badge) "
        f"![Disciplines](https://img.shields.io/badge/Disciplines-{len(categories)}-7c4dff?style=for-the-badge) "
        f"![Passive Safe](https://img.shields.io/badge/Passive_Safe-{passive_cnt}-00e676?style=for-the-badge) "
        f"![Open Source](https://img.shields.io/badge/GitHub_Repos-{oss_cnt}-ffab00?style=for-the-badge) "
        "![Stack](https://img.shields.io/badge/Python_3_Stdlib-Zero_Deps-ff5252?style=for-the-badge)",
        "",
        "[**🤖 Agent Protocol**](./AGENTS.md) · "
        "[**🗂️ Full 540-Tool Index**](./docs/FULL_INDEX.md) · "
        "[**🧭 Pivot Matrix**](./docs/PIVOT_MATRIX.md) · "
        f"[**🗺️ {len(workflows)} Playbooks**](./docs/WORKFLOWS.md) · "
        f"[**🎯 {len(dorks)} Dorks**](./docs/DORKS_ARSENAL.md) · "
        "[**🪦 2026 Graveyard**](./docs/GRAVEYARD_2026.md) · "
        "[**🛡️ OPSEC Guide**](./docs/OPSEC_TRADECRAFT.md)",
        "",
        "</div>",
        "",
        "---",
        "",
        "## ⚡ What's Inside",
        "",
        f"Unlike flat bookmark lists filled with dead links, **OSINT Monster Database** combines a **strictly validated {len(tools)}-tool multi-format catalog** ({no_auth_cnt} keyless/no-auth ready) with a **zero-dependency Python execution engine** (`osint_hunter/`) that AI agents, MCP hosts, and human analysts can run out of the box.",
        "",
        "| Capability | Entrypoint | Highlights |",
        "| :--- | :--- | :--- |",
        "| **🤖 Autonomous Hunter** | [`scripts/hunt.py`](./scripts/hunt.py) · [`osint_hunter/`](./osint_hunter/) | 35+ passive collectors & offline decoders, Wave-2/3 recursive entity pivoting, OASIS **STIX 2.1** & SHA-256 dossiers |",
        "| **🔌 Native MCP Server** | [`.mcp.json`](./.mcp.json) · [`scripts/mcp_server.py`](./scripts/mcp_server.py) | `stdio` JSON-RPC 2.0 + Streamable HTTP (`POST /api/mcp`) + OpenAI/Anthropic schemas ([`openai_tools.json`](./data/openai_tools.json)) |",
        "| **🖥️ Web Command Center** | [`scripts/server.py`](./scripts/server.py) · [`web/`](./web/) | Live Hunt UI, SVG entity-pivot graph, Active Authorization Modal, Live Dork Forge, & Case Loadout builder |",
        "| **🗃️ Multi-Format Data** | [`data/`](./data/) · [`scripts/osint.py`](./scripts/osint.py) | `tools.json`, **SQLite FTS5** (`osint.sqlite`), `tools.csv`, `tools.jsonl`, & terminal search/pivot CLI |",
        "",
        "---",
        "",
        "## 🚀 60-Second Quick Start",
        "",
        "*Requires only Python 3.9+ standard library — zero `pip install` needed.*",
        "",
        "```bash",
        "# 1. Instant Passive Hunt (Zero questions · Zero packets sent to target servers)",
        "python3 scripts/hunt.py \"@torvalds, +966501234567, aircraft AE01D5, MMSI 613123456, VIN 5YJ3E1EA7KF317000\"",
        "",
        "# 2. Active OSINT Mode (ALWAYS asks permission first via single-use ACT-XXXXXXXX gate)",
        "python3 scripts/hunt.py \"github.com\" --prepare-active",
        "python3 scripts/hunt.py \"github.com\" --active --request-id ACT-XXXXXXXX --user-approved \"yes\"",
        "",
        "# 3. Launch Web Command Center + REST Hunt API + HTTP MCP Server (http://0.0.0.0:8000)",
        "python3 scripts/server.py --port 8000",
        "",
        "# 4. Search the 540-Tool Arsenal, Pivot by Selector, or Forge Target Dorks",
        "python3 scripts/osint.py stats",
        "python3 scripts/osint.py pivot email --passive --free",
        "python3 scripts/osint.py dorks --engine Shodan --target example.com",
        "```",
        "",
        "---",
        "",
        "## 🤖 AI Agent Integration: The Two-Law Doctrine",
        "",
        "Connect **Claude Code, Codex, Cursor, Windsurf, Cline, OpenClaw, or any MCP client** directly to this repo. Pre-configured manifests ([`AGENTS.md`](./AGENTS.md), [`CLAUDE.md`](./CLAUDE.md), [`.cursorrules`](./.cursorrules), [`SKILL.md`](./SKILL.md)) enforce two strict rules:",
        "",
        "| Mode | Agent Behavior | Enforcement & Scope |",
        "| :--- | :--- | :--- |",
        "| **`🟢 Passive Mode`** *(Default)* | **Starts hunting on Turn 1 with zero clarifying questions** | Queries 35+ passive APIs & offline decoders (GitHub commit/SSH/PGP packet carving, npm/PyPI, DoH, `crt.sh`, RDAP, Wayback, InternetDB, RIPEstat, E.164, ICAO, MMSI, VIN, OUI, JPEG EXIF GPS). **Zero packets hit target servers.** |",
        "| **`🔴 Active Mode`** *(Gated)* | **ALWAYS asks your permission before every single run** | Enforced in code ([`osint_hunter/approval.py`](./osint_hunter/approval.py)) via **single-use, target-bound `ACT-XXXXXXXX` tokens**. Unlocks live `:443` TLS SANs, HTTP/CSP/GA4 headers, `robots.txt`/`security.txt`, **Shodan `mmh3` favicon hashes**, & TCP banners. |",
        "",
        "Every hunt writes a gitignored forensic bundle under `cases/<UTC_TIMESTAMP>_<SLUG>/` containing `dossier.md`, `report.json`, `graph.json`, `stix2_bundle.json`, and `manifest.sha256`.",
        "",
        "---",
        "",
        "## 📚 20 Intelligence Disciplines",
        "",
        f"Browse individual manuals below (with CLI `quick_start` commands and `Input → Output` tags) or open the [**Single-Page {len(tools)}-Tool Directory (`docs/FULL_INDEX.md`)**](./docs/FULL_INDEX.md).",
        "",
        "| # | Discipline | Tools | Flagship S-Tier Tools |",
        "| :---: | :--- | :---: | :--- |",
    ]

    for c in categories:
        c_tools = by_cat[c["id"]]
        flagships = [t for t in c_tools if t["tier"] == "S"][:4] or c_tools[:3]
        flag_links = ", ".join(f"[{t['name']}]({t['url']})" for t in flagships)
        lines.append(
            f"| **{c['order']:02d}** | [{c['icon']} **{c['short_title']}**](./categories/{c['filename']}) (`{c['code']}`) | "
            f"**{len(c_tools)}** | {flag_links} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 🧭 Quick Pivot Cheat Sheet — *\"I Have X, Where Do I Start?\"*",
            "",
            "See all 24 input selectors in [**`docs/PIVOT_MATRIX.md`**](./docs/PIVOT_MATRIX.md) or run `python3 scripts/osint.py pivot <selector> --passive`.",
            "",
            "| Starting Selector | Tools | Top Passive Starting Stack | Primary Outputs |",
            "| :--- | :---: | :--- | :--- |",
        ]
    )

    compact_pivots = [
        "username",
        "email",
        "phone",
        "person_name",
        "domain",
        "ip",
        "image",
        "company",
        "crypto_address",
        "vessel_imo",
        "aircraft_hex",
        "vin",
    ]
    for sel in compact_pivots:
        matched = by_input[sel]
        top_s = pick_top_tools_for_selector(sel, matched, count=3)
        links = ", ".join(f"[{t['name']}]({t['url']})" for t in top_s)
        outs = Counter(o for t in matched for o in t["outputs"])
        out_str = ", ".join(f"`{k}`" for k, _ in outs.most_common(3))
        label = SELECTOR_LABELS[sel][0]
        lines.append(
            f"| [**{label}**](./docs/PIVOT_MATRIX.md#selector-{sel.replace('_', '-')}) (`{sel}`) | `{len(matched)}` | {links} | {out_str} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 🗂️ Repository Layout",
            "",
            "```text",
            "OSINT/",
            "├── AGENTS.md / CLAUDE.md / SKILL.md / .mcp.json   # Zero-question Passive + User-Gated Active agent rules",
            "├── osint_hunter/                                  # Autonomous classifier, passive/active collectors & STIX engine",
            "├── scripts/                                       # hunt.py, osint.py, mcp_server.py, server.py, validate.py, build.py",
            "├── categories/01-*.md .. 20-*.md                  # 20 deep-dive manuals with CLI quick-starts & OPSEC notes",
            "├── docs/                                          # FULL_INDEX, PIVOT_MATRIX, WORKFLOWS, DORKS_ARSENAL, GRAVEYARD_2026",
            "├── data/                                          # tools.json, schema.json, osint.sqlite (FTS5), tools.csv, tools.jsonl",
            "└── web/                                           # Zero-build Interactive OSINT Command Center UI",
            "```",
            "",
            "---",
            "",
            "## 🪦 Critical 2026 Retired / Hijacked Tool Warnings",
            "",
            "- ⚠️ **`telegago.com` is hijacked** — use ONLY the [**Official Google CSE Link**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) & [**TGStat**](https://tgstat.com/).",
            "- **Sentinel Hub EO Browser** *(Retired Mar 2026)* → [**Copernicus Data Space Browser**](https://browser.dataspace.copernicus.eu/)",
            "- **GeoSpy (`geospy.ai`)** *(Public web closed Apr 2026)* → [**Picarta**](https://picarta.ai/), [**geo-sleuth**](https://github.com/Oldcircle/geo-sleuth), & [**Bellingcat OSM Search**](https://osm-search.bellingcat.com/)",
            "- **CrowdTangle** / **Pushshift** → [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library), [**Who Posted What?**](https://whopostedwhat.com/), & [**PullPush**](https://search.pullpush.io/) — full list in [**`docs/GRAVEYARD_2026.md`**](./docs/GRAVEYARD_2026.md).",
            "",
            "---",
            "",
            "## ⚖️ Legal & Ethical Use",
            "",
            "Curated strictly for **authorized security assessments, cyber threat intelligence, journalistic verification, academic research, compliance due diligence, and lawful open-source investigations**. Review [**`docs/OPSEC_TRADECRAFT.md`**](./docs/OPSEC_TRADECRAFT.md) before active probing · [**MIT License**](./LICENSE) · [**Contributing**](./CONTRIBUTING.md).",
        ]
    )

    (ROOT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    val = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate.py")], cwd=str(ROOT))
    if val.returncode != 0:
        return val.returncode

    categories = load_json("categories.json")
    tools = load_json("tools.json")
    workflows = load_json("workflows.json")
    dorks = load_json("dorks.json")
    graveyard = load_json("graveyard.json")

    build_exports(categories, tools, workflows, dorks, graveyard)
    build_category_pages(categories, tools)
    build_docs(categories, tools, workflows, dorks, graveyard)
    build_readme(categories, tools, workflows, dorks, graveyard)

    print("Build complete:")
    print(f"  - README.md + 20 category manuals in categories/")
    print(f"  - 5 tactical manuals in docs/ (FULL_INDEX, PIVOT_MATRIX, WORKFLOWS, DORKS_ARSENAL, GRAVEYARD_2026)")
    print(f"  - Multi-format data exports: data/tools.csv, data/tools.jsonl, data/osint.sqlite (FTS5)")
    print(f"  - Web Explorer bundle: web/data.js")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

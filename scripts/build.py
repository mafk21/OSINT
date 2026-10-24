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
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
CAT_DIR = ROOT / "categories"
DOCS_DIR = ROOT / "docs"
WEB_DIR = ROOT / "web"
SKILLS_DIR = ROOT / "skills"
RELEASES_DIR = ROOT / "releases"
FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)

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
        "generated_on": "2026-10-23",
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
        f"{len(workflows)} battle-tested operational workflows chaining multiple disciplines from initial seed selector to verified intelligence dossier. Query any playbook from the terminal via `python3 scripts/osint.py workflows <id>`.",
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
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from osint_hunter.approval import ACTIVE_MODULES_CATALOG

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        by_cat[t["category"]].append(t)

    by_input: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        for inp in t["inputs"]:
            by_input[inp].append(t)

    passive_cnt = sum(1 for t in tools if t["opsec"] == "Passive")
    active_hyb_cnt = sum(1 for t in tools if t["opsec"] in ("Active", "Hybrid"))
    free_cnt = sum(1 for t in tools if t["pricing"] in ("Free / Open Source", "Free"))
    oss_cnt = sum(1 for t in tools if t["github"])
    no_auth_cnt = sum(1 for t in tools if not t["auth_required"])
    s_tier_cnt = sum(1 for t in tools if t["tier"] == "S")
    act_mod_cnt = len(ACTIVE_MODULES_CATALOG)

    lines: list[str] = [
        "<div align=\"center\">",
        "",
        "# 🛰️ OSINT MONSTER",
        "",
        f"### Autonomous Multi-Stage Recon Engine · Zero-Network Forensic Decoders · {act_mod_cnt}-Probe Gated Active Recon · {len(tools)}-Tool Validated Intelligence Arsenal",
        "",
        f"[![CI Validation](https://img.shields.io/github/actions/workflow/status/mafk21/OSINT/validate.yml?branch=main&style=for-the-badge&label=CI%20Self-Tests)](https://github.com/mafk21/OSINT/actions) "
        f"![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B_%C2%B7_Zero_Deps-3776ab?style=for-the-badge&logo=python&logoColor=white) "
        f"![MCP Native](https://img.shields.io/badge/MCP_Server-13_Tools-00bfa5?style=for-the-badge) "
        f"![Agent Skills](https://img.shields.io/badge/Portable_Skills-Claude_%C2%B7_Codex_%C2%B7_75%2B-ff6d00?style=for-the-badge) "
        f"[![MIT License](https://img.shields.io/badge/License-MIT-9ca3af?style=for-the-badge)](./LICENSE)",
        "",
        f"![Verified Tools](https://img.shields.io/badge/Verified_Tools-{len(tools)}-00e5ff?style=flat-square) "
        f"![Passive Safe](https://img.shields.io/badge/Passive_Safe-{passive_cnt}-00e676?style=flat-square) "
        f"![Active & Hybrid](https://img.shields.io/badge/Active_%26_Hybrid-{active_hyb_cnt}-ff5252?style=flat-square) "
        f"![Free & OSS](https://img.shields.io/badge/Free_%26_OSS-{free_cnt}-10b981?style=flat-square) "
        f"![No-Auth Ready](https://img.shields.io/badge/Keyless_No--Auth-{no_auth_cnt}-38bdf8?style=flat-square) "
        f"![GitHub Repos](https://img.shields.io/badge/GitHub_Backed-{oss_cnt}-ffab00?style=flat-square) "
        f"![Search Dorks](https://img.shields.io/badge/Search_Dorks-{len(dorks)}-a855f7?style=flat-square) "
        f"![Playbooks](https://img.shields.io/badge/Playbooks-{len(workflows)}-ec4899?style=flat-square)",
        "",
        "[**⚡ Quick Start**](#quick-start) · "
        "[**🤖 Agent Skills & MCP**](#agent-skills-mcp) · "
        "[**🧬 Collectors & Forensic Decoders**](#collectors-decoders) · "
        "[**🖥️ Local Web Workspace**](#web-command-center) · "
        f"[**📚 {len(categories)} Disciplines**](#disciplines) · "
        "[**🧭 24-Selector Pivot Matrix**](#pivot-matrix)",
        "",
        "[**📜 Three-Law Agent Protocol (`AGENTS.md`)**](./AGENTS.md) · "
        "[**🧩 Skills Setup**](./docs/SKILLS_SETUP.md) · "
        f"[**🗂️ Master {len(tools)}-Tool Index**](./docs/FULL_INDEX.md) · "
        f"[**🗺️ {len(workflows)} Playbooks**](./docs/WORKFLOWS.md) · "
        f"[**🎯 {len(dorks)} Dorks**](./docs/DORKS_ARSENAL.md) · "
        f"[**🪦 {len(graveyard)} Graveyard Alerts**](./docs/GRAVEYARD_2026.md) · "
        "[**🛡️ OPSEC Guide**](./docs/OPSEC_TRADECRAFT.md)",
        "",
        "</div>",
        "",
        "---",
        "",
        "## 🔥 Not Another Bookmark List — An Executable Intelligence Monster",
        "",
        f"Most OSINT repositories are unmaintained Markdown walls full of dead URLs and hijacked domains. **OSINT Monster** unifies a **schema-validated, FTS5-indexed {len(tools)}-tool intelligence arsenal** ({s_tier_cnt} S-Tier flagships, {no_auth_cnt} keyless/no-auth ready) with a **zero-dependency Python 3 autonomous hunting, forensic decoding, cross-stage correlation, and STIX 2.1 reporting engine** (`osint_hunter/`).",
        "",
        "| Subsystem | Entrypoint | Operational Capabilities |",
        "| :--- | :--- | :--- |",
        "| **🤖 Exhaustive Multi-Stage Hunter** | [`scripts/hunt.py`](./scripts/hunt.py) · [`osint_hunter/`](./osint_hunter/) | Breadth-first recursive hunting (`--depth 4..6`), 45+ passive collectors (incl. Bluesky ATProto PLC audit, Mastodon `rel=me`, Entra M365, HuggingFace/Crates/DockerHub + optional BYOK), `--diff-last` drift & `0–100` Exposure Scoring |",
        "| **🧬 Zero-Network DFIR & Chronolocation** | [`dfir_forensics.py`](./osint_hunter/dfir_forensics.py) · [`offline_intel.py`](./osint_hunter/offline_intel.py) | **100% offline (`0` packets)**: `.eml` hop/SPF/DMARC forensics, `.pcap`/`.pcapng` DNS/SNI/HTTP carver, `.har`, `.mp4`/`.mov` `mvhd`+GPS, **PNG/WebP C2PA & ComfyUI/SD AI detection**, Google `ei=`, SSH/PEM, TikTok/Snowflake UTC, UUIDv1 MAC, IBAN & E.164 |",
        "| **🕒 Pattern-of-Life & Attribution Engine** | [`temporal.py`](./osint_hunter/temporal.py) · [`persona.py`](./osint_hunter/persona.py) | 24h UTC circadian activity & sleep-window inference, explicit UTC timezone leaks, **0–100% edge confidence & shortest attribution paths**, sockpuppet heuristics & offline **IDN Punycode typosquat** generator (`--typosquats`) |",
        f"| **🔴 {act_mod_cnt}-Probe Hard-Gated Active Recon** | [`active_collectors.py`](./osint_hunter/active_collectors.py) · [`approval.py`](./osint_hunter/approval.py) | Cryptographically gated (`ACT-XXXXXXXX` single-use tokens): DNS AXFR, SRV/M365, CNAME takeover, TLS 1.0–1.3, **62-char Salesforce JARM**, CORS/WAF, OpenAPI/GraphQL, `.git/HEAD`, JS bundle carver, S3/GCS/Azure buckets, 20-port TCP, SSH/SMTP & 16-site handle checks |",
        "| **📦 11-Artifact Forensic Case & Graph Vault** | [`exporters.py`](./osint_hunter/exporters.py) · `cases/<CASE_ID>/` | Emits `dossier.md`, `report.html`, `report.json`, `entities.csv`, **Gephi `graph.gexf`**, **`graph.graphml`**, **Neo4j `neo4j.cypher`**, **Obsidian `obsidian/` `[[WikiLink]]` vault**, **OASIS STIX 2.1**, `manifest.sha256`, `--compare-cases` & `--watchlist-run` |",
        f"| **🖥️ Local Web Workspace, Skills & MCP** | [`Start-Web-UI.*`](./start-web-ui.sh) · [`scripts/server.py`](./scripts/server.py) · [`web/`](./web/) | Clean, uncluttered **5-tab Local Browser Workspace** (`Investigate` · `Decode` · `Cases` · `Directory` · `Settings`) with 1-click desktop launchers, drag-and-drop file analysis, interactive entity graph, Watchlist & optional `.osint.env` API keys + **13-tool MCP Server** + portable Skills + SQLite **FTS5** |",
        "",
        "```mermaid",
        "flowchart LR",
        "    A[\"🎯 Raw Input / File / Prompt<br/>(24 Selector Types)\"] --> B[\"🧠 Selector & Checksum Classifier<br/>(osint_hunter/classify.py)\"]",
        "    B --> C[\"🟢 Stage 1..N Passive Sweep<br/>45+ Public APIs + 18 Offline DFIR Decoders<br/>(0 Packets to Target)\"]",
        "    C --> D[\"🔄 Exhaustive Stage Analyzer<br/>Carves Handles, Variants, Phones,<br/>Emails, Domains, Names & Orgs\"]",
        "    D -- \"New Unvisited Leads Found\" --> C",
        "    D -- \"Converged (0 New Leads)\" --> E[\"📊 Cross-Stage Correlator<br/>Identity/Infra + Pattern-of-Life +<br/>Confidence & 0-100 Exposure Score\"]",
        "    E --> F[\"📦 11-Artifact Case & Graph Bundle<br/>HTML · MD · CSV · GEXF · GraphML<br/>Cypher · Obsidian · STIX 2.1 · SHA-256\"]",
        "    E -. \"Explicit User Approval<br/>Single-Use ACT-XXXXXXXX\" .-> G[\"🔴 22 Live Active Probes<br/>JARM · TLS · AXFR · Buckets<br/>CORS/WAF · TCP · SSH/SMTP\"]",
        "    G --> F",
        "```",
        "",
        "---",
        "",
        "<a id=\"quick-start\"></a>",
        "## 🚀 60-Second Operator Quick Start",
        "",
        "*Runs out of the box on **Python 3.9+ standard library** — **zero `pip install` required** (optional `pip install -e .` provides `osint-hunt`, `osint-arsenal`, `osint-server`, and `osint-mcp` commands).* ",
        "",
        "### 🖥️ Option 0 — Clean Local Desktop Web Workspace (Double-Click Launch)",
        "Prefer a calm, simple visual workspace instead of the terminal? Double-click the launcher for your OS to start the local server on `127.0.0.1` and open the **5-tab Local Web Workspace** (`Investigate` · `Decode` · `Cases` · `Directory` · `Settings`) in your browser:",
        "- **Windows**: Double-click **`Start-Web-UI.bat`**",
        "- **macOS**: Double-click **`Start-Web-UI.command`**",
        "- **Linux / Any OS**: Run `./start-web-ui.sh` *(or `python3 scripts/server.py --open --auto-port`)*",
        "- **Inside the Browser**: Spotlight target search + drag-and-drop file hunting & offline DFIR inspection, clean 3-card overview, interactive pan/zoom relationship graph, matched findings shown first, a single **`Export ▾`** menu (`HTML`, `.md`, `.csv`, `.gexf`, `.graphml`, `.cypher`, `Obsidian .zip`, `STIX 2.1`, `.json`), case diff/watchlist, unified `760`-tool / `105`-dork / `20`-playbook directory, and optional `.osint.env` API key settings.",
        "",
        "### 1️⃣ Exhaustive Multi-Stage Passive Hunting, Watchlist & Case Link Analysis",
        "```bash",
        "# Instant Turn-1 Passive Hunt across multiple selector types (0 questions · 0 packets sent to target servers)",
        "python3 scripts/hunt.py \"@torvalds, +966501234567, aircraft AE01D5, MMSI 613123456, VIN 5YJ3E1EA7KF317000\" --depth 4",
        "",
        "# Feed external Stage-1 findings (bios, Linktrees, search snippets) back in to carve & hunt Stage 2..N",
        "python3 scripts/hunt.py --resume-case CASE-XXXX --ingest-file stage1_findings.txt",
        "",
        "# Saved cases, Cross-Case Link Analysis, Surface Drift (--diff-last), Watchlist & IDN Typosquats",
        "python3 scripts/hunt.py --list-cases",
        "python3 scripts/hunt.py --compare-cases CASE-AAAA CASE-BBBB",
        "python3 scripts/hunt.py \"example.com\" --diff-last",
        "python3 scripts/hunt.py --watchlist-add \"example.com\" && python3 scripts/hunt.py --watchlist-run",
        "python3 scripts/hunt.py \"example.com\" --typosquats",
        "```",
        "",
        "### 2️⃣ Zero-Network DFIR, Media Provenance & Chronolocation Decoder (`0` Outbound Packets)",
        "```bash",
        "# Extract exact UTC upload/search second from a TikTok video URL or Google Search ei= parameter",
        "python3 scripts/osint.py decode \"https://www.tiktok.com/@bellingcat/video/7345123456789012485\"",
        "python3 scripts/osint.py decode \"https://www.google.com/search?q=osint&ei=gIfsZQABAgM\"",
        "",
        "# Inspect local DFIR artifacts offline: .eml hops/SPF/DMARC, .pcap DNS/SNI/HTTP, .har, .mp4 GPS, PNG C2PA/ComfyUI, SSH keys",
        "python3 scripts/hunt.py --decode ./evidence/suspicious.eml",
        "python3 scripts/hunt.py --decode ./capture.pcap",
        "",
        "# Extract 100ns creation timestamp + generating machine's 48-bit IEEE MAC & vendor from UUIDv1",
        "python3 scripts/osint.py decode \"d9b2d63d-a233-11ee-8c90-005056c00008\"",
        "",
        "# Validate ISO 13616 IBAN MOD-97-10 checksum & resolve Saudi SAMA bank institution",
        "python3 scripts/osint.py decode \"SA0380000000608010167519\"",
        "",
        "# Decode Discord/X Snowflakes, MongoDB ObjectIds, GCC/MENA/UK/US E.164 phones, VINs, ICAO24, or local files",
        "python3 scripts/hunt.py --decode \"1216789012345678901 +971501234567 65f1a2b3c4d5e6f7a8b9c0d1\"",
        "```",
        "",
        "### 3️⃣ User-Gated Active Recon, Arsenal Search & Web Command Center",
        "```bash",
        "# Step A: Prepare single-use ACT-XXXXXXXX scope across ALL passive-discovered hosts (sends 0 packets)",
        "python3 scripts/hunt.py --prepare-active --from-case CASE-XXXX",
        "",
        "# Step B: Execute 22 direct active probes ONLY after explicit human confirmation",
        "python3 scripts/hunt.py \"example.com\" --active --request-id ACT-XXXXXXXX --user-approved \"yes\"",
        "",
        f"# Query the {len(tools)}-tool catalog, forge {len(dorks)} search dorks, audit local CLI binaries, or launch Web UI",
        "python3 scripts/osint.py doctor",
        "python3 scripts/osint.py pivot domain --passive --free --no-auth",
        "python3 scripts/osint.py dorks --engine Shodan --target example.com",
        "python3 scripts/server.py --port 8000",
        "```",
        "",
        "---",
        "",
        "<a id=\"agent-skills-mcp\"></a>",
        "## 🧩 Plug Into Any AI Agent in 10 Seconds",
        "",
        f"Both [**`osint-hunter`**](./skills/osint-hunter/SKILL.md) (autonomous Passive + {act_mod_cnt}-probe User-Gated Active recon engine + forensic decoders) and [**`osint-arsenal`**](./skills/osint-arsenal/SKILL.md) ({len(tools)}-tool pivot, playbook & dork advisor) are **100% self-contained** — install them globally and run investigations from **any working directory** without cloning this repository:",
        "",
        "```bash",
        "# 1. Universal Skills CLI (Claude Code, OpenAI Codex, Cursor, Windsurf, Copilot, Cline, Goose & 75+ agents)",
        "npx skills add mafk21/OSINT -g",
        "",
        "# 2. Claude Code Native Plugin Marketplace (run inside Claude Code)",
        "/plugin marketplace add mafk21/OSINT",
        "/plugin install osint-monster@osint-monster",
        "",
        "# 3. OpenAI Codex Native $skill-installer (run inside Codex)",
        "$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-hunter",
        "$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-arsenal",
        "",
        "# 4. Zero-Node Pure-Python Installer (installs to ~/.claude, ~/.codex, ~/.cursor, ~/.agents)",
        "python3 scripts/install_skills.py --all",
        "",
        "# 5. Native Global MCP Server Registration (exposes all 13 OSINT MCP tools)",
        "claude mcp add --scope user osint-monster -- python3 /absolute/path/to/OSINT/scripts/mcp_server.py",
        "codex mcp add osint-monster -- python3 /absolute/path/to/OSINT/scripts/mcp_server.py",
        "```",
        "",
        "> 💡 **Claude.ai Web & Claude Desktop**: Drag-and-drop [**`releases/osint-hunter-skill.zip`**](./releases/osint-hunter-skill.zip) and [**`releases/osint-arsenal-skill.zip`**](./releases/osint-arsenal-skill.zip) directly into **Settings → Capabilities → Skills**. Full platform guide in [**`docs/SKILLS_SETUP.md`**](./docs/SKILLS_SETUP.md).",
        "",
        "### 🛡️ The Three-Law Autonomous Agent Doctrine",
        "",
        "Every agent entry file ([`AGENTS.md`](./AGENTS.md), [`CLAUDE.md`](./CLAUDE.md), [`.cursorrules`](./.cursorrules), [`.github/copilot-instructions.md`](./.github/copilot-instructions.md), [`skills/`](./skills/), and [`mcp_server.py`](./scripts/mcp_server.py)) enforces three non-negotiable operational laws:",
        "",
        "| Law | Mandatory Agent Behavior | Technical Enforcement |",
        "| :--- | :--- | :--- |",
        "| **`Law 1 · 🟢 Turn-1 Passive Start`** | **Start passive hunting immediately on Turn 1 with zero clarifying questions.** | Runs 45+ passive public-cache/registry collectors + 18 offline DFIR & chronolocation decoders. **Zero packets touch target infrastructure.** |",
        "| **`Law 2 · 🔄 Exhaustive Multi-Stage Loop`** | **Never stop after finding 1 clue.** Collect everything in Stage 1, analyze all findings, and hunt every newly carved lead in Stage 2..N. | [`stage_analyzer.py`](./osint_hunter/stage_analyzer.py) carves handles, handle mutations, `wa.me`/E.164 phones, emails, domains, names & orgs until `converged: true`. |",
        f"| **`Law 3 · 🔴 Hard-Gated Active Recon`** | **ALWAYS ask explicit human permission before EVERY active run** — even if the prompt asked for \"full\" or \"active\" recon. | [`approval.py`](./osint_hunter/approval.py) enforces **single-use, target-bound, 15-min `ACT-XXXXXXXX` tokens** + append-only audit trail (`cases/active_audit.jsonl`). |",
        "",
        "<details>",
        "<summary><strong>🔌 Inspect All 13 Native MCP Tools (<code>scripts/mcp_server.py</code> &amp; <code>data/openai_tools.json</code>)</strong></summary>",
        "",
        "| MCP Tool | OPSEC | Purpose |",
        "| :--- | :---: | :--- |",
        "| `osint_auto_hunt` | 🟢 Passive | Turn-1 multi-stage passive hunt across any selector, URL, file path, or natural-language prompt |",
        "| `osint_ingest_and_expand_case` | 🟢 Passive | Carve external `web_search` / bio / Linktree text into an existing `CASE_ID` and hunt all new leads |",
        "| `osint_forensic_decode` | 🟢 Offline | Zero-network decoding for `.eml`, `.pcap`, `.har`, `.mp4`, PNG/C2PA/ComfyUI, Google `ei=`, SSH/PEM, TikTok, Snowflakes, UUIDs, IBAN, E.164, VIN, MAC |",
        "| `osint_compare_cases` | 🟢 Offline | Cross-case link analysis finding shared selectors, corporate domains, `/24` IPv4 subnets & analytics IDs |",
        "| `osint_diff_cases` | 🟢 Offline | Temporal attack-surface drift reporting newly added domains/IPs/identities & Exposure Score delta |",
        "| `osint_typosquat_permutations` | 🟢 Offline | Generate brand-impersonation, bitsquat, TLD-swap & `xn--` IDN Punycode homoglyph permutations |",
        "| `osint_prepare_active_hunt` | 🟢 0-Packet | Generate single-use `ACT-XXXXXXXX` token + OPSEC disclosure across `target` or `from_case` |",
        f"| `osint_execute_active_hunt` | 🔴 Active | Execute {act_mod_cnt} live TCP/TLS/HTTP/DNS/SSH/SMTP probes **only** with valid `request_id` + `user_confirmation` |",
        "| `osint_extract_selectors` | 🟢 Offline | Extract, normalize, and checksum-verify all 24 OSINT selector types from arbitrary text |",
        "| `osint_run_collector` | 🟢 Passive | Run passive collectors for one specific `(selector_type, value)` pair |",
        f"| `osint_query_arsenal` | 🟢 Offline | Search & filter all {len(tools)} verified OSINT tools by selector, discipline, pricing, tier, or OPSEC |",
        f"| `osint_forge_dorks` / `osint_get_playbook` | 🟢 Offline | Substitute targets into {len(dorks)} search dorks or retrieve any of the {len(workflows)} multi-phase playbooks |",
        "",
        "</details>",
        "",
        "---",
        "",
        "<a id=\"collectors-decoders\"></a>",
        "## 🧬 Built-In Collectors, Forensic Decoders & Active Probes",
        "",
        "### 1. Zero-Network Forensic & Chronolocation Decoders (`0` Packets Sent)",
        "",
        "| Artifact / Token | Decoder Mechanics | Intelligence Extracted Offline |",
        "| :--- | :--- | :--- |",
        "| **TikTok Video / Photo URL or ID** | 64-bit post ID bit-shift (`id >> 32`) | Exact **server-side UTC upload timestamp** (to the second), author handle & worker sequence |",
        "| **Google Search `ei=` URL / Token** | Little-endian protobuf varint/uint32 | Exact **UTC search execution timestamp** (down to microseconds) embedded in shared Google URLs |",
        "| **Email `.eml`, `.pcap`/`.pcapng` & `.har`** | RFC 5322 hop parser & raw packet carver | Transit hop delays, **SPF/DKIM/DMARC/Reply-To spoofing**, DNS queries, **TLS SNI**, HTTP hosts & cookies |",
        "| **Video `.mp4`/`.mov` & PNG/WebP/C2PA** | ISO BMFF `mvhd`/`©xyz` & JUMBF/tEXt | QuickTime creation UTC, **ISO-6709 GPS coordinates**, **C2PA Content Credentials**, & **ComfyUI / Stable Diffusion AI prompts** |",
        "| **OpenSSH Public Keys & X.509 PEM** | RFC 4253 wire parser & DER SHA-256 | `SHA256:...` & `MD5:...` key fingerprints, RSA modulus bit-length & leaked `user@host` key comments |",
        "| **Discord & X/Twitter Snowflakes** | 64-bit custom-epoch bit-shift (`id >> 22`) | Millisecond **UTC creation timestamp**, internal datacenter/worker ID, process ID & increment |",
        "| **UUIDv1 / UUIDv6 / UUIDv7** | RFC 4122 100ns Gregorian & RFC 9562 ms | Exact creation UTC + **generating machine's 48-bit IEEE MAC address & hardware OUI vendor** (v1) |",
        "| **ULID & MongoDB ObjectId** | 48-bit Crockford Base32 / 32-bit hex prefix | Millisecond UTC creation time (ULID) or second-level UTC + 5-byte machine/process hex & counter (ObjectId) |",
        "| **IBAN Bank Account (`ISO 13616`)** | 39-country length + `MOD-97-10` checksum | Checksum validity, country, BBAN & **Saudi SAMA bank resolution** (`Al Rajhi`, `SNB`, `Riyad`, `SAB`, `STC Bank`, etc.) |",
        "| **Phone Number (`ITU E.164`)** | Country calling code + carrier prefix tables | Country, line type, **US NANPA area state**, & **Saudi / UAE / Kuwait / Qatar / Bahrain / Oman / Egypt / UK** mobile carriers |",
        "| **Aircraft Mode-S ICAO24 Hex** | 24-bit ICAO registration block lookup | Registration country, airline/state block & **military / government / intelligence airframe flag** |",
        "| **Vessel MMSI & 7-Digit IMO** | Maritime `MID` prefix + IMO `MOD-10` check | Flag state, vessel transponders (coast station / SAR aircraft / craft) & verified IMO hull checksum |",
        "| **Vehicle 17-Char VIN (`ISO 3779`)** | WMI table + position-9 `MOD-11` check digit | Country of manufacture, automaker (`Tesla`, `Toyota`, `BMW`, ...), model year (`1980–2039`) & plant code |",
        "| **MAC Address / Wi-Fi BSSID** | IEEE OUI vendor table + U/L & I/G bitmask | Hardware manufacturer (`Apple`, `DJI`, `Cisco`, `VMware`, ...), randomized LA-MAC detection & multicast flag |",
        "| **JWT Bearer Token** | Base64URL header & payload inspection | Signing algorithm (`alg`), issuer (`iss`), subject (`sub`), audience, scopes & UTC `iat`/`exp` validity |",
        "| **Local Media, Docs & Binaries** | Pure-Python EXIF TIFF, ZIP/OOXML & PDF parser | **JPEG GPS coordinates**, camera serials, DOCX/XLSX `core.xml` authors, PDF `/Producer`, SHA-256 & carved IOCs |",
        "",
        "### 2. 45+ Live Passive Collectors + Optional BYOK Connectors (`collectors.py`, `modern_collectors.py`, `providers.py`)",
        "",
        "| Collection Domain | Live Zero-Target-Packet Collectors |",
        "| :--- | :--- |",
        "| **Developer & AI/Cloud Registries** | **GitHub API** + `.patch` commit email + `.keys` SSH + `.gpg` OpenPGP · **GitLab** · **npm** · **PyPI** · **HuggingFace Hub** models/datasets · **Crates.io** · **Docker Hub** · **Packagist** |",
        "| **Decentralized & Social Identity** | **Bluesky ATProto** + immutable **`plc.directory` handle-rename audit log** · **Mastodon Fediverse** + verified `rel=\"me\"` domains · **Keybase** proofs · **Reddit** · **HackerNews** · **Gravatar** |",
        "| **DNS, Cloud Tenant & Web Archives** | **Microsoft Entra ID / M365 Tenant** (`tenant_id` + Federated ADFS/Okta URL) · **Google DoH** + SPF/DMARC/BIMI · **`crt.sh`** CT SANs · **IANA RDAP** · **Wayback CDX** + sensitive path scan · **HackerTarget** |",
        "| **Network, CTI, Crypto & Optional BYOK** | **Shodan InternetDB** · **RIPEstat** BGP/ASN · **URLhaus** · **Nominatim** · **Mempool.space BTC** & **Ethereum RPC** · *Optional BYOK (`providers.py`)*: `SHODAN_API_KEY`, `VT_API_KEY`, `URLSCAN_API_KEY`, `HIBP_API_KEY`, `SECURITYTRAILS_API_KEY`, `ABUSEIPDB_API_KEY`, `GITHUB_TOKEN` |",
        "",
        "<details>",
        f"<summary><strong>🔴 Inspect All {act_mod_cnt} Hard-Gated Active Recon Probes (<code>osint_hunter/active_collectors.py</code> — Requires User Approval)</strong></summary>",
        "",
        "| # | Active Module ID | Applies To | Direct Network Probe & Extracted Intelligence |",
        "| :---: | :--- | :--- | :--- |",
    ]

    for idx, (mid, mmeta) in enumerate(ACTIVE_MODULES_CATALOG.items(), 1):
        applies = ", ".join(f"`{a}`" for a in mmeta["applies_to"])
        safe_impact = md_escape(mmeta["opsec_impact"]).replace("<", "`<").replace(">", ">`")
        lines.append(f"| **{idx:02d}** | `{mid}` | {applies} | **{md_escape(mmeta['title'])}** — {safe_impact} |")

    lines.extend(
        [
            "",
            "</details>",
            "",
            "---",
            "",
            "## 📦 11-Artifact Forensic Case & Graph Bundles",
            "",
            "Every hunt creates a tamper-evident, gitignored directory under `cases/<UTC_TIMESTAMP>_<TARGET_SLUG>/`:",
            "",
            "| Artifact | Format | Purpose |",
            "| :--- | :--- | :--- |",
            "| **`dossier.md`** | Markdown + Mermaid | Executive Synthesis, `0–100` Exposure Rating, Pattern-of-Life Timezone, Weighted Attribution Chains & Forged Dorks |",
            "| **`report.html`** | Standalone HTML5 + SVG | Single-file dark-mode executive briefing with interactive vector entity map & clean **Print-to-PDF** stylesheet |",
            "| **`graph.gexf` & `graph.graphml`** | Gephi 1.3 / GraphML | Color-coded, confidence-weighted link graphs ready to open directly in **Gephi, yEd, Cytoscape, or NetworkX** |",
            "| **`neo4j.cypher`** | Neo4j Cypher | Idempotent `MERGE` graph database import script creating `:OSINTCase`, `:OSINTEntity`, and `:PIVOTED_TO` edges |",
            "| **`obsidian/`** | Obsidian Vault | Interlinked Markdown notes (`00_Case_Index.md` + `[[Entity]]` WikiLinks) for **Obsidian Graph View** |",
            "| **`entities.csv`** | UTF-8 CSV | Flat spreadsheet export (`stage`, `type`, `value`, `source`, `via`) for **Excel, Maltego, or i2 Analyst's Notebook** |",
            "| **`stix2_bundle.json`** | OASIS STIX 2.1 | Standardized CTI graph (`identity`, `domain-name`, `ipv4-addr`, `autonomous-system`, `email-addr`, `user-account`, `relationship`) for **OpenCTI / MISP** |",
            "| **`report.json`, `graph.json`, `graph.mermaid`** | JSON + Mermaid | Full collector telemetry, temporal/confidence analytics, adjacency list & `flowchart LR` source |",
            "| **`manifest.sha256`** | SHA-256 Digest | Chain-of-custody cryptographic hashes over all generated case files |",
            "",
            "---",
            "",
            "<a id=\"web-command-center\"></a>",
            "## 🖥️ Clean Local Web Workspace & REST API",
            "",
            "Double-click **`Start-Web-UI.bat`** (Windows), **`Start-Web-UI.command`** (macOS), or run **`./start-web-ui.sh`** / `python3 scripts/server.py --port 8000` to launch the **clean 5-tab Local Browser Workspace** (`Investigate` · `Decode` · `Cases` · `Directory` · `Settings`) and the **JSON/HTML/Graph REST API**:",
            "",
            "| Method & Endpoint | Description |",
            "| :--- | :--- |",
            "| `GET  /api/health` · `/api/doctor` | Engine version (`2026.10.5`), catalog health, local CLI binary detection & configured BYOK providers |",
            "| `POST /api/detect` | Real-time 24-selector extraction & checksum validation (`{\"input\": \"...\"}`) |",
            "| `POST /api/decode` · `/api/decode/file` | Zero-network forensic & chronolocation decoding for text/URLs or uploaded binary DFIR files |",
            "| `POST /api/hunt` · `/api/hunt/file` | Exhaustive multi-stage passive hunt on any target string or uploaded file (`diff_last` supported) |",
            "| `POST /api/cases/expand` | Ingest external bios/snippets into a saved `case_id` and recursively hunt all newly carved leads |",
            "| `POST /api/cases/compare` · `/api/cases/diff` | Cross-case shared-entity link analysis or temporal attack-surface drift between two cases |",
            "| `GET  /api/cases` · `/api/cases/<ID>` | List recent investigations (with Exposure Scores) or load a complete saved case bundle |",
            "| `GET  /api/cases/<ID>/html` · `obsidian.zip` | Printable standalone HTML report or 1-click downloadable Obsidian `[[WikiLink]]` vault `.zip` |",
            "| `GET  /api/cases/<ID>/{gexf,graphml,cypher}` | Direct graph exports for Gephi (`.gexf`), yEd/Cytoscape (`.graphml`), and Neo4j (`.cypher`) |",
            "| `POST /api/typosquats` · `/api/graph/path` | Offline IDN Punycode lookalike domain generator & confidence-weighted shortest graph path tracer |",
            "| `GET  /api/watchlist` · `POST /api/watchlist/*` | Add, remove, or batch-sweep recurring watchlist targets with automatic drift calculation |",
            "| `POST /api/settings/byok` | Save or clear optional API keys locally in gitignored `.osint.env` with live hot-reload |",
            "| `POST /api/hunt/active/prepare` | Generate single-use `ACT-XXXXXXXX` approval request (supports `from_case` full-surface scoping; `0` packets) |",
            "| `POST /api/hunt/active` | Execute user-authorized Active+Passive hunt (enforces `X-Human-Modal-Confirmed: 1` + single-use token) |",
            "",
            "---",
            "",
            "<a id=\"disciplines\"></a>",
            f"## 📚 20 Intelligence Disciplines ({len(tools)} Verified Tools)",
            "",
            f"Open any discipline manual below for CLI `quick_start` one-liners, OPSEC guidance, and `Input → Output` pivot tags, or search the [**Single-Page {len(tools)}-Tool Master Index (`docs/FULL_INDEX.md`)**](./docs/FULL_INDEX.md).",
            "",
            "| # | Discipline | Tools | OPSEC Split | S-Tier | Flagship Tools |",
            "| :---: | :--- | :---: | :---: | :---: | :--- |",
        ]
    )

    for c in categories:
        c_tools = by_cat[c["id"]]
        c_pass = sum(1 for t in c_tools if t["opsec"] == "Passive")
        c_act = len(c_tools) - c_pass
        c_stier = sum(1 for t in c_tools if t["tier"] == "S")
        flagships = [t for t in c_tools if t["tier"] == "S"][:4] or c_tools[:3]
        flag_links = ", ".join(f"[{t['name']}]({t['url']})" for t in flagships)
        lines.append(
            f"| **{c['order']:02d}** | [{c['icon']} **{c['short_title']}**](./categories/{c['filename']}) (`{c['code']}`) | "
            f"**{len(c_tools)}** | `🟢{c_pass}` `🔴{c_act}` | `{c_stier}` | {flag_links} |"
        )

    lines.extend(
        [
            "",
            "<details>",
            f"<summary><strong>🗺️ Browse All {len(workflows)} End-to-End Investigation Playbooks (<code>docs/WORKFLOWS.md</code>)</strong></summary>",
            "",
            "| Playbook | Discipline | Difficulty | Seed Selector | Operational Objective |",
            "| :--- | :---: | :---: | :---: | :--- |",
        ]
    )
    for wf in workflows:
        lines.append(
            f"| [**{md_escape(wf['title'])}**](./docs/WORKFLOWS.md) (`{wf['id']}`) | `{wf['discipline']}` | `{wf['difficulty']}` | `{wf['starting_selector']}` | {md_escape(wf['summary'])} |"
        )
    lines.extend(
        [
            "",
            "</details>",
            "",
            "---",
            "",
            "<a id=\"pivot-matrix\"></a>",
            "## 🧭 24-Selector Pivot Matrix — *\"I Have X, Where Do I Start?\"*",
            "",
            "Full interactive chains in [**`docs/PIVOT_MATRIX.md`**](./docs/PIVOT_MATRIX.md) or via `python3 scripts/osint.py pivot <selector> --passive`.",
            "",
            "| Starting Selector | Tools | Top Passive Starting Stack | Primary Downstream Outputs |",
            "| :--- | :---: | :--- | :--- |",
        ]
    )

    for sel in SELECTOR_LABELS:
        if sel not in by_input:
            continue
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
            "## 🗂️ Repository Architecture",
            "",
            "```text",
            "OSINT/",
            "├── Start-Web-UI.bat · Start-Web-UI.command · start-web-ui.sh  # 1-Click Local Desktop Web Launchers",
            "├── osint_hunter/                                  # Zero-Dependency Python 3 Recon, DFIR & Graph Engine",
            "│   ├── classify.py                                # 24-selector regex + ISO/MOD-97/MOD-11 checksum classifier",
            "│   ├── offline_intel.py & dfir_forensics.py       # 18 offline decoders (.eml, .pcap, .har, .mp4, C2PA, TikTok, UUID, IBAN...)",
            "│   ├── collectors.py & modern_collectors.py       # 45+ passive collectors (GitHub, ATProto PLC, Mastodon, Entra M365, DoH, CT...)",
            "│   ├── providers.py                               # Optional BYOK connectors (Shodan, VT, urlscan, HIBP, SecurityTrails, AbuseIPDB)",
            "│   ├── stage_analyzer.py                          # Exhaustive multi-stage clue & handle-variant carver + noise filter",
            "│   ├── temporal.py & persona.py                   # 24h circadian timezone, shortest attribution paths, confidence & IDN typosquats",
            "│   ├── correlator.py & exporters.py               # Cross-stage synthesis, 0-100 Score, HTML/CSV/GEXF/GraphML/Cypher/Obsidian",
            "│   ├── watchlist.py                               # Recurring target watchlist & --diff-last attack-surface drift engine",
            "│   ├── active_collectors.py & approval.py         # 22 direct active probes + single-use ACT-XXXXXXXX cryptographic gate",
            "│   └── engine.py                                  # Orchestrator, STIX 2.1 builder & 11-artifact tamper-evident case writer",
            "├── scripts/                                       # CLI, Servers, Builder & CI Test Suite",
            "│   ├── hunt.py                                    # Autonomous hunter CLI (--depth, --resume-case, --decode, --diff-last, --typosquats)",
            "│   ├── osint.py                                   # Arsenal CLI (search, pivot, dorks, workflows, graveyard, decode, doctor)",
            "│   ├── server.py                                  # Local Web Workspace + 21-route JSON/HTML/Graph REST API server",
            "│   ├── mcp_server.py                              # 13-tool stdio JSON-RPC 2.0 Model Context Protocol server",
            "│   ├── install_skills.py                          # Zero-Node installer for Claude, Codex, Cursor & 75+ agents",
            "│   └── build.py / validate.py / selftest.py       # Deterministic multi-target generator, schema validator & integration tests",
            "├── web/                                           # Clean, minimal 5-tab Local Browser Workspace (Investigate, Decode, Cases, Directory, Settings)",
            "├── skills/osint-hunter & skills/osint-arsenal     # Portable standalone Agent Skills (work from any folder without repo)",
            "├── releases/*-skill.zip                           # Pre-built deterministic skill archives for Claude.ai & Claude Desktop",
            "├── .claude-plugin/ · .codex-plugin/ · .agents/    # Native Claude Code & OpenAI Codex plugin marketplace manifests",
            "├── AGENTS.md · CLAUDE.md · .cursorrules · .mcp.json # Three-Law autonomous agent protocols & auto-discovered MCP config",
            "├── data/                                          # tools (760), dorks (105), workflows (20), graveyard (25), openai_tools (13), osint.sqlite",
            "├── categories/01-*.md .. 20-*.md                  # 20 discipline field manuals with CLI quick-starts & OPSEC notes",
            "├── docs/                                          # FULL_INDEX, PIVOT_MATRIX, WORKFLOWS, DORKS_ARSENAL, GRAVEYARD_2026, SKILLS_SETUP, OPSEC",
            "└── pyproject.toml                                 # Optional pip install -e . entrypoints (osint-hunt, osint-arsenal, osint-server, osint-mcp)",
            "```",
            "",
            "---",
            "",
            f"## 🪦 Critical 2026 Hijacked & Retired Tool Warnings ([Full {len(graveyard)}-Entry Board →](./docs/GRAVEYARD_2026.md))",
            "",
            "- 🚨 **`telegago.com` IS HIJACKED** — Never visit the bare domain; bookmark **ONLY** the [**Official Google CSE URL**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) & [**TGStat**](https://tgstat.com/).",
            "- **Sentinel Hub EO Browser** *(Retired Mar 2026)* → [**Copernicus Data Space Browser**](https://browser.dataspace.copernicus.eu/) & [**NASA FIRMS**](https://firms.modaps.eosdis.nasa.gov/map/).",
            "- **GeoSpy (`geospy.ai`)** *(Public web closed Apr 2026)* → [**Picarta**](https://picarta.ai/), [**geo-sleuth**](https://github.com/Oldcircle/geo-sleuth), & [**Bellingcat OSM Search**](https://osm-search.bellingcat.com/).",
            "- **CrowdTangle / Pushshift / Samair / IntelTechniques Pastes** → [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library), [**Who Posted What?**](https://whopostedwhat.com/), & [**PullPush**](https://search.pullpush.io/).",
            "",
            "---",
            "",
            "## 🧪 Validation, Determinism & Legal Use",
            "",
            "```bash",
            "python3 scripts/validate.py   # Strict JSON Schema + URL + referential integrity check across all 760 tools",
            "python3 scripts/build.py      # Deterministically rebuild SQLite FTS5, manuals, skills, zip releases & README",
            "python3 scripts/selftest.py   # End-to-end tests: classifiers, decoders, multi-stage hunter, Active Gate, MCP & REST",
            "```",
            "",
            "Built strictly for **authorized security assessments, cyber threat intelligence (CTI), digital forensics (DFIR), journalistic verification, academic research, compliance due diligence, and lawful open-source investigations**. Review [**`docs/OPSEC_TRADECRAFT.md`**](./docs/OPSEC_TRADECRAFT.md) before active probing · [**MIT License**](./LICENSE) · [**Contributing**](./CONTRIBUTING.md).",
        ]
    )

    (ROOT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_deterministic_zip(skill_dir: Path, out_zip: Path) -> None:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(
        p
        for p in skill_dir.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.name != ".DS_Store"
        and not p.name.endswith(".pyc")
    )
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file_path in files:
            arcname = file_path.relative_to(skill_dir.parent).as_posix()
            info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_ZIP_DT)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if file_path.suffix == ".py" else 0o644) << 16
            zf.writestr(info, file_path.read_bytes())


def build_skills_and_packages(
    categories: list[dict],
    tools: list[dict],
    workflows: list[dict],
    dorks: list[dict],
    graveyard: list[dict],
    intel_tables: dict,
) -> None:
    license_txt = (ROOT / "LICENSE").read_text(encoding="utf-8")

    # ── 1. Build self-contained skills/osint-hunter ──────────────────────────
    hunter_dir = SKILLS_DIR / "osint-hunter"
    if hunter_dir.exists():
        shutil.rmtree(hunter_dir)
    (hunter_dir / "scripts" / "osint_hunter").mkdir(parents=True, exist_ok=True)
    (hunter_dir / "data").mkdir(parents=True, exist_ok=True)
    (hunter_dir / "agents").mkdir(parents=True, exist_ok=True)
    (hunter_dir / "references").mkdir(parents=True, exist_ok=True)

    (hunter_dir / "LICENSE.txt").write_text(license_txt, encoding="utf-8")
    shutil.copy2(ROOT / "scripts" / "hunt.py", hunter_dir / "scripts" / "hunt.py")
    for py_file in sorted((ROOT / "osint_hunter").glob("*.py")):
        shutil.copy2(py_file, hunter_dir / "scripts" / "osint_hunter" / py_file.name)

    for fname, obj in (
        ("tools.json", tools),
        ("workflows.json", workflows),
        ("dorks.json", dorks),
        ("intel_tables.json", intel_tables),
    ):
        (hunter_dir / "data" / fname).write_text(
            json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    (hunter_dir / "agents" / "openai.yaml").write_text(
        "\n".join(
            [
                "interface:",
                '  display_name: "OSINT Autonomous Hunter"',
                '  short_description: "Zero-question Passive OSINT + User-Gated Active Recon engine"',
                '  brand_color: "#00E5FF"',
                '  default_prompt: "Investigate @torvalds and https://github.com/torvalds using Passive OSINT and generate a forensic STIX 2.1 dossier."',
                "",
            ]
        ),
        encoding="utf-8",
    )

    hunter_skill_md = """---
name: osint-hunter
description: Autonomous multi-stage OSINT recon, DFIR forensics, and investigation engine. Use whenever the user provides a username, handle, email, phone number, domain, IP, ASN, URL, crypto wallet, 17-char VIN, aircraft ICAO hex, vessel IMO or MMSI, Wi-Fi BSSID, file hash, JWT, or local file (.eml, .pcap, .har, .mp4, .png, .jpg, .pdf, .docx) to investigate. Executes 45+ passive collectors and 18 offline decoders immediately on Turn 1 with zero clarifying questions, analyzes every stage to recursively hunt all newly discovered clues until surface convergence, and enforces a mandatory human permission gate before running 22 Active OSINT probes.
license: MIT
compatibility: Python 3.9+ standard library only (zero pip dependencies). Works standalone from any working directory in Claude Code, Codex, Cursor, Claude.ai, and 75+ agents.
---

# Autonomous OSINT Hunter (`osint-hunter`)

This skill bundles a complete, zero-dependency Python 3 OSINT execution engine (`scripts/hunt.py` + `scripts/osint_hunter/`) and offline lookup tables (`data/`). You can execute it from **any directory** without cloning the main repository.

## Locating `hunt.py`

Resolve the bundled `scripts/hunt.py` relative to this `SKILL.md` file (or via `${CLAUDE_SKILL_DIR}` when set):

```bash
HUNT_PY="${CLAUDE_SKILL_DIR:+${CLAUDE_SKILL_DIR}/scripts/hunt.py}"
if [ -z "$HUNT_PY" ] || [ ! -f "$HUNT_PY" ]; then
  for d in "./skills/osint-hunter" "$HOME/.claude/skills/osint-hunter" "$HOME/.codex/skills/osint-hunter" "$HOME/.agents/skills/osint-hunter" ".agents/skills/osint-hunter" ".claude/skills/osint-hunter" ".codex/skills/osint-hunter" "$HOME/.cursor/skills/osint-hunter" "/mnt/skills/user/osint-hunter" "/mnt/skills/private/osint-hunter"; do
    [ -f "$d/scripts/hunt.py" ] && HUNT_PY="$d/scripts/hunt.py" && break
  done
fi
```

---

## Law 1 & Law 2: Immediate Passive Start + Exhaustive Multi-Stage Surface Expansion

When the user supplies **any target** (handle, email, phone, domain, IP, ASN, URL, wallet, VIN, aircraft hex, vessel IMO/MMSI, BSSID, SHA-256, JWT, or local file):

1. **DO NOT ask clarifying questions.** Never stop after finding just 1 profile or 1 clue in a stage.
2. **Stage 1 — Exhaustive Seed Hunt** (runs up to 4 stages automatically across all collectors & handle variants, 0 packets sent to target servers):
   ```bash
   python3 "$HUNT_PY" "<target_or_prompt>" --depth 4
   ```
3. **Stage 2..N — Ingest Web/Search Findings & Hunt EVERY Newly Carved Clue Until Convergence**:
   - Run **all** forged search dorks (`report["forged_dorks"]`) via `web_search` / `fetch_page` to gather every bio, Linktree, WhatsApp `wa.me` phone, email, real name, company/clinic, and domain in Stage 1.
   - Feed **all** gathered text/snippets back into the case analyzer so it carves **every** new clue and hunts **all** of them across subsequent stages:
     ```bash
     python3 "$HUNT_PY" --resume-case <CASE_ID> --ingest-file <stage_findings.txt>
     ```
   - Repeat for any newly forged Stage-2/3 dorks until a stage yields **0 new unvisited target leads (`converged: true`)**.
   - Need zero-network DFIR, media provenance, or chronolocation decoding (`.eml`, `.pcap`/`.pcapng`, `.har`, `.mp4`/`.mov`, PNG/WebP C2PA & ComfyUI/SD, Google `ei=`, SSH/PEM, TikTok URL/ID, Discord/X Snowflake, UUIDv1/v6/v7, ULID, MongoDB ObjectId, IBAN, phone, VIN, ICAO24, IMO/MMSI, MAC)? Run `python3 "$HUNT_PY" --decode "<file_or_token>"`.
   - Need attack-surface drift, cross-case link analysis, or IDN Punycode typosquats? Run `--diff-last`, `--compare-cases <A> <B>`, or `--typosquats`.
4. Present the unified **Multi-Stage Intelligence Dossier** citing `./cases/<case_id>/` (`dossier.md`, `report.html`, `report.json`, `entities.csv`, `graph.gexf`, `graph.graphml`, `neo4j.cypher`, `obsidian/`, `stix2_bundle.json`, `manifest.sha256`).

---

## Law 3: Active OSINT — ALWAYS Ask User Permission Before Every Run (Hard Gate)

Active OSINT sends **direct TCP/TLS/HTTP/DNS/SMTP/SSH packets** across **22 built-in live probes** to target infrastructure.

**Even if the user explicitly asks for "full OSINT", "active recon", or "deep scan", you MUST ask for confirmation before EVERY single active run:**

1. **Step 1 — Prepare Single-Use Authorization Token Across the Full Discovered Surface (Sends ZERO Packets)**:
   ```bash
   python3 "$HUNT_PY" --prepare-active --from-case <CASE_ID>
   ```
   *(Or `python3 "$HUNT_PY" "<target>" --prepare-active`.)*
2. **Step 2 — Stop & Ask the User for Explicit Permission**:
   Use your platform's question/confirmation UI (e.g. `ask_user`) or ask clearly in chat, disclosing:
   - Single-use Request ID (`ACT-XXXXXXXX`) & all discovered target hosts/IPs/handles in scope
   - Planned active probing modules (from `--prepare-active` output)
   - OPSEC warning (target servers/WAF/IDS will log this machine's egress IP and TLS fingerprint)
3. **Step 3 — Execute ONLY After Explicit User Approval**:
   ```bash
   python3 "$HUNT_PY" "<target_from_plan>" --active --request-id ACT-XXXXXXXX --user-approved "<verbatim_user_reply>"
   ```
   Each `ACT-XXXXXXXX` token is **single-use**, **target-bound**, and expires in 15 minutes. A new active run always requires a fresh `--prepare-active` + fresh user approval.

For full collector and active-gate details, read `references/ACTIVE_GATE_AND_MODULES.md`.
"""
    (hunter_dir / "SKILL.md").write_text(hunter_skill_md, encoding="utf-8")

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from osint_hunter.approval import ACTIVE_MODULES_CATALOG

    mod_lines = [
        f"{idx}. `{mid}` — **{meta['title']}** (`{', '.join(meta['applies_to'])}`)"
        for idx, (mid, meta) in enumerate(ACTIVE_MODULES_CATALOG.items(), 1)
    ]
    (hunter_dir / "references" / "ACTIVE_GATE_AND_MODULES.md").write_text(
        "\n".join(
            [
                "# OSINT Hunter — Collector & Active Gate Reference",
                "",
                "## Passive Collectors & Offline DFIR Decoders (Law 1 — Instant, 0 Target Packets)",
                "- **Offline DFIR & Chronolocation Decoders**: `.eml` hop/SPF/DKIM/DMARC spoofing, `.pcap`/`.pcapng` DNS/SNI/HTTP carver, `.har`, `.mp4`/`.mov` `mvhd`+GPS, PNG/WebP C2PA Content Credentials & ComfyUI/Stable Diffusion AI provenance, Google Search `ei=` timestamp, OpenSSH/PEM fingerprints, TikTok/Snowflake/UUIDv1-v7/ULID/ObjectId UTC, ISO 13616 IBAN (SAMA), ITU E.164 phone + NANPA/GCC/MENA carriers, ICAO 24-bit hex + military block flag, Maritime IMO + MMSI MID, ISO 3779 VIN, IEEE OUI MAC/BSSID, JWT, JPEG EXIF GPS & PDF/OOXML authors.",
                "- **Passive Public APIs + Optional BYOK**: GitHub profile + `.patch` commit email + `.keys` SSH + `.gpg` OpenPGP, GitLab, HuggingFace Hub, Crates.io, Docker Hub, Packagist, npm, PyPI, Bluesky ATProto + `plc.directory` handle-rename audit, Mastodon `rel=me`, Keybase, Reddit, HackerNews, Gravatar, Microsoft Entra ID / M365 tenant, Google DoH + DMARC/SPF/BIMI, `crt.sh` CT SANs, IANA RDAP, Wayback CDX, HackerTarget, URLhaus, Shodan InternetDB, RIPEstat BGP/ASN, Nominatim, Mempool.space BTC & Ethereum RPC, plus optional BYOK (`SHODAN_API_KEY`, `VT_API_KEY`, `URLSCAN_API_KEY`, `HIBP_API_KEY`, `SECURITYTRAILS_API_KEY`, `ABUSEIPDB_API_KEY`, `GITHUB_TOKEN`).",
                "",
                f"## {len(ACTIVE_MODULES_CATALOG)} Gated Active Modules (Law 3 — Requires Single-Use `ACT-XXXXXXXX` Approval)",
                *mod_lines,
                "",
            ]
        ),
        encoding="utf-8",
    )

    # ── 2. Build self-contained skills/osint-arsenal ─────────────────────────
    arsenal_dir = SKILLS_DIR / "osint-arsenal"
    if arsenal_dir.exists():
        shutil.rmtree(arsenal_dir)
    (arsenal_dir / "scripts").mkdir(parents=True, exist_ok=True)
    (arsenal_dir / "data").mkdir(parents=True, exist_ok=True)
    (arsenal_dir / "agents").mkdir(parents=True, exist_ok=True)
    (arsenal_dir / "references").mkdir(parents=True, exist_ok=True)

    (arsenal_dir / "LICENSE.txt").write_text(license_txt, encoding="utf-8")
    shutil.copy2(ROOT / "scripts" / "osint.py", arsenal_dir / "scripts" / "osint.py")

    for fname, obj in (
        ("categories.json", categories),
        ("tools.json", tools),
        ("workflows.json", workflows),
        ("dorks.json", dorks),
        ("graveyard.json", graveyard),
    ):
        (arsenal_dir / "data" / fname).write_text(
            json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    (arsenal_dir / "agents" / "openai.yaml").write_text(
        "\n".join(
            [
                "interface:",
                f'  display_name: "OSINT {len(tools)}-Tool Arsenal & Dork Forge"',
                f'  short_description: "Search {len(tools)} OSINT tools (Passive & Active), selector pivots, playbooks & dorks"',
                '  brand_color: "#7C4DFF"',
                '  default_prompt: "Show me the top passive and active OSINT tools for a domain and forge target search dorks."',
                "",
            ]
        ),
        encoding="utf-8",
    )

    arsenal_skill_md = f"""---
name: osint-arsenal
description: Search and pivot across {len(tools)} verified OSINT tools, {len(categories)} intelligence disciplines, 24 input-to-output selector chains, {len(dorks)} Google/Shodan/Censys/FOFA/GitHub dorks, {len(workflows)} investigation playbooks, and 2026 dead or hijacked tool graveyard warnings. Use when selecting OSINT tools for any clue, planning investigation tradecraft, generating search engine dorks, or checking working replacements for retired tools.
license: MIT
compatibility: Python 3.9+ standard library only (zero pip dependencies). Also includes Markdown reference sheets for non-shell environments.
---

# OSINT {len(tools)}-Tool Arsenal, Pivot Advisor & Dork Forge (`osint-arsenal`)

This skill bundles the complete validated **{len(tools)}-tool OSINT Monster Database**, **{len(workflows)} multi-hop playbooks**, **{len(dorks)} search dorks**, and **2026 Graveyard warnings** inside `data/` + `scripts/osint.py`.

## Locating `osint.py`

```bash
OSINT_PY="${{CLAUDE_SKILL_DIR:+${{CLAUDE_SKILL_DIR}}/scripts/osint.py}}"
if [ -z "$OSINT_PY" ] || [ ! -f "$OSINT_PY" ]; then
  for d in "./skills/osint-arsenal" "$HOME/.claude/skills/osint-arsenal" "$HOME/.codex/skills/osint-arsenal" "$HOME/.agents/skills/osint-arsenal" ".agents/skills/osint-arsenal" ".claude/skills/osint-arsenal" ".codex/skills/osint-arsenal" "$HOME/.cursor/skills/osint-arsenal" "/mnt/skills/user/osint-arsenal" "/mnt/skills/private/osint-arsenal"; do
    [ -f "$d/scripts/osint.py" ] && OSINT_PY="$d/scripts/osint.py" && break
  done
fi
```

## Core Commands

```bash
# 1. Selector Pivot ("I have X, what passive free tools give me Y?")
python3 "$OSINT_PY" pivot email --passive --free
python3 "$OSINT_PY" pivot username --no-auth --tier S
python3 "$OSINT_PY" pivot domain --passive --limit 15

# 2. Full-Text Tool Search Across {len(tools)} Verified Tools
python3 "$OSINT_PY" search telegram --passive
python3 "$OSINT_PY" search satellite --free --no-auth
python3 "$OSINT_PY" search --category geoint-maps-satellites --tier S

# 3. Forge Target-Parameterized Google / Shodan / Censys / FOFA / GitHub Dorks
python3 "$OSINT_PY" dorks --target example.com
python3 "$OSINT_PY" dorks --engine Shodan --target example.com

# 4. Multi-Hop Investigation Playbooks & 2026 Dead/Hijacked Tool Graveyard
python3 "$OSINT_PY" workflows
python3 "$OSINT_PY" graveyard
python3 "$OSINT_PY" stats
```

## Supported Selector Types for `pivot`

`username`, `email`, `phone`, `person_name`, `domain`, `ip`, `asn`, `url`, `image`, `video`, `audio`, `coordinates`, `company`, `crypto_address`, `file_hash`, `vessel_imo`, `aircraft_hex`, `vin`, `mac_bssid`, `repo_code`, `onion_url`, `document`, `rf_frequency`, `keyword`.

## Bundled Markdown References (No-Shell Fallback)

If bash execution is unavailable, read directly from this skill directory:
- `references/PIVOT_CHEATSHEET.md` — Top specialist passive S-Tier starting stacks per selector
- `references/WORKFLOWS_QUICKREF.md` — {len(workflows)} multi-hop OSINT investigation playbooks
- `references/GRAVEYARD_2026.md` — Retired, paywalled, and hijacked OSINT domains to avoid (including the `telegago.com` hijack warning)
"""
    (arsenal_dir / "SKILL.md").write_text(arsenal_skill_md, encoding="utf-8")

    # Bundled lightweight Markdown references for osint-arsenal
    by_input: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        for inp in t["inputs"]:
            by_input[inp].append(t)

    piv_ref = [
        "# Selector Pivot Cheat Sheet (24 Selectors)",
        "",
        "| Selector | Tools | Specialist Passive Starting Stack | Primary Outputs |",
        "| :--- | :---: | :--- | :--- |",
    ]
    for sel in SELECTOR_LABELS:
        if sel not in by_input:
            continue
        matched = by_input[sel]
        top_s = pick_top_tools_for_selector(sel, matched, count=4)
        links = ", ".join(f"[{t['name']}]({t['url']})" for t in top_s)
        outs = Counter(o for t in matched for o in t["outputs"])
        out_str = ", ".join(f"`{k}`" for k, _ in outs.most_common(3))
        piv_ref.append(f"| `{sel}` ({SELECTOR_LABELS[sel][0]}) | `{len(matched)}` | {links} | {out_str} |")
    (arsenal_dir / "references" / "PIVOT_CHEATSHEET.md").write_text("\n".join(piv_ref) + "\n", encoding="utf-8")

    wf_ref = [f"# {len(workflows)} OSINT Investigation Playbooks", ""]
    for wf in workflows:
        wf_ref.append(f"## {wf['title']} (`{wf['id']}` — Seed: `{wf['starting_selector']}`)")
        wf_ref.append(f"*{wf['summary']}*")
        for s in wf["steps"]:
            wf_ref.append(f"{s['step']}. **{s['phase']}**: {s['action']} (`{', '.join(s['recommended_tools'])}`)")
        wf_ref.append("")
    (arsenal_dir / "references" / "WORKFLOWS_QUICKREF.md").write_text("\n".join(wf_ref) + "\n", encoding="utf-8")

    shutil.copy2(DOCS_DIR / "GRAVEYARD_2026.md", arsenal_dir / "references" / "GRAVEYARD_2026.md")

    # ── 3. Build deterministic zip packages for Claude.ai / Claude Desktop ───
    _write_deterministic_zip(hunter_dir, RELEASES_DIR / "osint-hunter-skill.zip")
    _write_deterministic_zip(arsenal_dir, RELEASES_DIR / "osint-arsenal-skill.zip")

    # ── 4. Build docs/SKILLS_SETUP.md ────────────────────────────────────────
    setup_md = f"""# 🧩 Agent Skills & Plugin Setup Guide (Claude, Codex, Cursor & 75+ Agents)

[⬅️ Back to Main Atlas](../README.md) · [`skills/osint-hunter`](../skills/osint-hunter/SKILL.md) · [`skills/osint-arsenal`](../skills/osint-arsenal/SKILL.md)

You do **not** need to clone or work inside this repository to use **OSINT Monster Database**. Both skills in [`skills/`](../skills/) bundle their own zero-dependency Python 3 runtime and compact intelligence datasets so they work **globally from any folder**.

---

## 📦 Included Skills

| Skill | Folder & Zip | What It Gives Your Agent |
| :--- | :--- | :--- |
| **`osint-hunter`** | [`skills/osint-hunter/`](../skills/osint-hunter/) · [`osint-hunter-skill.zip`](../releases/osint-hunter-skill.zip) | **Autonomous Recon & DFIR Engine**: Runs 45+ passive collectors & 18 offline DFIR/chronolocation decoders immediately on Turn 1 (zero questions), writes HTML/CSV/Gephi/Neo4j/Obsidian/STIX 2.1 + SHA-256 dossiers, and enforces a mandatory human permission gate (`ACT-XXXXXXXX`) before Active OSINT probing. |
| **`osint-arsenal`** | [`skills/osint-arsenal/`](../skills/osint-arsenal/) · [`osint-arsenal-skill.zip`](../releases/osint-arsenal-skill.zip) | **{len(tools)}-Tool Tradecraft & Dork Forge**: Searches all {len(tools)} verified tools, maps 24 `Input → Output` selector pivots, runs {len(workflows)} playbooks, forges {len(dorks)} Google/Shodan/Censys/FOFA/GitHub dorks, and flags 2026 hijacked/dead tools. |

---

## 1️⃣ Universal One-Liner (`npx skills` — 75+ Coding Agents)

Works with **Claude Code**, **OpenAI Codex**, **Cursor**, **OpenCode**, **Windsurf**, **Cline**, **GitHub Copilot**, **Goose**, **Roo**, **Kiro**, and 70+ other agents:

```bash
# Install both skills globally (auto-detects your installed agents)
npx skills add mafk21/OSINT -g

# Or target specific agents explicitly:
npx skills add mafk21/OSINT -g -a claude-code -a codex -a cursor

# Or install only one skill:
npx skills add mafk21/OSINT -g --skill osint-hunter
npx skills add mafk21/OSINT -g --skill osint-arsenal
```

---

## 2️⃣ Claude Code (Native `/plugin` Marketplace)

Inside any **Claude Code** session, register this repository as a plugin marketplace and install in two slash commands:

```text
/plugin marketplace add mafk21/OSINT
/plugin install osint-monster@osint-monster
```

*(Prefer installing just one? Run `/plugin install osint-hunter@osint-monster` or `/plugin install osint-arsenal@osint-monster`.)*

---

## 3️⃣ OpenAI Codex (CLI & Codex App)

### Method A — Codex Built-in `$skill-installer`
Paste either or both commands directly into **Codex**:

```text
$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-hunter
$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-arsenal
```
*(Restart Codex after installation so it picks up the newly installed skills + `agents/openai.yaml` metadata.)*

### Method B — `npx skills` Targeting Codex
```bash
npx skills add mafk21/OSINT -g -a codex
```

### Method C — Codex Plugin Manifest
This repo also ships native OpenAI Codex plugin manifests ([`.codex-plugin/plugin.json`](../.codex-plugin/plugin.json) and [`.agents/plugins/marketplace.json`](../.agents/plugins/marketplace.json)) bundling both `./skills/` and `./.mcp.json`.

---

## 4️⃣ Claude.ai Web & Claude Desktop (Drag-and-Drop `.zip` Upload)

For **Claude Pro, Max, Team, and Enterprise** users on **claude.ai** or **Claude Desktop**:

1. Download the pre-packaged skill archives from [`releases/`](../releases/):
   - [**`releases/osint-hunter-skill.zip`**](../releases/osint-hunter-skill.zip)
   - [**`releases/osint-arsenal-skill.zip`**](../releases/osint-arsenal-skill.zip)
2. Open Claude → **Settings → Capabilities → Skills** (ensure Code Execution is enabled).
3. Click **Upload skill** and select each `.zip` file.
4. Start any chat and drop a handle, domain, email, VIN, aircraft hex, or investigation question!

---

## 5️⃣ Zero-Node Pure-Python Local Installer (`install_skills.py`)

Don't want to use Node/`npx`? Run the zero-dependency Python installer from a local clone:

```bash
# Install globally to ~/.claude/skills, ~/.codex/skills, ~/.cursor/skills & ~/.agents/skills
python3 scripts/install_skills.py --all

# Or install only to Claude Code or Codex
python3 scripts/install_skills.py --claude
python3 scripts/install_skills.py --codex

# Or install into a specific case/project folder
python3 scripts/install_skills.py --project ~/investigations/case-2026

# Check installation status or uninstall cleanly
python3 scripts/install_skills.py --list
python3 scripts/install_skills.py --uninstall --all
```

---

## 6️⃣ Alternative: Global MCP Server Registration (13 Tools)

If you also want all 13 native Model Context Protocol tools (`osint_auto_hunt`, `osint_ingest_and_expand_case`, `osint_forensic_decode`, `osint_compare_cases`, `osint_diff_cases`, `osint_typosquat_permutations`, `osint_prepare_active_hunt`, `osint_execute_active_hunt`, `osint_query_arsenal`, `osint_forge_dorks`, etc.) exposed directly to your agent:

```bash
# Claude Code global MCP registration
claude mcp add --scope user osint-monster -- python3 /absolute/path/to/OSINT/scripts/mcp_server.py

# OpenAI Codex global MCP registration
codex mcp add osint-monster -- python3 /absolute/path/to/OSINT/scripts/mcp_server.py
```

---

## 🛡️ How the Three-Law Safety Doctrine Works Inside Skills

- **`Law 1 · 🟢 Passive Mode` (Default — Zero Questions)**: Give Claude or Codex any target or file (`"Investigate @torvalds and +966501234567"`). The `osint-hunter` skill immediately runs passive collection on Turn 1 without asking clarifying questions and writes an 11-artifact forensic bundle into `./cases/<case_id>/`.
- **`Law 2 · 🔄 Exhaustive Multi-Stage Loop` (Never Stop After One Hit)**: Collects all findings in Stage 1, feeds search/bio leads back via `--resume-case <CASE_ID> --ingest-file`, and hunts every newly carved clue across Stage 2..N until `converged: true`.
- **`Law 3 · 🔴 Active Mode` (Hard-Gated — Always Asks First)**: Even if you say `"Run active recon on example.com"`, the skill **cannot** send direct packets until it first runs `--prepare-active`, shows you the exact hosts + OPSEC exposure, waits for your explicit approval, and consumes a single-use `ACT-XXXXXXXX` token.
"""
    (DOCS_DIR / "SKILLS_SETUP.md").write_text(setup_md, encoding="utf-8")


def main() -> int:
    val = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate.py")], cwd=str(ROOT))
    if val.returncode != 0:
        return val.returncode

    categories = load_json("categories.json")
    tools = load_json("tools.json")
    workflows = load_json("workflows.json")
    dorks = load_json("dorks.json")
    graveyard = load_json("graveyard.json")
    intel_tables = load_json("intel_tables.json")

    build_exports(categories, tools, workflows, dorks, graveyard)
    build_category_pages(categories, tools)
    build_docs(categories, tools, workflows, dorks, graveyard)
    build_skills_and_packages(categories, tools, workflows, dorks, graveyard, intel_tables)
    build_readme(categories, tools, workflows, dorks, graveyard)

    print("Build complete:")
    print(f"  - README.md + 20 category manuals in categories/")
    print(f"  - 6 tactical manuals in docs/ (SKILLS_SETUP, FULL_INDEX, PIVOT_MATRIX, WORKFLOWS, DORKS_ARSENAL, GRAVEYARD_2026)")
    print(f"  - 2 portable Agent Skills in skills/ (osint-hunter, osint-arsenal) + zip bundles in releases/")
    print(f"  - Multi-format data exports: data/tools.csv, data/tools.jsonl, data/osint.sqlite (FTS5)")
    print(f"  - Web Explorer bundle: web/data.js")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

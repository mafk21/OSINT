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
        s_tools = [t for t in matched if t["tier"] == "S"][:4]
        if not s_tools:
            s_tools = matched[:3]
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


def build_readme(categories, tools, workflows, dorks, graveyard) -> None:
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        by_cat[t["category"]].append(t)

    by_input: dict[str, list[dict]] = defaultdict(list)
    for t in tools:
        for inp in t["inputs"]:
            by_input[inp].append(t)

    s_cnt = sum(1 for t in tools if t["tier"] == "S")
    passive_cnt = sum(1 for t in tools if t["opsec"] == "Passive")
    free_cnt = sum(1 for t in tools if t["pricing"] in ("Free / Open Source", "Free"))
    oss_cnt = sum(1 for t in tools if t["github"])
    no_auth_cnt = sum(1 for t in tools if not t["auth_required"])

    lines: list[str] = [
        "<div align=\"center\">",
        "",
        "# 🛰️ OSINT MONSTER DATABASE",
        "",
        "### The Multi-Format Open-Source Intelligence Arsenal, Selector Pivot Engine & Field Manual",
        "",
        f"![Verified Tools](https://img.shields.io/badge/Verified_Tools-{len(tools)}-00e5ff?style=for-the-badge) "
        f"![Disciplines](https://img.shields.io/badge/Disciplines-{len(categories)}-7c4dff?style=for-the-badge) "
        f"![Passive Tools](https://img.shields.io/badge/Passive_Safe-{passive_cnt}-00e676?style=for-the-badge) "
        f"![Open Source](https://img.shields.io/badge/GitHub_Repos-{oss_cnt}-ffab00?style=for-the-badge) "
        "![Formats](https://img.shields.io/badge/Formats-MD_%7C_JSON_%7C_CSV_%7C_SQLite_FTS5_%7C_CLI_%7C_Web-ff5252?style=for-the-badge)",
        "",
        "[**⚡ Zero-Question Agent Protocol (`AGENTS.md`)**](./AGENTS.md) · "
        "[**🧭 Selector Pivot Matrix**](./docs/PIVOT_MATRIX.md) · "
        "[**🗺️ 12 Investigation Playbooks**](./docs/WORKFLOWS.md) · "
        "[**🎯 56 Dorks Arsenal**](./docs/DORKS_ARSENAL.md) · "
        "[**🪦 2026 Graveyard & Replacements**](./docs/GRAVEYARD_2026.md) · "
        "[**🛡️ OPSEC Tradecraft**](./docs/OPSEC_TRADECRAFT.md) · "
        "[**➕ Contributing**](./CONTRIBUTING.md)",
        "",
        "</div>",
        "",
        "---",
        "",
        "## ⚡ Why This Is a Monster Database (Not Just a Link List)",
        "",
        f"Most `awesome-osint` repositories are flat lists of unverified links riddled with dead 2019 tools and zero operational context. **OSINT Monster Database** is engineered as a **single-source-of-truth intelligence system** spanning **{len(tools)} strictly validated active tools** across **{len(categories)} intelligence disciplines**:",
        "",
        f"- **OPSEC-Classified**: Every single tool is tagged `🟢 Passive` (**{passive_cnt}** tools — zero packets to target), `🟡 Hybrid`, or `🔴 Active`, plus whether login/API keys are required (**{no_auth_cnt}** keyless/no-auth tools).",
        "- **Selector Pivot Architecture**: Query by *what evidence you hold right now* (`email`, `username`, `phone`, `domain`, `ip`, `image`, `crypto_address`, `vessel_imo`, `aircraft_hex`, `vin`, `mac_bssid`, `onion_url`, …) and see what downstream intelligence it unlocks.",
        "- **Every Format Built-In**:",
        "  - 📄 **GitHub Markdown**: Full 540-tool `Ctrl+F` index below + 20 extended discipline manuals in [`categories/`](./categories/)",
        "  - 🗃️ **Relational SQLite 3 + FTS5**: [`data/osint.sqlite`](./data/osint.sqlite) ready for instant SQL & full-text search",
        "  - 📦 **Machine-Readable Exports**: [`data/tools.json`](./data/tools.json), [`data/tools.csv`](./data/tools.csv), [`data/tools.jsonl`](./data/tools.jsonl), validated by [`data/schema.json`](./data/schema.json)",
        "  - 💻 **Zero-Dependency Python CLI**: [`scripts/osint.py`](./scripts/osint.py) for terminal search, selector pivoting, and target-substituted dorks",
        "  - 🖥️ **Interactive Web Explorer**: [`web/index.html`](./web/index.html) dark-ops analyst dashboard with multi-facet filtering, pivot chips, playbooks, and custom case-loadout export",
        "",
        "---",
        "",
        "## 🤖 Autonomous Agent-Ready Architecture (Zero Questions Asked)",
        "",
        "Connect **Claude Code, OpenAI Codex, Cursor, Windsurf, Cline, OpenClaw, Arena Agent, LangGraph, or any MCP host** directly to this repository and drop **any** target (`@handle`, `email`, `domain`, `IP`, `phone`, `crypto_address`, `GitHub repo`, `VIN`, `aircraft ICAO hex`, `vessel IMO/MMSI`, `MAC/BSSID`, `JWT`, `file path`, or natural-language prompt):",
        "",
        "- **Two-Law Agent Doctrine ([`AGENTS.md`](./AGENTS.md) · [`CLAUDE.md`](./CLAUDE.md) · [`.cursorrules`](./.cursorrules) · [`SKILL.md`](./SKILL.md))**:\n"
        "  1. **`🟢 Passive Mode` (Default — Zero Questions)**: Connected agents start hunting immediately on Turn 1 without asking clarifying questions.\n"
        "  2. **`🔴 Active Mode` (Mandatory User-Approval Gate)**: Hard-enforced in [`osint_hunter/approval.py`](./osint_hunter/approval.py) — **ALWAYS asks the user for explicit permission before every single Active OSINT run** via single-use, target-bound `ACT-XXXXXXXX` approval tokens and logs to `cases/active_audit.jsonl`.",
        "- **Passive + Active Collector Suite ([`scripts/hunt.py`](./scripts/hunt.py) & [`osint_hunter/`](./osint_hunter/))**:\n"
        "  - **Passive (`35+` collectors & decoders)**: GitHub profile/commit-email/timezone/SSH/PGP packet carving, npm/PyPI maintainer attribution, 20-site handle probes, DoH DNS, `crt.sh` CT, RDAP, Wayback CDX, Shodan InternetDB, RIPEstat BGP, Tor Onionoo, Gravatar, Proton HKP, Mempool BTC, DexScreener EVM, ITU E.164 phone/carrier, ICAO military/gov hex blocks, Maritime MID & shadow-fleet flags, ISO 3779 VIN, IEEE OUI/EUI-64, JPEG EXIF GPS + DOCX/PDF carving.\n"
        "  - **Active (`7` direct probes — user-gated)**: Live TLS `:443` X.509 SAN & SHA-256 cert inspector, HTTP redirect/security-header/CSP-domain/GA4-GTM tracker fingerprinter, `/robots.txt` + `/.well-known/security.txt` + OpenID tenant harvester, live `/favicon.ico` **Shodan `mmh3` hash calculator**, TCP service banner reader, live DNS/PTR resolver, and JSON-LD `sameAs` social-graph extractor.",
        "- **Native MCP Server ([`.mcp.json`](./.mcp.json) · [`scripts/mcp_server.py`](./scripts/mcp_server.py)) + HTTP REST/MCP ([`scripts/server.py`](./scripts/server.py))**: Plugs into any MCP client over `stdio` or Streamable HTTP (`POST /api/mcp`), plus `POST /api/hunt` returning **Markdown Dossiers, Entity Graphs, OASIS STIX 2.1 Bundles, and SHA-256 Evidence Manifests** in `cases/`.",
        "- **Function-Calling Schemas ([`data/openai_tools.json`](./data/openai_tools.json))**: Drop-in JSON tool definitions for OpenAI, Anthropic, Gemini, and LangChain SDKs.",
        "",
        "---",
        "",
        "## 🚀 Quick Start: Autonomous Hunt, MCP, CLI, SQLite & Live Web UI",
        "",
        "```bash",
        "# 1. Passive Mode (Default — Zero Questions, Zero Target Packets)",
        "python3 scripts/hunt.py \"@torvalds, +966501234567, aircraft AE01D5, MMSI 613123456, VIN 5YJ3E1EA7KF317000\"",
        "",
        "# 2. Active Mode (ALWAYS Asks Permission First — Single-Use Request ID Gate)",
        "python3 scripts/hunt.py \"github.com\" --prepare-active",
        "python3 scripts/hunt.py \"github.com\" --active --request-id ACT-XXXXXXXX --user-approved \"yes\"",
        "",
        "# 3. Launch Interactive Command Center + Live Hunt API + HTTP MCP Server (http://0.0.0.0:8000)",
        "python3 scripts/server.py --port 8000",
        "",
        "# 3. Terminal Arsenal CLI (540 Tools, 24 Selectors, 56 Dorks, 12 Playbooks)",
        "python3 scripts/osint.py stats",
        "python3 scripts/osint.py pivot email --passive --free",
        "python3 scripts/osint.py dorks --engine Shodan --target example.com",
        "",
        "# 4. Query the SQLite FTS5 Database directly",
        "python3 -c \"import sqlite3; c=sqlite3.connect('data/osint.sqlite'); print(c.execute(\\\"SELECT name, url FROM tools_fts JOIN tools USING(id) WHERE tools_fts MATCH 'infostealer OR ransomware'\\\").fetchall())\"",
        "```",
        "",
        "---",
        "",
        "## 🧭 Quick Pivot Matrix — \"I Have an X, Where Do I Start?\"",
        "",
        "Full 24-selector breakdown in [**`docs/PIVOT_MATRIX.md`**](./docs/PIVOT_MATRIX.md).",
        "",
        "| Starting Evidence (Selector) | Tools | Top Passive / S-Tier Starting Stack | Pivots Into |",
        "| :--- | :---: | :--- | :--- |",
    ]

    featured_pivots = [
        "username",
        "email",
        "phone",
        "person_name",
        "domain",
        "ip",
        "image",
        "video",
        "coordinates",
        "company",
        "crypto_address",
        "vessel_imo",
        "aircraft_hex",
        "vin",
        "mac_bssid",
        "file_hash",
        "repo_code",
        "onion_url",
    ]
    for sel in featured_pivots:
        matched = by_input[sel]
        top_s = [t for t in matched if t["tier"] == "S"][:4] or matched[:3]
        links = ", ".join(f"[**{t['name']}**]({t['url']})" for t in top_s)
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
            "## 📚 20 Intelligence Disciplines — Master Navigation",
            "",
            "| # | Code | Discipline | Tools | S-Tier | Deep-Dive Manual (with CLI Commands) |",
            "| :---: | :--- | :--- | :---: | :---: | :--- |",
        ]
    )

    for c in categories:
        c_tools = by_cat[c["id"]]
        c_s = sum(1 for t in c_tools if t["tier"] == "S")
        anchor = f"{c['order']:02d}-{c['id']}"
        lines.append(
            f"| **{c['order']:02d}** | `{c['code']}` | [{c['icon']} **{c['short_title']}**](#{anchor}) | "
            f"**{len(c_tools)}** | `{c_s}` | [`categories/{c['filename']}`](./categories/{c['filename']}) |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 🗂️ Complete 540-Tool Master Directory",
            "",
            "Legend: **`S`** = Industry Gold Standard · **`A`** = Best-in-Class Specialist · **`B`** = Tactical / Regional · "
            "`🟢 Passive` = Zero packets sent to target · `🟡 Hybrid` = Configurable · `🔴 Active` = Touches target · "
            "✅ = No Login/Key Required · 🔑 = Account or API Key Required.",
            "",
        ]
    )

    for c in categories:
        c_tools = by_cat[c["id"]]
        anchor = f"{c['order']:02d}-{c['id']}"
        lines.append(f"<a id=\"{anchor}\"></a>")
        lines.append(f"### {c['icon']} {c['order']:02d}. {c['title']} (`{c['code']}`)")
        lines.append("")
        lines.append(
            f"*{c['description']}* — [**Open Extended Manual & CLI Quick-Starts (`{len(c_tools)}` tools) →**](./categories/{c['filename']})"
        )
        lines.append("")
        lines.append("| Tier | Tool | Subcategory | Type | Pricing | OPSEC | Auth | Description |")
        lines.append("| :---: | :--- | :--- | :--- | :--- | :--- | :---: | :--- |")
        for t in c_tools:
            gh = f" · [GH](https://github.com/{t['github']})" if t["github"] else ""
            auth_icon = "🔑" if t["auth_required"] else "✅"
            lines.append(
                f"| **{t['tier']}** | [**{md_escape(t['name'])}**]({t['url']}){gh} | {md_escape(t['subcategory'])} | "
                f"{t['type']} | {pricing_short(t['pricing'])} | {opsec_badge(t['opsec'])} | {auth_icon} | {md_escape(t['description'])} |"
            )
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 🪦 Notable Retired / Hijacked OSINT Tools (2026 Quick Check)",
            "",
            "Full breakdown in [**`docs/GRAVEYARD_2026.md`**](./docs/GRAVEYARD_2026.md).",
            "",
            "- **Sentinel Hub EO Browser** *(Retired Mar 2026)* → Use [**Copernicus Data Space Browser**](https://browser.dataspace.copernicus.eu/)",
            "- **GeoSpy (`geospy.ai`)** *(Public access closed Apr 2026)* → Use [**Picarta**](https://picarta.ai/), [**geo-sleuth**](https://github.com/Oldcircle/geo-sleuth), & [**Bellingcat OSM Search**](https://osm-search.bellingcat.com/)",
            "- **CrowdTangle** *(Shut down Aug 2024)* → Use [**Meta Content Library**](https://transparency.meta.com/researchtools/meta-content-library) & [**Who Posted What?**](https://whopostedwhat.com/)",
            "- **Pushshift / Camas / Unddit** *(Revoked 2023)* → Use [**PullPush**](https://search.pullpush.io/) & [**Arctic Shift**](https://arctic-shift.photon-reddit.com/)",
            "- **`telegago.com`** *(⚠️ Domain Hijacked!)* → Use ONLY the [**Official Google CSE Link**](https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg) & [**TGStat**](https://tgstat.com/)",
            "- **Google `cache:` Operator** *(Retired 2024)* → Use [**Wayback Machine**](https://web.archive.org/), [**archive.today**](https://archive.ph/), & [**Memento TimeTravel**](http://timetravel.mementoweb.org/)",
            "",
            "---",
            "",
            "## ⚖️ Legal & Ethical Use Notice",
            "",
            "All tools, playbooks, and search operators in this repository are compiled strictly for **authorized security assessments, cyber threat intelligence, journalistic verification, academic research, human-rights documentation, compliance/KYC due diligence, and lawful open-source investigations**. Always verify legal authorization and OPSEC impact ([`docs/OPSEC_TRADECRAFT.md`](./docs/OPSEC_TRADECRAFT.md)) before running active reconnaissance.",
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
    print(f"  - 4 tactical manuals in docs/ (PIVOT_MATRIX, WORKFLOWS, DORKS_ARSENAL, GRAVEYARD_2026)")
    print(f"  - Multi-format data exports: data/tools.csv, data/tools.jsonl, data/osint.sqlite (FTS5)")
    print(f"  - Web Explorer bundle: web/data.js")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

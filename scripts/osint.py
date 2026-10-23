#!/usr/bin/env python3
"""OSINT Monster Database CLI — Search, Selector Pivot, Dork Generator & Workflow Engine."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


def load_data():
    with (DATA_DIR / "categories.json").open("r", encoding="utf-8") as f:
        categories = json.load(f)
    with (DATA_DIR / "tools.json").open("r", encoding="utf-8") as f:
        tools = json.load(f)
    with (DATA_DIR / "workflows.json").open("r", encoding="utf-8") as f:
        workflows = json.load(f)
    with (DATA_DIR / "dorks.json").open("r", encoding="utf-8") as f:
        dorks = json.load(f)
    with (DATA_DIR / "graveyard.json").open("r", encoding="utf-8") as f:
        graveyard = json.load(f)
    return categories, tools, workflows, dorks, graveyard


def filter_tools(tools, *, category=None, opsec=None, free_only=False, no_auth=False, tier=None, tool_type=None):
    out = tools
    if category:
        q = category.lower()
        out = [t for t in out if q in t["category"].lower() or q in t["subcategory"].lower()]
    if opsec:
        out = [t for t in out if t["opsec"].lower() == opsec.lower()]
    if free_only:
        out = [t for t in out if t["pricing"] in ("Free / Open Source", "Free")]
    if no_auth:
        out = [t for t in out if not t["auth_required"]]
    if tier:
        out = [t for t in out if t["tier"].upper() == tier.upper()]
    if tool_type:
        out = [t for t in out if tool_type.lower() in t["type"].lower()]
    return out


def format_tool_row(t: dict) -> str:
    auth_flag = "Key/Login" if t["auth_required"] else "No-Auth"
    return (
        f"[{t['tier']}] {t['name']} ({t['id']})\n"
        f"    URL      : {t['url']}\n"
        f"    Category : {t['category']} > {t['subcategory']}\n"
        f"    Profile  : {t['type']} | {t['pricing']} | OPSEC: {t['opsec']} | {auth_flag}\n"
        f"    Inputs   : {', '.join(t['inputs'])}  -->  Outputs: {', '.join(t['outputs'])}\n"
        f"    Summary  : {t['description']}\n"
        f"    QuickUse : {t['quick_start']}"
    )


def cmd_stats(args, categories, tools, workflows, dorks, graveyard) -> int:
    print("=" * 78)
    print("  OSINT MONSTER DATABASE — TELEMETRY SUMMARY")
    print("=" * 78)
    print(f"  Verified Active Tools     : {len(tools)}")
    print(f"  Intelligence Disciplines  : {len(categories)}")
    print(f"  Investigation Playbooks   : {len(workflows)}")
    print(f"  Search Engine Dorks       : {len(dorks)}")
    print(f"  Graveyard / Replaced      : {len(graveyard)}")
    print("-" * 78)

    tiers = Counter(t["tier"] for t in tools)
    opsecs = Counter(t["opsec"] for t in tools)
    pricings = Counter(t["pricing"] for t in tools)
    no_auth_cnt = sum(1 for t in tools if not t["auth_required"])
    oss_cnt = sum(1 for t in tools if t["github"])

    print(f"  Tiers   : S-Tier={tiers['S']} | A-Tier={tiers['A']} | B-Tier={tiers['B']}")
    print(f"  OPSEC   : Passive={opsecs['Passive']} | Hybrid={opsecs['Hybrid']} | Active={opsecs['Active']}")
    print(
        f"  Pricing : Open-Source={pricings['Free / Open Source']} | Free={pricings['Free']} | "
        f"Freemium={pricings['Freemium']} | Paid={pricings['Paid']}"
    )
    print(f"  Access  : No-Auth Ready={no_auth_cnt} ({no_auth_cnt * 100 // len(tools)}%) | GitHub-Backed={oss_cnt}")
    print("-" * 78)
    print(f"  {'#':>2}  {'CODE':<10} {'DISCIPLINE':<44} {'TOOLS':>5}")
    print("-" * 78)
    cat_counts = Counter(t["category"] for t in tools)
    for c in categories:
        print(f"  {c['order']:>2}  {c['code']:<10} {c['short_title']:<44} {cat_counts[c['id']]:>5}")
    print("=" * 78)
    return 0


def cmd_search(args, categories, tools, *_rest) -> int:
    pool = filter_tools(
        tools,
        category=args.category,
        opsec=args.opsec,
        free_only=args.free,
        no_auth=args.no_auth,
        tier=args.tier,
        tool_type=args.type,
    )
    terms = [q.lower() for q in (args.query or [])]
    matched = []
    for t in pool:
        haystack = " ".join(
            [
                t["id"],
                t["name"],
                t["category"],
                t["subcategory"],
                t["description"],
                t["type"],
                " ".join(t["tags"]),
                " ".join(t["inputs"]),
                " ".join(t["outputs"]),
                t["quick_start"],
            ]
        ).lower()
        if all(term in haystack for term in terms):
            matched.append(t)

    if args.json:
        print(json.dumps(matched[: args.limit], indent=2, ensure_ascii=False))
        return 0

    print(f"Matched {len(matched)} tool(s)" + (f" (showing top {min(len(matched), args.limit)})" if matched else ""))
    print("-" * 78)
    for t in matched[: args.limit]:
        print(format_tool_row(t))
        print("-" * 78)
    return 0


def cmd_pivot(args, _categories, tools, *_rest) -> int:
    all_inputs = Counter(inp for t in tools for inp in t["inputs"])
    if args.list or not args.selector:
        print("Available Input Selectors (Pivot Starting Points):")
        for sel, cnt in sorted(all_inputs.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {sel:<18} ({cnt:>3} tools)")
        return 0

    selector = args.selector.strip().lower()
    if selector not in all_inputs:
        print(f"Unknown selector '{selector}'. Run with --list to inspect valid selectors.", file=sys.stderr)
        return 1

    opsec_val = args.opsec or ("Passive" if args.passive else None)
    pool = filter_tools(
        tools,
        opsec=opsec_val,
        free_only=args.free,
        no_auth=args.no_auth,
        tier=args.tier,
    )
    matched = [t for t in pool if selector in t["inputs"]]
    downstream = Counter(out for t in matched for out in t["outputs"])

    if args.json:
        print(json.dumps(matched[: args.limit], indent=2, ensure_ascii=False))
        return 0

    print("=" * 78)
    print(f"  SELECTOR PIVOT: '{selector}'  ->  {len(matched)} matching tool(s)")
    print(f"  Downstream Intelligence Outputs: {', '.join(k for k, _ in downstream.most_common(10))}")
    print("=" * 78)
    for t in matched[: args.limit]:
        print(format_tool_row(t))
        print("-" * 78)
    return 0


def cmd_info(args, _categories, tools, *_rest) -> int:
    by_id = {t["id"]: t for t in tools}
    tool = by_id.get(args.tool_id.lower())
    if not tool:
        print(f"Tool '{args.tool_id}' not found.", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(tool, indent=2, ensure_ascii=False))
    else:
        print("=" * 78)
        print(format_tool_row(tool))
        if tool["github"]:
            print(f"    GitHub   : https://github.com/{tool['github']}")
        print(f"    Platforms: {', '.join(tool['platforms'])}")
        print(f"    Tags     : {', '.join(tool['tags'])}")
        print("=" * 78)
    return 0


def cmd_workflows(args, _categories, tools, workflows, *_rest) -> int:
    by_id = {t["id"]: t for t in tools}
    if not args.workflow_id:
        print("OSINT Investigation Playbooks:")
        for wf in workflows:
            print(f"  - {wf['id']:<42} [{wf['discipline']}] ({wf['difficulty']})")
            print(f"    Start: {wf['starting_selector']} | {wf['title']}")
        return 0

    wf = next((w for w in workflows if w["id"] == args.workflow_id), None)
    if not wf:
        print(f"Workflow '{args.workflow_id}' not found.", file=sys.stderr)
        return 1

    print("=" * 78)
    print(f"  PLAYBOOK: {wf['title']} ({wf['difficulty']})")
    print(f"  Discipline: {wf['discipline']} | Seed Selector: {wf['starting_selector']}")
    print(f"  {wf['summary']}")
    print("=" * 78)
    for st in wf["steps"]:
        print(f"\n  Step {st['step']}: {st['phase']}")
        print(f"    Action: {st['action']}")
        print("    Recommended Tools:")
        for tid in st["recommended_tools"]:
            t = by_id[tid]
            print(f"      * [{t['tier']}] {t['name']} ({t['opsec']}, {t['pricing']}) -> {t['url']}")
    print()
    return 0


def cmd_dorks(args, _categories, _tools, _workflows, dorks, _graveyard) -> int:
    matched = dorks
    if args.engine:
        matched = [d for d in matched if args.engine.lower() in d["engine"].lower()]
    if args.query:
        q = args.query.lower()
        matched = [
            d
            for d in matched
            if q in d["title"].lower() or q in d["category"].lower() or q in d["purpose"].lower() or q in d["query"].lower()
        ]
    for d in matched:
        query_str = d["query"]
        if args.target:
            query_str = (
                query_str.replace("example.com", args.target)
                .replace("Target Corp", args.target)
                .replace("Target Company", args.target)
                .replace("target-company", args.target)
                .replace("target_company", args.target)
                .replace("target_keyword", args.target)
            )
        print(f"[{d['engine']}] {d['title']} ({d['category']})")
        print(f"  Query  : {query_str}")
        print(f"  Purpose: {d['purpose']}\n")
    return 0


def cmd_graveyard(_args, _categories, _tools, _workflows, _dorks, graveyard) -> int:
    print("OSINT Graveyard & Verified 2026 Replacements:")
    print("=" * 78)
    for g in graveyard:
        print(f"DEAD / RETIRED : {g['dead_tool']}  [{g['status']}]")
        print(f"  Context      : {g['what_happened']}")
        reps = ", ".join(f"{r['name']} ({r['id']})" for r in g["replacements"])
        print(f"  Use Instead  : {reps}")
        print("-" * 78)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint.py",
        description="OSINT Monster Database CLI — Search, Selector Pivot, Dorks & Playbooks",
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("stats", help="Display database telemetry and discipline counts")

    p_search = sub.add_parser("search", help="Full-text and multi-facet OSINT tool search")
    p_search.add_argument("query", nargs="*", help="Search keywords")
    p_search.add_argument("-c", "--category", help="Filter by category/subcategory substring")
    p_search.add_argument("-o", "--opsec", choices=["Passive", "Active", "Hybrid"], help="Filter by OPSEC mode")
    p_search.add_argument("--free", action="store_true", help="Only completely free / open-source tools")
    p_search.add_argument("--no-auth", action="store_true", help="Only tools requiring no login or API key")
    p_search.add_argument("--tier", choices=["S", "A", "B"], help="Filter by tier")
    p_search.add_argument("-t", "--type", help="Filter by tool type (CLI, Web Platform, AI / MCP, ...)")
    p_search.add_argument("-n", "--limit", type=int, default=25, help="Max results to display (default: 25)")
    p_search.add_argument("--json", action="store_true", help="Output raw JSON")

    p_pivot = sub.add_parser("pivot", help="Find tools accepting a given input selector (email, phone, ip, ...)")
    p_pivot.add_argument("selector", nargs="?", help="Input selector (e.g. email, username, domain, image, crypto_address)")
    p_pivot.add_argument("--list", action="store_true", help="List all 24 supported input selectors")
    p_pivot.add_argument("--passive", action="store_true", help="Strictly passive tools (zero target packets)")
    p_pivot.add_argument("-o", "--opsec", choices=["Passive", "Active", "Hybrid"], help="Filter by OPSEC mode")
    p_pivot.add_argument("--free", action="store_true", help="Only free / open-source tools")
    p_pivot.add_argument("--no-auth", action="store_true", help="Only keyless / accountless tools")
    p_pivot.add_argument("--tier", choices=["S", "A", "B"], help="Filter by tier")
    p_pivot.add_argument("-n", "--limit", type=int, default=30, help="Max results (default: 30)")
    p_pivot.add_argument("--json", action="store_true", help="Output raw JSON")

    p_info = sub.add_parser("info", help="Inspect full metadata record for a tool ID")
    p_info.add_argument("tool_id", help="Tool slug ID (e.g. sherlock, ghunt, shodan)")
    p_info.add_argument("--json", action="store_true", help="Output raw JSON")

    p_wf = sub.add_parser("workflows", help="List or view end-to-end investigation playbooks")
    p_wf.add_argument("workflow_id", nargs="?", help="Optional playbook slug")

    p_dorks = sub.add_parser("dorks", help="Query search-engine dorks with optional target substitution")
    p_dorks.add_argument("query", nargs="?", help="Filter dorks by keyword")
    p_dorks.add_argument("-e", "--engine", help="Filter by engine (Google, Shodan, Censys, FOFA, GitHub, URLScan)")
    p_dorks.add_argument("--target", help="Substitute example.com / Target Corp with your target domain/org")

    sub.add_parser("graveyard", help="Inspect retired/hijacked OSINT tools and 2026 replacements")

    p_dec = sub.add_parser("decode", help="Zero-network forensic decoder (Phone, IBAN, VIN, ICAO24, IMO/MMSI, MAC/BSSID, JWT, UUIDv1/v7, ObjectId, TikTok/Snowflake)")
    p_dec.add_argument("payload", nargs="+", help="Token(s), URL(s), or local file path to decode offline")

    p_doc = sub.add_parser("doctor", help="Audit Python runtime, catalog health, installed skills & local CLI recon binaries")
    p_doc.add_argument("--json", action="store_true", help="Output JSON environment diagnostics")

    p_hunt = sub.add_parser("hunt", help="Execute OSINT hunt (Passive instant by default; --active ALWAYS asks user first)")
    p_hunt.add_argument("target", nargs="+", help="Any selector, URL, file path, or natural-language prompt")
    p_hunt.add_argument("-d", "--depth", type=int, default=4, choices=[1, 2, 3, 4, 5, 6], help="Max exhaustive stages (default: 4)")
    p_hunt.add_argument("--prepare-active", action="store_true", help="Prepare Active OSINT approval request (sends 0 packets)")
    p_hunt.add_argument("--active", action="store_true", help="Run Active OSINT mode (requires user confirmation)")
    p_hunt.add_argument("--request-id", help="Single-use approval request_id")
    p_hunt.add_argument("--user-approved", help="Explicit user approval confirmation text")
    p_hunt.add_argument("--no-save", action="store_true", help="Do not persist artifacts in cases/")
    p_hunt.add_argument("--json", action="store_true", help="Output raw JSON report")
    return parser


def cmd_decode(args, *_rest) -> int:
    raw = " ".join(args.payload).strip()
    for cand in (ROOT, Path(__file__).resolve().parent):
        if (cand / "osint_hunter").is_dir() and str(cand) not in sys.path:
            sys.path.insert(0, str(cand))
            break
    try:
        from osint_hunter.offline_intel import universal_forensic_decode
    except ImportError:
        print("Offline forensic decoder requires osint_hunter (use osint-hunter skill or full repository).", file=sys.stderr)
        return 1
    print(json.dumps(universal_forensic_decode(raw), indent=2, ensure_ascii=False))
    return 0


def cmd_doctor(args, categories, tools, workflows, dorks, graveyard) -> int:
    import shutil

    cli_probes = [
        "nmap", "rustscan", "naabu", "httpx", "subfinder", "nuclei", "dnsx", "tlsx", "katana",
        "ffuf", "feroxbuster", "gobuster", "amass", "bbot", "maigret", "sherlock", "holehe",
        "exiftool", "binwalk", "qpdf", "tshark", "yt-dlp", "instaloader", "tor", "whois", "dig",
    ]
    installed_bins = {b: shutil.which(b) for b in cli_probes if shutil.which(b)}
    missing_bins = [b for b in cli_probes if b not in installed_bins]
    sqlite_ok = (DATA_DIR / "osint.sqlite").is_file()
    byok_info = []
    for cand in (ROOT, Path(__file__).resolve().parent):
        if (cand / "osint_hunter").is_dir() and str(cand) not in sys.path:
            sys.path.insert(0, str(cand))
            break
    try:
        from osint_hunter.providers import get_byok_status
        byok_info = get_byok_status()
    except ImportError:
        byok_info = []

    diag = {
        "python_version": sys.version.split()[0],
        "catalog_health": {
            "tools": len(tools),
            "disciplines": len(categories),
            "workflows": len(workflows),
            "dorks": len(dorks),
            "graveyard": len(graveyard),
            "sqlite_fts5_present": sqlite_ok,
        },
        "hunter_engine_present": (ROOT / "osint_hunter" / "engine.py").is_file(),
        "byok_providers": byok_info,
        "local_recon_binaries_detected": list(installed_bins.keys()),
        "local_recon_binaries_count": len(installed_bins),
        "optional_binaries_not_installed": missing_bins,
    }
    if getattr(args, "json", False):
        print(json.dumps(diag, indent=2))
        return 0

    print("=" * 78)
    print("  OSINT MONSTER ENVIRONMENT DOCTOR")
    print("=" * 78)
    print(f"  Python Runtime       : {diag['python_version']} (Zero pip deps required)")
    print(f"  Catalog Integrity    : {len(tools)} tools · {len(workflows)} playbooks · {len(dorks)} dorks · {len(graveyard)} graveyard")
    print(f"  SQLite FTS5 Index    : {'READY' if sqlite_ok else 'Standalone JSON Mode'}")
    print(f"  Autonomous Hunter    : {'READY (45+ Passive + 18 Offline DFIR + 22 Gated Active Probes)' if diag['hunter_engine_present'] else 'Skill-Only Arsenal Mode'}")
    print(f"  Optional BYOK Keys   : {sum(1 for p in byok_info if p.get('configured'))}/{len(byok_info)} configured")
    print(f"  Detected CLI Tools   : {len(installed_bins)}/{len(cli_probes)} ({', '.join(installed_bins.keys()) or 'none'})")
    print("=" * 78)
    return 0


def cmd_hunt(args, *_rest) -> int:
    import subprocess

    cmd = [sys.executable, str(ROOT / "scripts" / "hunt.py"), *args.target, "-d", str(args.depth)]
    if args.prepare_active:
        cmd.append("--prepare-active")
    if args.active:
        cmd.append("--active")
    if args.request_id:
        cmd.extend(["--request-id", args.request_id])
    if args.user_approved:
        cmd.extend(["--user-approved", args.user_approved])
    if args.no_save:
        cmd.append("--no-save")
    if args.json:
        cmd.append("--json")
    return subprocess.call(cmd)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    categories, tools, workflows, dorks, graveyard = load_data()

    dispatch = {
        "stats": cmd_stats,
        "search": cmd_search,
        "pivot": cmd_pivot,
        "info": cmd_info,
        "workflows": cmd_workflows,
        "dorks": cmd_dorks,
        "graveyard": cmd_graveyard,
        "decode": cmd_decode,
        "doctor": cmd_doctor,
        "hunt": cmd_hunt,
    }
    fn = dispatch.get(args.cmd or "stats")
    return fn(args, categories, tools, workflows, dorks, graveyard)


if __name__ == "__main__":
    raise SystemExit(main())

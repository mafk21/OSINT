#!/usr/bin/env python3
"""OSINT Monster Autonomous Hunter CLI (Passive Instant Mode + Mandatory-Ask Active Gate).

Usage:
    # 1. Passive Mode (Default — Zero Questions, Zero Target Packets)
    python3 scripts/hunt.py "torvalds"

    # 2. Prepare Active Mode Authorization (Agent Step 1 — Sends ZERO Packets, Issues Request ID)
    python3 scripts/hunt.py "https://github.com/torvalds" --prepare-active

    # 3. Execute Active Mode (Agent Step 2 — ONLY AFTER User Explicitly Approves!)
    python3 scripts/hunt.py "https://github.com/torvalds" --active --request-id ACT-XXXX --user-approved "yes"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
for _cand in (SCRIPT_DIR, ROOT):
    if (_cand / "osint_hunter").is_dir() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))
        break

from osint_hunter.approval import (  # noqa: E402
    ACTIVE_MODULES_CATALOG,
    ActiveAuthorizationError,
    prepare_active_request,
)
from osint_hunter.engine import (  # noqa: E402
    _resolve_case_dir,
    compare_saved_cases,
    expand_existing_case,
    get_case_active_target_string,
    run_autonomous_hunt,
)
from osint_hunter.offline_intel import universal_forensic_decode  # noqa: E402
from osint_hunter.paths import get_cases_dir  # noqa: E402
from osint_hunter.persona import generate_domain_typosquats  # noqa: E402
from osint_hunter.watchlist import (  # noqa: E402
    add_to_watchlist,
    compute_case_delta,
    load_watchlist,
    remove_from_watchlist,
)


def _print_approval_prompt_sheet(plan: dict) -> None:
    print("!" * 78)
    print("  🔴 ACTIVE OSINT AUTHORIZATION REQUIRED — ZERO PACKETS SENT YET")
    print("!" * 78)
    print(f"  Request ID   : {plan['request_id']}  (Single-Use · Expires in 15 min)")
    print(f"  Target Scope : {plan['target']}")
    sels = ", ".join(f"{s['type']}:{s['value']}" for s in plan["detected_selectors"])
    print(f"  Selectors    : {sels}")
    print(f"  OPSEC Notice : {plan['opsec_warning']}")
    print("-" * 78)
    print("  Planned Active Probing Modules:")
    for m in plan["planned_active_modules"]:
        print(f"    • [{m['module']}] {m['title']}")
        print(f"      Impact: {m['opsec_impact']}")
    print("-" * 78)
    print(f"  AGENT DIRECTIVE: {plan['mandatory_agent_instruction']}")
    print("!" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hunt.py",
        description="OSINT Hunter — Instant Passive Mode + User-Gated Active Recon Mode",
    )
    parser.add_argument("target", nargs="*", help="Any selector, URL, file path, or natural-language prompt")
    parser.add_argument("-d", "--depth", type=int, default=4, choices=[1, 2, 3, 4, 5, 6], help="Max exhaustive stages before stopping if not yet converged (default: 4)")
    parser.add_argument("-m", "--max-pivots", type=int, default=50, help="Max new leads hunted per stage (default: 50 — hunts every lead)")
    parser.add_argument("--resume-case", help="Existing CASE_ID or case directory to expand with newly ingested stage findings")
    parser.add_argument("--from-case", help="Build --prepare-active target scope from ALL entities discovered in an existing CASE_ID")
    parser.add_argument("--ingest-text", help="Unstructured findings (e.g. web_search snippets, bios, Linktree text) to carve & hunt")
    parser.add_argument("--ingest-file", help="Path to text/markdown/json file of external stage findings to carve & hunt")
    parser.add_argument("--decode", action="store_true", help="Run zero-network offline forensic decoder on input (.eml, .pcap, .har, .mp4, PNG/C2PA, SSH, Google ei=, Phone, IBAN, VIN, UUID, TikTok/Snowflake)")
    parser.add_argument("--typosquats", action="store_true", help="Generate offline typosquat, bitsquat & IDN punycode homoglyph permutations for a domain")
    parser.add_argument("--diff-last", action="store_true", help="Compute attack-surface & Exposure Score drift against the most recent saved case for this target")
    parser.add_argument("--diff-cases", nargs=2, metavar=("BASELINE_CASE", "CURRENT_CASE"), help="Compute temporal surface delta (added/removed entities & exposures) between two saved cases")
    parser.add_argument("--watchlist-add", metavar="TARGET", help="Add a target to persistent cases/watchlist.json monitoring")
    parser.add_argument("--watchlist-remove", metavar="TARGET", help="Remove a target from cases/watchlist.json")
    parser.add_argument("--watchlist-list", action="store_true", help="List monitored targets in cases/watchlist.json")
    parser.add_argument("--watchlist-run", action="store_true", help="Sweep all targets in cases/watchlist.json with automatic --diff-last surface drift detection")
    parser.add_argument("--list-cases", action="store_true", help="List saved forensic investigation cases")
    parser.add_argument("--compare-cases", nargs=2, metavar=("CASE_A", "CASE_B"), help="Cross-case link analysis finding shared entities, domains, /24 IPs & analytics IDs")
    parser.add_argument("--cases-dir", help="Custom output directory for forensic case bundles")
    parser.add_argument("--no-save", action="store_true", help="Do not write dossier/STIX artifacts to cases/")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output")

    # Active OSINT Authorization Gate options
    parser.add_argument(
        "--prepare-active",
        action="store_true",
        help="Generate a single-use Active OSINT authorization request & OPSEC scope (sends ZERO packets).",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable Active OSINT mode (ALWAYS requires explicit user approval via interactive prompt or --request-id).",
    )
    parser.add_argument("--request-id", help="Single-use request_id from --prepare-active")
    parser.add_argument("--user-approved", help="Verbatim affirmative confirmation from the user authorizing active mode")
    parser.add_argument(
        "--active-modules",
        help=f"Optional comma-separated active modules ({','.join(ACTIVE_MODULES_CATALOG.keys())})",
    )
    args = parser.parse_args()

    raw_target = " ".join(args.target).strip()
    mod_list = [m.strip() for m in args.active_modules.split(",") if m.strip()] if args.active_modules else None

    if args.decode:
        if not raw_target:
            parser.error("--decode requires an input token, URL, or file path")
        print(json.dumps(universal_forensic_decode(raw_target), indent=2, ensure_ascii=False))
        return 0

    if args.typosquats:
        if not raw_target:
            parser.error("--typosquats requires a domain name")
        print(json.dumps(generate_domain_typosquats(raw_target, limit=50), indent=2, ensure_ascii=False))
        return 0

    if args.watchlist_add:
        items = add_to_watchlist(args.watchlist_add, depth=args.depth, cases_dir=args.cases_dir)
        print(json.dumps({"watchlist": items}, indent=2, ensure_ascii=False))
        return 0

    if args.watchlist_remove:
        items = remove_from_watchlist(args.watchlist_remove, cases_dir=args.cases_dir)
        print(json.dumps({"watchlist": items}, indent=2, ensure_ascii=False))
        return 0

    if args.watchlist_list:
        print(json.dumps({"watchlist": load_watchlist(args.cases_dir)}, indent=2, ensure_ascii=False))
        return 0

    if args.watchlist_run:
        items = load_watchlist(args.cases_dir)
        sweep_results = []
        for entry in items:
            rep = run_autonomous_hunt(
                entry["target"],
                depth=int(entry.get("depth", 3)),
                save_case=not args.no_save,
                cases_dir=args.cases_dir,
                mode="passive",
                diff_last=True,
            )
            sweep_results.append(
                {
                    "target": entry["target"],
                    "case_id": rep["meta"]["case_id"],
                    "exposure_score": rep["intelligence_synthesis"]["exposure_score"],
                    "surface_delta": rep.get("surface_delta"),
                }
            )
        print(json.dumps({"swept_count": len(sweep_results), "results": sweep_results}, indent=2, ensure_ascii=False))
        return 0

    if args.diff_cases:
        d_base = _resolve_case_dir(args.diff_cases[0], cases_dir=args.cases_dir)
        d_curr = _resolve_case_dir(args.diff_cases[1], cases_dir=args.cases_dir)
        r_base = json.loads((d_base / "report.json").read_text(encoding="utf-8"))
        r_curr = json.loads((d_curr / "report.json").read_text(encoding="utf-8"))
        print(json.dumps(compute_case_delta(r_base, r_curr), indent=2, ensure_ascii=False))
        return 0

    if args.list_cases:
        cbase = get_cases_dir(args.cases_dir)
        rows = []
        if cbase.exists():
            for d in sorted(cbase.iterdir(), reverse=True):
                rf = d / "report.json"
                if d.is_dir() and rf.is_file():
                    rep = json.loads(rf.read_text(encoding="utf-8"))
                    syn = rep.get("intelligence_synthesis") or {}
                    rows.append(
                        {
                            "case_id": rep["meta"]["case_id"],
                            "timestamp_utc": rep["meta"]["timestamp_utc"],
                            "opsec_mode": rep["meta"]["opsec_mode"],
                            "entities": len(rep.get("graph", {}).get("nodes", [])),
                            "exposure_score": syn.get("exposure_score"),
                            "raw_input": rep["meta"]["raw_input"],
                        }
                    )
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0

    if args.compare_cases:
        cmp_res = compare_saved_cases(args.compare_cases[0], args.compare_cases[1], cases_dir=args.cases_dir)
        print(json.dumps(cmp_res, indent=2, ensure_ascii=False))
        return 0

    ingested_parts: list[str] = []
    if args.ingest_text:
        ingested_parts.append(args.ingest_text)
    if args.ingest_file:
        ingested_parts.append(Path(args.ingest_file).read_text(encoding="utf-8", errors="replace"))
    combined_ingested = "\n\n".join(ingested_parts).strip() or None

    # Resume & expand an existing multi-stage case with external findings (e.g. web_search / fetch_page)
    if args.resume_case:
        if not combined_ingested and raw_target:
            combined_ingested = raw_target
        if not combined_ingested:
            parser.error("--resume-case requires --ingest-text, --ingest-file, or trailing text findings")
        report = expand_existing_case(
            args.resume_case,
            ingested_text=combined_ingested,
            additional_stages=args.depth,
            max_pivots_per_wave=args.max_pivots,
            cases_dir=args.cases_dir,
        )
        if args.json:
            out = {k: v for k, v in report.items() if k != "dossier_markdown"}
            print(json.dumps(out, indent=2, ensure_ascii=False))
            return 0
        print(report["dossier_markdown"])
        return 0

    if args.from_case and not raw_target:
        raw_target = get_case_active_target_string(args.from_case, cases_dir=args.cases_dir)

    if not raw_target:
        parser.error("Provide a target selector/prompt, --resume-case, or --from-case")

    # Step 1: Explicit --prepare-active
    if args.prepare_active:
        plan = prepare_active_request(raw_target, requested_modules=mod_list, source="cli_prepare")
        if args.json:
            print(json.dumps(plan, indent=2, ensure_ascii=False))
        else:
            _print_approval_prompt_sheet(plan)
        return 0

    # Step 2: Active mode requested
    if args.active:
        req_id = args.request_id
        user_conf = args.user_approved
        enforce_delay = True

        if not req_id:
            plan = prepare_active_request(raw_target, requested_modules=mod_list, source="cli_active_gate")
            if sys.stdin.isatty():
                _print_approval_prompt_sheet(plan)
                try:
                    ans = input("\n  Authorize direct Active OSINT probing on this target now? Type 'yes' to confirm [yes/N]: ").strip()
                except EOFError:
                    ans = ""
                if ans.lower() not in {"yes", "y", "authorize", "approved", "proceed"}:
                    print("  [ABORTED] Active OSINT cancelled by user. Zero active packets were sent.", file=sys.stderr)
                    return 2
                req_id = plan["request_id"]
                user_conf = ans
                enforce_delay = False
            else:
                # Non-interactive shell (e.g., AI agent bash call without prior user approval!) -> HARD BLOCK!
                if args.json:
                    print(json.dumps(plan, indent=2, ensure_ascii=False))
                else:
                    _print_approval_prompt_sheet(plan)
                    script_cmd = f"python3 {json.dumps(str(Path(__file__).resolve()))}"
                    print(
                        f"\n  [BLOCKED] Active OSINT requires explicit user permission first!\n"
                        f"  1. Ask the user for permission showing the OPSEC scope above.\n"
                        f"  2. After they reply approving it, run:\n"
                        f"     {script_cmd} {json.dumps(raw_target)} --active "
                        f"--request-id {plan['request_id']} --user-approved \"<USER_CONFIRMATION>\"",
                        file=sys.stderr,
                    )
                return 2

        try:
            report = run_autonomous_hunt(
                raw_target,
                depth=args.depth,
                max_pivots_per_wave=args.max_pivots,
                save_case=not args.no_save,
                cases_dir=args.cases_dir,
                mode="active",
                approval_request_id=req_id,
                user_confirmation=user_conf,
                active_modules=mod_list,
                enforce_turn_delay=enforce_delay,
                diff_last=args.diff_last,
            )
        except ActiveAuthorizationError as exc:
            print(f"[ACTIVE GATE ERROR] {exc}", file=sys.stderr)
            return 2
    else:
        # Default Passive Mode — Instant, Zero Questions, Exhaustive Multi-Stage Convergence!
        report = run_autonomous_hunt(
            raw_target,
            depth=args.depth,
            max_pivots_per_wave=args.max_pivots,
            ingested_evidence_text=combined_ingested,
            save_case=not args.no_save,
            cases_dir=args.cases_dir,
            mode="passive",
            diff_last=args.diff_last,
        )

    if args.json:
        out = {k: v for k, v in report.items() if k != "dossier_markdown"}
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    print(report["dossier_markdown"])
    if report["meta"].get("case_dir"):
        cdir = report["meta"]["case_dir"]
        syn = report.get("intelligence_synthesis") or {}
        print("=" * 78)
        print(f"  FORENSIC CASE SAVED : {cdir}/  (Mode: {report['meta']['opsec_mode']} · Exposure: {syn.get('exposure_score', 0)}/100)")
        print(f"    - {cdir}/dossier.md        (Executive Markdown + Mermaid Graph)")
        print(f"    - {cdir}/report.html       (Standalone Dark-Mode Executive HTML + SVG Map)")
        print(f"    - {cdir}/report.json       (Machine-Readable Full Telemetry + Synthesis)")
        print(f"    - {cdir}/entities.csv      (Excel / Maltego / Gephi Spreadsheet Export)")
        print(f"    - {cdir}/graph.gexf        (Gephi 1.3 Link-Analysis Graph + RGB Colors)")
        print(f"    - {cdir}/graph.graphml     (yEd / Cytoscape / NetworkX GraphML)")
        print(f"    - {cdir}/neo4j.cypher      (Neo4j Graph DB MERGE Import Script)")
        print(f"    - {cdir}/obsidian/         (Obsidian [[WikiLink]] Knowledge Vault)")
        print(f"    - {cdir}/stix2_bundle.json (OASIS STIX 2.1 CTI Bundle)")
        print(f"    - {cdir}/manifest.sha256   (SHA-256 Chain-of-Custody Hashes)")
        print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

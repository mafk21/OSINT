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
from osint_hunter.engine import run_autonomous_hunt  # noqa: E402


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
    parser.add_argument("target", nargs="+", help="Any selector, URL, file path, or natural-language prompt")
    parser.add_argument("-d", "--depth", type=int, default=2, choices=[1, 2, 3], help="Recursive pivot depth (default: 2)")
    parser.add_argument("-m", "--max-pivots", type=int, default=6, help="Max new selectors pivoted per wave (default: 6)")
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
            )
        except ActiveAuthorizationError as exc:
            print(f"[ACTIVE GATE ERROR] {exc}", file=sys.stderr)
            return 2
    else:
        # Default Passive Mode — Instant, Zero Questions!
        report = run_autonomous_hunt(
            raw_target,
            depth=args.depth,
            max_pivots_per_wave=args.max_pivots,
            save_case=not args.no_save,
            cases_dir=args.cases_dir,
            mode="passive",
        )

    if args.json:
        out = {k: v for k, v in report.items() if k != "dossier_markdown"}
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    print(report["dossier_markdown"])
    if report["meta"].get("case_dir"):
        cdir = report["meta"]["case_dir"]
        print("=" * 78)
        print(f"  FORENSIC CASE SAVED : {cdir}/  (Mode: {report['meta']['opsec_mode']})")
        print(f"    - {cdir}/dossier.md        (Executive Markdown Intelligence Report)")
        print(f"    - {cdir}/report.json       (Machine-Readable Full Telemetry)")
        print(f"    - {cdir}/graph.json        (Entity Nodes & Pivot Edges)")
        print(f"    - {cdir}/stix2_bundle.json (OASIS STIX 2.1 CTI Bundle)")
        print(f"    - {cdir}/manifest.sha256   (SHA-256 Chain-of-Custody Hashes)")
        print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

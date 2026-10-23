#!/usr/bin/env python3
"""Zero-Dependency Model Context Protocol (MCP) Server for OSINT Monster Database.

Implements JSON-RPC 2.0 over stdio (compatible with Claude Desktop, Claude Code,
Cursor, Windsurf, Cline, Zed, OpenClaw, and all MCP 2024-11-05 / 2025-03-26 clients).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osint_hunter.approval import (  # noqa: E402
    ACTIVE_MODULES_CATALOG,
    ActiveAuthorizationError,
    prepare_active_request,
)
from osint_hunter.classify import extract_selectors  # noqa: E402
from osint_hunter.collectors import collect_for_selector  # noqa: E402
from osint_hunter.engine import (  # noqa: E402
    ALL_DORKS,
    ALL_TOOLS,
    ALL_WORKFLOWS,
    expand_existing_case,
    forge_dorks_for_targets,
    get_case_active_target_string,
    run_autonomous_hunt,
)

SERVER_INFO = {
    "name": "osint-monster-hunter",
    "version": "2026.10.1",
}

MCP_TOOLS = [
    {
        "name": "osint_auto_hunt",
        "description": (
            "PRIMARY PASSIVE OSINT TOOL (ZERO QUESTIONS — RUN IMMEDIATELY). Executes a strictly passive "
            "multi-wave OSINT hunt on ANY target or raw prompt (username, email, domain, IP, ASN, phone, "
            "crypto wallet, GitHub repo, VIN, aircraft ICAO hex, vessel IMO/MMSI, MAC/BSSID, GPS coordinates, "
            "JWT, file hash, local file path, person, or company) with ZERO packets sent directly to target "
            "infrastructure. Automatically pivots across discovered entities and writes a STIX 2.1 dossier."
        ),
        "annotations": {
            "title": "Passive Autonomous OSINT Hunt",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Raw selector, local file path, URL, or natural-language target description.",
                },
                "depth": {
                    "type": "integer",
                    "default": 4,
                    "minimum": 1,
                    "maximum": 6,
                    "description": "Exhaustive multi-stage surface expansion depth until 0 new leads remain (1-6, default 4).",
                },
                "ingested_evidence_text": {
                    "type": "string",
                    "description": "Optional unstructured text/bios/search snippets to carve & hunt alongside the seed.",
                },
                "save_case": {
                    "type": "boolean",
                    "default": True,
                    "description": "Save dossier.md, report.json, graph.json, stix2_bundle.json & manifest.sha256 in cases/.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "osint_ingest_and_expand_case",
        "description": (
            "MULTI-STAGE SURFACE EXPANSION TOOL (PASSIVE, ZERO QUESTIONS). Feed ALL raw findings gathered in "
            "a stage (e.g. web_search snippets, fetched bio pages, Linktrees, directories) into an existing case. "
            "Automatically carves EVERY new clue (handles, variants, phones, WhatsApp links, emails, domains, "
            "names, companies/clinics) and hunts ALL of them across subsequent stages until convergence."
        ),
        "annotations": {
            "title": "Ingest Findings & Expand Multi-Stage Case",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id_or_dir": {
                    "type": "string",
                    "description": "Existing CASE_ID or case directory path returned by `osint_auto_hunt`.",
                },
                "ingested_text": {
                    "type": "string",
                    "description": "All raw text, URLs, bios, and snippets collected during the current stage.",
                },
                "additional_stages": {
                    "type": "integer",
                    "default": 3,
                    "minimum": 1,
                    "maximum": 5,
                    "description": "Max additional passive stages to run until 0 new leads appear.",
                },
            },
            "required": ["case_id_or_dir", "ingested_text"],
        },
    },
    {
        "name": "osint_prepare_active_hunt",
        "description": (
            "STEP 1 OF ACTIVE OSINT (SENDS ZERO PACKETS). Generates an Active Recon OPSEC Impact Plan "
            "and a single-use `request_id` for direct target probing (TLS handshake, HTTP security headers/CSP, "
            "robots.txt/security.txt, Shodan favicon mmh3 hash, TCP banner triage). AFTER calling this tool, "
            "you MUST STOP and ask the user for explicit permission before calling `osint_execute_active_hunt`."
        ),
        "annotations": {
            "title": "Prepare Active OSINT Authorization Request",
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain, URL, IP, or selector."},
                "modules": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(ACTIVE_MODULES_CATALOG.keys())},
                    "description": "Optional subset of active modules to plan.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "osint_execute_active_hunt",
        "description": (
            "STEP 2 OF ACTIVE OSINT — HARD GATED! NEVER call this tool unless you ALREADY called "
            "`osint_prepare_active_hunt`, presented the OPSEC impact to the user, and received the user's "
            "explicit approval in a subsequent message! Sends direct TCP/TLS/HTTP/DNS probes to the target."
        ),
        "annotations": {
            "title": "Execute User-Approved Active OSINT Hunt",
            "readOnlyHint": False,
            "destructiveHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Exact target string authorized in `osint_prepare_active_hunt`."},
                "request_id": {"type": "string", "description": "Single-use `request_id` (e.g. ACT-XXXXXXXX) issued by `osint_prepare_active_hunt`."},
                "user_confirmation": {
                    "type": "string",
                    "description": "Verbatim quote of the user's message explicitly approving Active OSINT.",
                },
                "depth": {"type": "integer", "default": 2, "minimum": 1, "maximum": 3},
            },
            "required": ["target", "request_id", "user_confirmation"],
        },
    },
    {
        "name": "osint_extract_selectors",
        "description": "Extract, normalize, and checksum-validate all OSINT selectors from arbitrary text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Unstructured text, paste, email, or prompt."}
            },
            "required": ["text"],
        },
    },
    {
        "name": "osint_run_collector",
        "description": "Run passive live & offline collectors for one specific typed selector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector_type": {
                    "type": "string",
                    "description": "Selector type (username, email, domain, ip, asn, crypto_address, phone, vin, aircraft_hex, vessel_imo, mac_bssid, coordinates, file_hash, jwt_token, local_file, repo_code, company, person_name).",
                },
                "value": {"type": "string", "description": "Selector value."},
            },
            "required": ["selector_type", "value"],
        },
    },
    {
        "name": "osint_query_arsenal",
        "description": "Query the 680-tool OSINT Monster Database (502 Passive + 178 Active/Hybrid) by keyword, input selector, category, or OPSEC posture.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Optional search keywords."},
                "input_selector": {"type": "string", "description": "Optional input selector (e.g. email, domain, vessel_imo)."},
                "category": {"type": "string", "description": "Optional discipline ID."},
                "passive_only": {"type": "boolean", "default": True},
                "free_only": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 15},
            },
        },
    },
    {
        "name": "osint_forge_dorks",
        "description": "Generate target-substituted Google, Shodan, Censys, FOFA, ZoomEye, GitHub, and URLScan search dorks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain, organization, or handle to inject into dorks."},
                "engine": {"type": "string", "description": "Optional engine filter (Google, Shodan, Censys, GitHub, FOFA)."},
            },
            "required": ["target"],
        },
    },
    {
        "name": "osint_get_playbook",
        "description": "Retrieve one or all of the 12 multi-phase OSINT investigation workflows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workflow_id": {"type": "string", "description": "Optional workflow ID; omit to list all 12 playbooks."}
            },
        },
    },
]


def handle_tool_call(name: str, args: dict) -> str:
    if name == "osint_auto_hunt":
        report = run_autonomous_hunt(
            str(args["target"]),
            depth=int(args.get("depth", 4)),
            ingested_evidence_text=args.get("ingested_evidence_text"),
            save_case=bool(args.get("save_case", True)),
            mode="passive",
        )
        return report["dossier_markdown"] + "\n\n<!-- CASE_DIR: " + str(report["meta"].get("case_dir")) + " -->"

    if name == "osint_ingest_and_expand_case":
        report = expand_existing_case(
            str(args["case_id_or_dir"]),
            ingested_text=str(args["ingested_text"]),
            additional_stages=int(args.get("additional_stages", 3)),
        )
        return report["dossier_markdown"] + "\n\n<!-- CASE_DIR: " + str(report["meta"].get("case_dir")) + " -->"

    if name == "osint_prepare_active_hunt":
        raw_tgt = str(args.get("target") or "")
        if args.get("from_case") and not raw_tgt:
            raw_tgt = get_case_active_target_string(str(args["from_case"]))
        plan = prepare_active_request(
            raw_tgt,
            requested_modules=args.get("modules"),
            source="mcp_prepare",
        )
        return json.dumps(plan, indent=2, ensure_ascii=False)

    if name == "osint_execute_active_hunt":
        try:
            report = run_autonomous_hunt(
                str(args["target"]),
                depth=int(args.get("depth", 2)),
                save_case=True,
                mode="active",
                approval_request_id=str(args.get("request_id", "")),
                user_confirmation=str(args.get("user_confirmation", "")),
                enforce_turn_delay=True,
            )
            return report["dossier_markdown"] + "\n\n<!-- ACTIVE_CASE_DIR: " + str(report["meta"].get("case_dir")) + " -->"
        except ActiveAuthorizationError as exc:
            raise PermissionError(str(exc)) from exc

    if name == "osint_extract_selectors":
        return json.dumps(extract_selectors(str(args.get("text", ""))), indent=2, ensure_ascii=False)

    if name == "osint_run_collector":
        res = collect_for_selector(str(args["selector_type"]), str(args["value"]))
        return json.dumps(res, indent=2, ensure_ascii=False)

    if name == "osint_query_arsenal":
        q = str(args.get("query", "")).lower().strip()
        sel = str(args.get("input_selector", "")).lower().strip()
        cat = str(args.get("category", "")).lower().strip()
        passive_only = bool(args.get("passive_only", True))
        free_only = bool(args.get("free_only", False))
        limit = int(args.get("limit", 15))

        pool = ALL_TOOLS
        if passive_only:
            pool = [t for t in pool if t["opsec"] == "Passive"]
        if free_only:
            pool = [t for t in pool if t["pricing"] in ("Free / Open Source", "Free")]
        if sel:
            pool = [t for t in pool if sel in t["inputs"]]
        if cat:
            pool = [t for t in pool if cat in t["category"].lower()]
        if q:
            terms = q.split()
            pool = [
                t
                for t in pool
                if all(
                    term in f"{t['id']} {t['name']} {t['description']} {' '.join(t['tags'])} {t['quick_start']}".lower()
                    for term in terms
                )
            ]
        return json.dumps(pool[:limit], indent=2, ensure_ascii=False)

    if name == "osint_forge_dorks":
        target = str(args["target"]).strip()
        eng = str(args.get("engine", "")).lower().strip()
        dorks = forge_dorks_for_targets([target], limit=56)
        if eng:
            dorks = [d for d in dorks if eng in d["engine"].lower()]
        return json.dumps(dorks, indent=2, ensure_ascii=False)

    if name == "osint_get_playbook":
        wid = str(args.get("workflow_id", "")).strip()
        if not wid:
            return json.dumps(
                [{"id": w["id"], "title": w["title"], "starting_selector": w["starting_selector"]} for w in ALL_WORKFLOWS],
                indent=2,
            )
        wf = next((w for w in ALL_WORKFLOWS if w["id"] == wid), None)
        return json.dumps(wf or {"error": f"Unknown workflow_id '{wid}'"}, indent=2, ensure_ascii=False)

    raise ValueError(f"Unknown MCP tool: {name}")


def process_rpc(msg: dict) -> dict | None:
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    # Notifications have no id and expect no response
    if req_id is None:
        return None

    try:
        if method == "initialize":
            proto = params.get("protocolVersion", "2024-11-05")
            result = {
                "protocolVersion": proto,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": SERVER_INFO,
                "instructions": (
                    "TWO-LAW OSINT DOCTRINE: "
                    "(1) PASSIVE MODE: When given ANY target, immediately call `osint_auto_hunt` with ZERO clarifying questions. "
                    "(2) ACTIVE MODE GATE: NEVER run Active OSINT without asking the user first! Even if the user asks for "
                    "active/deep probing, you MUST first call `osint_prepare_active_hunt`, show the target packet scope & OPSEC "
                    "warning to the user, and wait for their explicit confirmation before calling `osint_execute_active_hunt`."
                ),
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": MCP_TOOLS}
        elif method == "tools/call":
            t_name = params.get("name", "")
            t_args = params.get("arguments") or {}
            text_out = handle_tool_call(t_name, t_args)
            result = {"content": [{"type": "text", "text": text_out}], "isError": False}
        elif method == "prompts/list":
            result = {
                "prompts": [
                    {
                        "name": "autonomous-hunt",
                        "description": "Execute an immediate zero-question passive OSINT hunt and intelligence dossier.",
                        "arguments": [{"name": "target", "description": "Target selector or prompt", "required": True}],
                    }
                ]
            }
        elif method == "prompts/get":
            tgt = (params.get("arguments") or {}).get("target", "")
            result = {
                "description": "Zero-question OSINT hunt directive",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (
                                f"Execute a comprehensive passive OSINT hunt on: {tgt}\n"
                                "Do NOT ask any clarifying questions. Immediately call `osint_auto_hunt`, "
                                "correlate all discovered pivots, forge targeted dorks, and deliver an executive intelligence dossier."
                            ),
                        },
                    }
                ],
            }
        else:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True},
        }


def main() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = process_rpc(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

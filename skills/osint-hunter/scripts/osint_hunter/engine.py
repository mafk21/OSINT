"""Autonomous Multi-Wave OSINT Hunt, Graph Pivot, STIX 2.1 & Dossier Engine."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .active_collectors import collect_active_for_selector
from .approval import ACTIVE_MODULES_CATALOG, verify_and_consume_approval
from .classify import extract_selectors
from .collectors import collect_for_selector
from .offline_intel import INTEL_TABLES
from .paths import DATA_DIR, IS_REPO_MODE, PKG_PARENT, get_cases_dir

with (DATA_DIR / "tools.json").open("r", encoding="utf-8") as _f:
    ALL_TOOLS = json.load(_f)
with (DATA_DIR / "workflows.json").open("r", encoding="utf-8") as _f:
    ALL_WORKFLOWS = json.load(_f)
with (DATA_DIR / "dorks.json").open("r", encoding="utf-8") as _f:
    ALL_DORKS = json.load(_f)

SELECTOR_TO_ARSENAL_INPUT = {
    "local_file": "document",
    "jwt_token": "document",
}

STIX_SCO_MAP = {
    "domain": ("domain-name", "value"),
    "ip": ("ipv4-addr", "value"),
    "email": ("email-addr", "value"),
    "url": ("url", "value"),
    "onion_url": ("url", "value"),
    "username": ("user-account", "account_login"),
    "mac_bssid": ("mac-addr", "value"),
    "asn": ("autonomous-system", "name"),
}


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", text.strip())
    return s.strip("-")[:48] or "target"


def forge_dorks_for_targets(targets: list[str], limit: int = 14) -> list[dict]:
    if not targets:
        return []
    primary = targets[0]
    forged = []
    for d in ALL_DORKS:
        q = d["query"]
        replaced = (
            q.replace("example.com", primary)
            .replace("Target Corp", primary)
            .replace("Target Company", primary)
            .replace("target-company", primary)
            .replace("target_company", primary)
            .replace("target_org", primary)
            .replace("target_keyword", primary)
            .replace("target_handle", primary)
            .replace("Target Name", primary)
        )
        if replaced != q:
            forged.append(
                {
                    "engine": d["engine"],
                    "category": d["category"],
                    "title": d["title"],
                    "query": replaced,
                    "purpose": d["purpose"],
                }
            )
        if len(forged) >= limit:
            break
    return forged


def recommend_arsenal_for_selectors(
    selector_types: list[str],
    target_values: dict[str, list[str]],
    *,
    include_active: bool = False,
) -> dict:
    mapped_types = [SELECTOR_TO_ARSENAL_INPUT.get(s, s) for s in selector_types]
    recommendations = {}
    active_recommendations = {}
    action_commands = []
    active_action_commands = []

    templates = INTEL_TABLES.get("action_templates", {})
    for stype in selector_types:
        vals = target_values.get(stype) or []
        for t_cfg in templates.get(stype, []):
            for v in vals[:2]:
                action_commands.append(
                    {
                        "selector_type": stype,
                        "target": v,
                        "tool_id": t_cfg["tool_id"],
                        "label": t_cfg["label"],
                        "command": t_cfg["cmd"].replace("{target}", v),
                    }
                )

    if include_active:
        act_templates = INTEL_TABLES.get("active_action_templates", {})
        for stype in selector_types:
            vals = target_values.get(stype) or []
            for t_cfg in act_templates.get(stype, []):
                for v in vals[:2]:
                    active_action_commands.append(
                        {
                            "selector_type": stype,
                            "target": v,
                            "tool_id": t_cfg["tool_id"],
                            "label": t_cfg["label"],
                            "command": t_cfg["cmd"].replace("{target}", v),
                        }
                    )

    for mtype in sorted(set(mapped_types)):
        matched = [
            t
            for t in ALL_TOOLS
            if mtype in t["inputs"] and t["opsec"] == "Passive"
        ]
        matched.sort(key=lambda t: (0 if t["tier"] == "S" else 1 if t["tier"] == "A" else 2, 0 if not t["auth_required"] else 1))
        recommendations[mtype] = [
            {
                "id": t["id"],
                "name": t["name"],
                "tier": t["tier"],
                "url": t["url"],
                "pricing": t["pricing"],
                "auth_required": t["auth_required"],
                "quick_start": t["quick_start"],
            }
            for t in matched[:8]
        ]

        if include_active:
            act_matched = [
                t
                for t in ALL_TOOLS
                if mtype in t["inputs"] and t["opsec"] in ("Active", "Hybrid")
            ]
            act_matched.sort(key=lambda t: (0 if t["tier"] == "S" else 1 if t["tier"] == "A" else 2))
            active_recommendations[mtype] = [
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tier": t["tier"],
                    "opsec": t["opsec"],
                    "url": t["url"],
                    "pricing": t["pricing"],
                    "quick_start": t["quick_start"],
                }
                for t in act_matched[:8]
            ]

    matched_workflows = [
        {
            "id": wf["id"],
            "title": wf["title"],
            "discipline": wf["discipline"],
            "starting_selector": wf["starting_selector"],
            "steps": wf["steps"],
        }
        for wf in ALL_WORKFLOWS
        if any(st in wf["starting_selector"].lower() for st in mapped_types)
    ][:4]

    return {
        "parameterized_commands": action_commands[:18],
        "active_parameterized_commands": active_action_commands[:20],
        "passive_tools_by_selector": recommendations,
        "active_tools_by_selector": active_recommendations,
        "matched_playbooks": matched_workflows,
    }


def build_stix2_bundle(case_id: str, raw_target: str, nodes: list[dict], edges: list[dict]) -> dict:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: list[dict] = []
    node_to_stix_id: dict[str, str] = {}

    report_refs: list[str] = []
    for n in nodes:
        nid = n["id"]
        stype, sval = n["type"], n["value"]
        sco_spec = STIX_SCO_MAP.get(stype)
        det_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"osint-monster:{nid}"))
        if sco_spec:
            stix_type, prop = sco_spec
            if stix_type == "ipv4-addr" and ":" in sval:
                stix_type = "ipv6-addr"
            sid = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": sid, prop: sval}
        else:
            sid = f" grouping--{det_uuid}".strip()
            obj = {
                "type": "note",
                "spec_version": "2.1",
                "id": f"note--{det_uuid}",
                "created": now_iso,
                "modified": now_iso,
                "abstract": f"[{stype}] {sval}",
                "content": f"Discovered OSINT selector ({stype}): {sval} at wave {n['wave']}",
                "object_refs": [],
            }
            sid = obj["id"]
        node_to_stix_id[nid] = sid
        objects.append(obj)
        report_refs.append(sid)

    for idx, e in enumerate(edges):
        src_sid = node_to_stix_id.get(e["source"])
        dst_sid = node_to_stix_id.get(e["target"])
        if src_sid and dst_sid and src_sid != dst_sid:
            rel_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"osint-rel:{src_sid}:{dst_sid}:{e['via']}"))
            rel_id = f"relationship--{rel_uuid}"
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "related-to",
                    "description": f"Discovered via passive OSINT collector '{e['via']}'",
                    "source_ref": src_sid,
                    "target_ref": dst_sid,
                }
            )
            report_refs.append(rel_id)

    rep_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"osint-report:{case_id}"))
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{rep_uuid}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"OSINT Autonomous Hunt Report: {raw_target[:80]}",
            "published": now_iso,
            "report_types": ["threat-actor", "infrastructure", "osint-dossier"],
            "object_refs": report_refs[:200],
        }
    )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def render_markdown_dossier(report: dict) -> str:
    meta = report["meta"]
    is_active = meta.get("opsec_mode") == "Active+Passive"
    opsec_line = (
        f"`🔴 Active + Passive (User-Authorized via {meta.get('approval_request_id')})`"
        if is_active
        else "`🟢 Strictly Passive (Zero Direct Packets to Target Infrastructure)`"
    )
    lines = [
        f"# 🛰️ OSINT Intelligence Dossier — `{meta['case_id']}`",
        "",
        f"- **Generated (UTC)**: `{meta['timestamp_utc']}`",
        f"- **Raw Target Input**: `{meta['raw_input']}`",
        f"- **OPSEC Posture**: {opsec_line}",
        f"- **Execution Depth**: `{meta['depth']}` wave(s) · `{meta['duration_seconds']}s` elapsed · `{len(report['graph']['nodes'])}` entity node(s) · `{len(report['graph']['edges'])}` pivot edge(s)",
    ]
    if is_active:
        lines.append(f"- **User Authorization Audit**: Request `{meta.get('approval_request_id')}` · Confirmation: `\"{meta.get('user_confirmation', '')}\"`")
    lines.extend([
        "",
        "---",
        "",
        "## 1. Confirmed & Discovered Entity Graph",
        "",
        "| Wave | Selector Type | Value | Discovered Via |",
        "| :---: | :--- | :--- | :--- |",
    ])
    edge_lookup = {e["target"]: f"`{e['source']}` via `{e['via']}`" for e in report["graph"]["edges"]}
    for n in report["graph"]["nodes"]:
        origin = "Initial Seed" if n["wave"] == 1 else edge_lookup.get(n["id"], "Autonomous Pivot")
        lines.append(f"| `{n['wave']}` | **`{n['type']}`** | `{n['value']}` | {origin} |")

    lines.extend(["", "---", "", "## 2. Collector Findings by Entity", ""])
    for item in report["wave_results"]:
        lines.append(f"### 🔹 `[{item['type']}]` `{item['value']}` *(Wave {item['wave']})*")
        for mod in item["collector_outputs"]:
            icon = "✅" if mod["status"] == "ok" else ("⚪" if mod["status"] == "not_found" else "🔒")
            mode_tag = " `🔴 ACTIVE`" if mod.get("opsec") == "Active" else ""
            lines.append(f"- {icon}{mode_tag} **`{mod['module']}`** — {mod['summary']}")
            if mod["status"] == "ok" and mod["data"]:
                preview = json.dumps(mod["data"], ensure_ascii=False, indent=2)
                if len(preview) > 1200:
                    preview = preview[:1200] + "\n  ... (see full payload in report.json)"
                lines.append("  ```json")
                for pl in preview.splitlines():
                    lines.append(f"  {pl}")
                lines.append("  ```")
        lines.append("")

    cmds = report["arsenal"]["parameterized_commands"]
    if cmds:
        lines.extend(["---", "", "## 3. Ready-to-Execute Deep Follow-Up Commands", "", "```bash"])
        for c in cmds:
            lines.append(f"# [{c['selector_type']}] {c['label']} ({c['tool_id']})")
            lines.append(c["command"])
        lines.extend(["```", ""])

    if report["forged_dorks"]:
        lines.extend(["---", "", "## 4. Target-Forged Search Engine Dorks", ""])
        for d in report["forged_dorks"][:10]:
            lines.append(f"- **[{d['engine']}] {d['title']}**: `{d['query']}`")
        lines.append("")

    lines.extend(["---", "", f"## 5. Recommended Passive S-Tier Tools from {len(ALL_TOOLS)}-Tool Arsenal", ""])
    for stype, tlist in report["arsenal"]["passive_tools_by_selector"].items():
        if not tlist:
            continue
        lines.append(f"### Selector `{stype}` (Passive)")
        for t in tlist[:6]:
            auth = "Key/Login" if t["auth_required"] else "No-Auth"
            lines.append(f"- **[`{t['tier']}`] [{t['name']}]({t['url']})** ({t['pricing']}, {auth}) — `{t['quick_start']}`")
        lines.append("")

    act_cmds = report["arsenal"].get("active_parameterized_commands") or []
    act_map = report["arsenal"].get("active_tools_by_selector") or {}
    if act_cmds or any(act_map.values()):
        lines.extend(["---", "", "## 6. Unlocked Active & Hybrid Recon Arsenal (User-Authorized Mode)", ""])
        if act_cmds:
            lines.extend(["### 🔴 Parameterized Active CLI Playbook", "", "```bash"])
            for c in act_cmds:
                lines.append(f"# [ACTIVE · {c['selector_type']}] {c['label']} ({c['tool_id']})")
                lines.append(c["command"])
            lines.extend(["```", ""])
        for stype, tlist in act_map.items():
            if not tlist:
                continue
            lines.append(f"### Selector `{stype}` (🔴 Active / 🟡 Hybrid)")
            for t in tlist[:8]:
                lines.append(f"- **[`{t['tier']}`] [{t['name']}]({t['url']})** (`{t['opsec']}`, {t['pricing']}) — `{t['quick_start']}`")
            lines.append("")

    return "\n".join(lines) + "\n"


def run_autonomous_hunt(
    raw_input: str,
    *,
    depth: int = 2,
    max_pivots_per_wave: int = 6,
    save_case: bool = True,
    cases_dir: str | Path | None = None,
    cwd: str | None = None,
    mode: str = "passive",
    approval_request_id: str | None = None,
    user_confirmation: str | None = None,
    active_modules: list[str] | None = None,
    enforce_turn_delay: bool = True,
) -> dict:
    """Execute an OSINT hunt.

    - `mode="passive"` (default): Zero questions, immediate execution, zero direct target packets.
    - `mode="active"`: HARD GATED — requires single-use `approval_request_id` + explicit `user_confirmation`.
    """
    is_active = mode.lower() == "active"
    approved_record = None
    enabled_active_mods: list[str] = []

    if is_active:
        approved_record = verify_and_consume_approval(
            raw_input,
            approval_request_id,
            user_confirmation,
            enforce_turn_delay=enforce_turn_delay,
        )
        enabled_active_mods = (
            [m for m in active_modules if m in ACTIVE_MODULES_CATALOG]
            if active_modules
            else approved_record.get("modules", list(ACTIVE_MODULES_CATALOG.keys()))
        )

    t0 = time.monotonic()
    depth = max(1, min(int(depth), 3))
    seeds = extract_selectors(raw_input, cwd=cwd)
    if not seeds:
        seeds = [{"type": "keyword", "value": raw_input.strip()[:100], "confidence": 0.5, "note": "Fallback keyword"}]

    ts = datetime.now(timezone.utc)
    case_slug = _slugify(seeds[0]["value"])
    prefix_tag = "ACTIVE_" if is_active else ""
    case_id = f"{prefix_tag}{ts.strftime('%Y%m%dT%H%M%SZ')}_{case_slug}"

    visited: set[str] = set()
    nodes: list[dict] = []
    edges: list[dict] = []
    wave_results: list[dict] = []
    values_by_type: dict[str, list[str]] = {}

    current_queue: list[tuple[str, str]] = []
    for s in seeds:
        nid = f"{s['type']}:{s['value'].lower()}"
        if nid not in visited:
            visited.add(nid)
            nodes.append({"id": nid, "type": s["type"], "value": s["value"], "wave": 1, "note": s.get("note", "")})
            values_by_type.setdefault(s["type"], []).append(s["value"])
            current_queue.append((s["type"], s["value"]))

    PIVOT_PRIORITY = {"email": 0, "domain": 1, "username": 2, "ip": 3, "crypto_address": 4, "coordinates": 5, "repo_code": 6, "asn": 7, "mac_bssid": 8, "url": 9}

    for wave_num in range(1, depth + 1):
        if not current_queue:
            break

        def _exec_one(item: tuple[str, str]):
            st, sv = item
            outs = collect_for_selector(st, sv)
            if is_active:
                outs = outs + collect_active_for_selector(st, sv, enabled_active_mods)
            return st, sv, outs

        next_candidates: list[tuple[int, str, str, str, str]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(current_queue))) as pool:
            for stype, sval, collector_outs in pool.map(_exec_one, current_queue):
                src_id = f"{stype}:{sval.lower()}"
                wave_results.append(
                    {
                        "wave": wave_num,
                        "type": stype,
                        "value": sval,
                        "collector_outputs": collector_outs,
                    }
                )
                for mod_res in collector_outs:
                    for piv in mod_res.get("pivots") or []:
                        pt, pv = piv["type"], str(piv["value"]).strip()
                        if not pv:
                            continue
                        dst_id = f"{pt}:{pv.lower()}"
                        edges.append({"source": src_id, "target": dst_id, "via": mod_res["module"]})
                        if dst_id not in visited:
                            prio = PIVOT_PRIORITY.get(pt, 99)
                            next_candidates.append((prio, pt, pv, dst_id, mod_res["module"]))

        # Deduplicate & cap pivots for next wave
        next_candidates.sort(key=lambda x: x[0])
        current_queue = []
        if wave_num < depth:
            for _, pt, pv, dst_id, via_mod in next_candidates:
                if dst_id in visited:
                    continue
                visited.add(dst_id)
                nodes.append({"id": dst_id, "type": pt, "value": pv, "wave": wave_num + 1, "note": f"Pivoted via {via_mod}"})
                values_by_type.setdefault(pt, []).append(pv)
                if pt in PIVOT_PRIORITY:
                    current_queue.append((pt, pv))
                if len(current_queue) >= max_pivots_per_wave:
                    break

    dork_seeds = (
        values_by_type.get("domain", [])
        + values_by_type.get("company", [])
        + values_by_type.get("username", [])
        + values_by_type.get("email", [])
        + values_by_type.get("person_name", [])
    )
    forged_dorks = forge_dorks_for_targets(dork_seeds, limit=14)
    arsenal = recommend_arsenal_for_selectors(list(values_by_type.keys()), values_by_type, include_active=is_active)
    elapsed = round(time.monotonic() - t0, 2)

    report = {
        "meta": {
            "case_id": case_id,
            "timestamp_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "raw_input": raw_input,
            "depth": depth,
            "duration_seconds": elapsed,
            "opsec_mode": "Active+Passive" if is_active else "Passive",
            "approval_request_id": approved_record["request_id"] if approved_record else None,
            "user_confirmation": approved_record.get("user_confirmation") if approved_record else None,
            "active_modules_executed": enabled_active_mods if is_active else [],
            "case_dir": None,
        },
        "initial_selectors": seeds,
        "graph": {"nodes": nodes, "edges": edges},
        "wave_results": wave_results,
        "forged_dorks": forged_dorks,
        "arsenal": arsenal,
    }

    dossier_md = render_markdown_dossier(report)
    stix_bundle = build_stix2_bundle(case_id, raw_input, nodes, edges)

    if save_case:
        base_cases_dir = get_cases_dir(cases_dir)
        case_dir = base_cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        ref_root = PKG_PARENT if IS_REPO_MODE else Path.cwd()
        try:
            report["meta"]["case_dir"] = str(case_dir.relative_to(ref_root))
        except ValueError:
            report["meta"]["case_dir"] = str(case_dir)

        (case_dir / "dossier.md").write_text(dossier_md, encoding="utf-8")
        (case_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (case_dir / "graph.json").write_text(json.dumps(report["graph"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (case_dir / "stix2_bundle.json").write_text(json.dumps(stix_bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        manifest_lines = []
        for artifact in ("dossier.md", "report.json", "graph.json", "stix2_bundle.json"):
            digest = hashlib.sha256((case_dir / artifact).read_bytes()).hexdigest()
            manifest_lines.append(f"{digest}  {artifact}")
        (case_dir / "manifest.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    report["dossier_markdown"] = dossier_md
    return report

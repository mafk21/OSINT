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
from .correlator import (
    compare_cases,
    render_entities_csv,
    render_mermaid_graph,
    render_standalone_html_dossier,
    synthesize_intelligence,
)
from .exporters import (
    render_gexf,
    render_graphml,
    render_neo4j_cypher,
    write_obsidian_vault,
)
from .image_intel import harvest_and_cache_visual_intel
from .offline_intel import INTEL_TABLES, analyze_local_file
from .paths import DATA_DIR, IS_REPO_MODE, PKG_PARENT, get_cases_dir
from .persona import enrich_graph_confidence_and_personas
from .providers import get_byok_status
from .stage_analyzer import (
    analyze_stage_and_extract_leads,
    forge_exhaustive_dorks_for_entities,
)
from .temporal import build_temporal_profile
from .watchlist import compute_case_delta, find_latest_case_for_target

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
    syn = report.get("intelligence_synthesis") or synthesize_intelligence(report)
    lines = [
        f"# 🛰️ OSINT Intelligence Dossier — `{meta['case_id']}`",
        "",
        f"- **Generated (UTC)**: `{meta['timestamp_utc']}`",
        f"- **Raw Target Input**: `{meta['raw_input']}`",
        f"- **OPSEC Posture**: {opsec_line}",
        f"- **Exposure Rating**: **`{syn['exposure_score']}/100 — {syn['exposure_rating']}`**",
        f"- **Multi-Stage Surface Expansion**: `{meta.get('stages_executed', meta['depth'])}` stage(s) executed (max `{meta['depth']}`) · Converged: `{meta.get('converged', False)}` · `{meta['duration_seconds']}s` elapsed · `{len(report['graph']['nodes'])}` entity node(s) · `{len(report['graph']['edges'])}` pivot edge(s)",
    ]
    if is_active:
        lines.append(f"- **User Authorization Audit**: Request `{meta.get('approval_request_id')}` · Confirmation: `\"{meta.get('user_confirmation', '')}\"`")

    id_c = syn["identity_cluster"]
    inf_c = syn["infrastructure_cluster"]
    lines.extend(["", "---", "", "## 0. Executive Intelligence Synthesis", ""])
    if id_c["person_names"] or id_c["organizations"]:
        lines.append(f"- **Resolved Names / Organizations**: `{', '.join(id_c['person_names'] + id_c['organizations'])}`")
    if id_c["usernames_and_variants"]:
        lines.append(f"- **Handles & Variants**: `{', '.join(id_c['usernames_and_variants'][:12])}`")
    if id_c["emails"]:
        lines.append(f"- **Attributed Emails**: `{', '.join(id_c['emails'][:10])}`")
    if id_c["phones"]:
        ph_strs = [f"{p['e164']}" + (f" ({p.get('country')}, {p.get('carrier')})" if p.get("country") else "") for p in id_c["phones"][:8]]
        lines.append(f"- **Decoded Phones**: `{'; '.join(ph_strs)}`")
    if id_c["locations"]:
        lines.append(f"- **Geographic Indicators**: `{', '.join(id_c['locations'][:8])}`")
    if inf_c["domains_and_subdomains"] or inf_c["ip_addresses"]:
        lines.append(f"- **Domains & Hosts**: `{', '.join((inf_c['domains_and_subdomains'] + inf_c['ip_addresses'])[:12])}`")
    if id_c.get("social_profiles_detailed"):
        lines.append("- **Discovered Accounts & Social Profiles**:")
        for sp in id_c["social_profiles_detailed"][:12]:
            dn_part = f" ({sp['display_name']})" if sp.get("display_name") else ""
            bio_part = f" — *{sp['bio'][:90]}*" if sp.get("bio") else ""
            lines.append(f"  - **[{sp['platform']}: `{sp['handle']}`]({sp['url']})**{dn_part}{bio_part}")
    if syn.get("web_and_news_mentions"):
        lines.append("- **Open-Web & News Mentions**:")
        for wm in syn["web_and_news_mentions"][:8]:
            lines.append(f"  - **[{wm.get('title') or wm['url']}]({wm['url']})** *({wm.get('engine', 'Web')})* — {(wm.get('snippet') or '')[:140]}")
    if syn["cross_entity_attribution_bridges"]:
        lines.append("- **High-Confidence Attribution Bridges**:")
        for b in syn["cross_entity_attribution_bridges"][:8]:
            lines.append(f"  - `{b}`")
    if syn["security_and_opsec_exposures"]:
        lines.append("- **Technical / OPSEC Exposures Flagged**:")
        for ex in syn["security_and_opsec_exposures"][:8]:
            lines.append(f"  - ⚠️ {ex}")

    vis = report.get("visual_intel") or {}
    if vis.get("images"):
        lines.append(
            f"- **Visual & Image Intelligence (`IMINT`)**: `{vis['total_images']}` image(s) harvested "
            f"(`{vis.get('cached_count', 0)}` forensically cached in `images/`)"
        )
        for reuse in (vis.get("avatar_reuse_matches") or [])[:4]:
            plats = ", ".join(p["platform"] for p in reuse["platforms"])
            lines.append(f"  - 🔗 **Identical Photo Reused Across Platforms** (`SHA256:{reuse['sha256'][:12]}…`): `{plats}`")
        for fa in (vis.get("forensic_alerts") or [])[:5]:
            lines.append(f"  - 📸 **Image Forensic Alert**: {fa}")
        for im in vis["images"][:10]:
            local_note = f" (`{im['local_rel_path']}`, `{im.get('width') or '?'}x{im.get('height') or '?'}`)" if im.get("local_rel_path") else ""
            lens_u = (im.get("reverse_search") or {}).get("google_lens") or im["url"]
            lines.append(f"  - 🖼️ **[{im['platform']} · {im['label'][:70]}]({im['url']})**{local_note} — [Google Lens]({lens_u})")

    tprof = report.get("temporal_profile") or {}
    if tprof.get("inferred_timezone_offsets") or tprof.get("estimated_sleep_window_utc"):
        tz_keys = ", ".join(tprof.get("inferred_timezone_offsets", {}).keys()) or "inferred via circadian trough"
        regions = ", ".join(tprof.get("likely_geographic_regions") or [])
        sleep = tprof.get("estimated_sleep_window_utc")
        sleep_txt = f" · Circadian Sleep Window: `{sleep['sleep_window_utc']}` (`{sleep['inferred_utc_offset']}`)" if sleep else ""
        reg_txt = f" ({regions})" if regions else ""
        lines.append(f"- **Pattern-of-Life & Timezone Profile**: `{tz_keys}`{reg_txt}{sleep_txt}")
        for sh in tprof.get("timezone_shift_anomalies") or []:
            lines.append(f"  - 🕒 {sh}")

    pconf = report.get("persona_and_confidence") or {}
    if pconf.get("attribution_chains"):
        lines.append("- **Weighted Attribution Chains**:")
        for ch in pconf["attribution_chains"][:6]:
            lines.append(f"  - `{ch['formatted_chain']}` *(Joint Confidence: **{int(round(ch['joint_confidence'] * 100))}%**)*")
    for sflag in pconf.get("sockpuppet_and_burner_indicators") or []:
        lines.append(f"  - 🎭 **Sockpuppet / Burner Heuristic**: {sflag}")

    sdelta = report.get("surface_delta")
    if sdelta:
        lines.append(
            f"- **Surface Drift vs `{sdelta['baseline_case_id']}`**: "
            f"`+{sdelta['added_entity_count']}` new / `-{sdelta['removed_entity_count']}` retired entities · "
            f"Exposure Score `{sdelta['exposure_score_before']} → {sdelta['exposure_score_after']}` (`{sdelta['exposure_score_delta']:+d}`)"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 1. Confirmed & Discovered Entity Graph",
        "",
        "| Stage | Selector Type | Value | Discovered Via (Confidence) |",
        "| :---: | :--- | :--- | :--- |",
    ])
    edge_lookup = {
        e["target"]: f"`{e['source']}` via `{e['via']}` ({int(round(float(e.get('confidence', 0.8)) * 100))}%)"
        for e in report["graph"]["edges"]
    }
    for n in report["graph"]["nodes"]:
        origin = "Initial Seed" if n["wave"] == 1 else edge_lookup.get(n["id"], n.get("note") or "Stage Analyzer Pivot")
        lines.append(f"| `Stage {n['wave']}` | **`{n['type']}`** | `{n['value']}` | {origin} |")

    if len(report["graph"]["nodes"]) > 1:
        lines.extend(["", "```mermaid", render_mermaid_graph(report["graph"]["nodes"], report["graph"]["edges"]).rstrip(), "```"])

    stage_logs = report.get("stage_analyses") or []
    if stage_logs:
        lines.extend(["", "---", "", "## 1B. Multi-Stage Analyzer & Surface-Expansion Log", ""])
        for st_log in stage_logs:
            s_no = st_log["stage_analyzed"]
            n_new = st_log["new_leads_count"]
            by_t = ", ".join(f"`{k}`×{v}" for k, v in st_log["new_leads_by_type"].items()) or "none"
            variants = st_log.get("handle_variants_generated") or []
            var_note = f" · Handle variants: `{', '.join(variants)}`" if variants else ""
            status_badge = "✅ **CONVERGED (0 new unvisited leads)**" if n_new == 0 else f"🔄 **Carved {n_new} new lead(s)** ({by_t}) → hunted in Stage {s_no + 1}"
            lines.append(
                f"- **Stage {s_no}** (`{st_log['entities_analyzed_in_stage']}` entities hunted, `{st_log.get('filtered_infra_noise_count', 0)}` CDN/CA noise filtered{var_note}): {status_badge}"
            )

    lines.extend(["", "---", "", "## 2. Collector Findings by Stage & Entity", ""])
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
        lines.extend(["---", "", "## 4. Target-Forged Multi-Stage Search Engine Dorks", ""])
        for d in report["forged_dorks"][:28]:
            tgt_tag = f" (`{d['target']}`)" if d.get("target") else ""
            lines.append(f"- **[{d['engine']}] {d['title']}**{tgt_tag}: `{d['query']}`")
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


def _write_case_artifacts(case_dir: Path, report: dict, dossier_md: str, stix_bundle: dict) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    ref_root = PKG_PARENT if IS_REPO_MODE else Path.cwd()
    try:
        report["meta"]["case_dir"] = str(case_dir.relative_to(ref_root))
    except ValueError:
        report["meta"]["case_dir"] = str(case_dir)

    html_doc = render_standalone_html_dossier(report)
    csv_doc = render_entities_csv(report)
    mermaid_doc = render_mermaid_graph(report["graph"]["nodes"], report["graph"]["edges"])
    gexf_doc = render_gexf(report)
    graphml_doc = render_graphml(report)
    cypher_doc = render_neo4j_cypher(report)

    (case_dir / "dossier.md").write_text(dossier_md, encoding="utf-8")
    (case_dir / "report.html").write_text(html_doc, encoding="utf-8")
    (case_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (case_dir / "entities.csv").write_text(csv_doc, encoding="utf-8")
    (case_dir / "graph.json").write_text(json.dumps(report["graph"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (case_dir / "graph.mermaid").write_text(mermaid_doc, encoding="utf-8")
    (case_dir / "graph.gexf").write_text(gexf_doc, encoding="utf-8")
    (case_dir / "graph.graphml").write_text(graphml_doc, encoding="utf-8")
    (case_dir / "neo4j.cypher").write_text(cypher_doc, encoding="utf-8")
    (case_dir / "stix2_bundle.json").write_text(json.dumps(stix_bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_obsidian_vault(case_dir, report)

    manifest_lines = []
    for artifact in (
        "dossier.md",
        "report.html",
        "report.json",
        "entities.csv",
        "graph.json",
        "graph.mermaid",
        "graph.gexf",
        "graph.graphml",
        "neo4j.cypher",
        "stix2_bundle.json",
    ):
        digest = hashlib.sha256((case_dir / artifact).read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  {artifact}")
    (case_dir / "manifest.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")


def _execute_stage_loop(
    *,
    current_queue: list[tuple[str, str]],
    start_stage: int,
    max_stage: int,
    max_pivots_per_wave: int,
    max_total_entities: int,
    visited: set[str],
    nodes: list[dict],
    edges: list[dict],
    wave_results: list[dict],
    stage_analyses: list[dict],
    values_by_type: dict[str, list[str]],
    is_active: bool,
    enabled_active_mods: list[str],
    initial_ingested_evidence: list[dict] | None = None,
    expand_handle_variants: bool = True,
) -> tuple[int, bool]:
    """Run exhaustive breadth-first OSINT stage after stage until 0 new leads remain or max_stage is reached."""
    stages_executed = 0
    converged = False
    seen_edges = {(e["source"], e["target"], e["via"]) for e in edges}

    for wave_num in range(start_stage, max_stage + 1):
        if not current_queue:
            converged = True
            break

        stages_executed += 1

        def _exec_one(item: tuple[str, str]):
            st, sv = item
            try:
                outs = collect_for_selector(st, sv)
            except Exception as exc:
                outs = [{"module": "passive_collector_guard", "opsec": "Passive", "status": "restricted_or_offline", "summary": f"Collector skipped ({exc})", "data": {}, "pivots": []}]
            if is_active:
                try:
                    outs = outs + collect_active_for_selector(st, sv, enabled_active_mods)
                except Exception as exc:
                    outs = outs + [{"module": "active_collector_guard", "opsec": "Active", "status": "restricted_or_offline", "status_code": 0, "summary": f"Active probe skipped ({exc})", "data": {}, "pivots": []}]
            return st, sv, outs

        stage_items: list[dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(current_queue))) as pool:
            for stype, sval, collector_outs in pool.map(_exec_one, current_queue):
                rec = {
                    "wave": wave_num,
                    "type": stype,
                    "value": sval,
                    "collector_outputs": collector_outs,
                }
                wave_results.append(rec)
                stage_items.append(rec)

        stage_ev = initial_ingested_evidence if wave_num == start_stage else None
        analysis = analyze_stage_and_extract_leads(
            stage_num=wave_num,
            stage_items=stage_items,
            visited=visited,
            ingested_evidence=stage_ev,
            expand_handle_variants=expand_handle_variants,
        )

        for e in analysis["edges"]:
            ekey = (e["source"], e["target"], e["via"])
            if ekey not in seen_edges:
                seen_edges.add(ekey)
                edges.append({"source": e["source"], "target": e["target"], "via": e["via"]})

        leads = analysis["leads"]
        queued_next: list[tuple[str, str]] = []
        if not leads:
            converged = True
        elif wave_num < max_stage:
            for ld in leads:
                if len(nodes) >= max_total_entities or len(queued_next) >= max_pivots_per_wave:
                    break
                dst_id = ld["id"]
                if dst_id in visited:
                    continue
                visited.add(dst_id)
                nodes.append(
                    {
                        "id": dst_id,
                        "type": ld["type"],
                        "value": ld["value"],
                        "wave": wave_num + 1,
                        "note": f"Stage {wave_num} -> {ld['via']}",
                    }
                )
                values_by_type.setdefault(ld["type"], []).append(ld["value"])
                queued_next.append((ld["type"], ld["value"]))

        stage_analyses.append(
            {
                "stage_analyzed": wave_num,
                "entities_analyzed_in_stage": analysis["entities_analyzed_in_stage"],
                "ingested_evidence_blocks": analysis["ingested_evidence_blocks"],
                "new_leads_count": analysis["new_leads_count"],
                "new_leads_by_type": analysis["new_leads_by_type"],
                "handle_variants_generated": analysis["handle_variants_generated"],
                "filtered_infra_noise_count": analysis["filtered_infra_noise_count"],
                "queued_for_next_stage": len(queued_next),
            }
        )
        current_queue = queued_next
        if converged:
            break

    return stages_executed, converged


def run_autonomous_hunt(
    raw_input: str,
    *,
    depth: int = 4,
    max_pivots_per_wave: int = 50,
    max_total_entities: int = 100,
    expand_handle_variants: bool = True,
    ingested_evidence_text: str | None = None,
    save_case: bool = True,
    cases_dir: str | Path | None = None,
    cwd: str | None = None,
    mode: str = "passive",
    approval_request_id: str | None = None,
    user_confirmation: str | None = None,
    active_modules: list[str] | None = None,
    enforce_turn_delay: bool = True,
    diff_last: bool = False,
    display_label: str | None = None,
) -> dict:
    """Execute an exhaustive multi-stage OSINT hunt until surface convergence.

    - `mode="passive"` (default): Zero questions, immediate execution, zero direct target packets.
      Exhaustively hunts Stage 1, analyzes ALL findings to carve EVERY new clue, hunts ALL new clues
      in Stage 2 -> Stage 3 -> Stage N until 0 new leads appear (or `depth` / `max_total_entities`).
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
    depth = max(1, min(int(depth), 6))
    max_pivots_per_wave = max(1, min(int(max_pivots_per_wave), 200))
    seeds = extract_selectors(raw_input, cwd=cwd)
    if not seeds:
        seeds = [{"type": "keyword", "value": raw_input.strip()[:100], "confidence": 0.5, "note": "Fallback keyword"}]

    source_file_info: dict | None = None
    pre_wave_results: list[dict] = []
    if len(seeds) == 1 and seeds[0]["type"] == "local_file":
        fpath_str = seeds[0]["value"]
        f_dec = analyze_local_file(fpath_str)
        fname_clean = f_dec["file_name"]
        content_sels = f_dec.get("content_selectors") or []
        txt_sample = (f_dec.get("extracted_text_sample") or "").strip()
        if txt_sample:
            ingested_evidence_text = f"{ingested_evidence_text}\n{txt_sample}".strip() if ingested_evidence_text else txt_sample

        source_file_info = {
            "file_name": fname_clean,
            "detected_format": f_dec["detected_format"],
            "size_bytes": f_dec["size_bytes"],
            "hashes": f_dec["hashes"],
            "extracted_metadata": f_dec["extracted_metadata"],
            "extracted_selector_count": len(content_sels),
        }
        if not display_label:
            display_label = f"File: {fname_clean}"

        if content_sels:
            seeds = [
                {
                    "type": pv["type"],
                    "value": pv["value"],
                    "confidence": 0.96,
                    "note": f"Extracted inside {fname_clean}",
                }
                for pv in content_sels
            ]
        else:
            # File had no embedded accounts/domains/phones/GPS — record clean file inspection without temp paths
            clean_fdec = {k: v for k, v in f_dec.items() if k not in ("absolute_path", "extracted_text_sample")}
            seeds = []
            pre_wave_results.append(
                {
                    "wave": 1,
                    "type": "document",
                    "value": fname_clean,
                    "collector_outputs": [
                        {
                            "module": "local_binary_forensics",
                            "opsec": "Passive",
                            "status": "ok",
                            "summary": f"{f_dec['detected_format']} ({f_dec['size_bytes']} B) · SHA256={f_dec['hashes']['sha256'][:16]}... · 0 target selectors found inside file",
                            "data": clean_fdec,
                            "pivots": [],
                        }
                    ],
                }
            )

    effective_label = (display_label or raw_input).strip()
    ts = datetime.now(timezone.utc)
    slug_source = source_file_info["file_name"] if source_file_info else (seeds[0]["value"] if seeds else effective_label)
    case_slug = _slugify(Path(slug_source).stem if source_file_info else slug_source)
    prefix_tag = "ACTIVE_" if is_active else ""
    case_id = f"{prefix_tag}{ts.strftime('%Y%m%dT%H%M%SZ')}_{case_slug}"

    visited: set[str] = set()
    nodes: list[dict] = []
    edges: list[dict] = []
    wave_results: list[dict] = list(pre_wave_results)
    stage_analyses: list[dict] = []
    values_by_type: dict[str, list[str]] = {}

    current_queue: list[tuple[str, str]] = []
    for s in seeds:
        nid = f"{s['type']}:{s['value'].lower()}"
        if nid not in visited:
            visited.add(nid)
            nodes.append({"id": nid, "type": s["type"], "value": s["value"], "wave": 1, "note": s.get("note", "")})
            values_by_type.setdefault(s["type"], []).append(s["value"])
            current_queue.append((s["type"], s["value"]))

    ev_src_id = f"{seeds[0]['type']}:{seeds[0]['value'].lower()}" if seeds else f"document:{case_slug}"
    ev_blocks = (
        [{"source_id": ev_src_id, "label": "ingested_evidence", "text": ingested_evidence_text}]
        if ingested_evidence_text and ingested_evidence_text.strip()
        else None
    )

    stages_executed, converged = _execute_stage_loop(
        current_queue=current_queue,
        start_stage=1,
        max_stage=depth,
        max_pivots_per_wave=max_pivots_per_wave,
        max_total_entities=max_total_entities,
        visited=visited,
        nodes=nodes,
        edges=edges,
        wave_results=wave_results,
        stage_analyses=stage_analyses,
        values_by_type=values_by_type,
        is_active=is_active,
        enabled_active_mods=enabled_active_mods,
        initial_ingested_evidence=ev_blocks,
        expand_handle_variants=expand_handle_variants,
    )

    all_entities = [(n["type"], n["value"]) for n in nodes]
    forged_dorks = forge_exhaustive_dorks_for_entities(all_entities, ALL_DORKS, max_total=60)
    arsenal = recommend_arsenal_for_selectors(list(values_by_type.keys()), values_by_type, include_active=is_active)
    elapsed = round(time.monotonic() - t0, 2)

    report = {
        "meta": {
            "case_id": case_id,
            "timestamp_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "raw_input": effective_label,
            "depth": depth,
            "stages_executed": stages_executed,
            "converged": converged,
            "duration_seconds": elapsed,
            "opsec_mode": "Active+Passive" if is_active else "Passive",
            "approval_request_id": approved_record["request_id"] if approved_record else None,
            "user_confirmation": approved_record.get("user_confirmation") if approved_record else None,
            "active_modules_executed": enabled_active_mods if is_active else [],
            "source_file": source_file_info,
            "case_dir": None,
        },
        "initial_selectors": seeds,
        "graph": {"nodes": nodes, "edges": edges},
        "stage_analyses": stage_analyses,
        "wave_results": wave_results,
        "forged_dorks": forged_dorks,
        "arsenal": arsenal,
    }

    case_dir = (get_cases_dir(cases_dir) / case_id) if save_case else None
    report["visual_intel"] = harvest_and_cache_visual_intel(report, case_dir=case_dir, is_active=is_active)
    report["intelligence_synthesis"] = synthesize_intelligence(report)
    report["temporal_profile"] = build_temporal_profile(report)
    report["persona_and_confidence"] = enrich_graph_confidence_and_personas(report)
    report["byok_providers_active"] = [p["provider"] for p in get_byok_status() if p["configured"]]
    if diff_last:
        prev = find_latest_case_for_target(effective_label, cases_dir=cases_dir, exclude_case_id=case_id)
        report["surface_delta"] = compute_case_delta(prev[1], report) if prev else None

    dossier_md = render_markdown_dossier(report)
    stix_bundle = build_stix2_bundle(case_id, effective_label, nodes, edges)

    if save_case and case_dir is not None:
        _write_case_artifacts(case_dir, report, dossier_md, stix_bundle)

    report["dossier_markdown"] = dossier_md
    return report


def _resolve_case_dir(case_id_or_dir: str | Path, cases_dir: str | Path | None = None) -> Path:
    cand = Path(case_id_or_dir)
    if cand.is_dir() and (cand / "report.json").is_file():
        return cand
    base = get_cases_dir(cases_dir)
    by_id = base / str(case_id_or_dir)
    if by_id.is_dir() and (by_id / "report.json").is_file():
        return by_id
    raise FileNotFoundError(f"Case directory or report.json not found for '{case_id_or_dir}'")


def expand_existing_case(
    case_id_or_dir: str | Path,
    *,
    ingested_text: str,
    additional_stages: int = 3,
    max_pivots_per_wave: int = 50,
    max_total_entities: int = 120,
    cases_dir: str | Path | None = None,
) -> dict:
    """Ingest external stage findings (e.g. web_search / fetch_page bios, snippets, pages) into an existing case,
    carve EVERY newly discovered clue, and hunt ALL new clues across subsequent passive stages until convergence.
    """
    t0 = time.monotonic()
    case_dir = _resolve_case_dir(case_id_or_dir, cases_dir=cases_dir)
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))

    nodes: list[dict] = report["graph"]["nodes"]
    edges: list[dict] = report["graph"]["edges"]
    wave_results: list[dict] = report.get("wave_results") or []
    stage_analyses: list[dict] = report.get("stage_analyses") or []

    visited: set[str] = {n["id"] for n in nodes}
    values_by_type: dict[str, list[str]] = {}
    for n in nodes:
        values_by_type.setdefault(n["type"], []).append(n["value"])

    last_stage = max((n.get("wave", 1) for n in nodes), default=1)
    anchor_id = nodes[0]["id"] if nodes else "seed:case"

    carve_res = analyze_stage_and_extract_leads(
        stage_num=last_stage,
        stage_items=[],
        visited=visited,
        ingested_evidence=[{"source_id": anchor_id, "label": f"stage_{last_stage}_ingested_intel", "text": ingested_text}],
        expand_handle_variants=True,
    )

    seen_edges = {(e["source"], e["target"], e["via"]) for e in edges}
    for e in carve_res["edges"]:
        ekey = (e["source"], e["target"], e["via"])
        if ekey not in seen_edges:
            seen_edges.add(ekey)
            edges.append({"source": e["source"], "target": e["target"], "via": e["via"]})

    next_queue: list[tuple[str, str]] = []
    next_stage_num = last_stage + 1
    for ld in carve_res["leads"]:
        if len(nodes) >= max_total_entities or len(next_queue) >= max_pivots_per_wave:
            break
        dst_id = ld["id"]
        if dst_id in visited:
            continue
        visited.add(dst_id)
        nodes.append(
            {
                "id": dst_id,
                "type": ld["type"],
                "value": ld["value"],
                "wave": next_stage_num,
                "note": f"Carved from ingested intel ({ld['via']})",
            }
        )
        values_by_type.setdefault(ld["type"], []).append(ld["value"])
        next_queue.append((ld["type"], ld["value"]))

    stage_analyses.append(
        {
            "stage_analyzed": last_stage,
            "entities_analyzed_in_stage": 0,
            "ingested_evidence_blocks": 1,
            "new_leads_count": carve_res["new_leads_count"],
            "new_leads_by_type": carve_res["new_leads_by_type"],
            "handle_variants_generated": carve_res["handle_variants_generated"],
            "filtered_infra_noise_count": carve_res["filtered_infra_noise_count"],
            "queued_for_next_stage": len(next_queue),
        }
    )

    add_exec, converged = (0, True)
    if next_queue:
        add_exec, converged = _execute_stage_loop(
            current_queue=next_queue,
            start_stage=next_stage_num,
            max_stage=last_stage + max(1, min(int(additional_stages), 5)),
            max_pivots_per_wave=max_pivots_per_wave,
            max_total_entities=max_total_entities,
            visited=visited,
            nodes=nodes,
            edges=edges,
            wave_results=wave_results,
            stage_analyses=stage_analyses,
            values_by_type=values_by_type,
            is_active=False,
            enabled_active_mods=[],
            initial_ingested_evidence=None,
            expand_handle_variants=True,
        )

    all_entities = [(n["type"], n["value"]) for n in nodes]
    report["forged_dorks"] = forge_exhaustive_dorks_for_entities(all_entities, ALL_DORKS, max_total=80)
    report["arsenal"] = recommend_arsenal_for_selectors(list(values_by_type.keys()), values_by_type, include_active=False)
    report["stage_analyses"] = stage_analyses
    report["meta"]["stages_executed"] = report["meta"].get("stages_executed", last_stage) + add_exec
    report["meta"]["depth"] = max(report["meta"]["depth"], next_stage_num + max(0, add_exec - 1))
    report["meta"]["converged"] = converged
    report["meta"]["duration_seconds"] = round(report["meta"].get("duration_seconds", 0.0) + (time.monotonic() - t0), 2)

    report["visual_intel"] = harvest_and_cache_visual_intel(report, case_dir=case_dir, is_active=False)
    report["intelligence_synthesis"] = synthesize_intelligence(report)
    report["temporal_profile"] = build_temporal_profile(report)
    report["persona_and_confidence"] = enrich_graph_confidence_and_personas(report)
    dossier_md = render_markdown_dossier(report)
    stix_bundle = build_stix2_bundle(report["meta"]["case_id"], report["meta"]["raw_input"], nodes, edges)
    _write_case_artifacts(case_dir, report, dossier_md, stix_bundle)
    report["dossier_markdown"] = dossier_md
    report["newly_hunted_entities"] = [{"type": t, "value": v} for t, v in next_queue]
    return report


def compare_saved_cases(case_a: str | Path, case_b: str | Path, cases_dir: str | Path | None = None) -> dict:
    """Compare two saved cases for shared selectors, domains, /24 IP subnets, and analytics tags."""
    dir_a = _resolve_case_dir(case_a, cases_dir=cases_dir)
    dir_b = _resolve_case_dir(case_b, cases_dir=cases_dir)
    return compare_cases(dir_a, dir_b)


def get_case_active_target_string(case_id_or_dir: str | Path, cases_dir: str | Path | None = None) -> str:
    """Build a unified active-recon target string covering ALL domains, URLs, IPs, emails, and handles in a case."""
    case_dir = _resolve_case_dir(case_id_or_dir, cases_dir=cases_dir)
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    parts: list[str] = []
    for n in report["graph"]["nodes"]:
        nt, nv = n["type"], n["value"]
        if nt == "username":
            parts.append(f"@{nv}")
        elif nt in {"domain", "url", "ip", "email", "onion_url"}:
            parts.append(nv)
    return ", ".join(parts[:35]) or report["meta"]["raw_input"]

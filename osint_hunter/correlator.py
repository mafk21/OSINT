"""Executive Intelligence Synthesis, Exposure Scoring, Cross-Case Link Analysis & HTML/CSV/Mermaid Exporters."""

from __future__ import annotations

import csv
import html
import io
import json
import math
import re
from pathlib import Path


def synthesize_intelligence(report: dict) -> dict:
    """Distill multi-stage collector outputs & graph topology into an Executive Intelligence Summary & Exposure Score."""
    nodes = report.get("graph", {}).get("nodes", [])
    edges = report.get("graph", {}).get("edges", [])
    wave_results = report.get("wave_results", [])

    by_type: dict[str, list[str]] = {}
    for n in nodes:
        by_type.setdefault(n["type"], [])
        if n["value"] not in by_type[n["type"]]:
            by_type[n["type"]].append(n["value"])

    verified_profiles: list[dict] = []
    locations: set[str] = set()
    phones_decoded: list[dict] = []
    jarm_hashes: list[str] = []
    favicon_hashes: list[str] = []
    analytics_ids: set[str] = set()
    security_exposures: list[str] = []
    open_ports_summary: dict[str, list[int]] = {}

    for item in wave_results:
        sval = item["value"]
        for mod in item.get("collector_outputs") or []:
            if mod.get("status") != "ok":
                continue
            mname = mod.get("module", "")
            data = mod.get("data") or {}
            if not isinstance(data, dict):
                continue

            # Profile URLs & Locations
            for url_k in ("profile_url", "html_url", "web_url"):
                if isinstance(data.get(url_k), str) and data[url_k].startswith("http"):
                    verified_profiles.append({"platform": mname, "entity": sval, "url": data[url_k]})
            if mname == "active_username_live_platform_probe":
                for hit in data.get("confirmed_profiles") or []:
                    if isinstance(hit, dict) and hit.get("url"):
                        verified_profiles.append({"platform": hit.get("platform", "web"), "entity": sval, "url": hit["url"]})

            for loc_k in ("location", "country", "registration_country", "flag_state"):
                lv = data.get(loc_k)
                if isinstance(lv, str) and lv.strip() and "Unknown" not in lv:
                    locations.add(lv.strip())

            # Phone decoding
            if mname == "phone_itu_decoder" and data.get("e164"):
                phones_decoded.append(
                    {
                        "e164": data["e164"],
                        "country": data.get("country"),
                        "carrier": data.get("carrier_or_region_hint"),
                    }
                )

            # Active/Passive Technical Fingerprints & Exposures
            if data.get("tls_stack_hash"):
                jarm_hashes.append(f"{sval}: {data['tls_stack_hash']}")
            if data.get("shodan_mmh3_hash") is not None:
                favicon_hashes.append(f"{sval}: http.favicon.hash:{data['shodan_mmh3_hash']}")
            for ak in ("ga4_ids", "gtm_ids", "ua_ids", "adsense_ids", "meta_pixels"):
                for tag_id in data.get(ak) or []:
                    analytics_ids.add(str(tag_id))
            if isinstance(data.get("tracking_ids"), dict):
                for arr in data["tracking_ids"].values():
                    if isinstance(arr, list):
                        for tag_id in arr:
                            analytics_ids.add(str(tag_id))

            if mname == "github_user_osint" and data.get("commit_emails"):
                security_exposures.append(f"Git commit header email leak on @{sval}: {', '.join(data['commit_emails'][:3])}")
            if mname == "bluesky_atproto":
                verified_profiles.append(f"Bluesky: {data.get('handle', sval)} ({data.get('did', '')})")
                if len(data.get("plc_handle_history") or []) > 1:
                    security_exposures.append(f"Bluesky PLC audit log exposed historical handle rename(s): {data['plc_handle_history']}")
            if mname == "mastodon_fediverse":
                verified_profiles.append(f"Mastodon: {data.get('acct', sval)}")
            if mname in ("modern_package_registries", "modern_pkg_registries_osint"):
                for reg_name in (data.get("hits") or data.get("registries") or {}):
                    verified_profiles.append(f"{reg_name}: {sval}")
            if mname == "microsoft_entra_tenant_passive" and data.get("federated_idp_auth_url"):
                security_exposures.append(f"Federated SSO IdP endpoint exposed via Microsoft GetUserRealm on {sval}: {data['federated_idp_auth_url']}")
            if mname == "byok_hibp_breaches" and data.get("breach_count", 0) > 0:
                security_exposures.append(f"HIBP flagged {data['breach_count']} credential breach(es) for {sval}")
            if mname == "byok_virustotal" and data.get("malicious", 0) > 0:
                security_exposures.append(f"VirusTotal flagged {data['malicious']} malicious vendor detection(s) on {sval}")
            if mname == "byok_abuseipdb" and (data.get("abuse_confidence_score") or 0) >= 25:
                security_exposures.append(f"AbuseIPDB score {data['abuse_confidence_score']}/100 ({data.get('total_reports')} reports) on {sval}")
            if mname == "local_file_forensics":
                meta_sub = data.get("extracted_metadata") or data
                eml_flags = ((meta_sub.get("eml_forensics") or {}).get("spoofing_and_anomaly_flags")) or []
                for flg in eml_flags[:3]:
                    security_exposures.append(f"Email (.eml) header anomaly: {flg}")
            if mname == "active_dns_zone_transfer_axfr" and data.get("axfr_vulnerable"):
                security_exposures.append(f"CRITICAL: DNS Zone Transfer (AXFR) open on {sval}")
            if mname == "active_subdomain_takeover_cname_audit" and data.get("vulnerable_cnames"):
                security_exposures.append(f"HIGH: Potential dangling CNAME subdomain takeover on {sval}")
            if mname == "active_http_methods_cors_and_waf" and data.get("cors_dangerous_reflection"):
                security_exposures.append(f"HIGH: Arbitrary Origin CORS credential reflection on {sval}")
            if mname == "active_exposed_vcs_and_env_check" and data.get("exposed_artifacts"):
                security_exposures.append(f"HIGH: Exposed VCS/config artifact on {sval}: {list(data['exposed_artifacts'].keys())}")
            if mname == "active_tls_protocol_alpn_matrix" and data.get("deprecated_protocols_enabled"):
                security_exposures.append(f"Deprecated TLS enabled on {sval}: {data['deprecated_protocols_enabled']}")
            if mname in ("shodan_internetdb", "active_tcp_service_banner_probe"):
                ports = data.get("ports") or [p.get("port") for p in (data.get("open_ports") or []) if isinstance(p, dict) and p.get("port")]
                if ports:
                    open_ports_summary[sval] = sorted(set(int(p) for p in ports if p))[:20]
                if data.get("vulns"):
                    security_exposures.append(f"Shodan InternetDB flagged {len(data['vulns'])} CVE(s) on {sval}: {', '.join(data['vulns'][:4])}")

    # Cross-type attribution bridges ("Smoking Guns")
    node_map = {n["id"]: n for n in nodes}
    attribution_bridges: list[str] = []
    for e in edges:
        sn = node_map.get(e["source"])
        dn = node_map.get(e["target"])
        if sn and dn and sn["type"] != dn["type"]:
            bridge = f"[{sn['type']}] {sn['value']} ──({e['via']})──► [{dn['type']}] {dn['value']}"
            if bridge not in attribution_bridges:
                attribution_bridges.append(bridge)

    # Compute 0-100 Surface Exposure & Footprint Score
    score = 0
    factors: list[dict] = []

    def _add_pts(pts: int, reason: str) -> None:
        nonlocal score
        if pts > 0:
            score += pts
            factors.append({"points": pts, "reason": reason})

    if by_type.get("email"):
        _add_pts(min(18, 8 + 4 * len(by_type["email"])), f"{len(by_type['email'])} public/leaked email selector(s) attributed")
    if by_type.get("phone"):
        _add_pts(min(14, 8 + 3 * len(by_type["phone"])), f"{len(by_type['phone'])} phone/WhatsApp number(s) exposed")
    if by_type.get("domain"):
        _add_pts(min(16, 6 + 2 * len(by_type["domain"])), f"{len(by_type['domain'])} domain/subdomain asset(s) mapped")
    if verified_profiles:
        _add_pts(min(15, 4 + 3 * len(verified_profiles)), f"{len(verified_profiles)} verified public profile(s) linked")
    if by_type.get("person_name") or by_type.get("company"):
        _add_pts(10, "Real-world human name or organization/corporate attribution established")
    if open_ports_summary:
        _add_pts(12, f"Open network services mapped across {len(open_ports_summary)} host(s)")
    if security_exposures:
        _add_pts(min(30, 12 * len(security_exposures)), f"{len(security_exposures)} technical OPSEC/security exposure finding(s)")
    if len(nodes) > 1 and score == 0:
        _add_pts(10, f"Multi-entity surface graph ({len(nodes)} nodes)")

    score = min(100, score)
    if score >= 75:
        rating = "CRITICAL SURFACE EXPOSURE"
    elif score >= 50:
        rating = "ELEVATED EXPOSURE"
    elif score >= 25:
        rating = "MODERATE FOOTPRINT"
    else:
        rating = "LOW / MINIMAL FOOTPRINT"

    return {
        "exposure_score": score,
        "exposure_rating": rating,
        "score_factors": factors,
        "identity_cluster": {
            "person_names": by_type.get("person_name", []),
            "organizations": by_type.get("company", []),
            "usernames_and_variants": by_type.get("username", []),
            "emails": by_type.get("email", []),
            "phones": phones_decoded or [{"e164": p} for p in by_type.get("phone", [])],
            "locations": sorted(locations),
            "verified_profiles": verified_profiles[:25],
        },
        "infrastructure_cluster": {
            "domains_and_subdomains": by_type.get("domain", []),
            "ip_addresses": by_type.get("ip", []),
            "asns": by_type.get("asn", []),
            "open_ports_by_host": open_ports_summary,
            "tls_jarm_hashes": jarm_hashes,
            "shodan_favicon_hashes": favicon_hashes,
            "analytics_and_ad_ids": sorted(analytics_ids),
            "crypto_wallets": by_type.get("crypto_address", []),
        },
        "security_and_opsec_exposures": security_exposures,
        "cross_entity_attribution_bridges": attribution_bridges[:25],
    }


def render_mermaid_graph(nodes: list[dict], edges: list[dict], max_nodes: int = 35) -> str:
    """Render a deterministic Mermaid `flowchart LR` diagram for GitHub Markdown & analyst viewers."""
    capped_nodes = nodes[:max_nodes]
    allowed_ids = {n["id"] for n in capped_nodes}
    id_alias = {n["id"]: f"N{idx}" for idx, n in enumerate(capped_nodes, 1)}

    lines = ["flowchart LR"]
    for n in capped_nodes:
        aid = id_alias[n["id"]]
        safe_lbl = f"[Stage {n.get('wave', 1)}] {n['type']}: {n['value']}".replace('"', "'").replace("`", "")
        lines.append(f'  {aid}["{safe_lbl}"]')

    for e in edges[:60]:
        if e["source"] in allowed_ids and e["target"] in allowed_ids:
            s_id = id_alias[e["source"]]
            t_id = id_alias[e["target"]]
            via = str(e.get("via", "pivot")).split(":")[-1].replace('"', "'")[:28]
            lines.append(f'  {s_id} -->|"{via}"| {t_id}')

    return "\n".join(lines) + "\n"


def render_entities_csv(report: dict) -> str:
    """Export all discovered graph entities as standard UTF-8 CSV for Excel, Maltego, or Gephi."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["stage", "selector_type", "value", "node_id", "discovery_origin"])
    edge_lookup = {e["target"]: f"{e['source']} via {e['via']}" for e in report.get("graph", {}).get("edges", [])}
    for n in report.get("graph", {}).get("nodes", []):
        origin = "Initial Seed" if n.get("wave") == 1 else edge_lookup.get(n["id"], n.get("note", ""))
        writer.writerow([n.get("wave", 1), n["type"], n["value"], n["id"], origin])
    return buf.getvalue()


def _render_inline_svg_graph(nodes: list[dict], edges: list[dict]) -> str:
    """Generate a zero-JS concentric stage SVG network map for standalone HTML reports."""
    if not nodes:
        return ""
    capped = nodes[:32]
    allowed = {n["id"] for n in capped}
    w, h = 860, 420
    cx, cy = w / 2, h / 2

    colors = {1: "#00e5ff", 2: "#00e676", 3: "#ffab00", 4: "#ff5252", 5: "#b388ff"}
    coords: dict[str, tuple[float, float]] = {}

    by_wave: dict[int, list[dict]] = {}
    for n in capped:
        by_wave.setdefault(int(n.get("wave", 1)), []).append(n)

    for wave_idx, grp in sorted(by_wave.items()):
        if wave_idx == 1 and len(grp) == 1:
            coords[grp[0]["id"]] = (cx, cy)
            continue
        radius = min(cx, cy) - 42 if wave_idx >= 3 else (75 if wave_idx == 1 else 145)
        for i, n in enumerate(grp):
            ang = (2 * math.pi * i / max(1, len(grp))) - math.pi / 2
            coords[n["id"]] = (cx + radius * 1.55 * math.cos(ang), cy + radius * 0.92 * math.sin(ang))

    svg = [f'<svg viewBox="0 0 {w} {h}" style="width:100%;max-height:420px;background:#070b14;border:1px solid #1e293b;border-radius:10px;">']
    for e in edges:
        if e["source"] in allowed and e["target"] in allowed and e["source"] in coords and e["target"] in coords:
            x1, y1 = coords[e["source"]]
            x2, y2 = coords[e["target"]]
            svg.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#334155" stroke-width="1.4" />')

    for n in capped:
        x, y = coords[n["id"]]
        col = colors.get(int(n.get("wave", 1)), "#38bdf8")
        lbl = html.escape(f"{n['type']}:{n['value']}"[:26])
        svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="{col}" stroke="#0f172a" stroke-width="2" />')
        svg.append(f'<text x="{x:.1f}" y="{y + 18:.1f}" fill="#cbd5e1" font-size="10.5" font-family="monospace" text-anchor="middle">{lbl}</text>')
    svg.append("</svg>")
    return "\n".join(svg)


def render_standalone_html_dossier(report: dict) -> str:
    """Render a self-contained, zero-dependency dark-mode Executive HTML Dossier (printable to PDF)."""
    meta = report["meta"]
    syn = report.get("intelligence_synthesis") or synthesize_intelligence(report)
    score = syn["exposure_score"]
    score_col = "#ff5252" if score >= 75 else ("#ffab00" if score >= 50 else ("#00e5ff" if score >= 25 else "#00e676"))
    svg_map = _render_inline_svg_graph(report["graph"]["nodes"], report["graph"]["edges"])

    rows_html = []
    edge_lookup = {e["target"]: f"{e['source']} via {e['via']}" for e in report["graph"]["edges"]}
    for n in report["graph"]["nodes"]:
        orig = "Initial Seed" if n.get("wave") == 1 else edge_lookup.get(n["id"], n.get("note", ""))
        rows_html.append(
            f"<tr><td>Stage {n.get('wave', 1)}</td><td><code>{html.escape(n['type'])}</code></td>"
            f"<td><strong>{html.escape(n['value'])}</strong></td><td>{html.escape(orig)}</td></tr>"
        )

    bridges_html = "".join(f"<li><code>{html.escape(b)}</code></li>" for b in syn["cross_entity_attribution_bridges"]) or "<li>No cross-type hops recorded.</li>"
    exposures_html = "".join(f"<li style='color:#ff8a80;'>{html.escape(x)}</li>" for x in syn["security_and_opsec_exposures"]) or "<li>Zero direct OPSEC/config exposures flagged.</li>"

    dorks_html = "".join(
        f"<li><strong>[{html.escape(d['engine'])}] {html.escape(d['title'])}</strong>: <code>{html.escape(d['query'])}</code></li>"
        for d in (report.get("forged_dorks") or [])[:25]
    )

    findings_blocks = []
    for item in report.get("wave_results") or []:
        mods_html = []
        for mod in item.get("collector_outputs") or []:
            st = mod.get("status")
            badge = "✅" if st == "ok" else ("⚪" if st == "not_found" else "🔒")
            payload_html = ""
            if st == "ok" and mod.get("data"):
                raw_j = html.escape(json.dumps(mod["data"], indent=2, ensure_ascii=False)[:2500])
                payload_html = f"<pre>{raw_j}</pre>"
            mods_html.append(
                f"<details {'open' if st == 'ok' else ''}><summary>{badge} <code>{html.escape(mod['module'])}</code> — {html.escape(mod.get('summary', ''))}</summary>{payload_html}</details>"
            )
        findings_blocks.append(
            f"<div class='card'><h3>[Stage {item['wave']}] <code>{html.escape(item['type'])}</code>: {html.escape(item['value'])}</h3>{''.join(mods_html)}</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>OSINT Dossier — {html.escape(meta['case_id'])}</title>
<style>
  body {{ background:#0b1020; color:#e2e8f0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; margin:0; padding:28px; line-height:1.55; }}
  .wrap {{ max-width:1120px; margin:0 auto; }}
  .hero {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:22px; display:flex; justify-content:space-between; align-items:center; gap:20px; flex-wrap:wrap; }}
  .score-box {{ text-align:center; padding:14px 22px; border-radius:10px; background:#070b14; border:2px solid {score_col}; min-width:165px; }}
  .score-num {{ font-size:34px; font-weight:800; color:{score_col}; }}
  .grid2 {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; margin-top:18px; }}
  .card {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:16px 18px; margin-top:16px; }}
  h1,h2,h3 {{ margin-top:0; color:#f8fafc; }}
  code {{ background:#1e293b; color:#38bdf8; padding:2px 6px; border-radius:4px; font-size:12.5px; }}
  pre {{ background:#070b14; color:#cbd5e1; padding:12px; border-radius:8px; overflow-x:auto; font-size:12px; border:1px solid #1e293b; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1f2937; }}
  th {{ color:#94a3b8; text-transform:uppercase; font-size:11px; }}
  details {{ margin:6px 0; padding:6px 10px; background:#0f172a; border-radius:6px; border:1px solid #1e293b; }}
  summary {{ cursor:pointer; font-size:13px; }}
  @media print {{ body {{ background:#fff; color:#111; padding:10px; }} .hero,.card,details,pre {{ background:#fff !important; color:#111 !important; border-color:#ccc !important; }} code {{ background:#f1f5f9; color:#0f172a; }} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>🛰️ OSINT Monster Executive Dossier</h1>
      <div>Case ID: <code>{html.escape(meta['case_id'])}</code> · Generated: <code>{html.escape(meta['timestamp_utc'])}</code></div>
      <div style="margin-top:6px;">Target Seed: <code>{html.escape(meta['raw_input'])}</code> · Mode: <code>{html.escape(meta['opsec_mode'])}</code> · Stages: <code>{meta.get('stages_executed', meta['depth'])}</code> · Entities: <code>{len(report['graph']['nodes'])}</code></div>
    </div>
    <div class="score-box">
      <div class="score-num">{score}/100</div>
      <div style="font-size:11px;font-weight:700;letter-spacing:0.6px;color:{score_col};">{html.escape(syn['exposure_rating'])}</div>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h3>🔗 Cross-Entity Attribution Bridges</h3>
      <ul>{bridges_html}</ul>
    </div>
    <div class="card">
      <h3>🛡️ Technical &amp; OPSEC Exposure Highlights</h3>
      <ul>{exposures_html}</ul>
    </div>
  </div>
  {"" if not report.get("temporal_profile") else (
      "<div class='grid2'><div class='card'><h3>🕒 Pattern-of-Life &amp; Timezone Intelligence</h3>"
      f"<p>Offsets: <code>{html.escape(', '.join((report['temporal_profile'].get('inferred_timezone_offsets') or {}).keys()) or 'None')}</code> · "
      f"Regions: <code>{html.escape(', '.join(report['temporal_profile'].get('likely_geographic_regions') or []) or 'Insufficient Human Events')}</code></p>"
      f"<p>Human Events Sampled: <code>{report['temporal_profile'].get('human_activity_events_count', 0)}</code>"
      + (f" · Est. Sleep Window: <code>{html.escape(report['temporal_profile']['estimated_sleep_window_utc']['sleep_window_utc'])}</code> (<code>{html.escape(report['temporal_profile']['estimated_sleep_window_utc']['inferred_utc_offset'])}</code>)"
         if report['temporal_profile'].get('estimated_sleep_window_utc') else "")
      + "</p></div>"
      + "<div class='card'><h3>🎯 Weighted Attribution Confidence</h3><ul>"
      + ("".join(f"<li><code>{html.escape(c['formatted_chain'])}</code> (Joint: <strong>{int(round(c['joint_confidence']*100))}%</strong>)</li>"
                 for c in ((report.get('persona_and_confidence') or {}).get('attribution_chains') or [])[:6])
         or "<li>Single-stage surface (no multi-hop chains yet).</li>")
      + "</ul></div></div>"
  )}

  <div class="card">
    <h2>🕸️ Multi-Stage Surface Graph</h2>
    {svg_map}
    <table style="margin-top:14px;">
      <thead><tr><th>Stage</th><th>Type</th><th>Selector Value</th><th>Discovery Origin</th></tr></thead>
      <tbody>{''.join(rows_html)}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>🎯 Target-Forged Search Dorks</h2>
    <ul>{dorks_html}</ul>
  </div>

  <h2 style="margin-top:24px;">🔬 Stage-by-Stage Collector Evidence</h2>
  {''.join(findings_blocks)}
</div>
</body>
</html>
"""


def compare_cases(case_a_dir: Path, case_b_dir: Path) -> dict:
    """Perform cross-case link analysis between two saved OSINT cases to uncover shared infrastructure or personas."""
    rep_a = json.loads((case_a_dir / "report.json").read_text(encoding="utf-8"))
    rep_b = json.loads((case_b_dir / "report.json").read_text(encoding="utf-8"))

    nodes_a = {n["id"]: n for n in rep_a.get("graph", {}).get("nodes", [])}
    nodes_b = {n["id"]: n for n in rep_b.get("graph", {}).get("nodes", [])}

    exact_overlaps = [nodes_a[k] for k in sorted(set(nodes_a.keys()) & set(nodes_b.keys()))]

    # Secondary fuzzy correlations: shared email domains, shared /24 IPv4 subnets, shared handle stems
    def _email_domains(nodes_map: dict) -> set[str]:
        out = set()
        for n in nodes_map.values():
            if n["type"] == "email" and "@" in n["value"]:
                dom = n["value"].split("@", 1)[1].lower()
                if dom not in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "proton.me"}:
                    out.add(dom)
            elif n["type"] == "domain":
                out.add(n["value"].lower())
        return out

    def _ipv4_subnets(nodes_map: dict) -> set[str]:
        out = set()
        for n in nodes_map.values():
            if n["type"] == "ip" and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", n["value"]):
                out.add(".".join(n["value"].split(".")[:3]) + ".0/24")
        return out

    shared_domains = sorted(_email_domains(nodes_a) & _email_domains(nodes_b))
    shared_subnets = sorted(_ipv4_subnets(nodes_a) & _ipv4_subnets(nodes_b))

    syn_a = rep_a.get("intelligence_synthesis") or synthesize_intelligence(rep_a)
    syn_b = rep_b.get("intelligence_synthesis") or synthesize_intelligence(rep_b)
    shared_analytics = sorted(
        set(syn_a["infrastructure_cluster"]["analytics_and_ad_ids"])
        & set(syn_b["infrastructure_cluster"]["analytics_and_ad_ids"])
    )

    linked = bool(exact_overlaps or shared_domains or shared_subnets or shared_analytics)
    return {
        "case_a": rep_a["meta"]["case_id"],
        "case_b": rep_b["meta"]["case_id"],
        "cases_linked": linked,
        "exact_entity_overlaps": exact_overlaps,
        "shared_corporate_domains": shared_domains,
        "shared_ipv4_24_subnets": shared_subnets,
        "shared_analytics_or_ad_ids": shared_analytics,
    }

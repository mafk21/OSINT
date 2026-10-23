"""Target Watchlist & Attack-Surface Delta / Drift Engine (`--diff-last`).

Compares a current investigation case against the most recent historical case for the
same target seed to detect newly appeared subdomains, IPs, identities, exposures, and
Exposure Score shifts. Also manages `cases/watchlist.json` for recurring monitoring.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import get_cases_dir


def find_latest_case_for_target(
    raw_input: str,
    cases_dir: str | Path | None = None,
    exclude_case_id: str | None = None,
) -> tuple[Path, dict] | None:
    """Locate the most recent saved `report.json` matching `raw_input` (excluding current run)."""
    cbase = get_cases_dir(cases_dir)
    if not cbase.exists():
        return None
    norm = (raw_input or "").strip().lower()
    if not norm:
        return None

    for d in sorted(cbase.iterdir(), reverse=True):
        rf = d / "report.json"
        if not d.is_dir() or not rf.is_file():
            continue
        try:
            rep = json.loads(rf.read_text(encoding="utf-8"))
            cid = rep.get("meta", {}).get("case_id")
            if exclude_case_id and cid == exclude_case_id:
                continue
            prev_raw = str(rep.get("meta", {}).get("raw_input", "")).strip().lower()
            if prev_raw == norm:
                return d, rep
        except Exception:
            continue
    return None


def compute_case_delta(prev_report: dict, curr_report: dict) -> dict[str, Any]:
    """Compute structured attack-surface & identity drift between two runs of a target."""
    prev_nodes = {n["id"]: n for n in prev_report.get("graph", {}).get("nodes", [])}
    curr_nodes = {n["id"]: n for n in curr_report.get("graph", {}).get("nodes", [])}

    added_ids = sorted(set(curr_nodes.keys()) - set(prev_nodes.keys()))
    removed_ids = sorted(set(prev_nodes.keys()) - set(curr_nodes.keys()))

    added_nodes = [curr_nodes[k] for k in added_ids]
    removed_nodes = [prev_nodes[k] for k in removed_ids]

    new_domains = [n["value"] for n in added_nodes if n.get("type") == "domain"]
    new_ips = [n["value"] for n in added_nodes if n.get("type") == "ip"]
    new_identities = [
        f"{n['type']}:{n['value']}"
        for n in added_nodes
        if n.get("type") in ("username", "email", "phone", "person_name", "company")
    ]

    prev_syn = prev_report.get("intelligence_synthesis") or {}
    curr_syn = curr_report.get("intelligence_synthesis") or {}
    prev_exp = set(prev_syn.get("security_and_opsec_exposures") or [])
    curr_exp = set(curr_syn.get("security_and_opsec_exposures") or [])

    score_before = int(prev_syn.get("exposure_score") or 0)
    score_after = int(curr_syn.get("exposure_score") or 0)
    score_delta = score_after - score_before

    drift = bool(added_nodes or removed_nodes or (curr_exp - prev_exp) or score_delta != 0)
    return {
        "baseline_case_id": prev_report.get("meta", {}).get("case_id"),
        "baseline_timestamp_utc": prev_report.get("meta", {}).get("timestamp_utc"),
        "current_case_id": curr_report.get("meta", {}).get("case_id"),
        "current_timestamp_utc": curr_report.get("meta", {}).get("timestamp_utc"),
        "drift_detected": drift,
        "exposure_score_before": score_before,
        "exposure_score_after": score_after,
        "exposure_score_delta": score_delta,
        "added_entity_count": len(added_nodes),
        "removed_entity_count": len(removed_nodes),
        "added_entities": added_nodes,
        "removed_entities": removed_nodes,
        "new_domains_and_subdomains": new_domains,
        "new_ip_addresses": new_ips,
        "new_identities_and_contacts": new_identities,
        "new_security_exposures": sorted(curr_exp - prev_exp),
        "resolved_security_exposures": sorted(prev_exp - curr_exp),
    }


def _watchlist_path(cases_dir: str | Path | None = None) -> Path:
    cbase = get_cases_dir(cases_dir)
    cbase.mkdir(parents=True, exist_ok=True)
    return cbase / "watchlist.json"


def load_watchlist(cases_dir: str | Path | None = None) -> list[dict[str, Any]]:
    wp = _watchlist_path(cases_dir)
    if not wp.is_file():
        return []
    try:
        data = json.loads(wp.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def add_to_watchlist(target: str, depth: int = 3, note: str = "", cases_dir: str | Path | None = None) -> list[dict[str, Any]]:
    clean = target.strip()
    items = load_watchlist(cases_dir)
    if not any(i.get("target", "").lower() == clean.lower() for i in items):
        items.append(
            {
                "target": clean,
                "depth": max(1, min(6, int(depth))),
                "note": note,
                "added_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
        _watchlist_path(cases_dir).write_text(json.dumps(items, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return items


def remove_from_watchlist(target: str, cases_dir: str | Path | None = None) -> list[dict[str, Any]]:
    clean = target.strip().lower()
    items = [i for i in load_watchlist(cases_dir) if i.get("target", "").lower() != clean]
    _watchlist_path(cases_dir).write_text(json.dumps(items, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return items

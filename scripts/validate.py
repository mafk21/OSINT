#!/usr/bin/env python3
"""Strict schema, uniqueness, and referential-integrity validator for the OSINT Monster Database."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


def load_json(name: str):
    path = DATA_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Missing required data file: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{host}{path}{query}"


def main() -> int:
    schema = load_json("schema.json")
    categories = load_json("categories.json")
    tools = load_json("tools.json")
    workflows = load_json("workflows.json")
    dorks = load_json("dorks.json")
    graveyard = load_json("graveyard.json")

    errors: list[str] = []
    warnings: list[str] = []

    required_keys = set(schema["required"])
    props = schema["properties"]
    id_re = re.compile(props["id"]["pattern"])
    url_re = re.compile(props["url"]["pattern"])
    gh_re = re.compile(props["github"]["pattern"])

    cat_ids = {c["id"] for c in categories}
    if set(props["category"]["enum"]) != cat_ids:
        errors.append("Mismatch between schema.json category enum and categories.json IDs")

    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    seen_urls: dict[str, str] = {}
    seen_gh: dict[str, str] = {}

    for idx, tool in enumerate(tools):
        prefix = f"tools[{idx}] ({tool.get('id', 'UNKNOWN')})"
        keys = set(tool.keys())
        missing = required_keys - keys
        extra = keys - set(props.keys())
        if missing:
            errors.append(f"{prefix}: missing keys {sorted(missing)}")
            continue
        if extra:
            errors.append(f"{prefix}: unexpected keys {sorted(extra)}")

        tid = tool["id"]
        if not isinstance(tid, str) or not id_re.match(tid):
            errors.append(f"{prefix}: invalid id format '{tid}'")
        if tid in seen_ids:
            errors.append(f"{prefix}: duplicate id '{tid}'")
        seen_ids.add(tid)

        name_key = tool["name"].strip().lower()
        if len(name_key) < 2:
            errors.append(f"{prefix}: name too short")
        if name_key in seen_names:
            errors.append(f"{prefix}: duplicate name '{tool['name']}'")
        seen_names.add(name_key)

        url = tool["url"]
        if not isinstance(url, str) or not url_re.match(url):
            errors.append(f"{prefix}: invalid url '{url}'")
        else:
            norm = normalize_url(url)
            if norm in seen_urls:
                errors.append(f"{prefix}: duplicate URL '{url}' (already used by '{seen_urls[norm]}')")
            seen_urls[norm] = tid

        gh = tool.get("github")
        if gh is not None:
            if not isinstance(gh, str) or not gh_re.match(gh):
                errors.append(f"{prefix}: invalid github slug '{gh}'")
            elif gh.lower() in seen_gh:
                warnings.append(f"{prefix}: shares github repo '{gh}' with '{seen_gh[gh.lower()]}'")
            else:
                seen_gh[gh.lower()] = tid

        for enum_field in ("category", "type", "pricing", "opsec", "tier"):
            if tool[enum_field] not in props[enum_field]["enum"]:
                errors.append(f"{prefix}: invalid {enum_field}='{tool[enum_field]}'")

        if not isinstance(tool["auth_required"], bool):
            errors.append(f"{prefix}: auth_required must be boolean")

        if not isinstance(tool["description"], str) or len(tool["description"].strip()) < 30:
            errors.append(f"{prefix}: description must be >= 30 chars")

        if not isinstance(tool["quick_start"], str) or len(tool["quick_start"].strip()) < 5:
            errors.append(f"{prefix}: quick_start must be >= 5 chars")

        for list_field in ("inputs", "outputs", "platforms"):
            vals = tool[list_field]
            if not isinstance(vals, list) or len(vals) < 1:
                errors.append(f"{prefix}: {list_field} must be a non-empty list")
                continue
            allowed = set(props[list_field]["items"]["enum"])
            for v in vals:
                if v not in allowed:
                    errors.append(f"{prefix}: invalid {list_field} item '{v}'")

        if not isinstance(tool["tags"], list) or len(tool["tags"]) < 2:
            errors.append(f"{prefix}: tags must have at least 2 items")

    # Referential integrity: workflows
    seen_wf_ids: set[str] = set()
    for wf in workflows:
        if wf["id"] in seen_wf_ids:
            errors.append(f"Duplicate workflow id: {wf['id']}")
        seen_wf_ids.add(wf["id"])
        for step in wf["steps"]:
            for tid in step["recommended_tools"]:
                if tid not in seen_ids:
                    errors.append(f"Workflow '{wf['id']}' step {step['step']} references unknown tool '{tid}'")

    # Referential integrity: graveyard
    for item in graveyard:
        for rep in item["replacements"]:
            if rep["id"] not in seen_ids:
                errors.append(f"Graveyard '{item['dead_tool']}' references unknown replacement tool '{rep['id']}'")

    # Dorks uniqueness
    seen_dorks: set[str] = set()
    for d in dorks:
        if d["id"] in seen_dorks:
            errors.append(f"Duplicate dork id: {d['id']}")
        seen_dorks.add(d["id"])

    counts = Counter(t["category"] for t in tools)
    for cat in categories:
        if counts[cat["id"]] == 0:
            errors.append(f"Category '{cat['id']}' has 0 tools")

    print(f"Validated {len(tools)} OSINT tools across {len(categories)} disciplines")
    print(f"Validated {len(workflows)} investigation workflows, {len(dorks)} dorks, {len(graveyard)} graveyard entries")

    if warnings:
        print(f"Notices ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print(f"\nVALIDATION FAILED with {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  [ERROR] {err}", file=sys.stderr)
        return 1

    print("STATUS: PASS (0 schema, uniqueness, or referential-integrity errors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

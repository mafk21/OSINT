#!/usr/bin/env python3
"""Offline deterministic self-test suite for OSINT Monster Database, Hunter, MCP & Active Gate."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osint_hunter.active_collectors import MODULE_DISPATCH, shodan_favicon_mmh3  # noqa: E402
from osint_hunter.approval import (  # noqa: E402
    ACTIVE_MODULES_CATALOG,
    ActiveAuthorizationError,
    prepare_active_request,
    verify_and_consume_approval,
)
from osint_hunter.classify import extract_selectors  # noqa: E402
from osint_hunter.engine import run_autonomous_hunt  # noqa: E402
from osint_hunter.offline_intel import (  # noqa: E402
    decode_aircraft_hex,
    decode_mac_bssid,
    decode_phone,
    decode_vessel_identifier,
    decode_vin,
)
from scripts.mcp_server import process_rpc  # noqa: E402


def main() -> int:
    # 1. Schema & referential integrity validation + Active Arsenal checks
    rc = subprocess.call([sys.executable, str(ROOT / "scripts" / "validate.py")])
    assert rc == 0, "validate.py failed"

    all_tools = json.loads((ROOT / "data" / "tools.json").read_text(encoding="utf-8"))
    assert len(all_tools) >= 680, f"Expected >=680 tools, got {len(all_tools)}"
    active_cnt = sum(1 for t in all_tools if t["opsec"] == "Active")
    hybrid_cnt = sum(1 for t in all_tools if t["opsec"] == "Hybrid")
    assert active_cnt >= 130 and (active_cnt + hybrid_cnt) >= 175, f"Active/Hybrid count low: {active_cnt}/{hybrid_cnt}"
    assert len(ACTIVE_MODULES_CATALOG) == 22, f"Expected 22 active modules, got {len(ACTIVE_MODULES_CATALOG)}"
    assert set(ACTIVE_MODULES_CATALOG.keys()) == set(MODULE_DISPATCH.keys()), "Active catalog/dispatch mismatch!"

    # 2. Multi-selector extraction test
    sels = extract_selectors(
        "Investigate @torvalds, +966501234567, aircraft AE01D5, MMSI 613123456, VIN 5YJ3E1EA7KF317000, BSSID 60:60:1F:AA:BB:CC"
    )
    found_types = {s["type"] for s in sels}
    expected = {"username", "phone", "aircraft_hex", "vessel_imo", "vin", "mac_bssid"}
    assert expected.issubset(found_types), f"Missing selector types: {expected - found_types}"

    # 3. Offline intelligence decoders
    assert decode_phone("+966501234567")["country"] == "Saudi Arabia"
    assert decode_aircraft_hex("AE01D5")["is_military_or_gov_block"] is True
    assert decode_vessel_identifier("MMSI 613123456")["shadow_fleet_high_watch_flag"] is True
    assert "Tesla" in decode_vin("5YJ3E1EA7KF317000")["manufacturer"]
    assert "DJI" in decode_mac_bssid("60:60:1F:AA:BB:CC")["vendor"]
    assert isinstance(shodan_favicon_mmh3(b"favicon-test-bytes"), int)

    # 4. Active OSINT Hard Gate tests
    try:
        run_autonomous_hunt("example.com", mode="active", save_case=False)
        raise AssertionError("Active mode MUST raise ActiveAuthorizationError when unapproved!")
    except ActiveAuthorizationError:
        pass

    plan = prepare_active_request("example.com", source="selftest")
    rid = plan["request_id"]
    # Sub-second automated self-approval must fail
    try:
        verify_and_consume_approval("example.com", rid, "yes", enforce_turn_delay=True)
        raise AssertionError("Sub-second self-approval MUST be blocked!")
    except ActiveAuthorizationError:
        pass

    time.sleep(1.6)
    # Wrong target must fail
    try:
        verify_and_consume_approval("other.org", rid, "yes", enforce_turn_delay=True)
        raise AssertionError("Target mismatch MUST be blocked!")
    except ActiveAuthorizationError:
        pass

    # Valid single-use approval must succeed once, then block on replay
    approved = verify_and_consume_approval("example.com", rid, "yes approved", enforce_turn_delay=True)
    assert approved["consumed"] is True
    try:
        verify_and_consume_approval("example.com", rid, "yes approved", enforce_turn_delay=True)
        raise AssertionError("Token replay MUST be blocked!")
    except ActiveAuthorizationError:
        pass

    # Clean up temporary selftest files in cases/
    for fn in (".active_approvals.json", "active_audit.jsonl"):
        p = ROOT / "cases" / fn
        if p.exists():
            p.unlink()

    # 5. MCP JSON-RPC initialize & tools/list verification
    init_res = process_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_res and "result" in init_res
    tools_res = process_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    mcp_names = {t["name"] for t in tools_res["result"]["tools"]}
    assert {"osint_auto_hunt", "osint_prepare_active_hunt", "osint_execute_active_hunt"}.issubset(mcp_names)

    # 6. Agent Skills, Claude/Codex Plugin Marketplaces & Standalone Out-of-Repo Zip Isolation Test
    assert not (ROOT / "SKILL.md").exists(), "Root SKILL.md must not exist (blocks npx skills subdir discovery)"
    claude_mp = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert claude_mp["name"] == "osint-monster" and len(claude_mp["plugins"]) >= 3
    codex_plugin = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert codex_plugin["skills"] == "./skills/" and (ROOT / ".codex-plugin" / "assets" / "icon.svg").is_file()
    codex_mp = json.loads((ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"))
    assert codex_mp["plugins"][0]["name"] == "osint-monster"

    allowed_fm_keys = {"name", "description", "license", "allowed-tools", "metadata", "compatibility"}
    for sname in ("osint-hunter", "osint-arsenal"):
        sdir = ROOT / "skills" / sname
        smd = (sdir / "SKILL.md").read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---\n", smd, re.DOTALL)
        assert m, f"{sname}/SKILL.md missing YAML frontmatter"
        fm_keys = set()
        fm_map = {}
        for line in m.group(1).splitlines():
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                fm_keys.add(k.strip())
                fm_map[k.strip()] = v.strip().strip('"')
        assert fm_keys.issubset(allowed_fm_keys), f"Unexpected frontmatter keys in {sname}: {fm_keys - allowed_fm_keys}"
        assert fm_map.get("name") == sname, f"Skill name mismatch in {sname}"
        desc = fm_map.get("description", "")
        assert 20 < len(desc) <= 1024 and "<" not in desc and ">" not in desc, f"Invalid description in {sname}"
        assert (sdir / "agents" / "openai.yaml").is_file(), f"Missing openai.yaml in {sname}"

    with tempfile.TemporaryDirectory(prefix="osint_skill_iso_") as tmp:
        tmp_path = Path(tmp)
        installed_dir = tmp_path / "installed_skills"
        work_cwd = tmp_path / "user_workspace"
        state_dir = tmp_path / "state"
        installed_dir.mkdir()
        work_cwd.mkdir()
        state_dir.mkdir()

        for sname in ("osint-hunter", "osint-arsenal"):
            zpath = ROOT / "releases" / f"{sname}-skill.zip"
            assert zpath.is_file(), f"Missing release archive: {zpath}"
            with zipfile.ZipFile(zpath, "r") as zf:
                names = zf.namelist()
                assert f"{sname}/SKILL.md" in names, f"{sname}/SKILL.md missing at zip root"
                zf.extractall(installed_dir)

        env = {**os.environ, "OSINT_STATE_DIR": str(state_dir)}

        # Run standalone osint-hunter from empty user_workspace outside repo!
        hunt_script = installed_dir / "osint-hunter" / "scripts" / "hunt.py"
        p_passive = subprocess.run(
            [sys.executable, str(hunt_script), "+966501234567 aircraft AE01D5 VIN 5YJ3E1EA7KF317000", "--depth", "1"],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert p_passive.returncode == 0, f"Standalone passive skill failed: {p_passive.stderr}"
        created_cases = list((work_cwd / "cases").glob("*"))
        assert len(created_cases) == 1 and (created_cases[0] / "stix2_bundle.json").is_file()

        # Verify standalone osint-hunter blocks unapproved --active with exit code 2
        p_active_block = subprocess.run(
            [sys.executable, str(hunt_script), "example.com", "--active"],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert p_active_block.returncode == 2, "Standalone skill MUST block unapproved --active!"

        # Run standalone osint-arsenal from empty user_workspace outside repo!
        arsenal_script = installed_dir / "osint-arsenal" / "scripts" / "osint.py"
        p_arsenal = subprocess.run(
            [sys.executable, str(arsenal_script), "pivot", "email", "--passive", "--free", "--json"],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert p_arsenal.returncode == 0 and len(json.loads(p_arsenal.stdout)) >= 10

    print("SELFTEST PASS: Schema, Classifier, Decoders, Active Gate, MCP & Standalone Portable Skills verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

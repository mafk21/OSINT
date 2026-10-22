#!/usr/bin/env python3
"""Offline deterministic self-test suite for OSINT Monster Database, Hunter, MCP & Active Gate."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osint_hunter.active_collectors import shodan_favicon_mmh3  # noqa: E402
from osint_hunter.approval import (  # noqa: E402
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
    # 1. Schema & referential integrity validation
    rc = subprocess.call([sys.executable, str(ROOT / "scripts" / "validate.py")])
    assert rc == 0, "validate.py failed"

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

    print("SELFTEST PASS: Schema, Classifier, Decoders, Active Gate & MCP Server verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

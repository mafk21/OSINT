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
from osint_hunter.classify import extract_selectors, generate_handle_variants  # noqa: E402
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

    # 2. Multi-selector & labeled social-handle extraction test
    sels = extract_selectors(
        "Investigate @torvalds, +966501234567, aircraft AE01D5, MMSI 613123456, VIN 5YJ3E1EA7KF317000, BSSID 60:60:1F:AA:BB:CC"
    )
    found_types = {s["type"] for s in sels}
    expected = {"username", "phone", "aircraft_hex", "vessel_imo", "vin", "mac_bssid"}
    assert expected.issubset(found_types), f"Missing selector types: {expected - found_types}"

    insta_sels = extract_selectors("do a full OSINT on insta username: dr.sample_handle")
    assert len(insta_sels) == 1 and insta_sels[0]["type"] == "username" and insta_sels[0]["value"] == "dr.sample_handle"
    h_vars = generate_handle_variants("dr.sample_handle")
    assert "dr_sample_handle" in h_vars and "sample_handle" in h_vars

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
    assert {
        "osint_auto_hunt",
        "osint_ingest_and_expand_case",
        "osint_prepare_active_hunt",
        "osint_execute_active_hunt",
    }.issubset(mcp_names)

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

        # Verify standalone multi-stage resume + exhaustive carving hunts EVERY discovered clue!
        case_dir_created = created_cases[0]
        p_expand = subprocess.run(
            [
                sys.executable,
                str(hunt_script),
                "--resume-case",
                str(case_dir_created),
                "--depth",
                "2",
                "--ingest-text",
                "Full Name: Dr Sample Investigator | Clinic: Horizon Diagnostics Group | https://wa.me/966559876543 | https://linktr.ee/dr.sample_bio | contact [at] horizondiagnostics-example [dot] org",
            ],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert p_expand.returncode == 0, f"Multi-stage --resume-case failed: {p_expand.stderr}"
        exp_rep = json.loads((case_dir_created / "report.json").read_text(encoding="utf-8"))
        exp_types = {n["type"] for n in exp_rep["graph"]["nodes"]}
        for req_t in ("person_name", "company", "phone", "username", "email", "domain", "url"):
            assert req_t in exp_types, f"Multi-stage analyzer missed clue type '{req_t}' (got {exp_types})"
        hunted_waves = {(w["type"], w["value"]) for w in exp_rep["wave_results"]}
        assert ("phone", "+966559876543") in hunted_waves, "Phone lead was carved but not hunted in Stage 2!"
        assert ("email", "contact@horizondiagnostics-example.org") in hunted_waves, "Email lead was carved but not hunted!"
        assert ("domain", "horizondiagnostics-example.org") in hunted_waves, "Domain lead was carved but not hunted!"

        # Verify all 7 forensic artifacts + SHA-256 manifest + Intelligence Synthesis + Exposure Score!
        for req_art in ("dossier.md", "report.html", "report.json", "entities.csv", "graph.json", "graph.mermaid", "stix2_bundle.json", "manifest.sha256"):
            assert (case_dir_created / req_art).is_file(), f"Missing case artifact: {req_art}"
        assert "intelligence_synthesis" in exp_rep and isinstance(exp_rep["intelligence_synthesis"]["exposure_score"], int)
        assert "<!DOCTYPE html>" in (case_dir_created / "report.html").read_text(encoding="utf-8")

        # Create a second standalone case sharing the phone + domain to test Cross-Case Link Analysis!
        p_case2 = subprocess.run(
            [sys.executable, str(hunt_script), "+966559876543 horizondiagnostics-example.org", "--depth", "1"],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert p_case2.returncode == 0
        all_cases = sorted((work_cwd / "cases").glob("*"))
        assert len(all_cases) == 2

        p_cmp = subprocess.run(
            [sys.executable, str(hunt_script), "--compare-cases", str(all_cases[0]), str(all_cases[1])],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert p_cmp.returncode == 0
        cmp_json = json.loads(p_cmp.stdout)
        assert cmp_json["cases_linked"] is True and len(cmp_json["exact_entity_overlaps"]) >= 2 and "horizondiagnostics-example.org" in cmp_json["shared_corporate_domains"]

        # Verify standalone --prepare-active --from-case covers the full multi-stage discovered surface!
        p_prep_full = subprocess.run(
            [sys.executable, str(hunt_script), "--prepare-active", "--from-case", str(case_dir_created), "--json"],
            cwd=str(work_cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert p_prep_full.returncode == 0
        prep_plan = json.loads(p_prep_full.stdout)
        assert "horizondiagnostics-example.org" in prep_plan["target"]

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

    # 8. Verify New Zero-Network Forensic Decoders, CLI Doctor/Decode, MCP & Live REST API
    from osint_hunter.offline_intel import universal_forensic_decode

    tt_dec = universal_forensic_decode("https://www.tiktok.com/@bellingcat/video/7345123456789012485")
    assert any(a["decoder"] == "tiktok_chronolocation" and "2024-03-11" in a["upload_utc_iso"] for a in tt_dec["results"])
    iban_dec = universal_forensic_decode("SA0380000000608010167519")
    assert any(a["decoder"] == "iban_iso13616" and "Al Rajhi Bank" in (a.get("bank_name") or "") for a in iban_dec["results"])
    uuid_dec = universal_forensic_decode("d9b2d63d-a233-11ee-8c90-005056c00008")
    assert any(a["decoder"] == "uuid_forensics" and a["embedded_node_mac"] == "00:50:56:C0:00:08" for a in uuid_dec["results"])
    ae_dec = universal_forensic_decode("+971501234567")
    assert any(a["decoder"] == "phone_itu_e164" and a["country"] == "United Arab Emirates" for a in ae_dec["results"])

    p_doc = subprocess.run([sys.executable, str(ROOT / "scripts" / "osint.py"), "doctor", "--json"], capture_output=True, text=True, timeout=15)
    assert p_doc.returncode == 0
    doc_json = json.loads(p_doc.stdout)
    assert doc_json["catalog_health"]["tools"] >= 760 and doc_json["catalog_health"]["dorks"] >= 105 and doc_json["catalog_health"]["workflows"] >= 20

    # Test MCP osint_forensic_decode via process_rpc
    rpc_dec = process_rpc({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "osint_forensic_decode", "arguments": {"payload": "65f1a2b3c4d5e6f7a8b9c0d1"}}})
    assert "mongodb_objectid_forensics" in rpc_dec["result"]["content"][0]["text"]

    # Test Live HTTP Command Center REST API on ephemeral port 0
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    from scripts.server import OSINTCommandHandler

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), OSINTCommandHandler)
    port = httpd.server_address[1]
    srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    srv_thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=5) as resp:
            h_data = json.loads(resp.read().decode("utf-8"))
            assert h_data["status"] == "ok" and h_data["tools"] >= 760
        req_dec = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/decode",
            data=json.dumps({"payload": "SA0380000000608010167519"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_dec, timeout=5) as resp:
            d_data = json.loads(resp.read().decode("utf-8"))
            assert d_data["decoded_count"] >= 1
        # Verify unapproved /api/hunt/active without modal header returns 403
        req_act = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/hunt/active",
            data=json.dumps({"target": "example.com"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req_act, timeout=5)
            raise AssertionError("Expected 403 from unapproved /api/hunt/active!")
        except urllib.error.HTTPError as he:
            assert he.code == 403

        # Verify /api/typosquats & /api/graph/path REST endpoints (Upgrades #4 & #7)
        req_typo = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/typosquats",
            data=json.dumps({"domain": "tesla.com", "limit": 25}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_typo, timeout=5) as resp:
            typo_data = json.loads(resp.read().decode("utf-8"))
            assert typo_data["count"] == 25 and any(p["fuzzer"] == "idn-homoglyph-punycode" for p in typo_data["permutations"])

        req_path = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/graph/path",
            data=json.dumps(
                {
                    "nodes": [{"id": "username:a"}, {"id": "email:a@b.io"}, {"id": "domain:b.io"}],
                    "edges": [
                        {"source": "username:a", "target": "email:a@b.io", "via": "github_commit_patch", "confidence": 0.98},
                        {"source": "email:a@b.io", "target": "domain:b.io", "via": "email_domain", "confidence": 0.88},
                    ],
                    "source": "username:a",
                    "target": "domain:b.io",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_path, timeout=5) as resp:
            p_res = json.loads(resp.read().decode("utf-8"))["path"]
            assert p_res["hops"] == 2 and p_res["joint_confidence"] > 0.85

        # Verify Local Web App zero-terminal endpoints (/api/doctor, /api/decode/file, /api/watchlist)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/doctor", timeout=5) as resp:
            doc_api = json.loads(resp.read().decode("utf-8"))
            assert doc_api["catalog_health"]["tools"] >= 760 and isinstance(doc_api["byok_providers"], list)

        import base64 as _b64
        sample_eml_b64 = _b64.b64encode(
            b"From: Test <ceo@acme.io>\r\nReply-To: drop@evil.net\r\nDate: Fri, 23 Oct 2026 17:00:00 +0300\r\nSubject: Hi\r\n\r\nBody\r\n"
        ).decode()
        req_fdec = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/decode/file",
            data=json.dumps({"filename": "dragdrop.eml", "content_base64": sample_eml_b64}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_fdec, timeout=5) as resp:
            fdec_res = json.loads(resp.read().decode("utf-8"))
            assert fdec_res["decoded_count"] == 1 and "eml_forensics" in fdec_res["results"][0]["extracted_metadata"]
    finally:
        httpd.shutdown()
        httpd.server_close()

    # 9. Verify All 8 Next-Level Upgrades (Temporal, DFIR 2.0, Modern Collectors, Persona, BYOK, Watchlist/Diff, Graph Exporters)
    import base64
    import struct
    import xml.etree.ElementTree as ET
    import zlib
    from osint_hunter.dfir_forensics import (
        analyze_eml_bytes,
        analyze_har_bytes,
        analyze_mp4_mov_bytes,
        analyze_pcap_bytes,
        analyze_png_webp_c2pa_bytes,
    )
    from osint_hunter.modern_collectors import (
        collect_bluesky_atproto,
        collect_entra_m365_tenant_passive,
        collect_mastodon_fediverse,
    )
    from osint_hunter.engine import expand_existing_case
    from osint_hunter.offline_intel import analyze_local_file
    from osint_hunter.providers import get_byok_status
    from osint_hunter.temporal import build_temporal_profile
    from osint_hunter.watchlist import add_to_watchlist, compute_case_delta, load_watchlist, remove_from_watchlist

    # Upgrade #1: Pattern-of-Life & Circadian Sleep-Window Inference
    fake_rep = {
        "wave_results": [
            {
                "type": "username",
                "value": "night_coder",
                "collector_outputs": [
                    {
                        "module": "github_user_osint",
                        "status": "ok",
                        "data": {
                            "commit_timezone_offsets": ["+03:00", "+03:00"],
                            "events": [f"2026-10-{10 + i:02d}T{9 + (i % 10):02d}:15:00Z" for i in range(14)],
                        },
                    }
                ],
            }
        ]
    }
    t_prof = build_temporal_profile(fake_rep)
    assert "+03:00" in t_prof["inferred_timezone_offsets"], t_prof
    assert t_prof["estimated_sleep_window_utc"] is not None and t_prof["human_activity_events_count"] >= 14, t_prof

    # Upgrade #2: DFIR Pocket-Knife 2.0 (.eml, .pcap, .har, .mp4, PNG C2PA/ComfyUI, Google ei=, SSH key)
    ei_tok = base64.urlsafe_b64encode(struct.pack("<I", 1710000000) + b"\x00\x01\x02\x03").decode().rstrip("=")
    ei_dec = universal_forensic_decode(f"https://www.google.com/search?q=osint&ei={ei_tok}")
    assert any(r["decoder"] == "google_ei_chronolocation" and r["search_utc_iso"] == "2024-03-09T16:00:00Z" for r in ei_dec["results"])

    ssh_wire = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + (b"\x42" * 32)
    ssh_dec = universal_forensic_decode("ssh-ed25519 " + base64.b64encode(ssh_wire).decode() + " dev@sec-ops.org")
    assert any(r["decoder"] == "openssh_public_key" and r["leaked_email_in_comment"] == "dev@sec-ops.org" for r in ssh_dec["results"])

    with tempfile.TemporaryDirectory(prefix="osint_dfir_") as dfir_tmp:
        dtmp = Path(dfir_tmp)
        eml_p = dtmp / "phish.eml"
        eml_p.write_bytes(
            b"Received: from mx.corp.io ([198.51.100.9]) by inbox.corp.io; Fri, 23 Oct 2026 14:00:15 +0000\r\n"
            b"Received: from relay.bad-ops.net ([203.0.113.55]) by mx.corp.io; Fri, 23 Oct 2026 14:00:05 +0000\r\n"
            b"From: Finance <cfo@corp.io>\r\nReply-To: drop@bad-ops.net\r\n"
            b"Authentication-Results: mx.corp.io; spf=fail; dmarc=fail\r\n"
            b"Date: Fri, 23 Oct 2026 17:00:00 +0300\r\nSubject: Wire\r\n\r\nSee https://login.bad-ops.net\r\n"
        )
        eml_f = analyze_local_file(str(eml_p))
        eml_meta = eml_f["extracted_metadata"]["eml_forensics"]
        assert eml_meta["sender_timezone_offset"] == "+03:00" and len(eml_meta["spoofing_and_anomaly_flags"]) >= 2

        eth = b"\x00" * 12 + b"\x08\x00"
        dns_q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02c2\x07darknet\x02io\x00\x00\x01\x00\x01"
        udp = struct.pack("!HHHH", 51111, 53, 8 + len(dns_q), 0) + dns_q
        ip4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, b"\x08\x08\x04\x04", b"\x01\x01\x01\x01")
        frame = eth + ip4 + udp
        pcap_p = dtmp / "trace.pcap"
        pcap_p.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1710000000, 0, len(frame), len(frame)) + frame)
        pcap_f = analyze_local_file(str(pcap_p))
        assert "c2.darknet.io" in pcap_f["extracted_metadata"]["pcap_forensics"]["dns_queries"]

        har_f = analyze_har_bytes(json.dumps({"log": {"entries": [{"startedDateTime": "2026-10-23T10:00:00Z", "serverIPAddress": "93.184.216.34", "request": {"url": "https://api.example.org/v1", "headers": [{"name": "Authorization", "value": "Bearer secret"}], "cookies": [{"name": "sid"}]}}]}}).encode())
        assert "api.example.org" in har_f["unique_domains"] and len(har_f["auth_headers_detected"]) == 1

        ftyp = struct.pack(">I4s4sI", 16, b"ftyp", b"isom", 0)
        mvhd_b = struct.pack(">IIIIII", 0, 1710000000 + 2082844800, 1710000000 + 2082844800, 1000, 9000, 0) + b"\x00" * 80
        xyz_b = b"\x00\x12\x15\xc7+24.7136+046.6753/"
        udta = struct.pack(">I4s", 16 + len(xyz_b), b"udta") + struct.pack(">I4s", 8 + len(xyz_b), b"\xa9xyz") + xyz_b
        moov = struct.pack(">I4s", 16 + len(mvhd_b) + len(udta), b"moov") + struct.pack(">I4s", 8 + len(mvhd_b), b"mvhd") + mvhd_b + udta
        mp4_f = analyze_mp4_mov_bytes(ftyp + moov)
        assert mp4_f["gps_coordinates"] == "24.713600,46.675300"

        def _pchunk(tp: bytes, bd: bytes) -> bytes:
            return struct.pack(">I", len(bd)) + tp + bd + struct.pack(">I", zlib.crc32(tp + bd) & 0xFFFFFFFF)

        png_f = analyze_png_webp_c2pa_bytes(
            b"\x89PNG\r\n\x1a\n" + _pchunk(b"IHDR", struct.pack(">IIBBBBB", 512, 512, 8, 2, 0, 0, 0)) + _pchunk(b"tEXt", b"parameters\x00Negative prompt: blurry\nSteps: 25, Sampler: Euler") + _pchunk(b"caBX", b"c2pa.claim") + _pchunk(b"IEND", b"")
        )
        assert png_f["c2pa_content_credentials_detected"] is True and "Stable Diffusion" in png_f["ai_provenance_classification"]

    # Upgrade #3: Modern & Decentralized Collectors via deterministic mock _fetch_json
    import osint_hunter.modern_collectors as mc_mod

    orig_fetch = mc_mod._fetch_json

    def _mock_fetch_json(url: str, timeout: float = 4.0):
        if "getProfile" in url:
            return 200, {"did": "did:plc:abc123xyz", "handle": "alice.corp-test.io", "displayName": "Alice Sec", "description": "Contact sec@corp-test.io"}, None
        if "plc.directory" in url:
            return 200, [{"createdAt": "2024-05-01T12:00:00Z", "operation": {"alsoKnownAs": ["at://oldhandle.bsky.social"], "services": {"atproto_pds": {"endpoint": "https://bsky.network"}}}}], None
        if "mastodon.social" in url:
            return 200, {"acct": "alice", "display_name": "Alice", "url": "https://mastodon.social/@alice", "fields": [{"name": "Site", "value": '<a href="https://corp-test.io" rel="me">corp-test.io</a>', "verified_at": "2026-01-01T00:00:00Z"}]}, None
        if "openid-configuration" in url:
            return 200, {"issuer": "https://sts.windows.net/11111111-2222-3333-4444-555555555555/", "tenant_region_scope": "EU"}, None
        if "getuserrealm" in url:
            return 200, {"NameSpaceType": "Federated", "FederationBrandName": "CorpTest Ltd", "AuthURL": "https://sso.corp-test.io/adfs/ls/"}, None
        return 404, None, "HTTP 404"

    mc_mod._fetch_json = _mock_fetch_json
    try:
        bsky_r = collect_bluesky_atproto("alice")
        assert bsky_r["status"] == "ok" and "oldhandle.bsky.social" in bsky_r["data"]["plc_handle_history"], bsky_r
        masto_r = collect_mastodon_fediverse("alice")
        assert masto_r["status"] == "ok" and any(p["value"] == "corp-test.io" for p in masto_r["pivots"]), masto_r
        entra_r = collect_entra_m365_tenant_passive("corp-test.io")
        assert entra_r["status"] == "ok" and entra_r["data"]["entra_tenant_uuid"] == "11111111-2222-3333-4444-555555555555", entra_r
    finally:
        mc_mod._fetch_json = orig_fetch

    # Upgrade #5: BYOK Provider Registry & Doctor Status
    assert len(get_byok_status()) == 7 and "byok_providers" in doc_json

    # Upgrade #6 & #8: Watchlist, --diff-last Delta, Gephi GEXF, GraphML, Neo4j Cypher, Obsidian Vault & MCP Tools
    with tempfile.TemporaryDirectory(prefix="osint_upg68_") as upg_tmp:
        utmp = Path(upg_tmp)
        add_to_watchlist("+966501234567", depth=1, cases_dir=utmp)
        assert len(load_watchlist(utmp)) == 1
        remove_from_watchlist("+966501234567", cases_dir=utmp)
        assert len(load_watchlist(utmp)) == 0

        r1 = run_autonomous_hunt("+966501234567", depth=1, cases_dir=utmp)
        cdir1 = utmp / r1["meta"]["case_id"]
        # Validate XML structure of Gephi GEXF & GraphML + Neo4j Cypher + Obsidian Vault
        ET.fromstring((cdir1 / "graph.gexf").read_text(encoding="utf-8"))
        ET.fromstring((cdir1 / "graph.graphml").read_text(encoding="utf-8"))
        assert "MERGE (c:OSINTCase" in (cdir1 / "neo4j.cypher").read_text(encoding="utf-8")
        assert (cdir1 / "obsidian" / "00_Case_Index.md").is_file()

        r2 = expand_existing_case(cdir1, ingested_text="Ops Lead: Tariq Al-Mansoor | https://ops-horizon-example.io", additional_stages=1, cases_dir=utmp)
        delta = compute_case_delta(r1, r2)
        assert delta["drift_detected"] is True and delta["added_entity_count"] >= 2 and "ops-horizon-example.io" in delta["new_domains_and_subdomains"]

    rpc_typo = process_rpc({"jsonrpc": "2.0", "id": 101, "method": "tools/call", "params": {"name": "osint_typosquat_permutations", "arguments": {"domain": "github.com", "limit": 15}}})
    assert "idn-homoglyph-punycode" in rpc_typo["result"]["content"][0]["text"]

    # Regression checks: IPv6 URL bracketing in Active probes, bare phone normalization & inside-file hunting
    from osint_hunter.active_collectors import _normalize_url_ipv6, _raw_http_request, _target_url
    assert _normalize_url_ipv6("https://2606:4700:4403::ac40:9045/test") == "https://[2606:4700:4403::ac40:9045]/test"
    assert _target_url("ip", "2606:4700:4403::ac40:9045") == "https://[2606:4700:4403::ac40:9045]/"
    _hops6, _st6, _, _, _err6 = _raw_http_request("https://2606:4700:4403::ac40:9045/", max_hops=1, max_bytes=512)
    assert isinstance(_st6, int)  # Must never raise ValueError on bare IPv6 URLs

    bare_ph = extract_selectors("966559106068")
    assert any(s["type"] == "phone" and s["value"] == "+966559106068" for s in bare_ph), f"Bare phone failed: {bare_ph}"

    import zlib as _zlib
    with tempfile.TemporaryDirectory(prefix="osint_filehunt_") as fhtmp:
        fhd = Path(fhtmp)
        # 1. Multi-line target file (.txt)
        t_txt = fhd / "targets.txt"
        t_txt.write_text("dr.abo3tab\n966559106068\nsec@horizon-demo.io\n", encoding="utf-8")
        rep_txt = run_autonomous_hunt(str(t_txt), depth=1, cases_dir=fhd)
        node_ids = {n["id"] for n in rep_txt["graph"]["nodes"]}
        assert "username:dr.abo3tab" in node_ids and "phone:+966559106068" in node_ids and "email:sec@horizon-demo.io" in node_ids
        assert not any(n["type"] == "local_file" for n in rep_txt["graph"]["nodes"])
        assert rep_txt["meta"]["source_file"]["extracted_selector_count"] >= 3

        # 2. Word .docx with body XML + .rels hyperlink
        docx_p = fhd / "brief.docx"
        with zipfile.ZipFile(docx_p, "w") as zf:
            zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:t>Contact +971501234567 or @lead_analyst</w:t></w:p></w:body></w:document>')
            zf.writestr("word/_rels/document.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="https://portal.alpha-target.org/login"/></Relationships>')
        docx_dec = analyze_local_file(str(docx_p))
        docx_sels = {(s["type"], s["value"]) for s in docx_dec["content_selectors"]}
        assert ("phone", "+971501234567") in docx_sels and ("username", "lead_analyst") in docx_sels and ("domain", "portal.alpha-target.org") in docx_sels
        assert all("openxmlformats.org" not in v for _, v in docx_sels)

        # 3. PDF with FlateDecode compressed text stream
        pdf_stream = _zlib.compress(b"BT (Reach ops@delta-labs.io or +966509998877) Tj ET")
        pdf_p = fhd / "intel.pdf"
        pdf_p.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Length " + str(len(pdf_stream)).encode() + b" /Filter /FlateDecode >>\nstream\n" + pdf_stream + b"\nendstream\nendobj\n%%EOF")
        pdf_dec = analyze_local_file(str(pdf_p))
        pdf_sels = {(s["type"], s["value"]) for s in pdf_dec["content_selectors"]}
        assert ("email", "ops@delta-labs.io") in pdf_sels and ("phone", "+966509998877") in pdf_sels

    # Deep Open-Web Search, Social/Bio-Link Parsers, Webpage Carver, Phone Variants & Launchpad Verification
    from osint_hunter.cli_runner import get_local_cli_status
    from osint_hunter.social_deep import (
        parse_instagram_meta_html,
        parse_linktree_html,
        parse_snapchat_html,
        parse_telegram_html,
        parse_tiktok_html,
    )
    from osint_hunter.web_search_intel import (
        carve_webpage_intelligence,
        classify_social_profile_url,
        generate_phone_search_variants,
        parse_duckduckgo_html,
        parse_rss_search_xml,
        parse_yahoo_search_html,
    )

    assert len(get_local_cli_status()) >= 8
    ph_vars = generate_phone_search_variants("+966559106068")
    assert "0559106068" in ph_vars["local_formats"] and ph_vars["whatsapp_direct_url"] == "https://wa.me/966559106068"

    soc_ig = classify_social_profile_url("https://www.instagram.com/dr.abo3tab/?hl=en", title="Dr. Abo 3tab")
    assert soc_ig and soc_ig["platform"] == "Instagram" and soc_ig["handle"] == "dr.abo3tab"
    soc_wa = classify_social_profile_url("https://wa.me/966559106068")
    assert soc_wa and soc_wa["pivot_type"] == "phone" and soc_wa["pivot_value"] == "+966559106068"
    assert classify_social_profile_url("https://www.instagram.com/p/C12345/") is None  # Must ignore post URLs

    ddg_sample = (
        '<div class="result results_links"><div class="links_main">'
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.tiktok.com%2F%40dr.abo3tab">Dr Abo 3tab (@dr.abo3tab) | TikTok</a>'
        '<a class="result__snippet">Bookings: +966559106068 · info@abo3tab-clinic.sa</a></div></div>'
    )
    ddg_rows = parse_duckduckgo_html(ddg_sample)
    assert len(ddg_rows) == 1 and ddg_rows[0]["url"] == "https://www.tiktok.com/@dr.abo3tab"

    yh_sample = (
        '<li><div class="dd algo"><div class="compTitle"><a href="https://r.search.yahoo.com/_ylt=A/RU=https%3A%2F%2Flinktr.ee%2Fdr.abo3tab/RK=2/RS=x">Dr Abo3tab Linktree</a></div>'
        '<div class="compText"><p>Official links and clinic booking.</p></div></div></li>'
    )
    yh_rows = parse_yahoo_search_html(yh_sample)
    assert len(yh_rows) == 1 and yh_rows[0]["url"] == "https://linktr.ee/dr.abo3tab"

    rss_rows = parse_rss_search_xml(
        '<rss><channel><item><title>Clinic Feature</title><link>https://news.example-clinic.sa/post</link><description>Contact +966559106068</description></item></channel></rss>',
        "Bing",
    )
    assert len(rss_rows) == 1 and rss_rows[0]["engine"] == "Bing"

    lt_parsed = parse_linktree_html(
        '<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"account":{"username":"dr.abo3tab","pageTitle":"Dr. Abo 3tab Clinic","description":"Riyadh & Khobar","links":[{"title":"WhatsApp","url":"https://wa.me/966559106068"}],"socialLinks":[{"type":"INSTAGRAM","url":"https://instagram.com/dr.abo3tab"}]}}}}</script>',
        "dr.abo3tab",
    )
    assert lt_parsed and lt_parsed["display_name"] == "Dr. Abo 3tab Clinic" and len(lt_parsed["external_links"]) == 2

    tg_parsed = parse_telegram_html(
        '<div class="tgme_page_title"><span>Dr. Abo 3tab</span></div><div class="tgme_page_extra">14 200 subscribers</div><div class="tgme_page_description">Clinic site: <a href="https://abo3tab-clinic.sa">abo3tab-clinic.sa</a></div>',
        "dr_abo3tab",
        '<div class="tgme_widget_message_text">Call +966559106068 for appointments</div>',
    )
    assert tg_parsed and tg_parsed["display_name"] == "Dr. Abo 3tab" and len(tg_parsed["recent_channel_posts"]) == 1

    sc_parsed = parse_snapchat_html(
        '<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"userProfile":{"publicProfileInfo":{"username":"dr.abo3tab","title":"Dr. Abo 3tab","bio":"Consultant","websiteUrl":"https://abo3tab-clinic.sa","subscriberCount":"45000"}}}}}</script>',
        "dr.abo3tab",
    )
    assert sc_parsed and sc_parsed["display_name"] == "Dr. Abo 3tab" and sc_parsed["subscribers"] == "45000"

    tt_parsed = parse_tiktok_html(
        '<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">{"__DEFAULT_SCOPE__":{"webapp.user-detail":{"userInfo":{"user":{"uniqueId":"dr.abo3tab","nickname":"Dr Abo 3tab","signature":"Khobar Clinic","region":"SA","bioLink":{"link":"https://abo3tab-clinic.sa"}},"stats":{"followerCount":89000,"heartCount":1200000,"videoCount":140}}}}}</script>',
        "dr.abo3tab",
    )
    assert tt_parsed and tt_parsed["followers"] == 89000 and tt_parsed["region"] == "SA"

    ig_parsed = parse_instagram_meta_html(
        '<meta property="og:title" content="Dr. Abo 3tab (@dr.abo3tab) • Instagram photos and videos"/><meta property="og:description" content="52K Followers, 120 Following, 310 Posts"/>',
        "dr.abo3tab",
    )
    assert ig_parsed and ig_parsed["display_name"] == "Dr. Abo 3tab"

    carved_page = carve_webpage_intelligence(
        '<html><head><title>Horizon Medical</title><script type="application/ld+json">{"@type":"MedicalClinic","name":"Horizon Medical Center","telephone":"+966559106068","geo":{"latitude":26.2794,"longitude":50.2083},"sameAs":["https://www.instagram.com/horizon_med"]}</script></head>'
        '<body><a href="mailto:care@horizon-med.sa">Email</a><a href="https://wa.me/966559106068">WA</a><a href="/contact-us">Contact</a><script>gtag("config","G-ABCD1234EF")</script></body></html>',
        base_url="https://horizon-med.sa/",
    )
    assert "care@horizon-med.sa" in carved_page["emails"] and "+966559106068" in carved_page["phones"]
    assert any(s["platform"] == "Instagram" for s in carved_page["social_profiles"])
    assert "G-ABCD1234EF" in carved_page["tracking_ids"]["ga4_ids"]
    assert "https://horizon-med.sa/contact-us" in carved_page["contact_subpages"]

    print("SELFTEST PASS: 760-Tool Catalog + All 8 Next-Level Upgrades (Temporal, DFIR 2.0, Modern Collectors, Persona, BYOK, Watchlist/Diff, Graph Studio & Gephi/Neo4j/Obsidian) verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

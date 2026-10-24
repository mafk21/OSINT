#!/usr/bin/env python3
"""Local OSINT Web Workspace + Autonomous Hunter HTTP Server (Zero Dependencies).

Serves the clean 5-tab browser workspace (`web/`: Investigate, Decode, Cases, Directory, Settings)
and provides live JSON/HTML/Graph REST endpoints:
  - GET  /api/health, /api/doctor, /api/watchlist
  - GET  /api/cases, /api/cases/<CASE_ID>, /api/cases/<CASE_ID>/html, /api/cases/<CASE_ID>/obsidian.zip
  - GET  /api/cases/<CASE_ID>/{gexf,graphml,cypher}
  - POST /api/detect
  - POST /api/decode, /api/decode/file
  - POST /api/hunt, /api/hunt/file
  - POST /api/cases/expand, /api/cases/compare, /api/cases/diff
  - POST /api/typosquats, /api/graph/path
  - POST /api/watchlist/{add,remove,run}
  - POST /api/settings/byok
  - POST /api/hunt/active/prepare (and alias /api/hunt/prepare-active)
  - POST /api/hunt/active
"""

from __future__ import annotations

import argparse
import base64
import io
import ipaddress
import json
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
DATA_DIR = ROOT / "data"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osint_hunter.approval import (  # noqa: E402
    ACTIVE_MODULES_CATALOG,
    ActiveAuthorizationError,
    prepare_active_request,
)
from osint_hunter.classify import extract_selectors  # noqa: E402
from osint_hunter.correlator import render_entities_csv, render_standalone_html_dossier  # noqa: E402
from osint_hunter.engine import (  # noqa: E402
    ALL_DORKS,
    ALL_TOOLS,
    ALL_WORKFLOWS,
    build_stix2_bundle,
    compare_saved_cases,
    expand_existing_case,
    get_case_active_target_string,
    render_markdown_dossier,
    run_autonomous_hunt,
)
from osint_hunter.offline_intel import analyze_local_file, universal_forensic_decode  # noqa: E402
from osint_hunter.paths import get_cases_dir  # noqa: E402
from osint_hunter.persona import (  # noqa: E402
    find_shortest_attribution_path,
    generate_domain_typosquats,
)
from osint_hunter.cli_runner import get_local_cli_status  # noqa: E402
from osint_hunter.image_intel import (  # noqa: E402
    BROWSER_UA as IMG_UA,
    detect_image_format_and_dimensions,
    is_safe_public_http_url,
)
from osint_hunter.providers import get_byok_status, update_byok_dotenv  # noqa: E402
from osint_hunter.watchlist import (  # noqa: E402
    add_to_watchlist,
    compute_case_delta,
    load_watchlist,
    remove_from_watchlist,
)


class OSINTCommandHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Human-Modal-Confirmed")
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def _safe_write(self, body: bytes) -> None:
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._safe_write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def _send_html(self, html_doc: str, status: int = 200) -> None:
        body = html_doc.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._safe_write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 36_000_000))
        return json.loads(raw.decode("utf-8"))

    def _find_case_dir(self, case_id: str) -> Path | None:
        cases_dir = get_cases_dir()
        cand = cases_dir / Path(case_id).name
        if cand.is_dir() and (cand / "report.json").is_file():
            return cand
        return None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/favicon.ico":
            svg_icon = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#12141b"/><circle cx="16" cy="16" r="6" fill="#3b82f6"/></svg>'
            try:
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(svg_icon)))
                self.end_headers()
                self._safe_write(svg_icon)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass
            return

        if path == "/api/health":
            self._send_json(
                {
                    "status": "ok",
                    "engine": "osint-monster-hunter",
                    "version": "2026.10.5",
                    "tools": len(ALL_TOOLS),
                    "dorks": len(ALL_DORKS),
                    "workflows": len(ALL_WORKFLOWS),
                    "active_modules": list(ACTIVE_MODULES_CATALOG.keys()),
                    "byok_providers": get_byok_status(),
                }
            )
            return

        if path == "/api/doctor":
            cli_probes = [
                "nmap", "rustscan", "naabu", "httpx", "subfinder", "nuclei", "dnsx", "tlsx", "katana",
                "ffuf", "feroxbuster", "gobuster", "amass", "bbot", "maigret", "sherlock", "holehe",
                "ignorant", "dnstwist", "exiftool", "binwalk", "qpdf", "tshark", "yt-dlp", "instaloader",
                "tor", "whois", "dig",
            ]
            installed = [b for b in cli_probes if shutil.which(b)]
            self._send_json(
                {
                    "python_version": sys.version.split()[0],
                    "platform": sys.platform,
                    "cases_dir": str(get_cases_dir()),
                    "catalog_health": {
                        "tools": len(ALL_TOOLS),
                        "workflows": len(ALL_WORKFLOWS),
                        "dorks": len(ALL_DORKS),
                        "sqlite_fts5_present": (DATA_DIR / "osint.sqlite").is_file(),
                    },
                    "byok_providers": get_byok_status(),
                    "auto_integrated_cli_tools": get_local_cli_status(),
                    "local_recon_binaries_detected": installed,
                    "optional_binaries_not_installed": [b for b in cli_probes if b not in installed],
                }
            )
            return

        if path == "/api/image-proxy":
            qs = urllib.parse.parse_qs(parsed.query)
            raw_url = (qs.get("url") or [""])[0].strip()
            if not is_safe_public_http_url(raw_url):
                self._send_json({"error": "Blocked or invalid external image URL"}, status=400)
                return
            try:
                p_u = urllib.parse.urlparse(raw_url)
                addrs = socket.getaddrinfo(p_u.hostname, p_u.port or (443 if p_u.scheme == "https" else 80))
                for addr_item in addrs:
                    ip_obj = ipaddress.ip_address(addr_item[4][0])
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                        self._send_json({"error": "Resolved private/internal IP blocked"}, status=403)
                        return
                req = urllib.request.Request(
                    raw_url,
                    headers={"User-Agent": IMG_UA, "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"},
                )
                with urllib.request.urlopen(req, timeout=4.5) as resp:
                    img_bytes = resp.read(4_000_000)
                fmt_info = detect_image_format_and_dimensions(img_bytes)
                if not fmt_info:
                    self._send_json({"error": "Remote resource is not a valid raster image"}, status=415)
                    return
                mime_map = {"JPEG": "image/jpeg", "PNG": "image/png", "WebP": "image/webp", "GIF": "image/gif"}
                self.send_response(200)
                self.send_header("Content-Type", mime_map.get(fmt_info["format"], "image/jpeg"))
                self.send_header("Content-Length", str(len(img_bytes)))
                self.end_headers()
                self._safe_write(img_bytes)
            except Exception as exc:
                self._send_json({"error": f"Image fetch failed: {exc}"}, status=502)
            return

        if path == "/api/watchlist":
            self._send_json({"watchlist": load_watchlist()})
            return

        if path == "/api/cases":
            cases_dir = get_cases_dir()
            cases = []
            if cases_dir.exists():
                for d in sorted(cases_dir.iterdir(), reverse=True)[:50]:
                    if d.is_dir() and (d / "report.json").exists():
                        try:
                            meta_full = json.loads((d / "report.json").read_text(encoding="utf-8"))
                            syn = meta_full.get("intelligence_synthesis") or {}
                            cases.append(
                                {
                                    "case_id": meta_full["meta"]["case_id"],
                                    "timestamp_utc": meta_full["meta"]["timestamp_utc"],
                                    "raw_input": meta_full["meta"]["raw_input"],
                                    "opsec_mode": meta_full["meta"].get("opsec_mode", "Passive"),
                                    "stages_executed": meta_full["meta"].get("stages_executed", meta_full["meta"].get("depth", 1)),
                                    "converged": meta_full["meta"].get("converged", False),
                                    "nodes": len(meta_full.get("graph", {}).get("nodes", [])),
                                    "edges": len(meta_full.get("graph", {}).get("edges", [])),
                                    "exposure_score": syn.get("exposure_score"),
                                    "exposure_rating": syn.get("exposure_rating"),
                                    "images_count": (meta_full.get("visual_intel") or {}).get("total_images", 0),
                                }
                            )
                        except Exception:
                            continue
            self._send_json({"cases": cases})
            return

        if path.startswith("/api/cases/"):
            parts = path.split("/")
            # /api/cases/<CASE_ID> or /api/cases/<CASE_ID>/html
            if len(parts) >= 4:
                cid = urllib.parse.unquote(parts[3])
                cdir = self._find_case_dir(cid)
                if not cdir:
                    self._send_json({"error": f"Case '{cid}' not found"}, status=404)
                    return
                if len(parts) == 6 and parts[4] == "images":
                    fname = urllib.parse.unquote(parts[5])
                    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:jpg|jpeg|png|webp|gif)", fname):
                        self._send_json({"error": "Invalid image filename"}, status=400)
                        return
                    img_path = cdir / "images" / fname
                    if not img_path.is_file():
                        self._send_json({"error": "Image file not found"}, status=404)
                        return
                    data_b = img_path.read_bytes()
                    ext_l = img_path.suffix.lower()
                    mime_m = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif"}
                    self.send_response(200)
                    self.send_header("Content-Type", mime_m.get(ext_l, "image/jpeg"))
                    self.send_header("Content-Length", str(len(data_b)))
                    self.end_headers()
                    self._safe_write(data_b)
                    return
                if len(parts) == 5 and parts[4] == "html":
                    html_file = cdir / "report.html"
                    if html_file.is_file():
                        self._send_html(html_file.read_text(encoding="utf-8"))
                    else:
                        rep = json.loads((cdir / "report.json").read_text(encoding="utf-8"))
                        self._send_html(render_standalone_html_dossier(rep))
                    return
                if len(parts) == 5 and parts[4] == "obsidian.zip":
                    obs_dir = cdir / "obsidian"
                    if not obs_dir.is_dir():
                        self._send_json({"error": "Obsidian vault not found for case"}, status=404)
                        return
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        for md_p in sorted(obs_dir.glob("*.md")):
                            zf.writestr(f"{cid}-obsidian/{md_p.name}", md_p.read_bytes())
                    zbytes = buf.getvalue()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Disposition", f'attachment; filename="{cid}-obsidian-vault.zip"')
                    self.send_header("Content-Length", str(len(zbytes)))
                    self.end_headers()
                    self._safe_write(zbytes)
                    return
                if len(parts) == 5 and parts[4] in ("gexf", "graphml", "cypher"):
                    ext_map = {
                        "gexf": ("graph.gexf", "application/xml; charset=utf-8"),
                        "graphml": ("graph.graphml", "application/xml; charset=utf-8"),
                        "cypher": ("neo4j.cypher", "text/plain; charset=utf-8"),
                    }
                    fname, ctype = ext_map[parts[4]]
                    fpath = cdir / fname
                    if not fpath.is_file():
                        self._send_json({"error": f"Artifact {fname} not found"}, status=404)
                        return
                    body = fpath.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self._safe_write(body)
                    return
                rep = json.loads((cdir / "report.json").read_text(encoding="utf-8"))
                md_file = cdir / "dossier.md"
                rep["dossier_markdown"] = md_file.read_text(encoding="utf-8") if md_file.is_file() else render_markdown_dossier(rep)
                stix_file = cdir / "stix2_bundle.json"
                if stix_file.is_file():
                    rep["stix2_bundle"] = json.loads(stix_file.read_text(encoding="utf-8"))
                for art_key, art_file in (("gexf_xml", "graph.gexf"), ("graphml_xml", "graph.graphml"), ("neo4j_cypher", "neo4j.cypher")):
                    if (cdir / art_file).is_file():
                        rep[art_key] = (cdir / art_file).read_text(encoding="utf-8")
                rep["entities_csv"] = render_entities_csv(rep)
                self._send_json(rep)
                return

        super().do_GET()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        try:
            data = self._read_json()
        except Exception as exc:
            self._send_json({"error": f"Invalid JSON body: {exc}"}, status=400)
            return

        if path == "/api/detect":
            raw = str(data.get("input", "")).strip()
            self._send_json({"selectors": extract_selectors(raw)})
            return

        if path == "/api/decode":
            raw = str(data.get("payload") or data.get("input") or "").strip()
            if not raw:
                self._send_json({"error": "payload is required"}, status=400)
                return
            self._send_json(universal_forensic_decode(raw))
            return

        if path == "/api/decode/file":
            fname = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(str(data.get("filename") or "evidence.bin")).name)[:120]
            b64 = str(data.get("content_base64") or "").strip()
            if "," in b64 and b64.startswith("data:"):
                b64 = b64.split(",", 1)[1]
            if not b64:
                self._send_json({"error": "content_base64 is required"}, status=400)
                return
            try:
                raw_bytes = base64.b64decode(b64)
            except Exception as exc:
                self._send_json({"error": f"Invalid base64 payload: {exc}"}, status=400)
                return
            with tempfile.TemporaryDirectory(prefix="osint_web_dfir_") as tmpd:
                fpath = Path(tmpd) / fname
                fpath.write_bytes(raw_bytes)
                res = analyze_local_file(str(fpath))
                res.pop("absolute_path", None)
                self._send_json({"input": fname, "decoded_count": 1, "results": [{"decoder": "local_binary_forensics", **res}]})
            return

        if path == "/api/hunt/file":
            fname = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(str(data.get("filename") or "evidence.bin")).name)[:120]
            b64 = str(data.get("content_base64") or "").strip()
            if "," in b64 and b64.startswith("data:"):
                b64 = b64.split(",", 1)[1]
            if not b64:
                self._send_json({"error": "content_base64 is required"}, status=400)
                return
            depth = max(1, min(6, int(data.get("depth", 4))))
            diff_last = bool(data.get("diff_last", False))
            try:
                raw_bytes = base64.b64decode(b64)
                with tempfile.TemporaryDirectory(prefix="osint_web_hunt_") as tmpd:
                    fpath = Path(tmpd) / fname
                    fpath.write_bytes(raw_bytes)
                    report = run_autonomous_hunt(
                        str(fpath),
                        depth=depth,
                        save_case=True,
                        mode="passive",
                        diff_last=diff_last,
                        display_label=f"File: {fname}",
                    )
                report["stix2_bundle"] = build_stix2_bundle(
                    report["meta"]["case_id"],
                    f"File: {fname}",
                    report["graph"]["nodes"],
                    report["graph"]["edges"],
                )
                report["entities_csv"] = render_entities_csv(report)
                cdir = self._find_case_dir(report["meta"]["case_id"])
                if cdir:
                    for art_key, art_file in (("gexf_xml", "graph.gexf"), ("graphml_xml", "graph.graphml"), ("neo4j_cypher", "neo4j.cypher")):
                        if (cdir / art_file).is_file():
                            report[art_key] = (cdir / art_file).read_text(encoding="utf-8")
                self._send_json(report)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/watchlist/add":
            tgt = str(data.get("target") or "").strip()
            if not tgt:
                self._send_json({"error": "target is required"}, status=400)
                return
            depth = max(1, min(6, int(data.get("depth", 3))))
            note = str(data.get("note") or "").strip()
            self._send_json({"watchlist": add_to_watchlist(tgt, depth=depth, note=note)})
            return

        if path == "/api/watchlist/remove":
            tgt = str(data.get("target") or "").strip()
            self._send_json({"watchlist": remove_from_watchlist(tgt)})
            return

        if path == "/api/watchlist/run":
            items = load_watchlist()
            results = []
            for entry in items:
                rep = run_autonomous_hunt(
                    entry["target"],
                    depth=int(entry.get("depth", 3)),
                    save_case=True,
                    mode="passive",
                    diff_last=True,
                )
                results.append(
                    {
                        "target": entry["target"],
                        "case_id": rep["meta"]["case_id"],
                        "exposure_score": rep["intelligence_synthesis"]["exposure_score"],
                        "surface_delta": rep.get("surface_delta"),
                    }
                )
            self._send_json({"swept_count": len(results), "results": results})
            return

        if path == "/api/settings/byok":
            updates = data.get("updates")
            if not isinstance(updates, dict):
                self._send_json({"error": "updates object is required"}, status=400)
                return
            self._send_json({"byok_providers": update_byok_dotenv(updates)})
            return

        if path == "/api/hunt":
            raw = str(data.get("target", "")).strip()
            if not raw:
                self._send_json({"error": "target is required"}, status=400)
                return
            depth = max(1, min(6, int(data.get("depth", 4))))
            save_case = bool(data.get("save_case", True))
            diff_last = bool(data.get("diff_last", False))
            ingested = data.get("ingested_evidence_text")
            try:
                report = run_autonomous_hunt(
                    raw,
                    depth=depth,
                    ingested_evidence_text=ingested,
                    save_case=save_case,
                    mode="passive",
                    diff_last=diff_last,
                )
                stix = build_stix2_bundle(
                    report["meta"]["case_id"],
                    raw,
                    report["graph"]["nodes"],
                    report["graph"]["edges"],
                )
                report["stix2_bundle"] = stix
                report["entities_csv"] = render_entities_csv(report)
                cdir = self._find_case_dir(report["meta"]["case_id"]) if save_case else None
                if cdir:
                    for art_key, art_file in (("gexf_xml", "graph.gexf"), ("graphml_xml", "graph.graphml"), ("neo4j_cypher", "neo4j.cypher")):
                        if (cdir / art_file).is_file():
                            report[art_key] = (cdir / art_file).read_text(encoding="utf-8")
                self._send_json(report)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/cases/expand":
            cid = str(data.get("case_id", "")).strip()
            ingested = str(data.get("ingested_text", "")).strip()
            if not cid or not ingested:
                self._send_json({"error": "case_id and ingested_text are required"}, status=400)
                return
            additional_stages = max(1, min(5, int(data.get("additional_stages", 3))))
            try:
                report = expand_existing_case(cid, ingested_text=ingested, additional_stages=additional_stages)
                report["stix2_bundle"] = build_stix2_bundle(
                    report["meta"]["case_id"],
                    report["meta"]["raw_input"],
                    report["graph"]["nodes"],
                    report["graph"]["edges"],
                )
                report["entities_csv"] = render_entities_csv(report)
                self._send_json(report)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return

        if path == "/api/cases/compare":
            ca = str(data.get("case_a", "")).strip()
            cb = str(data.get("case_b", "")).strip()
            if not ca or not cb:
                self._send_json({"error": "case_a and case_b are required"}, status=400)
                return
            try:
                self._send_json(compare_saved_cases(ca, cb))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return

        if path == "/api/cases/diff":
            ca = str(data.get("baseline_case") or data.get("case_a") or "").strip()
            cb = str(data.get("current_case") or data.get("case_b") or "").strip()
            dir_a = self._find_case_dir(ca)
            dir_b = self._find_case_dir(cb)
            if not dir_a or not dir_b:
                self._send_json({"error": "Both baseline_case and current_case must exist"}, status=404)
                return
            rep_a = json.loads((dir_a / "report.json").read_text(encoding="utf-8"))
            rep_b = json.loads((dir_b / "report.json").read_text(encoding="utf-8"))
            self._send_json(compute_case_delta(rep_a, rep_b))
            return

        if path == "/api/typosquats":
            dom = str(data.get("domain", "")).strip()
            if not dom:
                self._send_json({"error": "domain is required"}, status=400)
                return
            lim = max(5, min(120, int(data.get("limit", 45))))
            self._send_json(generate_domain_typosquats(dom, limit=lim))
            return

        if path == "/api/graph/path":
            nodes = data.get("nodes") or []
            edges = data.get("edges") or []
            src = str(data.get("source", "")).strip()
            dst = str(data.get("target", "")).strip()
            res = find_shortest_attribution_path(nodes, edges, src, dst)
            self._send_json({"path": res})
            return

        if path in ("/api/hunt/active/prepare", "/api/hunt/prepare-active"):
            raw = str(data.get("target", "")).strip()
            from_case = str(data.get("from_case", "")).strip()
            if from_case:
                try:
                    raw = get_case_active_target_string(from_case)
                except Exception:
                    pass
            if not raw:
                self._send_json({"error": "target or from_case is required"}, status=400)
                return
            mods = data.get("modules")
            plan = prepare_active_request(raw, requested_modules=mods, source="web_modal")
            self._send_json(plan)
            return

        if path == "/api/hunt/active":
            raw = str(data.get("target", "")).strip()
            req_id = str(data.get("request_id", "")).strip()
            user_conf = str(data.get("user_confirmation", "")).strip()
            modal_hdr = self.headers.get("X-Human-Modal-Confirmed", "")
            if modal_hdr != "1":
                self._send_json(
                    {
                        "error": (
                            "Active OSINT requires interactive human confirmation via the Web Authorization Modal "
                            "(missing X-Human-Modal-Confirmed header)."
                        )
                    },
                    status=403,
                )
                return
            depth = max(1, min(4, int(data.get("depth", 2))))
            save_case = bool(data.get("save_case", True))
            mods = data.get("modules")
            try:
                report = run_autonomous_hunt(
                    raw,
                    depth=depth,
                    save_case=save_case,
                    mode="active",
                    approval_request_id=req_id,
                    user_confirmation=user_conf,
                    active_modules=mods,
                    enforce_turn_delay=False,
                )
                stix = build_stix2_bundle(
                    report["meta"]["case_id"],
                    raw,
                    report["graph"]["nodes"],
                    report["graph"]["edges"],
                )
                report["stix2_bundle"] = stix
                report["entities_csv"] = render_entities_csv(report)
                self._send_json(report)
            except ActiveAuthorizationError as exc:
                self._send_json({"error": str(exc)}, status=403)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "Unknown API endpoint"}, status=404)


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve OSINT Command Center + Local Web App")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="TCP port (default: 8000)")
    parser.add_argument("--open", action="store_true", help="Automatically open the Web UI in your default browser")
    parser.add_argument("--auto-port", action="store_true", help="Automatically select the next free TCP port if --port is busy")
    args = parser.parse_args()

    httpd = None
    chosen_port = args.port
    max_tries = 25 if args.auto_port else 1
    for offset in range(max_tries):
        cand_port = args.port + offset
        try:
            httpd = ThreadingHTTPServer((args.host, cand_port), OSINTCommandHandler)
            chosen_port = cand_port
            break
        except OSError:
            if offset + 1 == max_tries:
                raise

    browser_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    local_url = f"http://{browser_host}:{chosen_port}"
    print("=" * 72)
    print(f"  🛰️  OSINT MONSTER LOCAL WEB APP RUNNING")
    print(f"  👉 Open in Browser : {local_url}")
    print(f"  📁 Saved Cases Dir : {get_cases_dir()}")
    print("  Press Ctrl+C (or close this window) to stop the local server.")
    print("=" * 72)

    if args.open:
        def _launch_browser() -> None:
            time.sleep(0.35)
            try:
                webbrowser.open(local_url)
            except Exception:
                pass

        threading.Thread(target=_launch_browser, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down local Web UI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

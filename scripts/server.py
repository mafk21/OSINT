#!/usr/bin/env python3
"""Unified OSINT Command Center + Autonomous Hunter HTTP Server (Zero Dependencies).

Serves the interactive web interface (`web/`) AND provides live REST endpoints:
  - GET  /api/health
  - GET  /api/cases
  - GET  /api/cases/<CASE_ID>
  - GET  /api/cases/<CASE_ID>/html
  - POST /api/detect
  - POST /api/decode
  - POST /api/hunt               (Instant Passive Multi-Stage Hunt)
  - POST /api/cases/expand       (Ingest Findings & Expand Multi-Stage Case)
  - POST /api/cases/compare      (Cross-Case Link Analysis)
  - POST /api/hunt/active/prepare (and alias /api/hunt/prepare-active)
  - POST /api/hunt/active        (User-Approved Active+Passive Hunt)
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
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
from osint_hunter.offline_intel import universal_forensic_decode  # noqa: E402
from osint_hunter.paths import get_cases_dir  # noqa: E402
from osint_hunter.persona import (  # noqa: E402
    find_shortest_attribution_path,
    generate_domain_typosquats,
)
from osint_hunter.providers import get_byok_status  # noqa: E402
from osint_hunter.watchlist import compute_case_delta  # noqa: E402


class OSINTCommandHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Human-Modal-Confirmed")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_doc: str, status: int = 200) -> None:
        body = html_doc.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(min(length, 4_000_000))
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

        if path == "/api/health":
            self._send_json(
                {
                    "status": "ok",
                    "engine": "osint-monster-hunter",
                    "version": "2026.10.4",
                    "tools": len(ALL_TOOLS),
                    "dorks": len(ALL_DORKS),
                    "workflows": len(ALL_WORKFLOWS),
                    "active_modules": list(ACTIVE_MODULES_CATALOG.keys()),
                    "byok_providers": get_byok_status(),
                }
            )
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
                if len(parts) == 5 and parts[4] == "html":
                    html_file = cdir / "report.html"
                    if html_file.is_file():
                        self._send_html(html_file.read_text(encoding="utf-8"))
                    else:
                        rep = json.loads((cdir / "report.json").read_text(encoding="utf-8"))
                        self._send_html(render_standalone_html_dossier(rep))
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
                    self.wfile.write(body)
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
    parser = argparse.ArgumentParser(description="Serve OSINT Command Center + Autonomous Hunter API")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="TCP port (default: 8000)")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), OSINTCommandHandler)
    print(f"OSINT Command Center + Autonomous Hunter running on http://{args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

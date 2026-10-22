#!/usr/bin/env python3
"""OSINT Monster Command Center HTTP + REST Hunt API + Streamable HTTP MCP Server.

Serves `web/` static UI and exposes:
  - GET  /api/health
  - POST /api/detect   {"input": "..."}
  - POST /api/hunt     {"target": "...", "depth": 2, "save_case": true}
  - GET  /api/cases
  - POST /api/mcp      (JSON-RPC 2.0 Streamable HTTP MCP endpoint)
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
CASES_DIR = ROOT / "cases"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osint_hunter.approval import (  # noqa: E402
    ACTIVE_MODULES_CATALOG,
    ActiveAuthorizationError,
    prepare_active_request,
)
from osint_hunter.classify import extract_selectors  # noqa: E402
from osint_hunter.engine import ALL_TOOLS, build_stix2_bundle, run_autonomous_hunt  # noqa: E402
from scripts.mcp_server import process_rpc  # noqa: E402


class MonsterRequestHandler(BaseHTTPRequestHandler):
    server_version = "OSINTMonsterHunter/2026.10"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[http] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, status: int, payload: object) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 2_000_000:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return json.loads(raw) if raw.strip() else {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path

        if route == "/api/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "engine": "osint-monster-hunter",
                    "version": "2026.10.2",
                    "arsenal_tools": len(ALL_TOOLS),
                    "active_modules_available": list(ACTIVE_MODULES_CATALOG.keys()),
                    "active_mode_policy": "ALWAYS_ASK_USER_SINGLE_USE_TOKEN",
                    "mcp_http_endpoint": "/api/mcp",
                    "passive_hunt_endpoint": "/api/hunt",
                    "prepare_active_endpoint": "/api/hunt/prepare-active",
                    "execute_active_endpoint": "/api/hunt/active",
                },
            )
            return

        if route == "/api/cases":
            cases = []
            if CASES_DIR.exists():
                for p in sorted(CASES_DIR.iterdir(), reverse=True):
                    rep_file = p / "report.json"
                    if p.is_dir() and rep_file.exists():
                        try:
                            meta = json.loads(rep_file.read_text(encoding="utf-8")).get("meta", {})
                            cases.append(meta)
                        except Exception:
                            pass
            self._send_json(200, {"cases": cases[:25]})
            return

        # Static file serving from WEB_DIR
        rel = "index.html" if route in ("", "/") else route.lstrip("/")
        target_path = (WEB_DIR / rel).resolve()
        if not str(target_path).startswith(str(WEB_DIR.resolve())) or not target_path.is_file():
            self._send_json(404, {"error": "Not found"})
            return

        ctype, _ = mimetypes.guess_type(str(target_path))
        data = target_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype or 'application/octet-stream'}; charset=utf-8" if (ctype or "").startswith("text/") or ctype == "application/javascript" else (ctype or "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        try:
            body = self._read_json_body()
        except Exception as exc:
            self._send_json(400, {"error": f"Invalid JSON body: {exc}"})
            return

        if route == "/api/detect":
            raw = str(body.get("input", ""))
            self._send_json(200, {"selectors": extract_selectors(raw, cwd=str(ROOT))})
            return

        if route == "/api/hunt":
            target = str(body.get("target", "")).strip()
            if not target:
                self._send_json(400, {"error": "Missing 'target' field"})
                return
            depth = int(body.get("depth", 2))
            save_case = bool(body.get("save_case", True))
            # /api/hunt is STRICTLY PASSIVE — Active OSINT can only run via /api/hunt/active after approval!
            report = run_autonomous_hunt(target, depth=depth, save_case=save_case, cwd=str(ROOT), mode="passive")
            stix = build_stix2_bundle(
                report["meta"]["case_id"],
                target,
                report["graph"]["nodes"],
                report["graph"]["edges"],
            )
            report["stix2_bundle"] = stix
            self._send_json(200, report)
            return

        if route == "/api/hunt/prepare-active":
            target = str(body.get("target", "")).strip()
            if not target:
                self._send_json(400, {"error": "Missing 'target' field"})
                return
            mods = body.get("modules") if isinstance(body.get("modules"), list) else None
            plan = prepare_active_request(target, requested_modules=mods, cwd=str(ROOT), source="web_or_api")
            plan["all_available_modules"] = [
                {"module": k, **v} for k, v in ACTIVE_MODULES_CATALOG.items()
            ]
            self._send_json(200, plan)
            return

        if route == "/api/hunt/active":
            target = str(body.get("target", "")).strip()
            req_id = str(body.get("request_id", "")).strip()
            user_conf = str(body.get("user_confirmation", "")).strip()
            depth = int(body.get("depth", 2))
            save_case = bool(body.get("save_case", True))
            mods = body.get("modules") if isinstance(body.get("modules"), list) else None
            ui_modal = self.headers.get("X-Human-Modal-Confirmed") == "1"

            try:
                report = run_autonomous_hunt(
                    target,
                    depth=depth,
                    save_case=save_case,
                    cwd=str(ROOT),
                    mode="active",
                    approval_request_id=req_id,
                    user_confirmation=user_conf,
                    active_modules=mods,
                    enforce_turn_delay=not ui_modal,
                )
            except ActiveAuthorizationError as exc:
                self._send_json(403, {"error": str(exc), "code": "ACTIVE_AUTHORIZATION_REQUIRED"})
                return

            stix = build_stix2_bundle(
                report["meta"]["case_id"],
                target,
                report["graph"]["nodes"],
                report["graph"]["edges"],
            )
            report["stix2_bundle"] = stix
            self._send_json(200, report)
            return

        if route == "/api/mcp":
            resp = process_rpc(body)
            if resp is None:
                self.send_response(202)
                self.end_headers()
            else:
                self._send_json(200, resp)
            return

        self._send_json(404, {"error": f"Unknown API endpoint: {route}"})


def main() -> int:
    parser = argparse.ArgumentParser(description="OSINT Monster Command Center & Hunt API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="TCP port (default: 8000)")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), MonsterRequestHandler)
    print(f"OSINT Monster Command Center + Hunt API + MCP HTTP listening on http://{args.host}:{args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

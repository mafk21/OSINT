"""Optional Bring-Your-Own-Key (BYOK) Passive Intelligence Turbo Connectors.

100% OPTIONAL & KEYLESS BY DEFAULT:
- If no API keys are set in environment variables (or `.osint.env` / `.env`), every
  function returns `[]` immediately with zero warnings and zero behavioral changes.
- Raw secret values are NEVER placed into collector outputs or logs; diagnostics
  expose only boolean `configured` status and masked hints (`abcd****xy`).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .paths import PKG_PARENT

DEFAULT_TIMEOUT = 5.5
USER_AGENT = "OSINT-Monster-Hunter/2026.10 (+https://github.com/mafk21/OSINT)"

SUPPORTED_BYOK_PROVIDERS: list[dict[str, Any]] = [
    {
        "id": "github",
        "env_vars": ["GITHUB_TOKEN", "GH_TOKEN"],
        "title": "GitHub Personal Access Token",
        "selectors": ["username", "repo_code"],
        "benefit": "Elevates GitHub passive API rate limits from 60 req/hr to 5,000 req/hr.",
    },
    {
        "id": "shodan",
        "env_vars": ["SHODAN_API_KEY"],
        "title": "Shodan Passive DNS & Host Intelligence",
        "selectors": ["domain", "ip"],
        "benefit": "Unlocks historical Shodan DNS subdomains, full service banners, ISP/ASN, and CVE tags.",
    },
    {
        "id": "virustotal",
        "env_vars": ["VT_API_KEY", "VIRUSTOTAL_API_KEY"],
        "title": "VirusTotal v3 Passive DNS, IP & File Hash CTI",
        "selectors": ["domain", "ip", "file_hash"],
        "benefit": "Unlocks passive DNS sibling subdomains, multi-AV verdicts, JARM, and certificate history.",
    },
    {
        "id": "urlscan",
        "env_vars": ["URLSCAN_API_KEY"],
        "title": "URLScan.io Historical DOM & Screenshot Search",
        "selectors": ["domain", "ip"],
        "benefit": "Queries passive historical web scans, DOM hashes, server headers, and screenshot URLs.",
    },
    {
        "id": "hibp",
        "env_vars": ["HIBP_API_KEY"],
        "title": "Have I Been Pwned v3 Breach Attribution",
        "selectors": ["email"],
        "benefit": "Queries verified credential breach names, dates, and exposed data classes for emails.",
    },
    {
        "id": "securitytrails",
        "env_vars": ["SECURITYTRAILS_API_KEY"],
        "title": "SecurityTrails Passive Subdomain Inventory",
        "selectors": ["domain"],
        "benefit": "Enumerates apex subdomain inventories from historical DNS datasets.",
    },
    {
        "id": "abuseipdb",
        "env_vars": ["ABUSEIPDB_API_KEY"],
        "title": "AbuseIPDB Threat & Scanner Reputation",
        "selectors": ["ip"],
        "benefit": "Returns abuse confidence score, ISP, usage type, and total abuse report count.",
    },
]


def _load_dotenv_map() -> dict[str, str]:
    out: dict[str, str] = {}
    candidates = [Path.cwd() / ".osint.env", Path.cwd() / ".env", PKG_PARENT / ".osint.env", PKG_PARENT / ".env"]
    for p in candidates:
        try:
            if not p.is_file():
                continue
            for raw_line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("\"'")
                if k and v and k not in out:
                    out[k] = v
        except Exception:
            continue
    return out


def get_api_key(*env_names: str) -> str | None:
    """Resolve an optional API key from process env first, then gitignored `.osint.env`/`.env`."""
    for name in env_names:
        val = os.environ.get(name, "").strip()
        if val:
            return val
    dotenv_vals = _load_dotenv_map()
    for name in env_names:
        val = dotenv_vals.get(name, "").strip()
        if val:
            return val
    return None


def _mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "****"
    return f"{secret[:3]}****{secret[-2:]}"


def get_byok_status() -> list[dict[str, Any]]:
    """Return secret-safe diagnostics for `osint.py doctor` and `/api/health`."""
    rows: list[dict[str, Any]] = []
    for p in SUPPORTED_BYOK_PROVIDERS:
        key = get_api_key(*p["env_vars"])
        rows.append(
            {
                "provider": p["id"],
                "title": p["title"],
                "env_vars": p["env_vars"],
                "selectors": p["selectors"],
                "configured": bool(key),
                "masked_preview": _mask_secret(key) if key else None,
                "benefit": p["benefit"],
            }
        )
    return rows


ALLOWED_BYOK_ENV_VARS: set[str] = {ev for p in SUPPORTED_BYOK_PROVIDERS for ev in p["env_vars"]}


def update_byok_dotenv(updates: dict[str, str], dotenv_path: Path | None = None) -> list[dict[str, Any]]:
    """Safely save or clear optional BYOK API keys in local gitignored `.osint.env` (mode 0600)."""
    target_path = dotenv_path or (PKG_PARENT / ".osint.env")
    existing: dict[str, str] = {}
    if target_path.is_file():
        for raw_line in target_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            k, v = line.split("=", 1)
            existing[k.strip()] = v.strip().strip("\"'")

    for k, v in updates.items():
        key_name = str(k).strip()
        if key_name not in ALLOWED_BYOK_ENV_VARS:
            continue
        clean_val = str(v or "").strip()
        if clean_val:
            existing[key_name] = clean_val
        else:
            existing.pop(key_name, None)
            os.environ.pop(key_name, None)

    lines = ["# Local gitignored OSINT Monster optional BYOK API keys (managed via Web UI / .osint.env)"]
    for k in sorted(existing.keys()):
        safe_v = existing[k].replace("\n", "").replace("\r", "").replace('"', "")
        lines.append(f'{k}="{safe_v}"')
    target_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        target_path.chmod(0o600)
    except OSError:
        pass
    return get_byok_status()


def _json_req(url: str, headers: dict[str, str], timeout: float = DEFAULT_TIMEOUT) -> tuple[int, Any, str | None]:
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json", **headers}
    req = urllib.request.Request(url, headers=merged)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(1_048_576).decode("utf-8", errors="replace")
            return resp.status, json.loads(raw), None
    except urllib.error.HTTPError as exc:
        return exc.code, None, f"HTTP {exc.code}"
    except Exception as exc:
        return 0, None, str(exc)


def _res(module: str, status: str, summary: str, data: dict | list, pivots: list[dict] | None = None) -> dict:
    norm_pivots = [{"type": p["type"], "value": p["value"]} for p in (pivots or []) if p.get("type") and p.get("value")]
    return {
        "module": module,
        "status": "restricted_or_offline" if status == "unavailable" else status,
        "summary": summary,
        "data": data,
        "pivots": norm_pivots,
    }


def collect_byok_for_domain(domain: str) -> list[dict]:
    """Run any configured BYOK passive domain collectors (0 packets sent to target)."""
    dom = domain.lower().strip(".")
    out: list[dict] = []

    vt_key = get_api_key("VT_API_KEY", "VIRUSTOTAL_API_KEY")
    if vt_key:
        code, obj, err = _json_req(
            f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(dom)}/subdomains?limit=30",
            {"x-apikey": vt_key},
        )
        if code == 200 and isinstance(obj, dict):
            subs = [str(item.get("id", "")).lower() for item in (obj.get("data") or []) if item.get("id")]
            pivots = [{"type": "domain", "value": s, "reason": "virustotal_byok_subdomain"} for s in subs[:15] if s != dom]
            out.append(_res("byok_virustotal_domain", "ok", f"VirusTotal passive DNS returned {len(subs)} subdomain(s)", {"subdomains": subs}, pivots))
        elif err:
            out.append(_res("byok_virustotal_domain", "unavailable", f"VirusTotal API returned {err}", {}))

    shodan_key = get_api_key("SHODAN_API_KEY")
    if shodan_key:
        code, obj, err = _json_req(
            f"https://api.shodan.io/dns/domain/{urllib.parse.quote(dom)}?key={urllib.parse.quote(shodan_key)}",
            {},
        )
        if code == 200 and isinstance(obj, dict):
            subs = [f"{s}.{dom}".lower() for s in (obj.get("subdomains") or [])[:30] if s]
            pivots = [{"type": "domain", "value": s, "reason": "shodan_byok_dns"} for s in subs[:15]]
            out.append(_res("byok_shodan_dns", "ok", f"Shodan DNS returned {len(subs)} subdomain(s)", {"subdomains": subs, "tags": obj.get("tags", [])}, pivots))

    urlscan_key = get_api_key("URLSCAN_API_KEY")
    if urlscan_key:
        q = urllib.parse.quote(f"domain:{dom}")
        code, obj, err = _json_req(f"https://urlscan.io/api/v1/search/?q={q}&size=15", {"API-Key": urlscan_key})
        if code == 200 and isinstance(obj, dict):
            hits = []
            pivots = []
            for r in (obj.get("results") or [])[:15]:
                pg = r.get("page") or {}
                hits.append({"url": pg.get("url"), "ip": pg.get("ip"), "server": pg.get("server"), "asn": pg.get("asn")})
                if pg.get("ip"):
                    pivots.append({"type": "ip", "value": str(pg["ip"]), "reason": "urlscan_byok_historical_ip"})
            out.append(_res("byok_urlscan_search", "ok", f"URLScan returned {len(hits)} historical scan(s)", {"scans": hits}, pivots[:10]))

    st_key = get_api_key("SECURITYTRAILS_API_KEY")
    if st_key:
        code, obj, err = _json_req(
            f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(dom)}/subdomains",
            {"APIKEY": st_key},
        )
        if code == 200 and isinstance(obj, dict):
            subs = [f"{s}.{dom}".lower() for s in (obj.get("subdomains") or [])[:30] if s]
            pivots = [{"type": "domain", "value": s, "reason": "securitytrails_byok_subdomain"} for s in subs[:15]]
            out.append(_res("byok_securitytrails_dns", "ok", f"SecurityTrails returned {len(subs)} subdomain(s)", {"subdomains": subs}, pivots))

    return out


def collect_byok_for_ip(ip_str: str) -> list[dict]:
    """Run any configured BYOK passive IP collectors."""
    out: list[dict] = []
    shodan_key = get_api_key("SHODAN_API_KEY")
    if shodan_key:
        code, obj, _err = _json_req(
            f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip_str)}?key={urllib.parse.quote(shodan_key)}",
            {},
        )
        if code == 200 and isinstance(obj, dict):
            hosts = [str(h).lower() for h in (obj.get("hostnames") or [])[:15]]
            pivots = [{"type": "domain", "value": h, "reason": "shodan_byok_host"} for h in hosts]
            out.append(
                _res(
                    "byok_shodan_host",
                    "ok",
                    f"Shodan Host: Org={obj.get('org')} · Ports={obj.get('ports', [])}",
                    {
                        "org": obj.get("org"),
                        "isp": obj.get("isp"),
                        "asn": obj.get("asn"),
                        "country_name": obj.get("country_name"),
                        "ports": obj.get("ports", []),
                        "vulns": list((obj.get("vulns") or []))[:25],
                        "hostnames": hosts,
                    },
                    pivots,
                )
            )

    abuse_key = get_api_key("ABUSEIPDB_API_KEY")
    if abuse_key:
        code, obj, _err = _json_req(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip_str)}&maxAgeInDays=90",
            {"Key": abuse_key},
        )
        if code == 200 and isinstance(obj, dict) and isinstance(obj.get("data"), dict):
            d = obj["data"]
            out.append(
                _res(
                    "byok_abuseipdb",
                    "ok",
                    f"AbuseIPDB score {d.get('abuseConfidenceScore')}% ({d.get('totalReports')} reports)",
                    {
                        "abuse_confidence_score": d.get("abuseConfidenceScore"),
                        "total_reports": d.get("totalReports"),
                        "isp": d.get("isp"),
                        "usage_type": d.get("usageType"),
                        "domain": d.get("domain"),
                    },
                )
            )

    vt_key = get_api_key("VT_API_KEY", "VIRUSTOTAL_API_KEY")
    if vt_key:
        code, obj, _err = _json_req(f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip_str)}", {"x-apikey": vt_key})
        if code == 200 and isinstance(obj, dict):
            attrs = ((obj.get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats") or {}
            out.append(
                _res(
                    "byok_virustotal_ip",
                    "ok",
                    f"VirusTotal IP: malicious={stats.get('malicious', 0)}, suspicious={stats.get('suspicious', 0)}",
                    {"last_analysis_stats": stats, "as_owner": attrs.get("as_owner"), "jarm": attrs.get("jarm")},
                )
            )
    return out


def collect_byok_for_email(email_addr: str) -> list[dict]:
    """Run optional Have I Been Pwned v3 breach check when HIBP_API_KEY is configured."""
    hibp_key = get_api_key("HIBP_API_KEY")
    if not hibp_key:
        return []
    code, obj, _err = _json_req(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email_addr.lower())}?truncateResponse=false",
        {"hibp-api-key": hibp_key},
    )
    if code == 200 and isinstance(obj, list):
        breaches = [
            {
                "name": b.get("Name"),
                "domain": b.get("Domain"),
                "breach_date": b.get("BreachDate"),
                "data_classes": (b.get("DataClasses") or [])[:10],
            }
            for b in obj[:25]
        ]
        return [_res("byok_hibp_breaches", "ok", f"HIBP found {len(obj)} verified breach(es)", {"breaches": breaches})]
    if code == 404:
        return [_res("byok_hibp_breaches", "not_found", "0 HIBP breaches recorded for email", {})]
    return []


def collect_byok_for_hash(file_hash: str) -> list[dict]:
    """Run optional VirusTotal file hash lookup when VT_API_KEY is configured."""
    vt_key = get_api_key("VT_API_KEY", "VIRUSTOTAL_API_KEY")
    if not vt_key:
        return []
    code, obj, _err = _json_req(f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(file_hash)}", {"x-apikey": vt_key})
    if code == 200 and isinstance(obj, dict):
        attrs = ((obj.get("data") or {}).get("attributes") or {})
        stats = attrs.get("last_analysis_stats") or {}
        return [
            _res(
                "byok_virustotal_hash",
                "ok",
                f"VirusTotal File: malicious={stats.get('malicious', 0)}, meaningful_name={attrs.get('meaningful_name')}",
                {
                    "meaningful_name": attrs.get("meaningful_name"),
                    "type_description": attrs.get("type_description"),
                    "last_analysis_stats": stats,
                    "popular_threat_classification": attrs.get("popular_threat_classification"),
                },
            )
        ]
    return []

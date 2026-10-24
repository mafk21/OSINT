"""Optional Local CLI Arsenal Auto-Detector & Safe Subprocess Runner (`shell=False`).

If the user has popular open-source OSINT CLI tools installed locally on their OS
(`sherlock`, `maigret`, `holehe`, `ignorant`, `subfinder`, `whois`, `httpx`, `dnstwist`),
this module safely invokes them with strict timeouts and merges their findings into the hunt.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from .classify import DOMAIN_RE, EMAIL_RE, NOISE_DOMAINS

SUPPORTED_LOCAL_CLIS: list[dict[str, str]] = [
    {"bin": "holehe", "opsec": "Passive", "selectors": "email", "install": "pip install holehe"},
    {"bin": "ignorant", "opsec": "Passive", "selectors": "phone", "install": "pip install ignorant"},
    {"bin": "sherlock", "opsec": "Passive", "selectors": "username", "install": "pip install sherlock-project"},
    {"bin": "maigret", "opsec": "Passive", "selectors": "username", "install": "pip install maigret"},
    {"bin": "subfinder", "opsec": "Passive", "selectors": "domain", "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    {"bin": "whois", "opsec": "Passive", "selectors": "domain,ip", "install": "apt/brew/winget install whois"},
    {"bin": "dnstwist", "opsec": "Active", "selectors": "domain", "install": "pip install dnstwist"},
    {"bin": "httpx", "opsec": "Active", "selectors": "domain,url", "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
]


def get_local_cli_status() -> list[dict[str, Any]]:
    """Return installed status for optional local CLI OSINT tools (exposed in `/api/doctor`)."""
    out = []
    for item in SUPPORTED_LOCAL_CLIS:
        path = shutil.which(item["bin"])
        out.append(
            {
                "tool": item["bin"],
                "opsec": item["opsec"],
                "selectors": item["selectors"].split(","),
                "installed": bool(path),
                "binary_path": path,
                "install_hint": item["install"],
            }
        )
    return out


def _safe_run(args: list[str], timeout: float = 12.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        return -1, ""


def run_installed_passive_clis(sel_type: str, value: str) -> list[dict]:
    """Run any installed strictly-passive local CLI OSINT tools matching `(sel_type, value)`."""
    results: list[dict] = []

    if sel_type == "email" and EMAIL_RE.fullmatch(value.strip()):
        holehe_bin = shutil.which("holehe")
        if holehe_bin:
            rc, out = _safe_run([holehe_bin, "--only-used", "--no-color", value.strip()], timeout=18.0)
            used = sorted(set(re.findall(r"\[\+\]\s*([A-Za-z0-9_.-]+\.[A-Za-z]{2,})", out)))
            if rc == 0 or used:
                results.append(
                    {
                        "module": "local_cli_holehe",
                        "status": "ok" if used else "not_found",
                        "summary": f"Local `holehe` confirmed email registered on {len(used)} platform(s): {', '.join(used[:8])}",
                        "data": {"registered_services": used},
                        "pivots": [],
                    }
                )

    elif sel_type == "phone":
        ig_bin = shutil.which("ignorant")
        digits = re.sub(r"\D", "", value)
        # Try common 1-3 digit country code split for ignorant
        if ig_bin and len(digits) >= 9:
            for cc_len in (3, 2, 1):
                cc, num = digits[:cc_len], digits[cc_len:]
                if cc in ("966", "971", "965", "974", "973", "968", "962", "20", "44", "33", "49", "90", "91", "1"):
                    rc, out = _safe_run([ig_bin, "--only-used", "--no-color", cc, num], timeout=15.0)
                    used = sorted(set(re.findall(r"\[\+\]\s*([A-Za-z0-9_.-]+)", out)))
                    if rc == 0 or used:
                        results.append(
                            {
                                "module": "local_cli_ignorant",
                                "status": "ok" if used else "not_found",
                                "summary": f"Local `ignorant` checked +{cc} {num} -> registered on: {used or ['none']}",
                                "data": {"registered_apps": used},
                                "pivots": [],
                            }
                        )
                    break

    elif sel_type == "username" and re.fullmatch(r"[A-Za-z0-9_.-]{2,38}", value.strip()):
        sherlock_bin = shutil.which("sherlock")
        if sherlock_bin:
            _, out = _safe_run([sherlock_bin, value.strip(), "--print-found", "--timeout", "4", "--no-txt"], timeout=20.0)
            urls = sorted(set(re.findall(r"\[\+\]\s*[^:]+:\s*(https?://\S+)", out)))
            if urls:
                results.append(
                    {
                        "module": "local_cli_sherlock",
                        "status": "ok",
                        "summary": f"Local `sherlock` discovered {len(urls)} profile URL(s)",
                        "data": {"profile_urls": urls[:40]},
                        "pivots": [{"type": "url", "value": u} for u in urls[:10]],
                    }
                )

    elif sel_type == "domain" and DOMAIN_RE.fullmatch(value.strip().lower()):
        dom = value.strip().lower()
        sf_bin = shutil.which("subfinder")
        if sf_bin:
            rc, out = _safe_run([sf_bin, "-d", dom, "-silent", "-timeout", "5"], timeout=16.0)
            subs = sorted({ln.strip().lower() for ln in out.splitlines() if ln.strip().lower().endswith(dom) and DOMAIN_RE.fullmatch(ln.strip().lower())})
            if rc == 0 and subs:
                results.append(
                    {
                        "module": "local_cli_subfinder",
                        "status": "ok",
                        "summary": f"Local `subfinder` enumerated {len(subs)} subdomain(s)",
                        "data": {"subdomains": subs[:80]},
                        "pivots": [{"type": "domain", "value": s} for s in subs if s != dom][:12],
                    }
                )

        whois_bin = shutil.which("whois")
        if whois_bin:
            rc, out = _safe_run([whois_bin, dom], timeout=6.0)
            if rc == 0 and len(out) > 80 and "No match" not in out and "NOT FOUND" not in out:
                kv: dict[str, str] = {}
                emails: set[str] = set()
                for ln in out.splitlines():
                    if ":" in ln:
                        k, v = [x.strip() for x in ln.split(":", 1)]
                        kl = k.lower()
                        if v and any(w in kl for w in ("registrar", "registrant", "creation", "expir", "org", "name server", "status")):
                            kv.setdefault(k, v[:140])
                    for em in EMAIL_RE.findall(ln):
                        el = em.lower()
                        if not any(x in el for x in ("abuse@", "privacy", "redacted", "whois", "domainops")):
                            emails.add(el)
                if kv:
                    results.append(
                        {
                            "module": "local_cli_whois",
                            "status": "ok",
                            "summary": f"Local WHOIS: Registrar='{kv.get('Registrar') or kv.get('registrar') or 'resolved'}' · {len(kv)} fields",
                            "data": {"whois_fields": kv, "non_abuse_emails": sorted(emails)},
                            "pivots": [{"type": "email", "value": e} for e in sorted(emails)[:4]],
                        }
                    )

    return results

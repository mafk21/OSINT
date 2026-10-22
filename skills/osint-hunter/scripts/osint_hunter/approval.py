"""Mandatory Single-Use Human Authorization Gate for Active OSINT Mode.

Enforces the strict repository invariant:
  1. Passive OSINT runs immediately with zero questions.
  2. Active OSINT ALWAYS requires explicit, per-run, target-bound user approval
     before sending a single direct packet to target infrastructure.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from .classify import extract_selectors
from .paths import get_state_dir

APPROVAL_TTL_SECONDS = 900  # 15 minutes
MIN_HUMAN_TURN_DELAY_SECONDS = 1.5

ACTIVE_MODULES_CATALOG = {
    "active_dns_live_resolver": {
        "title": "Live DNS & Reverse PTR Resolution",
        "opsec_impact": "Queries live DNS / reverse PTR records for target hostnames and IP addresses.",
        "applies_to": ["domain", "url", "ip", "email"],
    },
    "active_tls_cert_inspector": {
        "title": "Live TLS Handshake & X.509 SAN Certificate Inspector",
        "opsec_impact": "Initiates direct TCP/TLS handshake to target port 443; target logs record your source IP and TLS JA3/JA4 client hello.",
        "applies_to": ["domain", "url", "ip"],
    },
    "active_http_fingerprint_and_headers": {
        "title": "Live HTTP Redirect, Security Header, CSP & Analytics Tag Fingerprinter",
        "opsec_impact": "Sends direct HTTP/HTTPS GET request(s) to target web server; leaves User-Agent and source IP in target access logs.",
        "applies_to": ["domain", "url", "ip"],
    },
    "active_wellknown_and_robots_harvester": {
        "title": "Live /robots.txt, /.well-known/security.txt & OpenID Tenant Harvester",
        "opsec_impact": "Sends 4 targeted HTTP GET requests (/robots.txt, /.well-known/security.txt, /.well-known/openid-configuration, /humans.txt) directly to target origin.",
        "applies_to": ["domain", "url"],
    },
    "active_favicon_hash_extractor": {
        "title": "Live /favicon.ico Shodan MurmurHash3 (mmh3) & SHA-256 Calculator",
        "opsec_impact": "Fetches /favicon.ico directly from target server to compute origin-unmasking Shodan mmh3 hash.",
        "applies_to": ["domain", "url"],
    },
    "active_tcp_service_banner_probe": {
        "title": "Non-Intrusive TCP Service Port & SSH/SMTP/HTTP Banner Read",
        "opsec_impact": "Opens brief TCP connections to common public ports (21, 22, 25, 80, 443, 8080, 8443); detectable by target firewall/IDS.",
        "applies_to": ["ip", "domain"],
    },
    "active_url_jsonld_opengraph": {
        "title": "Live Webpage OpenGraph, JSON-LD sameAs Social Graph & Contact Extractor",
        "opsec_impact": "Fetches target URL HTML directly to extract embedded schema.org links, metadata, and mailto/tel contacts.",
        "applies_to": ["url", "domain"],
    },
}


class ActiveAuthorizationError(PermissionError):
    """Raised whenever Active OSINT is invoked without valid single-use human approval."""


def _canonical_target_hash(raw_target: str) -> str:
    return hashlib.sha256(raw_target.strip().lower().encode("utf-8")).hexdigest()[:24]


def _load_store() -> dict:
    approvals_file = get_state_dir() / ".active_approvals.json"
    if not approvals_file.exists():
        return {}
    try:
        return json.loads(approvals_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_store(store: dict) -> None:
    state_dir = get_state_dir()
    approvals_file = state_dir / ".active_approvals.json"
    now = time.time()
    # Prune expired entries automatically
    cleaned = {
        k: v
        for k, v in store.items()
        if isinstance(v, dict) and (now - v.get("created_epoch", 0)) < APPROVAL_TTL_SECONDS
    }
    approvals_file.write_text(json.dumps(cleaned, indent=2) + "\n", encoding="utf-8")


def append_active_audit_log(entry: dict) -> None:
    audit_log_file = get_state_dir() / "active_audit.jsonl"
    record = {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **entry,
    }
    with audit_log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def prepare_active_request(
    raw_target: str,
    requested_modules: list[str] | None = None,
    cwd: str | None = None,
    source: str = "agent_or_cli",
) -> dict:
    """Create a pending single-use Active OSINT authorization request (sends ZERO packets)."""
    target_clean = raw_target.strip()
    if not target_clean:
        raise ValueError("Target cannot be empty.")

    selectors = extract_selectors(target_clean, cwd=cwd)
    sel_types = {s["type"] for s in selectors}

    if requested_modules:
        valid_mods = [m for m in requested_modules if m in ACTIVE_MODULES_CATALOG]
    else:
        valid_mods = [
            m_id
            for m_id, meta in ACTIVE_MODULES_CATALOG.items()
            if sel_types & set(meta["applies_to"])
        ]
        if not valid_mods:
            valid_mods = list(ACTIVE_MODULES_CATALOG.keys())[:4]

    request_id = f"ACT-{secrets.token_hex(4).upper()}"
    now = time.time()
    target_hash = _canonical_target_hash(target_clean)

    store = _load_store()
    store[request_id] = {
        "request_id": request_id,
        "raw_target": target_clean,
        "target_hash": target_hash,
        "selectors": selectors,
        "modules": valid_mods,
        "created_epoch": now,
        "expires_epoch": now + APPROVAL_TTL_SECONDS,
        "consumed": False,
        "source": source,
    }
    _save_store(store)

    planned_details = [
        {
            "module": m,
            "title": ACTIVE_MODULES_CATALOG[m]["title"],
            "opsec_impact": ACTIVE_MODULES_CATALOG[m]["opsec_impact"],
        }
        for m in valid_mods
    ]

    append_active_audit_log(
        {
            "event": "active_authorization_prepared",
            "request_id": request_id,
            "target": target_clean,
            "modules": valid_mods,
            "source": source,
        }
    )

    return {
        "status": "PENDING_USER_APPROVAL",
        "request_id": request_id,
        "expires_in_seconds": APPROVAL_TTL_SECONDS,
        "target": target_clean,
        "detected_selectors": selectors,
        "planned_active_modules": planned_details,
        "opsec_warning": (
            "ACTIVE OSINT SENDS DIRECT NETWORK PACKETS (TCP/TLS/HTTP/DNS) TO TARGET INFRASTRUCTURE. "
            "Target web servers, firewalls, and SIEMs will see this environment's egress IP address, "
            "TLS client hello, and User-Agent."
        ),
        "mandatory_agent_instruction": (
            "STOP! DO NOT execute Active OSINT yet. You MUST ask the user for explicit permission first "
            "(use the `ask_user` tool if available, or ask clearly in chat) showing the target(s), "
            "planned active modules, and OPSEC warning above. Only AFTER the user explicitly approves "
            f"in their next response may you execute with request_id='{request_id}'."
        ),
    }


def verify_and_consume_approval(
    raw_target: str,
    request_id: str | None,
    user_confirmation: str | None,
    *,
    enforce_turn_delay: bool = True,
) -> dict:
    """Validate and atomically consume a single-use Active OSINT approval token."""
    if not request_id or not request_id.strip():
        raise ActiveAuthorizationError(
            "ACTIVE OSINT BLOCKED: Missing `request_id`. Active OSINT ALWAYS requires explicit user approval first. "
            "Run with `--prepare-active` (or call `osint_prepare_active_hunt`), ask the user for permission, "
            "and pass `--request-id <ID> --user-approved \"<user reply>\"` only after they approve."
        )

    conf = (user_confirmation or "").strip()
    if len(conf) < 2 or conf.lower() in {"no", "n", "cancel", "deny", "false", "stop", "abort"}:
        raise ActiveAuthorizationError(
            "ACTIVE OSINT BLOCKED: Explicit affirmative user confirmation is required before running Active OSINT."
        )

    req_key = request_id.strip().upper()
    store = _load_store()
    rec = store.get(req_key)
    if not rec:
        raise ActiveAuthorizationError(
            f"ACTIVE OSINT BLOCKED: Unknown or expired `request_id` '{req_key}'. "
            "Prepare a fresh active authorization request and ask the user to approve it."
        )

    if rec.get("consumed"):
        raise ActiveAuthorizationError(
            f"ACTIVE OSINT BLOCKED: `request_id` '{req_key}' was already used! "
            "Every Active OSINT execution requires fresh explicit user permission—prepare a new request and ask the user again."
        )

    now = time.time()
    if now > rec.get("expires_epoch", 0):
        raise ActiveAuthorizationError(
            f"ACTIVE OSINT BLOCKED: `request_id` '{req_key}' has expired (>15m). Ask the user again with a fresh request."
        )

    if enforce_turn_delay and (now - rec.get("created_epoch", 0)) < MIN_HUMAN_TURN_DELAY_SECONDS:
        raise ActiveAuthorizationError(
            "ACTIVE OSINT BLOCKED: Approval cannot be generated and consumed in the same sub-second automated call! "
            "You MUST stop, ask the user for permission, and wait for their response before executing Active Mode."
        )

    expected_hash = _canonical_target_hash(raw_target)
    if rec.get("target_hash") != expected_hash:
        raise ActiveAuthorizationError(
            f"ACTIVE OSINT BLOCKED: `request_id` '{req_key}' was authorized ONLY for '{rec.get('raw_target')}', "
            f"not '{raw_target}'. Ask the user for permission on the new target."
        )

    # Atomically mark consumed (single-use!)
    rec["consumed"] = True
    rec["consumed_epoch"] = now
    rec["user_confirmation"] = conf[:200]
    store[req_key] = rec
    _save_store(store)

    append_active_audit_log(
        {
            "event": "active_authorization_approved_and_consumed",
            "request_id": req_key,
            "target": raw_target.strip(),
            "modules": rec.get("modules", []),
            "user_confirmation": conf[:200],
        }
    )
    return rec

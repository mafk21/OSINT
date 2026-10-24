"""Modern & Decentralized Passive Identity + Cloud Tenant Collectors (Zero-Auth).

Queries public third-party registries & identity directories with ZERO packets sent
to target-owned infrastructure:
  1. Bluesky / ATProto (`public.api.bsky.app` + immutable `plc.directory` handle-rename log)
  2. Mastodon / Fediverse (`mastodon.social` public account lookup + verified `rel="me"` sites)
  3. AI & Systems Package Registries (HuggingFace Hub, Crates.io, Docker Hub, Packagist)
  4. Passive Microsoft Entra ID / M365 Tenant UUID & Federation Resolver (`login.microsoftonline.com`)
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

USER_AGENT = "OSINT-Monster-Hunter/2026.10 (+https://github.com/mafk21/OSINT)"
FAST_TIMEOUT = 4.2
HTML_TAG_RE = re.compile(r"<[^>]+>")


def _fetch_json(url: str, timeout: float = FAST_TIMEOUT) -> tuple[int, Any, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(524_288).decode("utf-8", errors="replace")
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


# ============================================================================
# 1. BLUESKY / ATPROTO + IMMUTABLE PLC.DIRECTORY HANDLE HISTORY
# ============================================================================

def collect_bluesky_atproto(handle_or_actor: str) -> dict:
    """Resolve Bluesky profile & inspect `plc.directory` audit log for past handle renames."""
    raw = handle_or_actor.strip().lstrip("@").lower()
    actors_to_try = [raw] if ("." in raw or raw.startswith("did:")) else [f"{raw}.bsky.social"]

    for actor in actors_to_try:
        url = f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={urllib.parse.quote(actor)}"
        code, prof, err = _fetch_json(url)
        if code != 200 or not isinstance(prof, dict):
            if code in (0, 400, 404):
                continue
            return _res("bluesky_atproto", "unavailable", f"Bluesky API unavailable ({err})", {})

        did = str(prof.get("did") or "")
        cur_handle = str(prof.get("handle") or actor)
        display_name = str(prof.get("displayName") or "").strip()
        desc = str(prof.get("description") or "").strip()
        created_at = prof.get("createdAt")

        past_handles: list[str] = []
        pds_endpoint: str | None = None
        if did.startswith("did:plc:"):
            lcode, audit_log, _ = _fetch_json(f"https://plc.directory/{urllib.parse.quote(did)}/log/audit")
            if lcode == 200 and isinstance(audit_log, list):
                for entry in audit_log:
                    op = entry.get("operation") or {}
                    for aka in op.get("alsoKnownAs") or []:
                        if isinstance(aka, str) and aka.startswith("at://"):
                            h_cand = aka[5:].strip().lower()
                            if h_cand and h_cand not in past_handles:
                                past_handles.append(h_cand)
                    svcs = op.get("services") or {}
                    pds = (svcs.get("atproto_pds") or {}).get("endpoint")
                    if isinstance(pds, str) and pds:
                        pds_endpoint = pds

        pivots: list[dict[str, str]] = []
        if not cur_handle.endswith(".bsky.social") and "." in cur_handle:
            pivots.append({"type": "domain", "value": cur_handle, "reason": "bluesky_verified_custom_domain_handle"})
        for old_h in past_handles:
            if old_h != cur_handle:
                if not old_h.endswith(".bsky.social") and "." in old_h:
                    pivots.append({"type": "domain", "value": old_h, "reason": "bluesky_plc_historical_domain_handle"})
                else:
                    stem = old_h.removesuffix(".bsky.social")
                    pivots.append({"type": "username", "value": stem, "reason": "bluesky_plc_historical_handle"})
        if display_name and " " in display_name and 4 <= len(display_name) <= 45:
            pivots.append({"type": "person_name", "value": display_name, "reason": "bluesky_display_name"})

        return _res(
            "bluesky_atproto",
            "ok",
            f"Bluesky @{cur_handle} ({did}) · {len(past_handles)} PLC handle record(s)",
            {
                "did": did,
                "handle": cur_handle,
                "display_name": display_name,
                "avatar": prof.get("avatar"),
                "banner": prof.get("banner"),
                "description": desc,
                "created_utc_iso": created_at,
                "followers_count": prof.get("followersCount"),
                "follows_count": prof.get("followsCount"),
                "posts_count": prof.get("postsCount"),
                "plc_handle_history": past_handles,
                "pds_endpoint": pds_endpoint,
            },
            pivots,
        )

    return _res("bluesky_atproto", "not_found", f"No Bluesky profile for '{raw}'", {})


# ============================================================================
# 2. MASTODON / FEDIVERSE ACCOUNT & VERIFIED `rel="me"` LINK COLLECTOR
# ============================================================================

def collect_mastodon_fediverse(username: str) -> dict:
    """Lookup fediverse handle on mastodon.social & harvest verified `rel=me` external domains."""
    clean = username.strip().lstrip("@").lower()
    if not clean or "/" in clean:
        return _res("mastodon_fediverse", "not_found", "Invalid handle", {})

    url = f"https://mastodon.social/api/v1/accounts/lookup?acct={urllib.parse.quote(clean)}"
    code, acct, err = _fetch_json(url)
    if code != 200 or not isinstance(acct, dict):
        if code == 404:
            return _res("mastodon_fediverse", "not_found", f"No mastodon.social account for @{clean}", {})
        return _res("mastodon_fediverse", "unavailable", f"Mastodon lookup unavailable ({err})", {})

    verified_links: list[str] = []
    all_fields: list[dict[str, Any]] = []
    pivots: list[dict[str, str]] = []

    for fld in acct.get("fields") or []:
        orig_html = str(fld.get("value") or "")
        href_m = re.search(r'href=["\'](https?://[^"\'>\s]+)["\']', orig_html, re.IGNORECASE)
        raw_val = HTML_TAG_RE.sub("", orig_html).strip()
        ver_at = fld.get("verified_at")
        url_cand = href_m.group(1) if href_m else (raw_val if raw_val.startswith(("http://", "https://")) else "")
        all_fields.append({"name": fld.get("name"), "value": url_cand or raw_val, "verified_at": ver_at})
        if url_cand:
            parsed = urllib.parse.urlparse(url_cand)
            if ver_at and parsed.hostname:
                verified_links.append(url_cand)
                pivots.append({"type": "domain", "value": parsed.hostname.lower().removeprefix("www."), "reason": "mastodon_rel_me_verified"})

    disp = str(acct.get("display_name") or "").strip()
    if disp and " " in disp and 4 <= len(disp) <= 45:
        pivots.append({"type": "person_name", "value": disp, "reason": "mastodon_display_name"})

    avatar_masto = acct.get("avatar")
    if avatar_masto and "missing.png" in str(avatar_masto):
        avatar_masto = None

    return _res(
        "mastodon_fediverse",
        "ok",
        f"Mastodon @{acct.get('acct')} ({len(verified_links)} cryptographically verified rel=me link(s))",
        {
            "acct": acct.get("acct"),
            "url": acct.get("url"),
            "display_name": disp,
            "avatar_url": avatar_masto,
            "note_plain": HTML_TAG_RE.sub("", str(acct.get("note") or "")).strip()[:400],
            "created_utc_iso": acct.get("created_at"),
            "followers_count": acct.get("followers_count"),
            "statuses_count": acct.get("statuses_count"),
            "verified_rel_me_links": verified_links,
            "profile_fields": all_fields,
        },
        pivots,
    )


# ============================================================================
# 3. AI & SYSTEMS PACKAGE REGISTRIES (HuggingFace, Crates.io, DockerHub, Packagist)
# ============================================================================

def collect_modern_pkg_registries(username: str) -> dict:
    """Concurrently check HuggingFace Hub, Crates.io, Docker Hub, and Packagist for handle reuse."""
    clean = username.strip().lstrip("@")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{2,42}", clean):
        return _res("modern_pkg_registries", "not_found", "Handle outside registry charset", {})

    q_user = urllib.parse.quote(clean)
    q_low = urllib.parse.quote(clean.lower())
    checks = {
        "huggingface_models": f"https://huggingface.co/api/models?author={q_user}&limit=10",
        "crates_io": f"https://crates.io/api/v1/users/{q_low}",
        "dockerhub": f"https://hub.docker.com/v2/users/{q_low}/",
        "packagist": f"https://packagist.org/packages/list.json?vendor={q_low}",
    }

    hits: dict[str, Any] = {}
    pivots: list[dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(_fetch_json, u, 3.8): name for name, u in checks.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            code, data, _ = fut.result()
            if code != 200 or data is None:
                continue
            if name == "huggingface_models" and isinstance(data, list) and len(data) > 0:
                hits["huggingface"] = {
                    "profile_url": f"https://huggingface.co/{clean}",
                    "public_models_sample": [m.get("id") for m in data[:8] if isinstance(m, dict)],
                }
            elif name == "crates_io" and isinstance(data, dict) and isinstance(data.get("user"), dict):
                u_obj = data["user"]
                hits["crates_io"] = {
                    "login": u_obj.get("login"),
                    "name": u_obj.get("name"),
                    "url": u_obj.get("url"),
                }
                if u_obj.get("name") and " " in str(u_obj["name"]):
                    pivots.append({"type": "person_name", "value": str(u_obj["name"]), "reason": "crates_io_author_name"})
            elif name == "dockerhub" and isinstance(data, dict) and data.get("username"):
                hits["dockerhub"] = {
                    "username": data.get("username"),
                    "full_name": data.get("full_name"),
                    "company": data.get("company"),
                    "location": data.get("location"),
                    "date_joined": data.get("date_joined"),
                }
                if data.get("company"):
                    pivots.append({"type": "company", "value": str(data["company"]), "reason": "dockerhub_company"})
            elif name == "packagist" and isinstance(data, dict) and data.get("packageNames"):
                pkgs = data["packageNames"]
                if isinstance(pkgs, list) and len(pkgs) > 0:
                    hits["packagist"] = {"package_count": len(pkgs), "packages_sample": pkgs[:10]}

    if not hits:
        return _res("modern_pkg_registries", "not_found", f"0 hits across HuggingFace, Crates.io, DockerHub & Packagist for '{clean}'", {})

    return _res(
        "modern_pkg_registries",
        "ok",
        f"Matched {len(hits)} AI/package registry profile(s): {', '.join(sorted(hits.keys()))}",
        hits,
        pivots,
    )


# ============================================================================
# 4. PASSIVE MICROSOFT ENTRA ID / M365 CLOUD TENANT RESOLVER
# ============================================================================

def collect_entra_m365_tenant_passive(domain: str) -> dict:
    """Query Microsoft's public identity cloud (`login.microsoftonline.com`) — ZERO packets to target!"""
    dom = domain.strip().lower().strip(".")
    if not dom or "." not in dom:
        return _res("microsoft_entra_tenant_passive", "not_found", "Invalid domain", {})

    oid_url = f"https://login.microsoftonline.com/{urllib.parse.quote(dom)}/v2.0/.well-known/openid-configuration"
    realm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login={urllib.parse.quote('osint-check@' + dom)}&json=1"

    code_oid, oid_data, err_oid = _fetch_json(oid_url)
    code_rlm, rlm_data, _ = _fetch_json(realm_url)

    tenant_id = None
    region_scope = None
    cloud_instance = None
    if code_oid == 200 and isinstance(oid_data, dict):
        issuer = str(oid_data.get("issuer") or "")
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", issuer, re.IGNORECASE)
        if m:
            tenant_id = m.group(1).lower()
        region_scope = oid_data.get("tenant_region_scope")
        cloud_instance = oid_data.get("cloud_instance_name")

    ns_type = None
    fed_brand = None
    auth_url = None
    pivots: list[dict[str, str]] = []
    if code_rlm == 200 and isinstance(rlm_data, dict):
        ns_type = rlm_data.get("NameSpaceType")
        fed_brand = rlm_data.get("FederationBrandName")
        auth_url = rlm_data.get("AuthURL")
        if isinstance(auth_url, str) and auth_url.startswith("https://"):
            sso_host = (urllib.parse.urlparse(auth_url).hostname or "").lower()
            if sso_host and not sso_host.endswith(("microsoftonline.com", "live.com")):
                pivots.append({"type": "domain", "value": sso_host, "reason": "entra_federated_idp_host"})
        if fed_brand and isinstance(fed_brand, str) and 2 <= len(fed_brand) <= 60:
            pivots.append({"type": "company", "value": fed_brand.strip(), "reason": "entra_federation_brand_name"})

    if not tenant_id and ns_type in (None, "Unknown"):
        if code_oid == 0:
            return _res("microsoft_entra_tenant_passive", "unavailable", f"Microsoft identity endpoint unreachable ({err_oid})", {})
        return _res("microsoft_entra_tenant_passive", "not_found", f"No Microsoft Entra ID / M365 tenant bound to {dom}", {})

    return _res(
        "microsoft_entra_tenant_passive",
        "ok",
        f"Entra ID Tenant {tenant_id or 'detected'} · Region={region_scope or 'Global'} · Namespace={ns_type or 'Managed'}",
        {
            "domain": dom,
            "entra_tenant_uuid": tenant_id,
            "tenant_region_scope": region_scope,
            "cloud_instance": cloud_instance,
            "namespace_type": ns_type,
            "federation_brand_name": fed_brand,
            "federated_idp_auth_url": auth_url,
        },
        pivots,
    )

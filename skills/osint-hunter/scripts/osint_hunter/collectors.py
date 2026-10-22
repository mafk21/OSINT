"""Parallel Passive OSINT Collector Modules (Python 3 stdlib, zero external deps)."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .classify import EMAIL_RE, NOISE_DOMAINS
from .offline_intel import (
    INTEL_TABLES,
    analyze_local_file,
    decode_aircraft_hex,
    decode_crypto_address,
    decode_ip_offline,
    decode_jwt,
    decode_mac_bssid,
    decode_phone,
    decode_vessel_identifier,
    decode_vin,
    parse_pgp_armored_keys,
)

USER_AGENT = "OSINT-Monster-Hunter/2026.10 (Passive-Research; +https://github.com/mafk21/OSINT)"
DEFAULT_TIMEOUT = 5.5

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "proton.me", "protonmail.com", "protonmail.ch", "tutanota.com", "live.com", "aol.com",
    "users.noreply.github.com",
}


def _http_get(url: str, headers: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, str, str | None]:
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(350_000).decode("utf-8", errors="replace")
            return status, body, None
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(32_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return exc.code, body, f"HTTP {exc.code}"
    except Exception as exc:
        return 0, "", str(exc)


def _http_json(url: str, headers: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, object, str | None]:
    status, body, err = _http_get(url, headers=headers, timeout=timeout)
    if status == 200 and body:
        try:
            return status, json.loads(body), None
        except Exception as exc:
            return status, None, f"Invalid JSON: {exc}"
    return status, None, err


def _res(module: str, status: str, summary: str, data: dict | list, pivots: list[dict] | None = None) -> dict:
    return {
        "module": module,
        "status": status,  # "ok" | "not_found" | "restricted_or_offline"
        "summary": summary,
        "data": data,
        "pivots": pivots or [],
    }


def _clean_email_pivots(emails: set[str] | list[str]) -> list[dict]:
    pivots: list[dict] = []
    for em in sorted({e.lower().strip() for e in emails}):
        if not em or "noreply.github.com" in em or em.endswith(".invalid") or "example." in em:
            continue
        pivots.append({"type": "email", "value": em})
        dom = em.split("@", 1)[1]
        if dom not in FREEMAIL_DOMAINS and dom not in NOISE_DOMAINS:
            pivots.append({"type": "domain", "value": dom})
    return pivots


# ============================================================================
# USERNAME / DEVELOPER COLLECTORS
# ============================================================================

def collect_github_user(username: str) -> dict:
    u_enc = urllib.parse.quote(username)
    st, profile, err = _http_json(f"https://api.github.com/users/{u_enc}")
    if st == 404:
        return _res("github_user_osint", "not_found", f"No GitHub user '{username}'", {})
    if st != 200 or not isinstance(profile, dict):
        return _res("github_user_osint", "restricted_or_offline", f"GitHub API unavailable ({err})", {})

    pivots: list[dict] = []
    emails_found: set[str] = set()
    tz_offsets: set[str] = set()

    if profile.get("email"):
        emails_found.add(profile["email"])
    if profile.get("twitter_username"):
        pivots.append({"type": "username", "value": profile["twitter_username"]})
    blog = (profile.get("blog") or "").strip()
    if blog:
        full_blog = blog if blog.startswith("http") else f"https://{blog}"
        pivots.append({"type": "url", "value": full_blog})
        host = (urllib.parse.urlparse(full_blog).hostname or "").lower().removeprefix("www.")
        if host and host not in NOISE_DOMAINS:
            pivots.append({"type": "domain", "value": host})

    # Fetch top updated repos & public events in parallel
    _, repos, _ = _http_json(f"https://api.github.com/users/{u_enc}/repos?sort=updated&per_page=8")
    _, events, _ = _http_json(f"https://api.github.com/users/{u_enc}/events/public?per_page=30")
    _, orgs, _ = _http_json(f"https://api.github.com/users/{u_enc}/orgs")

    repo_summaries = []
    first_owned_commit_patch_url = None
    if isinstance(repos, list):
        for r in repos[:8]:
            if not isinstance(r, dict):
                continue
            repo_summaries.append(
                {
                    "full_name": r.get("full_name"),
                    "stars": r.get("stargazers_count", 0),
                    "language": r.get("language"),
                    "description": (r.get("description") or "")[:140],
                    "pushed_at": r.get("pushed_at"),
                }
            )
            if not r.get("fork") and not first_owned_commit_patch_url and r.get("full_name"):
                first_owned_commit_patch_url = r["full_name"]

    target_name_low = (profile.get("name") or "").strip().lower()
    target_login_low = (profile.get("login") or username).strip().lower()
    collaborator_emails: set[str] = set()

    if isinstance(events, list):
        for ev in events:
            if isinstance(ev, dict) and ev.get("type") == "PushEvent":
                commits = (ev.get("payload") or {}).get("commits") or []
                for c in commits:
                    author = c.get("author") or {}
                    em = (author.get("email") or "").strip()
                    aname = (author.get("name") or "").strip().lower()
                    if not em or "noreply.github.com" in em:
                        continue
                    if (target_name_low and aname == target_name_low) or aname == target_login_low or target_login_low in em.lower():
                        emails_found.add(em)
                    else:
                        collaborator_emails.add(em)

    # Patch timezone + author email carving from latest non-fork repository commit!
    if first_owned_commit_patch_url:
        _, commits_list, _ = _http_json(f"https://api.github.com/repos/{first_owned_commit_patch_url}/commits?author={u_enc}&per_page=3")
        if isinstance(commits_list, list) and commits_list:
            sha = commits_list[0].get("sha")
            c_author = ((commits_list[0].get("commit") or {}).get("author") or {})
            if c_author.get("email"):
                emails_found.add(c_author["email"])
            if sha:
                pst, patch_txt, _ = _http_get(f"https://github.com/{first_owned_commit_patch_url}/commit/{sha}.patch")
                if pst == 200 and patch_txt:
                    for line in patch_txt.splitlines()[:10]:
                        if line.startswith("Date:"):
                            tz_m = re.search(r"([+-]\d{4})\b", line)
                            if tz_m:
                                tz_offsets.add(tz_m.group(1))
                        elif line.startswith("From:"):
                            for em in EMAIL_RE.findall(line):
                                emails_found.add(em)

    pivots.extend(_clean_email_pivots(emails_found))
    clean_emails = sorted(e for e in emails_found if "noreply.github.com" not in e)
    org_logins = [o.get("login") for o in (orgs if isinstance(orgs, list) else []) if isinstance(o, dict) and o.get("login")]

    data = {
        "login": profile.get("login"),
        "id": profile.get("id"),
        "type": profile.get("type"),
        "name": profile.get("name"),
        "company": profile.get("company"),
        "location": profile.get("location"),
        "bio": profile.get("bio"),
        "blog": blog or None,
        "twitter_username": profile.get("twitter_username"),
        "public_repos": profile.get("public_repos"),
        "followers": profile.get("followers"),
        "following": profile.get("following"),
        "created_at": profile.get("created_at"),
        "organizations": org_logins,
        "carved_commit_emails": clean_emails,
        "commit_timezone_offsets": sorted(tz_offsets),
        "recent_repositories": repo_summaries,
    }
    summary = (
        f"GitHub {profile.get('type')} '{profile.get('login')}' ({profile.get('name') or 'no display name'}) · "
        f"{profile.get('public_repos', 0)} repos · {len(clean_emails)} commit email(s) · TZ {sorted(tz_offsets) or ['n/a']}"
    )
    return _res("github_user_osint", "ok", summary, data, pivots)


def collect_github_keys(username: str) -> dict:
    u_enc = urllib.parse.quote(username)
    st_ssh, ssh_txt, _ = _http_get(f"https://github.com/{u_enc}.keys")
    st_gpg, gpg_txt, _ = _http_get(f"https://github.com/{u_enc}.gpg")

    if st_ssh not in (200,) and st_gpg not in (200,):
        return _res("github_ssh_gpg_keys", "not_found", "No public SSH/GPG keys found on GitHub", {})

    ssh_lines = [ln.strip() for ln in (ssh_txt or "").splitlines() if ln.strip() and not ln.startswith("#")]
    ssh_types = [ln.split()[0] for ln in ssh_lines if len(ln.split()) >= 2]
    has_hardware_fido_key = any(t.startswith("sk-") for t in ssh_types)

    pgp_info = parse_pgp_armored_keys(gpg_txt) if (st_gpg == 200 and "BEGIN PGP" in gpg_txt) else {
        "pgp_key_blocks_found": 0,
        "user_ids": [],
        "extracted_emails": [],
        "key_creation_timestamps_utc": [],
    }
    pivots = _clean_email_pivots(pgp_info["extracted_emails"])

    data = {
        "ssh_key_count": len(ssh_lines),
        "ssh_key_algorithms": ssh_types,
        "uses_hardware_security_key_sk": has_hardware_fido_key,
        "pgp": pgp_info,
    }
    summary = f"{len(ssh_lines)} SSH key(s) ({', '.join(set(ssh_types)) or 'none'}) · {pgp_info['pgp_key_blocks_found']} GPG key(s) · {len(pgp_info['user_ids'])} PGP UID(s)"
    return _res("github_ssh_gpg_keys", "ok", summary, data, pivots)


def collect_npm_maintainer(handle_or_query: str) -> dict:
    q = urllib.parse.quote(f"maintainer:{handle_or_query}")
    st, obj, err = _http_json(f"https://registry.npmjs.org/-/v1/search?text={q}&size=12")
    if st != 200 or not isinstance(obj, dict):
        return _res("npm_maintainer_osint", "restricted_or_offline", f"npm registry unreachable ({err})", {})

    objs = obj.get("objects") or []
    if not objs:
        return _res("npm_maintainer_osint", "not_found", f"0 npm packages maintained by '{handle_or_query}'", {"total": 0})

    emails: set[str] = set()
    packages = []
    co_maintainers: set[str] = set()
    h_low = handle_or_query.lower()
    for item in objs[:15]:
        pkg = item.get("package") or {}
        pub = pkg.get("publisher") or {}
        maintainers = pkg.get("maintainers") or []
        exact_match = (pub.get("username") or "").lower() == h_low or any(
            (m.get("username") or "").lower() == h_low for m in maintainers
        )
        if not exact_match:
            continue
        if (pub.get("username") or "").lower() == h_low and pub.get("email"):
            emails.add(pub["email"])
        for m in maintainers:
            if m.get("username") and m["username"].lower() != h_low:
                co_maintainers.add(m["username"])
            if m.get("email") and (m.get("username") or "").lower() == h_low:
                emails.add(m["email"])
        packages.append(
            {
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "date": pkg.get("date"),
                "publisher": pub,
                "repository": (pkg.get("links") or {}).get("repository"),
            }
        )

    if not packages:
        return _res("npm_maintainer_osint", "not_found", f"0 npm packages maintained by exact user '{handle_or_query}'", {"total": 0})

    pivots = _clean_email_pivots(emails)
    data = {
        "total_packages": obj.get("total", len(packages)),
        "publisher_emails": sorted(emails),
        "frequent_co_maintainers": sorted(co_maintainers)[:12],
        "sample_packages": packages,
    }
    return _res(
        "npm_maintainer_osint",
        "ok",
        f"Found {obj.get('total', len(packages))} npm package(s) · {len(emails)} maintainer email(s)",
        data,
        pivots,
    )


def collect_pypi_package(slug: str) -> dict:
    st, obj, _ = _http_json(f"https://pypi.org/pypi/{urllib.parse.quote(slug)}/json")
    if st != 200 or not isinstance(obj, dict):
        return _res("pypi_package_osint", "not_found", f"No exact PyPI package named '{slug}'", {})
    info = obj.get("info") or {}
    emails: set[str] = set()
    for field in ("author_email", "maintainer_email"):
        val = info.get(field) or ""
        for em in EMAIL_RE.findall(val):
            emails.add(em)
    pivots = _clean_email_pivots(emails)
    urls = info.get("project_urls") or {}
    for _, u in urls.items():
        if isinstance(u, str) and "github.com/" in u:
            m = re.search(r"github\.com/([a-zA-Z0-9-]+)/([a-zA-Z0-9._-]+)", u)
            if m:
                pivots.append({"type": "repo_code", "value": f"{m.group(1)}/{m.group(2).removesuffix('.git')}"})
    data = {
        "name": info.get("name"),
        "version": info.get("version"),
        "summary": info.get("summary"),
        "author": info.get("author"),
        "author_emails": sorted(emails),
        "home_page": info.get("home_page"),
        "project_urls": urls,
    }
    return _res("pypi_package_osint", "ok", f"PyPI package '{info.get('name')}' v{info.get('version')} by {info.get('author') or 'unknown'}", data, pivots)


def collect_username_matrix(username: str) -> dict:
    probes = INTEL_TABLES["username_probes"]
    found = []
    restricted = 0

    def _probe(p: dict):
        url = p["url"].replace("{u}", urllib.parse.quote(username))
        st, body, err = _http_get(url, timeout=4.5)
        if st == 0:
            return ("offline", p, url, err)
        if st != p.get("expect_status", 200):
            return ("miss", p, url, None)
        if p.get("not_body") and p["not_body"] in body:
            return ("miss", p, url, None)
        if p.get("must_body") and p["must_body"] not in body:
            return ("miss", p, url, None)
        return ("hit", p, url, None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        for state, p, url, _ in pool.map(_probe, probes):
            if state == "hit":
                found.append({"site": p["site"], "category": p["category"], "probe_url": url})
            elif state == "offline":
                restricted += 1

    status = "ok" if (found or restricted < len(probes)) else "restricted_or_offline"
    summary = f"Confirmed {len(found)} platform profile(s) across {len(probes) - restricted} reachable endpoints"
    if restricted:
        summary += f" ({restricted} external sites blocked by sandbox network policy)"
    return _res("username_platform_sweep", status, summary, {"hits": found, "offline_skipped": restricted})


# ============================================================================
# EMAIL COLLECTORS
# ============================================================================

def collect_email_osint(email: str) -> list[dict]:
    em = email.strip().lower()
    local, domain = em.split("@", 1)
    base_local = local.split("+", 1)[0]
    md5_h = hashlib.md5(em.encode("utf-8")).hexdigest()
    sha256_h = hashlib.sha256(em.encode("utf-8")).hexdigest()

    pivots_base = [{"type": "username", "value": base_local}]
    if domain not in FREEMAIL_DOMAINS and domain not in NOISE_DOMAINS:
        pivots_base.append({"type": "domain", "value": domain})

    results = [
        _res(
            "email_forensic_decomposition",
            "ok",
            f"Local handle '{base_local}' on '{domain}' · MD5/SHA256 Gravatar hashes computed",
            {
                "email": em,
                "local_part": local,
                "canonical_handle": base_local,
                "domain": domain,
                "is_freemail_provider": domain in FREEMAIL_DOMAINS,
                "gravatar_md5": md5_h,
                "gravatar_sha256": sha256_h,
                "avatar_direct_url": f"https://www.gravatar.com/avatar/{md5_h}?d=404&s=512",
            },
            pivots_base,
        )
    ]

    # GitHub user & commit search by email (works live on api.github.com!)
    q_enc = urllib.parse.quote(f"{em} in:email")
    st_u, gh_u, _ = _http_json(f"https://api.github.com/search/users?q={q_enc}")
    st_c, gh_c, _ = _http_json(
        f"https://api.github.com/search/commits?q={urllib.parse.quote('author-email:' + em)}&per_page=5",
        headers={"Accept": "application/vnd.github+json"},
    )
    gh_pivots = []
    matched_logins = []
    commit_repos = []
    if st_u == 200 and isinstance(gh_u, dict):
        for item in (gh_u.get("items") or [])[:5]:
            if item.get("login"):
                matched_logins.append(item["login"])
                gh_pivots.append({"type": "username", "value": item["login"]})
    if st_c == 200 and isinstance(gh_c, dict):
        for item in (gh_c.get("items") or [])[:5]:
            author_obj = item.get("author") or {}
            if author_obj.get("login") and author_obj["login"] not in matched_logins:
                matched_logins.append(author_obj["login"])
                gh_pivots.append({"type": "username", "value": author_obj["login"]})
            repo_obj = item.get("repository") or {}
            if repo_obj.get("full_name"):
                commit_repos.append(repo_obj["full_name"])
    if st_u == 200 or st_c == 200:
        results.append(
            _res(
                "github_email_attribution",
                "ok" if (matched_logins or commit_repos) else "not_found",
                f"GitHub email search matched {len(matched_logins)} account(s) & {len(commit_repos)} repo(s)",
                {"github_accounts": matched_logins, "commit_repositories": sorted(set(commit_repos))},
                gh_pivots,
            )
        )

    # npm search by email
    st_npm, npm_obj, _ = _http_json(f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(em)}&size=8")
    if st_npm == 200 and isinstance(npm_obj, dict):
        pkgs = []
        npm_users: set[str] = set()
        for it in npm_obj.get("objects") or []:
            p = it.get("package") or {}
            pub = p.get("publisher") or {}
            if pub.get("email", "").lower() == em:
                pkgs.append(p.get("name"))
                if pub.get("username"):
                    npm_users.add(pub["username"])
        results.append(
            _res(
                "npm_email_attribution",
                "ok" if pkgs else "not_found",
                f"npm email attribution matched {len(pkgs)} package(s) & {len(npm_users)} handle(s)",
                {"packages": pkgs, "npm_usernames": sorted(npm_users)},
                [{"type": "username", "value": u} for u in sorted(npm_users)],
            )
        )

    # Gravatar JSON, OpenPGP VKS & Proton HKP (works on unrestricted internet)
    st_grav, grav_obj, _ = _http_json(f"https://en.gravatar.com/{md5_h}.json")
    if st_grav == 200 and isinstance(grav_obj, dict):
        entries = grav_obj.get("entry") or []
        e0 = entries[0] if entries else {}
        results.append(
            _res(
                "gravatar_profile",
                "ok",
                f"Gravatar profile found: {e0.get('displayName') or e0.get('preferredUsername')}",
                e0,
                [{"type": "username", "value": e0["preferredUsername"]}] if e0.get("preferredUsername") else [],
            )
        )

    st_p, p_txt, _ = _http_get(f"https://api.protonmail.ch/pks/lookup?op=index&search={urllib.parse.quote(em)}")
    if st_p == 200 and "pub:" in p_txt:
        results.append(_res("proton_hkp_keyserver", "ok", "Active ProtonMail / PGP public key indexed", {"raw_index": p_txt[:600]}))

    return results


# ============================================================================
# DOMAIN & IP COLLECTORS
# ============================================================================

def collect_domain_osint(domain: str) -> list[dict]:
    d = domain.strip().lower().removeprefix("www.")
    results: list[dict] = []

    def _doh():
        records = {}
        ip_pivots = []
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            st, obj, _ = _http_json(
                f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(d)}&type={rtype}",
                headers={"Accept": "application/dns-json"},
            )
            if st == 200 and isinstance(obj, dict) and obj.get("Answer"):
                vals = [a.get("data") for a in obj["Answer"] if a.get("data")]
                records[rtype] = vals
                if rtype in ("A", "AAAA"):
                    for v in vals[:4]:
                        ip_pivots.append({"type": "ip", "value": v})
        if not records:
            return _res("dns_over_https", "restricted_or_offline", "DoH endpoint unreachable in current network", {})
        return _res("dns_over_https", "ok", f"Resolved DNS records ({', '.join(records.keys())})", records, ip_pivots)

    def _crtsh():
        st, arr, err = _http_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(d)}&output=json", timeout=7.0)
        if st != 200 or not isinstance(arr, list):
            return _res("crtsh_certificate_transparency", "restricted_or_offline", f"crt.sh unreachable ({err})", {})
        subs: set[str] = set()
        issuers: set[str] = set()
        for row in arr[:400]:
            if isinstance(row, dict):
                if row.get("issuer_name"):
                    issuers.add(row["issuer_name"][:80])
                for nv in (row.get("name_value") or "").splitlines():
                    nv = nv.strip().lower().removeprefix("*.")
                    if nv.endswith(d):
                        subs.add(nv)
        return _res(
            "crtsh_certificate_transparency",
            "ok",
            f"Discovered {len(subs)} unique CT hostname(s) across {len(issuers)} CA issuer(s)",
            {"subdomains": sorted(subs)[:60], "total_subdomains": len(subs), "issuers": sorted(issuers)[:10]},
        )

    def _rdap():
        st, obj, err = _http_json(f"https://rdap.org/domain/{urllib.parse.quote(d)}")
        if st != 200 or not isinstance(obj, dict):
            return _res("rdap_domain_registry", "restricted_or_offline", f"RDAP unreachable ({err})", {})
        events = {ev.get("eventAction"): ev.get("eventDate") for ev in (obj.get("events") or []) if isinstance(ev, dict)}
        ns = [n.get("ldhName") for n in (obj.get("nameservers") or []) if isinstance(n, dict) and n.get("ldhName")]
        return _res(
            "rdap_domain_registry",
            "ok",
            f"RDAP status: {', '.join(obj.get('status') or [])[:80]} · Events: {events}",
            {"handle": obj.get("handle"), "status": obj.get("status"), "events": events, "nameservers": ns},
        )

    def _wayback():
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(d)}/*&output=json&fl=timestamp,original,mimetype,statuscode&collapse=urlkey&limit=40"
        st, arr, err = _http_json(url, timeout=6.5)
        if st != 200 or not isinstance(arr, list):
            return _res("wayback_cdx_archive", "restricted_or_offline", f"Wayback CDX unreachable ({err})", {})
        rows = arr[1:] if len(arr) > 1 else []
        urls = [r[1] for r in rows if len(r) >= 2]
        return _res("wayback_cdx_archive", "ok", f"Sampled {len(urls)} archived URL endpoints from Wayback CDX", {"sample_urls": urls[:25]})

    def _gh_domain():
        q = urllib.parse.quote(f'"{d}"')
        st, obj, err = _http_json(f"https://api.github.com/search/repositories?q={q}&sort=stars&per_page=8")
        if st != 200 or not isinstance(obj, dict):
            return _res("github_domain_footprints", "restricted_or_offline", f"GitHub search unavailable ({err})", {})
        repos = []
        pivots = []
        owners_seen: set[str] = set()
        for it in (obj.get("items") or [])[:8]:
            owner = (it.get("owner") or {}).get("login")
            repos.append({"full_name": it.get("full_name"), "stars": it.get("stargazers_count"), "description": (it.get("description") or "")[:120]})
            if owner and owner not in owners_seen and it.get("homepage") and d in (it.get("homepage") or "").lower():
                owners_seen.add(owner)
                pivots.append({"type": "username", "value": owner})
        return _res(
            "github_domain_footprints",
            "ok" if repos else "not_found",
            f"Found {obj.get('total_count', 0)} GitHub repository mention(s) for '{d}'",
            {"total_count": obj.get("total_count", 0), "top_repositories": repos},
            pivots,
        )

    def _npm_domain():
        st, obj, err = _http_json(f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(d)}&size=10")
        if st != 200 or not isinstance(obj, dict):
            return _res("npm_domain_ecosystems", "restricted_or_offline", f"npm unreachable ({err})", {})
        pkgs = []
        emails: set[str] = set()
        for it in obj.get("objects") or []:
            p = it.get("package") or {}
            pub = p.get("publisher") or {}
            em = (pub.get("email") or "").lower()
            if em.endswith("@" + d):
                emails.add(em)
            pkgs.append({"name": p.get("name"), "version": p.get("version"), "publisher_email": em or None})
        return _res(
            "npm_domain_ecosystems",
            "ok" if pkgs else "not_found",
            f"Found {obj.get('total', 0)} npm package reference(s) & {len(emails)} @{d} corporate email(s)",
            {"total": obj.get("total", 0), "corporate_emails": sorted(emails), "packages": pkgs[:8]},
            [{"type": "email", "value": e} for e in sorted(emails)[:5]],
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(fn) for fn in (_gh_domain, _npm_domain, _doh, _crtsh, _rdap, _wayback)]
        for f in futs:
            results.append(f.result())
    return results


def collect_ip_osint(ip_str: str) -> list[dict]:
    offline = decode_ip_offline(ip_str)
    pivots0 = []
    if offline.get("embedded_eui64_mac"):
        pivots0.append({"type": "mac_bssid", "value": offline["embedded_eui64_mac"]})
    results = [_res("ip_offline_forensics", "ok", f"{offline['version']} · Global={offline['is_global_routable']} · PTR={offline['reverse_ptr_name']}", offline, pivots0)]

    if not offline["is_global_routable"]:
        return results

    # Shodan InternetDB (keyless!)
    st_s, shodan_obj, err_s = _http_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip_str)}")
    if st_s == 200 and isinstance(shodan_obj, dict):
        pivots_s = [{"type": "domain", "value": h} for h in (shodan_obj.get("hostnames") or [])[:5] if h not in NOISE_DOMAINS]
        results.append(
            _res(
                "shodan_internetdb",
                "ok",
                f"Ports: {shodan_obj.get('ports')} · Vulns: {len(shodan_obj.get('vulns') or [])} · Tags: {shodan_obj.get('tags')}",
                shodan_obj,
                pivots_s,
            )
        )
    elif st_s == 0:
        results.append(_res("shodan_internetdb", "restricted_or_offline", f"InternetDB unreachable in sandbox ({err_s})", {}))

    # RIPEstat Network Info
    st_r, ripe_obj, err_r = _http_json(f"https://stat.ripe.net/data/network-info/data.json?resource={urllib.parse.quote(ip_str)}")
    if st_r == 200 and isinstance(ripe_obj, dict):
        d = ripe_obj.get("data") or {}
        asns = d.get("asns") or []
        pivots_r = [{"type": "asn", "value": f"AS{a}"} for a in asns[:3]]
        results.append(_res("ripestat_bgp_prefix", "ok", f"Prefix {d.get('prefix')} · ASNs {asns}", d, pivots_r))

    # Tor Onionoo check
    st_t, tor_obj, _ = _http_json(f"https://onionoo.torproject.org/details?search={urllib.parse.quote(ip_str)}")
    if st_t == 200 and isinstance(tor_obj, dict):
        relays = tor_obj.get("relays") or []
        if relays:
            r0 = relays[0]
            results.append(
                _res(
                    "tor_relay_attribution",
                    "ok",
                    f"CONFIRMED Tor Relay '{r0.get('nickname')}' · Flags: {r0.get('flags')}",
                    {"nickname": r0.get("nickname"), "flags": r0.get("flags"), "contact": r0.get("contact"), "as_name": r0.get("as_name")},
                )
            )
    return results


# ============================================================================
# REPO, CRYPTO, TRANSPORT, HARDWARE, FILE & ENTITY COLLECTORS
# ============================================================================

def collect_repo_osint(repo_slug: str) -> list[dict]:
    st, repo, err = _http_json(f"https://api.github.com/repos/{repo_slug}")
    if st != 200 or not isinstance(repo, dict):
        return [_res("github_repo_forensics", "not_found" if st == 404 else "restricted_or_offline", f"Repo '{repo_slug}' lookup failed ({err})", {})]

    _, commits, _ = _http_json(f"https://api.github.com/repos/{repo_slug}/commits?per_page=10")
    _, contribs, _ = _http_json(f"https://api.github.com/repos/{repo_slug}/contributors?per_page=10")

    emails: set[str] = set()
    handles: list[str] = []
    if isinstance(commits, list):
        for c in commits:
            ca = ((c.get("commit") or {}).get("author") or {})
            if ca.get("email"):
                emails.add(ca["email"])
    if isinstance(contribs, list):
        for ct in contribs[:8]:
            if isinstance(ct, dict) and ct.get("login"):
                handles.append(ct["login"])

    pivots = _clean_email_pivots(emails) + [{"type": "username", "value": h} for h in handles[:4]]
    data = {
        "full_name": repo.get("full_name"),
        "description": repo.get("description"),
        "stars": repo.get("stargazers_count"),
        "forks": repo.get("forks_count"),
        "language": repo.get("language"),
        "created_at": repo.get("created_at"),
        "pushed_at": repo.get("pushed_at"),
        "homepage": repo.get("homepage"),
        "topics": repo.get("topics"),
        "top_contributors": handles,
        "commit_author_emails": sorted(e for e in emails if "noreply.github.com" not in e),
    }
    return [_res("github_repo_forensics", "ok", f"Repo {repo.get('full_name')} ({repo.get('stargazers_count')}★) · {len(handles)} top contributors", data, pivots)]


def collect_crypto_osint(addr: str) -> list[dict]:
    dec = decode_crypto_address(addr)
    results = [_res("crypto_address_classifier", "ok", f"{dec['ecosystem']}", dec)]

    # Off-chain code attribution on GitHub!
    st_gh, gh_obj, _ = _http_json(f"https://api.github.com/search/repositories?q={urllib.parse.quote(addr)}&per_page=5")
    if st_gh == 200 and isinstance(gh_obj, dict) and gh_obj.get("total_count", 0) > 0:
        repos = [it.get("full_name") for it in (gh_obj.get("items") or []) if it.get("full_name")]
        results.append(
            _res(
                "github_wallet_attribution",
                "ok",
                f"Wallet referenced in {gh_obj['total_count']} public GitHub repo(s)!",
                {"repositories": repos},
                [{"type": "repo_code", "value": r} for r in repos[:3]],
            )
        )

    if addr.startswith(("1", "3", "bc1")):
        st_m, mem, _ = _http_json(f"https://mempool.space/api/address/{urllib.parse.quote(addr)}")
        if st_m == 200 and isinstance(mem, dict):
            cs = mem.get("chain_stats") or {}
            funded = cs.get("funded_txo_sum", 0) / 1e8
            spent = cs.get("spent_txo_sum", 0) / 1e8
            results.append(
                _res(
                    "bitcoin_mempool_live",
                    "ok",
                    f"BTC Funded: {funded:.6f} BTC · Balance: {(funded - spent):.6f} BTC · Txs: {cs.get('tx_count', 0)}",
                    mem,
                )
            )
    elif addr.startswith("0x"):
        st_dx, dx, _ = _http_json(f"https://api.dexscreener.com/latest/dex/search?q={urllib.parse.quote(addr)}")
        if st_dx == 200 and isinstance(dx, dict) and dx.get("pairs"):
            p0 = dx["pairs"][0]
            results.append(
                _res(
                    "dexscreener_liquidity",
                    "ok",
                    f"Matched DEX token/pair on {p0.get('chainId')}: {(p0.get('baseToken') or {}).get('symbol')}",
                    {"top_pair": p0},
                )
            )
    return results


def collect_for_selector(sel_type: str, value: str) -> list[dict]:
    """Dispatch all passive collectors registered for a given selector type."""
    if sel_type == "username":
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            f_gh = pool.submit(collect_github_user, value)
            f_keys = pool.submit(collect_github_keys, value)
            f_npm = pool.submit(collect_npm_maintainer, value)
            f_pypi = pool.submit(collect_pypi_package, value)
            f_mat = pool.submit(collect_username_matrix, value)
            return [f_gh.result(), f_keys.result(), f_npm.result(), f_pypi.result(), f_mat.result()]

    if sel_type == "email":
        return collect_email_osint(value)

    if sel_type == "domain":
        return collect_domain_osint(value)

    if sel_type == "ip":
        return collect_ip_osint(value)

    if sel_type == "asn":
        asn_clean = value.upper()
        st, obj, err = _http_json(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_clean}")
        if st == 200 and isinstance(obj, dict):
            pfxs = [p.get("prefix") for p in ((obj.get("data") or {}).get("prefixes") or [])[:30]]
            return [_res("ripestat_asn_prefixes", "ok", f"{asn_clean} announces {len(pfxs)}+ prefixes", {"prefixes": pfxs})]
        return [_res("asn_lookup", "restricted_or_offline", f"RIPEstat unreachable ({err})", {"asn": asn_clean})]

    if sel_type == "repo_code":
        return collect_repo_osint(value)

    if sel_type == "crypto_address":
        return collect_crypto_osint(value)

    if sel_type == "phone":
        dec = decode_phone(value)
        return [_res("phone_itu_e164_decoder", "ok", f"{dec['e164']} -> {dec['country']} ({dec.get('carrier_or_region_hint') or 'Mobile/Fixed'})", dec)]

    if sel_type == "aircraft_hex":
        dec = decode_aircraft_hex(value)
        out = [_res("icao24_hex_decoder", "ok", f"ICAO {dec['icao24_hex']} -> {dec['registration_country']} (Military/Gov={dec['is_military_or_gov_block']})", dec)]
        st, adsb, _ = _http_json(f"https://api.adsbdb.com/v0/aircraft/{dec['icao24_hex']}")
        if st == 200 and isinstance(adsb, dict):
            ac = (adsb.get("response") or {}).get("aircraft") or {}
            if ac:
                out.append(_res("adsbdb_airframe_registry", "ok", f"{ac.get('manufacturer')} {ac.get('type')} · Tail {ac.get('registration')} · Owner: {ac.get('registered_owner')}", ac))
        return out

    if sel_type == "vessel_imo":
        dec = decode_vessel_identifier(value)
        label = dec.get("flag_state") or f"ValidChecksum={dec.get('imo_checksum_valid')}"
        return [_res("maritime_imo_mmsi_decoder", "ok", f"{dec['identifier_type']} decoded -> {label}", dec)]

    if sel_type == "vin":
        dec = decode_vin(value)
        out = [_res("iso3779_vin_decoder", "ok", f"{dec['manufacturer']} · Est. Year {dec['model_year_estimate']} · CheckDigit={dec['north_america_check_digit_valid']}", dec)]
        st, nhtsa, _ = _http_json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{dec['vin']}?format=json")
        if st == 200 and isinstance(nhtsa, dict) and nhtsa.get("Results"):
            r0 = {k: v for k, v in nhtsa["Results"][0].items() if v}
            out.append(_res("nhtsa_vpic_factory_specs", "ok", f"{r0.get('ModelYear')} {r0.get('Make')} {r0.get('Model')} ({r0.get('BodyClass')})", r0))
        return out

    if sel_type == "mac_bssid":
        dec = decode_mac_bssid(value)
        return [_res("ieee_oui_bssid_forensics", "ok", f"{dec['bssid_mac']} -> {dec['vendor']}", dec)]

    if sel_type == "coordinates":
        lat_s, lon_s = value.split(",", 1)
        lat, lon = float(lat_s), float(lon_s)
        maps = {
            "lat": lat,
            "lon": lon,
            "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon}",
            "copernicus_sentinel2": f"https://browser.dataspace.copernicus.eu/?zoom=15&lat={lat}&lng={lon}",
            "suncalc_shadow": f"https://www.suncalc.org/#/{lat},{lon},17",
            "overpass_turbo": f"https://overpass-turbo.eu/?lat={lat}&lon={lon}&zoom=16",
        }
        out = [_res("geoint_coordinate_pivot_links", "ok", f"WGS84 ({lat:.6f}, {lon:.6f}) satellite & chronolocation links generated", maps)]
        st, nom, _ = _http_json(f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=jsonv2")
        if st == 200 and isinstance(nom, dict) and nom.get("display_name"):
            out.append(_res("osm_nominatim_reverse_geocode", "ok", f"Address: {nom['display_name']}", nom))
        return out

    if sel_type == "file_hash":
        out = []
        st, circl, err = _http_json(f"https://hashlookup.circl.lu/lookup/sha256/{value}")
        if st == 200 and isinstance(circl, dict):
            out.append(_res("circl_nsrl_hashlookup", "ok", f"Known NSRL file: {circl.get('FileName')}", circl))
        else:
            out.append(_res("file_hash_triage", "not_found" if st == 404 else "restricted_or_offline", f"Hash {value[:16]}... triage ({err or 'not in NSRL known-good DB'})", {"hash": value}))
        return out

    if sel_type == "jwt_token":
        dec = decode_jwt(value)
        return [_res("jwt_forensic_decoder", "ok", f"JWT alg={dec.get('header', {}).get('alg')} · sub={dec.get('payload', {}).get('sub')}", dec, dec.get("extracted_pivots", []))]

    if sel_type == "local_file":
        dec = analyze_local_file(value)
        return [
            _res(
                "local_binary_forensics",
                "ok",
                f"{dec['detected_format']} ({dec['size_bytes']} B) · SHA256={dec['hashes']['sha256'][:16]}...",
                dec,
                dec["discovered_pivots"],
            )
        ]

    if sel_type in ("company", "person_name", "keyword"):
        q_enc = urllib.parse.quote(value)
        out = []
        st_u, gh_u, _ = _http_json(f"https://api.github.com/search/users?q={q_enc}&per_page=6")
        pivots = []
        if st_u == 200 and isinstance(gh_u, dict) and gh_u.get("items"):
            accts = [{"login": i.get("login"), "type": i.get("type"), "url": i.get("html_url")} for i in gh_u["items"][:6]]
            if accts and accts[0].get("login"):
                pivots.append({"type": "username", "value": accts[0]["login"]})
            out.append(_res("github_entity_search", "ok", f"Matched {gh_u.get('total_count', 0)} GitHub user/org profile(s) for '{value}'", {"accounts": accts}, pivots))

        if sel_type == "company":
            st_l, gleif, _ = _http_json(f"https://api.gleif.org/api/v1/lei-records?filter%5Bentity.legalName%5D={q_enc}&page%5Bsize%5D=5")
            if st_l == 200 and isinstance(gleif, dict) and gleif.get("data"):
                recs = []
                for r in gleif["data"][:5]:
                    ent = ((r.get("attributes") or {}).get("entity") or {})
                    recs.append({"lei": r.get("id"), "legal_name": (ent.get("legalName") or {}).get("name"), "jurisdiction": ent.get("jurisdiction")})
                out.append(_res("gleif_corporate_lei", "ok", f"Matched {len(recs)} global LEI corporate registration(s)", {"lei_records": recs}))
        return out or [_res("entity_seed_indexed", "ok", f"Prepared dorks & 540-tool arsenal pivots for '{value}'", {"query": value})]

    if sel_type in ("url", "onion_url"):
        parsed = urllib.parse.urlparse(value if "://" in value else f"http://{value}")
        return [
            _res(
                "url_structural_decomposition",
                "ok",
                f"Host={(parsed.hostname or '')} · Path={parsed.path or '/'}",
                {
                    "url": value,
                    "scheme": parsed.scheme,
                    "hostname": parsed.hostname,
                    "path": parsed.path,
                    "query_params": dict(urllib.parse.parse_qsl(parsed.query)),
                    "is_tor_onion": (parsed.hostname or "").endswith(".onion"),
                },
            )
        ]

    return []

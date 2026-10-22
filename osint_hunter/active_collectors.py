"""Active OSINT Reconnaissance Collectors (Direct Target Network Probing).

IMPORTANT: Functions in this module send direct TCP, TLS, DNS, and HTTP/HTTPS
requests to target infrastructure. They MUST ONLY be invoked by `engine.py`
after `approval.verify_and_consume_approval()` succeeds!
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import http.client
import json
import re
import socket
import ssl
import urllib.parse
from html.parser import HTMLParser

from .classify import DOMAIN_RE, EMAIL_RE, NOISE_DOMAINS

ACTIVE_USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Active-Inspector/2026.10)"
SOCKET_TIMEOUT = 4.0


def mmh3_32_signed(data: bytes, seed: int = 0) -> int:
    """Pure-Python 32-bit x86 MurmurHash3 signed integer (exact Shodan favicon hash spec)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x3

    for i in range(0, rounded_end, 4):
        k1 = (
            data[i]
            | (data[i + 1] << 8)
            | (data[i + 2] << 16)
            | (data[i + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x3
    if tail == 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if (h1 & 0x80000000) else h1


def shodan_favicon_mmh3(raw_icon_bytes: bytes) -> int:
    """Compute Shodan-compatible `http.favicon.hash` (RFC 2045 76-col base64 with newlines)."""
    b64_bytes = base64.encodebytes(raw_icon_bytes)
    return mmh3_32_signed(b64_bytes, seed=0)


def _res(module: str, status: str, summary: str, data: dict | list, pivots: list[dict] | None = None) -> dict:
    return {
        "module": module,
        "opsec": "Active",
        "status": status,
        "summary": summary,
        "data": data,
        "pivots": pivots or [],
    }


def _extract_host(selector_type: str, value: str) -> str:
    if selector_type == "url":
        return (urllib.parse.urlparse(value).hostname or "").lower()
    if selector_type == "email" and "@" in value:
        return value.split("@", 1)[1].lower()
    return value.strip().lower()


# ============================================================================
# 1. LIVE DNS & REVERSE PTR RESOLVER
# ============================================================================

def active_dns_live_resolver(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    if not host:
        return _res("active_dns_live_resolver", "not_found", "No resolvable hostname", {})

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as exc:
        return _res("active_dns_live_resolver", "restricted_or_offline", f"Live DNS lookup failed for '{host}' ({exc})", {"host": host})

    ips = sorted({item[4][0] for item in infos if item[4]})
    ptr_map: dict[str, str | None] = {}
    pivots: list[dict] = []
    for ip in ips[:6]:
        if selector_type != "ip":
            pivots.append({"type": "ip", "value": ip})
        try:
            ptr_host, _, _ = socket.gethostbyaddr(ip)
            ptr_map[ip] = ptr_host
        except Exception:
            ptr_map[ip] = None

    return _res(
        "active_dns_live_resolver",
        "ok",
        f"Live DNS resolved '{host}' -> {len(ips)} IP(s) · PTRs: {[v for v in ptr_map.values() if v][:3]}",
        {"target_host": host, "resolved_ips": ips, "reverse_ptr": ptr_map},
        pivots,
    )


# ============================================================================
# 2. LIVE TLS HANDSHAKE & X.509 SAN CERTIFICATE INSPECTOR
# ============================================================================

def active_tls_cert_inspector(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    port = 443
    if selector_type == "url":
        p = urllib.parse.urlparse(value)
        if p.port:
            port = p.port

    ctx = ssl.create_default_context()
    cert_dict = {}
    der_bytes = b""
    tls_version = None
    cipher_info = None
    verified = True

    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert_dict = tls_sock.getpeercert() or {}
                der_bytes = tls_sock.getpeercert(binary_form=True) or b""
                tls_version = tls_sock.version()
                cipher_info = tls_sock.cipher()
    except ssl.SSLCertVerificationError:
        # Fallback unverified handshake to still capture self-signed/expired cert DER thumbprint!
        verified = False
        ctx_unv = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as raw_sock:
                with ctx_unv.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    der_bytes = tls_sock.getpeercert(binary_form=True) or b""
                    tls_version = tls_sock.version()
                    cipher_info = tls_sock.cipher()
        except Exception as exc:
            return _res("active_tls_cert_inspector", "restricted_or_offline", f"TLS handshake failed ({exc})", {"host": host})
    except Exception as exc:
        return _res("active_tls_cert_inspector", "restricted_or_offline", f"Direct TCP/TLS to {host}:{port} unreachable ({exc})", {"host": host})

    sha256_fp = hashlib.sha256(der_bytes).hexdigest() if der_bytes else None
    sans = []
    pivots = []
    for k, v in cert_dict.get("subjectAltName", ()):
        if k == "DNS":
            clean_san = v.lower().removeprefix("*.")
            sans.append(v)
            if clean_san != host and clean_san not in NOISE_DOMAINS:
                pivots.append({"type": "domain", "value": clean_san})

    subject = {k: v for tup in cert_dict.get("subject", ()) for k, v in tup}
    issuer = {k: v for tup in cert_dict.get("issuer", ()) for k, v in tup}

    data = {
        "host": host,
        "port": port,
        "ca_chain_verified": verified,
        "tls_version": tls_version,
        "cipher": cipher_info[0] if cipher_info else None,
        "cert_sha256_fingerprint": sha256_fp,
        "subject": subject,
        "issuer": issuer,
        "not_before": cert_dict.get("notBefore"),
        "not_after": cert_dict.get("notAfter"),
        "serial_number": cert_dict.get("serialNumber"),
        "subject_alt_names": sans[:40],
        "censys_cert_pivot": f"services.tls.certificates.leaf_data.fingerprint: {sha256_fp}" if sha256_fp else None,
    }
    return _res(
        "active_tls_cert_inspector",
        "ok",
        f"Live {tls_version} cert on {host}:{port} · Issuer={issuer.get('organizationName') or 'Self/Custom'} · {len(sans)} SAN(s) · SHA256={str(sha256_fp)[:16]}...",
        data,
        pivots[:8],
    )


# ============================================================================
# 3. LIVE HTTP REDIRECTS, SECURITY HEADERS, CSP & ANALYTICS TAG FINGERPRINTER
# ============================================================================

def _raw_http_fetch(url: str, max_hops: int = 5) -> tuple[list[dict], int, dict[str, str], bytes, str | None]:
    hops = []
    curr = url
    for _ in range(max_hops):
        p = urllib.parse.urlparse(curr)
        scheme = p.scheme or "https"
        host = p.hostname
        if not host:
            return hops, 0, {}, b"", "Invalid URL hostname"
        port = p.port or (443 if scheme == "https" else 80)
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")

        try:
            if scheme == "https":
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=SOCKET_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=SOCKET_TIMEOUT)
            conn.request("GET", path, headers={"User-Agent": ACTIVE_USER_AGENT, "Accept": "*/*", "Connection": "close"})
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read(250_000)
            status = resp.status
            conn.close()
        except Exception as exc:
            return hops, 0, {}, b"", str(exc)

        hops.append({"url": curr, "status": status, "server": hdrs.get("server"), "location": hdrs.get("location")})
        if status in (301, 302, 303, 307, 308) and hdrs.get("location"):
            curr = urllib.parse.urljoin(curr, hdrs["location"])
            continue
        return hops, status, hdrs, body, None

    return hops, hops[-1]["status"] if hops else 0, {}, b"", None


def active_http_fingerprint_and_headers(selector_type: str, value: str) -> dict:
    url = value if selector_type == "url" else f"https://{_extract_host(selector_type, value)}/"
    hops, status, hdrs, body_bytes, err = _raw_http_fetch(url)
    if status == 0:
        return _res("active_http_fingerprint_and_headers", "restricted_or_offline", f"Direct HTTP probe unreachable ({err})", {"url": url})

    html = body_bytes.decode("utf-8", errors="replace")
    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:140] if title_m else None

    # Extract analytics / tracking IDs for cross-domain ownership attribution!
    ga4_ids = sorted(set(re.findall(r"\bG-[A-Z0-9]{8,12}\b", html)))
    gtm_ids = sorted(set(re.findall(r"\bGTM-[A-Z0-9]{5,10}\b", html)))
    ua_ids = sorted(set(re.findall(r"\bUA-\d{4,10}-\d{1,4}\b", html)))
    adsense_ids = sorted(set(re.findall(r"\bpub-\d{14,18}\b", html)))

    # Parse domains referenced inside Content-Security-Policy!
    csp = hdrs.get("content-security-policy", "")
    csp_domains = sorted({d.lower() for d in DOMAIN_RE.findall(csp) if d.lower() not in NOISE_DOMAINS})[:25]

    pivots = []
    if hdrs.get("onion-location"):
        pivots.append({"type": "onion_url", "value": hdrs["onion-location"]})
    for mail in sorted(set(EMAIL_RE.findall(html)))[:5]:
        if not mail.endswith((".png", ".jpg", ".svg", ".webp")):
            pivots.append({"type": "email", "value": mail.lower()})

    interesting_headers = {
        k: hdrs[k]
        for k in (
            "server", "x-powered-by", "via", "cf-ray", "x-amz-cf-id", "x-vercel-id",
            "x-github-request-id", "strict-transport-security", "x-frame-options",
            "onion-location", "www-authenticate",
        )
        if k in hdrs
    }

    data = {
        "final_status": status,
        "redirect_chain": hops,
        "page_title": title,
        "fingerprint_headers": interesting_headers,
        "csp_whitelisted_domains": csp_domains,
        "analytics_and_ad_trackers": {
            "ga4": ga4_ids,
            "gtm": gtm_ids,
            "ua": ua_ids,
            "adsense": adsense_ids,
        },
    }
    return _res(
        "active_http_fingerprint_and_headers",
        "ok",
        f"HTTP {status} · Title='{title or 'n/a'}' · Server={hdrs.get('server') or 'hidden'} · Hops={len(hops)} · Trackers={len(ga4_ids)+len(gtm_ids)}",
        data,
        pivots,
    )


# ============================================================================
# 4. LIVE /robots.txt, /.well-known/security.txt & OPENID TENANT HARVESTER
# ============================================================================

def active_wellknown_and_robots_harvester(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    base = f"https://{host}"
    endpoints = {
        "robots_txt": "/robots.txt",
        "security_txt": "/.well-known/security.txt",
        "openid_config": "/.well-known/openid-configuration",
        "humans_txt": "/humans.txt",
    }

    collected: dict = {}
    pivots: list[dict] = []
    reachable = 0

    for key, path in endpoints.items():
        _, st, hdrs, raw, _ = _raw_http_fetch(base + path, max_hops=2)
        if st == 0:
            continue
        reachable += 1
        txt = raw.decode("utf-8", errors="replace")
        if st == 200 and "<html" not in txt[:300].lower():
            if key == "robots_txt":
                disallows = [ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.lower().startswith("disallow:")][:25]
                sitemaps = [ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.lower().startswith("sitemap:")][:10]
                collected["robots_txt"] = {"disallow_paths": disallows, "sitemaps": sitemaps}
            elif key == "security_txt":
                contacts = [ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.lower().startswith("contact:")]
                encryption = [ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.lower().startswith("encryption:")]
                collected["security_txt"] = {"contacts": contacts, "encryption_keys": encryption}
                for c in contacts:
                    for em in EMAIL_RE.findall(c):
                        pivots.append({"type": "email", "value": em.lower()})
            elif key == "openid_config":
                try:
                    oid = json.loads(txt)
                    collected["openid_configuration"] = {
                        "issuer": oid.get("issuer"),
                        "authorization_endpoint": oid.get("authorization_endpoint"),
                    }
                except Exception:
                    pass
            elif key == "humans_txt":
                collected["humans_txt_excerpt"] = txt[:500]

    if reachable == 0:
        return _res("active_wellknown_and_robots_harvester", "restricted_or_offline", f"Origin {base} unreachable from current network", {})
    return _res(
        "active_wellknown_and_robots_harvester",
        "ok" if collected else "not_found",
        f"Harvested {len(collected)} discovery manifest(s): {list(collected.keys())}",
        collected,
        pivots,
    )


# ============================================================================
# 5. LIVE /favicon.ico SHODAN MURMURHASH3 (mmh3) & SHA-256 EXTRACTOR
# ============================================================================

def active_favicon_hash_extractor(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    _, st, hdrs, raw, err = _raw_http_fetch(f"https://{host}/favicon.ico", max_hops=3)
    if st == 0:
        return _res("active_favicon_hash_extractor", "restricted_or_offline", f"Favicon fetch unreachable ({err})", {})
    if st != 200 or not raw or b"<html" in raw[:200].lower():
        return _res("active_favicon_hash_extractor", "not_found", f"No binary /favicon.ico returned (HTTP {st})", {})

    mmh3_val = shodan_favicon_mmh3(raw)
    sha256_val = hashlib.sha256(raw).hexdigest()
    md5_val = hashlib.md5(raw).hexdigest()

    data = {
        "favicon_bytes": len(raw),
        "content_type": hdrs.get("content-type"),
        "shodan_mmh3_hash": mmh3_val,
        "md5": md5_val,
        "sha256": sha256_val,
        "origin_unmask_dorks": {
            "shodan": f"http.favicon.hash:{mmh3_val}",
            "zoomeye": f"iconhash:\"{mmh3_val}\"",
            "censys": f"services.http.response.favicons.md5_hash: \"{md5_val}\"",
        },
    }
    return _res(
        "active_favicon_hash_extractor",
        "ok",
        f"Computed Shodan http.favicon.hash:{mmh3_val} ({len(raw)} bytes)",
        data,
    )


# ============================================================================
# 6. NON-INTRUSIVE TCP PORT & SERVICE BANNER PROBE
# ============================================================================

COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
]


def active_tcp_service_banner_probe(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)

    def _check_port(item: tuple[int, str]):
        port, proto = item
        try:
            with socket.create_connection((host, port), timeout=2.2) as s:
                s.settimeout(1.5)
                banner = ""
                if port in (21, 22, 25):
                    try:
                        banner = s.recv(160).decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass
                return {"port": port, "service": proto, "state": "open", "banner": banner or None}
        except ConnectionRefusedError:
            return {"port": port, "service": proto, "state": "closed"}
        except Exception as exc:
            return {"port": port, "service": proto, "state": "filtered_or_blocked", "detail": str(exc)[:60]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        results = list(pool.map(_check_port, COMMON_PORTS))

    open_ports = [r for r in results if r["state"] == "open"]
    all_blocked = all(r["state"] == "filtered_or_blocked" for r in results)
    if all_blocked:
        return _res("active_tcp_service_banner_probe", "restricted_or_offline", f"Direct TCP probes to {host} blocked by sandbox/firewall", {"host": host})

    return _res(
        "active_tcp_service_banner_probe",
        "ok",
        f"Open TCP ports on {host}: {[r['port'] for r in open_ports]} · Banners: {[r['banner'] for r in open_ports if r.get('banner')]}",
        {"host": host, "open_ports": open_ports},
    )


# ============================================================================
# 7. LIVE WEBPAGE OPENGRAPH, JSON-LD `sameAs` SOCIAL GRAPH & CONTACT HARVESTER
# ============================================================================

class _MetaAndJsonLdParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta: dict[str, str] = {}
        self.jsonld_blocks: list[str] = []
        self._in_ld = False
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "meta":
            key = ad.get("property") or ad.get("name")
            if key and ad.get("content"):
                self.meta[key.lower()] = ad["content"][:240]
        elif tag.lower() == "script" and "ld+json" in ad.get("type", "").lower():
            self._in_ld = True
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._in_ld:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_ld:
            self._in_ld = False
            self.jsonld_blocks.append("".join(self._buf))


def active_url_jsonld_opengraph(selector_type: str, value: str) -> dict:
    url = value if selector_type == "url" else f"https://{_extract_host(selector_type, value)}/"
    _, st, _, raw, err = _raw_http_fetch(url, max_hops=4)
    if st == 0:
        return _res("active_url_jsonld_opengraph", "restricted_or_offline", f"Live HTML fetch unreachable ({err})", {"url": url})

    parser = _MetaAndJsonLdParser()
    try:
        parser.feed(raw.decode("utf-8", errors="replace"))
    except Exception:
        pass

    same_as: list[str] = []
    for blk in parser.jsonld_blocks[:6]:
        try:
            obj = json.loads(blk)
            items = obj if isinstance(obj, list) else (obj.get("@graph") if isinstance(obj, dict) and isinstance(obj.get("@graph"), list) else [obj])
            for it in items:
                if isinstance(it, dict) and it.get("sameAs"):
                    sa = it["sameAs"]
                    same_as.extend(sa if isinstance(sa, list) else [sa])
        except Exception:
            pass

    pivots = [{"type": "url", "value": u} for u in same_as[:8] if isinstance(u, str) and u.startswith("http")]
    og_subset = {k: v for k, v in parser.meta.items() if k.startswith(("og:", "twitter:", "author", "generator"))}

    return _res(
        "active_url_jsonld_opengraph",
        "ok",
        f"Extracted {len(og_subset)} OpenGraph/meta tag(s) & {len(same_as)} JSON-LD sameAs social link(s)",
        {"meta_tags": og_subset, "schema_same_as_links": same_as[:20]},
        pivots,
    )


MODULE_DISPATCH = {
    "active_dns_live_resolver": active_dns_live_resolver,
    "active_tls_cert_inspector": active_tls_cert_inspector,
    "active_http_fingerprint_and_headers": active_http_fingerprint_and_headers,
    "active_wellknown_and_robots_harvester": active_wellknown_and_robots_harvester,
    "active_favicon_hash_extractor": active_favicon_hash_extractor,
    "active_tcp_service_banner_probe": active_tcp_service_banner_probe,
    "active_url_jsonld_opengraph": active_url_jsonld_opengraph,
}


def collect_active_for_selector(sel_type: str, value: str, enabled_modules: list[str]) -> list[dict]:
    """Run authorized Active OSINT modules applicable to `(sel_type, value)`."""
    from .approval import ACTIVE_MODULES_CATALOG

    applicable = [
        m
        for m in enabled_modules
        if m in MODULE_DISPATCH and sel_type in ACTIVE_MODULES_CATALOG[m]["applies_to"]
    ]
    if not applicable:
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(applicable)) as pool:
        futs = [pool.submit(MODULE_DISPATCH[m], sel_type, value) for m in applicable]
        return [f.result() for f in futs]

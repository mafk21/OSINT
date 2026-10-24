"""Active OSINT Reconnaissance Collectors (22 Direct Target Network Probing Modules).

IMPORTANT: Functions in this module send direct TCP, TLS, DNS, SMTP, SSH, and HTTP/HTTPS
requests to target infrastructure. They MUST ONLY be invoked by `engine.py`
after `approval.verify_and_consume_approval()` succeeds!
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import struct
import urllib.parse
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

from .classify import DOMAIN_RE, EMAIL_RE, NOISE_DOMAINS
from .web_search_intel import carve_webpage_intelligence

ACTIVE_USER_AGENT = "Mozilla/5.0 (compatible; OSINT-Active-Inspector/2026.10)"
SOCKET_TIMEOUT = 3.5


# ============================================================================
# SHARED CRYPTO / HASHING / HTTP / DNS WIRE HELPERS
# ============================================================================

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


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def _url_host(host: str) -> str:
    """Format a hostname or IPv4/IPv6 literal safely for RFC 3986 URLs."""
    h = (host or "").strip().strip("[]")
    if ":" in h:
        return f"[{h}]"
    return h


def _normalize_url_ipv6(url: str) -> str:
    """Repair bare unbracketed IPv6 literals inside URLs (e.g. https://2606:4700::1/path)."""
    m = re.match(r"^(https?://)([^/?#]+)(.*)$", (url or "").strip(), flags=re.IGNORECASE)
    if not m:
        return url
    scheme_pfx, authority, rest = m.groups()
    if not authority.startswith("[") and authority.count(":") >= 2:
        try:
            ipaddress.ip_address(authority)
            return f"{scheme_pfx}[{authority}]{rest}"
        except ValueError:
            pass
    return url


def _extract_host(selector_type: str, value: str) -> str:
    if selector_type == "url":
        try:
            return (urllib.parse.urlparse(_normalize_url_ipv6(value)).hostname or "").strip("[]").lower()
        except ValueError:
            return ""
    if selector_type == "email" and "@" in value:
        return value.split("@", 1)[1].strip("[]").lower()
    return value.strip().strip("[]").lower()


def _target_url(selector_type: str, value: str, scheme: str = "https", path: str = "/") -> str:
    if selector_type == "url":
        return _normalize_url_ipv6(value)
    host = _extract_host(selector_type, value)
    return f"{scheme}://{_url_host(host)}{path}"


def _raw_http_request(
    url: str,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    max_hops: int = 4,
    max_bytes: int = 250_000,
) -> tuple[list[dict], int, dict[str, str], bytes, str | None]:
    hops = []
    curr = _normalize_url_ipv6(url)
    req_headers = {"User-Agent": ACTIVE_USER_AGENT, "Accept": "*/*", "Connection": "close"}
    if extra_headers:
        req_headers.update(extra_headers)

    for _ in range(max_hops):
        curr = _normalize_url_ipv6(curr)
        try:
            p = urllib.parse.urlparse(curr)
            scheme = p.scheme or "https"
            host = p.hostname
            if not host:
                return hops, 0, {}, b"", "Invalid URL hostname"
            port = p.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            return hops, 0, {}, b"", f"Malformed URL ({exc})"
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")

        try:
            if scheme == "https":
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=SOCKET_TIMEOUT, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=SOCKET_TIMEOUT)
            conn.request(method, path, headers=req_headers)
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            body = b"" if method == "HEAD" else resp.read(max_bytes)
            status = resp.status
            conn.close()
        except Exception as exc:
            return hops, 0, {}, b"", str(exc)

        hops.append({"url": curr, "status": status, "server": hdrs.get("server"), "location": hdrs.get("location")})
        if method == "GET" and status in (301, 302, 303, 307, 308) and hdrs.get("location"):
            curr = urllib.parse.urljoin(curr, hdrs["location"])
            continue
        return hops, status, hdrs, body, None

    return hops, hops[-1]["status"] if hops else 0, {}, b"", None


def _doh_query(name: str, rrtype: str) -> list[dict]:
    """Query Google DNS-over-HTTPS JSON endpoint for NS/MX/CNAME/SRV lookups."""
    qurl = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={urllib.parse.quote(rrtype)}"
    _, st, _, body, _ = _raw_http_request(qurl, max_hops=2, max_bytes=65_536)
    if st != 200 or not body:
        return []
    try:
        return json.loads(body.decode("utf-8", errors="replace")).get("Answer") or []
    except Exception:
        return []


def _encode_dns_qname(domain: str) -> bytes:
    parts = [p for p in domain.strip(".").split(".") if p]
    return b"".join(bytes([len(p)]) + p.encode("ascii", errors="ignore") for p in parts) + b"\x00"


def _tcp_dns_query(ns_host: str, qname: str, qtype: int, qclass: int = 1) -> tuple[int, int, bytes]:
    """Send a single RFC 1035 TCP DNS query and return `(rcode, ancount, raw_payload)`."""
    header = struct.pack("!HHHHHH", 0x4F53, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_qname(qname) + struct.pack("!HH", qtype, qclass)
    pkt = header + question
    framed = struct.pack("!H", len(pkt)) + pkt
    with socket.create_connection((ns_host, 53), timeout=2.5) as s:
        s.settimeout(2.5)
        s.sendall(framed)
        len_bytes = s.recv(2)
        if len(len_bytes) < 2:
            return -1, 0, b""
        resp_len = struct.unpack("!H", len_bytes)[0]
        buf = b""
        while len(buf) < min(resp_len, 8192):
            chunk = s.recv(min(4096, resp_len - len(buf)))
            if not chunk:
                break
            buf += chunk
    if len(buf) < 12:
        return -1, 0, buf
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", buf[:12])
    rcode = flags & 0x000F
    return rcode, ancount, buf


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
# 2. AUTHORITATIVE DNS ZONE TRANSFER (AXFR) & CHAOS VERSION AUDIT
# ============================================================================

def active_dns_zone_transfer_axfr(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    parts = host.split(".")
    zone = ".".join(parts[-2:]) if len(parts) >= 2 else host

    ns_answers = _doh_query(zone, "NS")
    nameservers = sorted({a.get("data", "").rstrip(".").lower() for a in ns_answers if a.get("data")})[:4]
    if not nameservers:
        nameservers = [f"ns1.{zone}", f"ns2.{zone}"]

    checks = []
    vulnerable_axfr = []
    reachable = 0
    for ns in nameservers:
        entry: dict = {"nameserver": ns, "axfr_allowed": False, "version_bind": None}
        try:
            rcode, ancount, _ = _tcp_dns_query(ns, zone, qtype=252, qclass=1)  # AXFR = 252
            reachable += 1
            if rcode == 0 and ancount > 0:
                entry["axfr_allowed"] = True
                entry["axfr_records_preview_count"] = ancount
                vulnerable_axfr.append(ns)
            else:
                entry["axfr_rcode"] = rcode
            # CHAOS (class=3) TXT (type=16) version.bind check
            c_rcode, c_ancount, c_raw = _tcp_dns_query(ns, "version.bind", qtype=16, qclass=3)
            if c_rcode == 0 and c_ancount > 0:
                printable = re.findall(rb"[ -~]{4,48}", c_raw[28:])
                if printable:
                    entry["version_bind"] = printable[-1].decode("ascii", errors="ignore")
        except Exception as exc:
            entry["error"] = str(exc)[:60]
        checks.append(entry)

    if reachable == 0:
        return _res("active_dns_zone_transfer_axfr", "restricted_or_offline", f"TCP/53 to authoritative NS for '{zone}' blocked or unreachable", {"zone": zone, "nameservers": nameservers})

    summary = (
        f"CRITICAL: Zone transfer (AXFR) OPEN on {vulnerable_axfr}!"
        if vulnerable_axfr
        else f"Tested {reachable} authoritative NS for '{zone}' — AXFR properly refused"
    )
    return _res("active_dns_zone_transfer_axfr", "ok", summary, {"zone": zone, "checks": checks})


# ============================================================================
# 3. LIVE SRV SERVICE RECORDS & M365/ENTRA TENANT FEDERATION PROBE
# ============================================================================

SRV_PROBES = [
    "_autodiscover._tcp",
    "_sip._tls",
    "_sipfederationtls._tcp",
    "_xmpp-server._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_matrix._tcp",
    "_caldavs._tcp",
]


def active_dns_srv_and_federation(selector_type: str, value: str) -> dict:
    domain = _extract_host(selector_type, value)
    discovered_srv: dict[str, list[str]] = {}
    for prefix in SRV_PROBES:
        ans = _doh_query(f"{prefix}.{domain}", "SRV")
        vals = [a.get("data", "").strip() for a in ans if a.get("data")]
        if vals:
            discovered_srv[prefix] = vals[:5]

    # Microsoft Entra ID / M365 Unauthenticated Tenant & Federation Realm Lookup
    m365_info: dict = {}
    realm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{urllib.parse.quote(domain)}&json=1"
    _, st, _, body, _ = _raw_http_request(realm_url, max_hops=2, max_bytes=32_768)
    if st == 200 and body:
        try:
            rj = json.loads(body.decode("utf-8", errors="replace"))
            m365_info = {
                "name_space_type": rj.get("NameSpaceType"),
                "federation_brand_name": rj.get("FederationBrandName"),
                "cloud_instance": rj.get("CloudInstanceName"),
                "auth_url": rj.get("AuthURL"),
            }
        except Exception:
            pass

    oid_url = f"https://login.microsoftonline.com/{urllib.parse.quote(domain)}/v2.0/.well-known/openid-configuration"
    _, ost, _, obody, _ = _raw_http_request(oid_url, max_hops=2, max_bytes=32_768)
    if ost == 200 and obody:
        try:
            oj = json.loads(obody.decode("utf-8", errors="replace"))
            issuer = oj.get("issuer", "")
            tid_m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", issuer)
            if tid_m:
                m365_info["entra_tenant_id"] = tid_m.group(0)
        except Exception:
            pass

    if not discovered_srv and not m365_info:
        return _res("active_dns_srv_and_federation", "not_found", f"No public SRV records or M365 tenant metadata for '{domain}'", {"domain": domain})

    return _res(
        "active_dns_srv_and_federation",
        "ok",
        f"SRV services={list(discovered_srv.keys())} · Entra/M365={m365_info.get('name_space_type') or 'none'} (Tenant={m365_info.get('entra_tenant_id') or 'n/a'})",
        {"domain": domain, "srv_records": discovered_srv, "microsoft_federation": m365_info},
    )


# ============================================================================
# 4. LIVE CNAME CHAIN & DANGLING SUBDOMAIN TAKEOVER FINGERPRINT CHECK
# ============================================================================

TAKEOVER_SIGNATURES = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3 Bucket"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("azurewebsites.net", "404 Web Site not found", "Azure App Service"),
    ("cloudapp.net", "404", "Azure CloudApp"),
    ("trafficmanager.net", "404", "Azure Traffic Manager"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly CDN"),
    ("pantheonsite.io", "404 error unknown site", "Pantheon"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("tumblr.com", "Whatever you were looking for doesn't currently exist", "Tumblr"),
    ("wpengine.com", "The site you were looking for couldn't be found", "WP Engine"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "Repository not found", "Bitbucket Pages"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("readme.io", "Project doesnt exist", "ReadMe.io"),
    ("fly.dev", "404 Not Found", "Fly.io"),
    ("vercel.app", "DEPLOYMENT_NOT_FOUND", "Vercel"),
]


def active_subdomain_takeover_cname_audit(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    uhost = _url_host(host)
    cnames = [a.get("data", "").rstrip(".").lower() for a in _doh_query(host, "CNAME") if a.get("data")]
    _, st, _, body, err = _raw_http_request(f"https://{uhost}/", max_hops=2, max_bytes=80_000)
    if st == 0:
        _, st, _, body, err = _raw_http_request(f"http://{uhost}/", max_hops=2, max_bytes=80_000)

    text = body.decode("utf-8", errors="replace") if body else ""
    candidates = []
    for cname_pat, body_fp, provider in TAKEOVER_SIGNATURES:
        if any(cname_pat in c for c in cnames) or (body_fp and body_fp.lower() in text.lower()):
            matched_body = body_fp.lower() in text.lower()
            candidates.append(
                {
                    "provider": provider,
                    "cname_matched": any(cname_pat in c for c in cnames),
                    "http_fingerprint_confirmed": matched_body,
                    "severity": "HIGH" if (any(cname_pat in c for c in cnames) and matched_body) else "INFO_CNAME_ONLY",
                }
            )

    pivots = [{"type": "domain", "value": c} for c in cnames if c and c != host and c not in NOISE_DOMAINS]
    status = "ok" if (cnames or st > 0) else "restricted_or_offline"
    high = [c for c in candidates if c["severity"] == "HIGH"]
    summary = (
        f"POTENTIAL SUBDOMAIN TAKEOVER on {host}: {[c['provider'] for c in high]}"
        if high
        else f"Audited '{host}' · CNAMEs={cnames or ['none']} · Dangling takeover hits=0"
    )
    return _res(
        "active_subdomain_takeover_cname_audit",
        status,
        summary,
        {"host": host, "cname_chain": cnames, "http_status": st, "takeover_findings": candidates},
        pivots[:5],
    )


# ============================================================================
# 5. LIVE TLS HANDSHAKE & X.509 SAN CERTIFICATE INSPECTOR
# ============================================================================

def active_tls_cert_inspector(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    port = 443
    if selector_type == "url":
        try:
            p = urllib.parse.urlparse(_normalize_url_ipv6(value))
            if p.port:
                port = p.port
        except ValueError:
            pass

    is_ip = _is_ip_literal(host)
    sni_name = None if is_ip else host
    ctx = ssl._create_unverified_context() if is_ip else ssl.create_default_context()
    cert_dict = {}
    der_bytes = b""
    tls_version = None
    cipher_info = None
    verified = not is_ip

    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni_name) as tls_sock:
                cert_dict = tls_sock.getpeercert() or {}
                der_bytes = tls_sock.getpeercert(binary_form=True) or b""
                tls_version = tls_sock.version()
                cipher_info = tls_sock.cipher()
    except ssl.SSLCertVerificationError:
        verified = False
        ctx_unv = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as raw_sock:
                with ctx_unv.wrap_socket(raw_sock, server_hostname=sni_name) as tls_sock:
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
# 6. TLS PROTOCOL VERSION (1.0–1.3), CIPHER, PFS & ALPN MATRIX AUDITOR
# ============================================================================

def active_tls_protocol_alpn_matrix(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    supported_versions: list[str] = []
    cipher_by_version: dict[str, str] = {}
    negotiated_alpn = None

    proto_candidates = []
    for attr, label in (
        ("TLSv1_3", "TLSv1.3"),
        ("TLSv1_2", "TLSv1.2"),
        ("TLSv1_1", "TLSv1.1"),
        ("TLSv1", "TLSv1.0"),
    ):
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is not None:
            proto_candidates.append((ver, label))

    sni_name = None if _is_ip_literal(host) else host
    reachable = False
    for ver_enum, label in proto_candidates:
        try:
            ctx = ssl._create_unverified_context()
            ctx.minimum_version = ver_enum
            ctx.maximum_version = ver_enum
            if hasattr(ctx, "set_alpn_protocols"):
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((host, 443), timeout=2.5) as s:
                with ctx.wrap_socket(s, server_hostname=sni_name) as ts:
                    reachable = True
                    supported_versions.append(label)
                    ciph = ts.cipher()
                    if ciph:
                        cipher_by_version[label] = f"{ciph[0]} ({ciph[2]}-bit)"
                    if not negotiated_alpn:
                        negotiated_alpn = ts.selected_alpn_protocol()
        except ssl.SSLError:
            reachable = True
        except Exception:
            pass

    if not reachable and not supported_versions:
        return _res("active_tls_protocol_alpn_matrix", "restricted_or_offline", f"Port 443 unreachable on '{host}'", {"host": host})

    deprecated = [v for v in supported_versions if v in ("TLSv1.0", "TLSv1.1")]
    pfs = any("ECDHE" in c or "DHE" in c or "TLS_AES" in c or "CHACHA20" in c for c in cipher_by_version.values())
    return _res(
        "active_tls_protocol_alpn_matrix",
        "ok",
        f"Supported TLS={supported_versions} · ALPN={negotiated_alpn or 'none'} · PFS={pfs} · Deprecated={deprecated or 'none'}",
        {
            "host": host,
            "supported_tls_versions": supported_versions,
            "ciphers_negotiated": cipher_by_version,
            "alpn_selected": negotiated_alpn,
            "forward_secrecy": pfs,
            "deprecated_protocols_enabled": deprecated,
        },
    )


# ============================================================================
# 7. ACTIVE TLS SERVERHELLO STACK & JARM-STYLE ORIGIN FINGERPRINTER
# ============================================================================

def _build_tls_client_hello(host: str, max_ver: bytes, ciphers: list[int], alpn: list[bytes]) -> bytes:
    random_bytes = b"\x53\x4f\x53\x49" + bytes(range(28))
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    # SNI extension (0x0000)
    host_b = host.encode("ascii", errors="ignore")
    sni_list = b"\x00" + struct.pack("!H", len(host_b)) + host_b
    ext_sni = struct.pack("!HH", 0x0000, len(sni_list) + 2) + struct.pack("!H", len(sni_list)) + sni_list
    # Supported groups (0x000a) & ec_point_formats (0x000b) & sig_algs (0x000d)
    groups = struct.pack("!HHHH", 6, 0x001D, 0x0017, 0x0018)
    ext_groups = struct.pack("!HH", 0x000A, len(groups)) + groups
    ext_ec = struct.pack("!HHBB", 0x000B, 2, 1, 0)
    sigs = struct.pack("!HHHHH", 8, 0x0403, 0x0804, 0x0401, 0x0503)
    ext_sigs = struct.pack("!HH", 0x000D, len(sigs)) + sigs
    # Supported versions (0x002b) if TLS 1.3 requested
    ext_ver = b""
    if max_ver == b"\x03\x04":
        ext_ver = struct.pack("!HHBHH", 0x002B, 5, 4, 0x0304, 0x0303)
    # ALPN (0x0010)
    alpn_payload = b"".join(bytes([len(a)]) + a for a in alpn)
    ext_alpn = struct.pack("!HHH", 0x0010, len(alpn_payload) + 2, len(alpn_payload)) + alpn_payload

    extensions = ext_sni + ext_groups + ext_ec + ext_sigs + ext_ver + ext_alpn
    body = (
        b"\x03\x03"
        + random_bytes
        + b"\x00"
        + struct.pack("!H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _parse_server_hello(raw: bytes) -> str:
    if len(raw) < 44 or raw[0] != 0x16 or raw[5] != 0x02:
        return "000000|0000|00|"
    sh_ver = raw[9:11].hex()
    sid_len = raw[43]
    pos = 44 + sid_len
    if pos + 3 > len(raw):
        return f"0000|{sh_ver}|00|"
    cipher_hex = raw[pos : pos + 2].hex()
    pos += 3  # cipher (2) + compression (1)
    ext_types: list[str] = []
    alpn_str = ""
    if pos + 2 <= len(raw):
        ext_total = struct.unpack("!H", raw[pos : pos + 2])[0]
        end = min(len(raw), pos + 2 + ext_total)
        cur = pos + 2
        while cur + 4 <= end:
            etype, elen = struct.unpack("!HH", raw[cur : cur + 4])
            ext_types.append(f"{etype:04x}")
            if etype == 0x0010 and cur + 8 <= end:
                alen = raw[cur + 6]
                alpn_str = raw[cur + 7 : cur + 7 + alen].decode("ascii", errors="ignore")
            elif etype == 0x002B and elen == 2 and cur + 6 <= end:
                sh_ver = raw[cur + 4 : cur + 6].hex()
            cur += 4 + elen
    return f"{cipher_hex}|{sh_ver}|{alpn_str}|{'-'.join(ext_types)}"


def active_jarm_tls_fingerprint(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    probes = [
        ("tls13_modern", b"\x03\x04", [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B, 0xC030], [b"h2", b"http/1.1"]),
        ("tls12_ecdhe", b"\x03\x03", [0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9], [b"http/1.1"]),
        ("tls12_reverse", b"\x03\x03", [0xCCA9, 0xCCA8, 0xC02C, 0xC02B, 0x009C, 0x009D], [b"h2"]),
        ("tls12_rsa_fallback", b"\x03\x03", [0x009C, 0x009D, 0x002F, 0x0035], [b"http/1.1"]),
    ]

    raw_tokens: list[str] = []
    probe_details: dict[str, str] = {}
    reachable = 0
    for label, ver, ciphers, alpn in probes:
        pkt = _build_tls_client_hello(host, ver, ciphers, alpn)
        try:
            with socket.create_connection((host, 443), timeout=2.5) as s:
                s.settimeout(2.2)
                s.sendall(pkt)
                resp = s.recv(2048)
                reachable += 1
                tok = _parse_server_hello(resp)
                raw_tokens.append(tok)
                probe_details[label] = tok
        except Exception:
            raw_tokens.append("0000|0000||")
            probe_details[label] = "unreachable_or_alert"

    if reachable == 0:
        return _res("active_jarm_tls_fingerprint", "restricted_or_offline", f"Direct raw TLS ClientHello to {host}:443 unreachable", {"host": host})

    stack_digest = hashlib.sha256(",".join(raw_tokens).encode("utf-8")).hexdigest()[:40]
    return _res(
        "active_jarm_tls_fingerprint",
        "ok",
        f"Computed TLS ServerHello stack hash `{stack_digest[:20]}...` across {reachable}/4 ClientHello probes",
        {"host": host, "tls_stack_hash": stack_digest, "probe_responses": probe_details},
    )


# ============================================================================
# 8. LIVE HTTP REDIRECTS, SECURITY HEADERS, CSP & ANALYTICS TAG FINGERPRINTER
# ============================================================================

def active_http_fingerprint_and_headers(selector_type: str, value: str) -> dict:
    url = _target_url(selector_type, value)
    hops, status, hdrs, body_bytes, err = _raw_http_request(url)
    if status == 0:
        return _res("active_http_fingerprint_and_headers", "restricted_or_offline", f"Direct HTTP probe unreachable ({err})", {"url": url})

    html = body_bytes.decode("utf-8", errors="replace")
    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:140] if title_m else None

    ga4_ids = sorted(set(re.findall(r"\bG-[A-Z0-9]{8,12}\b", html)))
    gtm_ids = sorted(set(re.findall(r"\bGTM-[A-Z0-9]{5,10}\b", html)))
    ua_ids = sorted(set(re.findall(r"\bUA-\d{4,10}-\d{1,4}\b", html)))
    adsense_ids = sorted(set(re.findall(r"\bpub-\d{14,18}\b", html)))

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
            "onion-location", "www-authenticate", "x-served-by", "x-cache",
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
# 9. LIVE HTTP OPTIONS METHODS, CORS REFLECTION & WAF/CDN EDGE DETECTOR
# ============================================================================

WAF_CDN_SIGNATURES = [
    ("Cloudflare", ("cf-ray", "cf-cache-status"), "cloudflare"),
    ("AWS CloudFront", ("x-amz-cf-id", "x-amz-cf-pop"), "cloudfront"),
    ("Fastly", ("x-fastly-request-id", "fastly-restarts"), "varnish"),
    ("Akamai", ("x-akamai-transformed", "akamai-grn"), "akamaighost"),
    ("Vercel", ("x-vercel-id", "x-vercel-cache"), "vercel"),
    ("Netlify", ("x-nf-request-id",), "netlify"),
    ("GitHub.com Edge", ("x-github-request-id",), "github.com"),
    ("Google Cloud / GSE", ("x-goog-generation", "x-guploader-uploadid"), "gws"),
    ("Imperva Incapsula", ("x-iinfo", "x-cdn"), "incapsula"),
    ("Sucuri Cloudproxy", ("x-sucuri-id", "x-sucuri-cache"), "sucuri"),
    ("Fly.io", ("fly-request-id",), "fly"),
    ("Envoy Proxy", ("x-envoy-upstream-service-time",), "envoy"),
]


def active_http_methods_cors_and_waf(selector_type: str, value: str) -> dict:
    url = _target_url(selector_type, value)
    _, opt_st, opt_hdrs, _, err = _raw_http_request(url, method="OPTIONS", max_hops=2, max_bytes=4096)
    canary_origin = "https://osint-cors-audit.example"
    _, cors_st, cors_hdrs, _, _ = _raw_http_request(
        url,
        method="GET",
        extra_headers={"Origin": canary_origin},
        max_hops=3,
        max_bytes=16_384,
    )
    if opt_st == 0 and cors_st == 0:
        return _res("active_http_methods_cors_and_waf", "restricted_or_offline", f"HTTP OPTIONS/CORS probe unreachable ({err})", {"url": url})

    merged = {**opt_hdrs, **cors_hdrs}
    server_val = (merged.get("server") or "").lower()
    detected_edges = []
    for name, hdr_keys, srv_sub in WAF_CDN_SIGNATURES:
        if any(k in merged for k in hdr_keys) or (srv_sub and srv_sub in server_val):
            detected_edges.append(name)

    allow_methods = opt_hdrs.get("allow") or opt_hdrs.get("access-control-allow-methods")
    acao = cors_hdrs.get("access-control-allow-origin")
    acac = cors_hdrs.get("access-control-allow-credentials")
    cors_misconfig = bool(acao == canary_origin and str(acac).lower() == "true")

    return _res(
        "active_http_methods_cors_and_waf",
        "ok",
        f"Edge/WAF={detected_edges or ['unfingerprinted']} · Allow={allow_methods or 'n/a'} · ACAO={acao or 'none'} · Arbitrary-CORS-Creds={cors_misconfig}",
        {
            "options_status": opt_st,
            "allowed_methods": allow_methods,
            "detected_waf_or_cdn": detected_edges,
            "cors_allow_origin": acao,
            "cors_allow_credentials": acac,
            "cors_origin_reflection_with_credentials": cors_misconfig,
            "server_timing": merged.get("server-timing"),
        },
    )


# ============================================================================
# 10. LIVE /robots.txt, /.well-known/security.txt & OPENID TENANT HARVESTER
# ============================================================================

def active_wellknown_and_robots_harvester(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    base = f"https://{_url_host(host)}"
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
        _, st, _, raw, _ = _raw_http_request(base + path, max_hops=2)
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
# 11. ANDROID assetlinks, APPLE APP-SITE-ASSOCIATION, NOSTR & ATPROTO LINKS
# ============================================================================

def active_mobile_app_and_fediverse_links(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    base = f"https://{_url_host(host)}"
    paths = {
        "android_assetlinks": "/.well-known/assetlinks.json",
        "apple_app_site_association": "/.well-known/apple-app-site-association",
        "nostr_nip05": "/.well-known/nostr.json",
        "matrix_server": "/.well-known/matrix/server",
        "bluesky_atproto_did": "/.well-known/atproto-did",
        "web_manifest": "/manifest.json",
    }

    findings: dict = {}
    reachable = 0
    for key, rel in paths.items():
        _, st, _, raw, _ = _raw_http_request(base + rel, max_hops=2, max_bytes=120_000)
        if st == 0:
            continue
        reachable += 1
        if st != 200 or not raw:
            continue
        txt = raw.decode("utf-8", errors="replace").strip()
        if "<html" in txt[:200].lower():
            continue
        if key == "bluesky_atproto_did" and txt.startswith("did:"):
            findings[key] = txt[:120]
            continue
        try:
            parsed = json.loads(txt)
        except Exception:
            continue

        if key == "android_assetlinks" and isinstance(parsed, list):
            apps = []
            for item in parsed[:15]:
                tgt = item.get("target") or {}
                if tgt.get("package_name"):
                    apps.append(
                        {
                            "package_name": tgt.get("package_name"),
                            "sha256_cert_fingerprints": (tgt.get("sha256_cert_fingerprints") or [])[:3],
                        }
                    )
            if apps:
                findings[key] = apps
        elif key == "apple_app_site_association" and isinstance(parsed, dict):
            applinks = (parsed.get("applinks") or {}).get("details") or []
            app_ids = []
            for d in applinks[:15]:
                if isinstance(d, dict):
                    aid = d.get("appID") or d.get("appIDs")
                    if aid:
                        app_ids.append(aid)
            webcreds = (parsed.get("webcredentials") or {}).get("apps") or []
            if app_ids or webcreds:
                findings[key] = {"applink_bundle_ids": app_ids[:10], "webcredentials_apps": webcreds[:10]}
        elif key == "nostr_nip05" and isinstance(parsed, dict) and parsed.get("names"):
            findings[key] = dict(list(parsed["names"].items())[:20])
        elif key in ("matrix_server", "web_manifest") and isinstance(parsed, dict):
            findings[key] = {k: parsed[k] for k in ("m.server", "name", "short_name", "start_url") if k in parsed}

    if reachable == 0:
        return _res("active_mobile_app_and_fediverse_links", "restricted_or_offline", f"Origin {base} unreachable", {})
    return _res(
        "active_mobile_app_and_fediverse_links",
        "ok" if findings else "not_found",
        f"Discovered {len(findings)} mobile/identity manifest(s): {list(findings.keys())}",
        findings,
    )


# ============================================================================
# 12. LIVE XML SITEMAP & RSS/ATOM AUTHOR HARVESTER
# ============================================================================

def active_sitemap_and_feed_harvester(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    base = f"https://{_url_host(host)}"
    urls_found: list[str] = []
    authors: set[str] = set()
    feeds_hit: list[str] = []
    reachable = 0

    for path in ("/sitemap.xml", "/sitemap_index.xml", "/feed", "/rss.xml", "/atom.xml"):
        _, st, _, raw, _ = _raw_http_request(base + path, max_hops=3, max_bytes=200_000)
        if st == 0:
            continue
        reachable += 1
        if st != 200 or not raw:
            continue
        txt = raw.decode("utf-8", errors="replace")
        if "<urlset" in txt or "<sitemapindex" in txt or "<rss" in txt or "<feed" in txt:
            feeds_hit.append(path)
            for loc in re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", txt)[:35]:
                urls_found.append(loc)
            try:
                root = ET.fromstring(raw)
                for elem in root.iter():
                    tname = elem.tag.split("}")[-1].lower()
                    if tname in ("creator", "author", "name") and elem.text and 2 <= len(elem.text.strip()) <= 64:
                        authors.add(elem.text.strip())
            except Exception:
                pass

    if reachable == 0:
        return _res("active_sitemap_and_feed_harvester", "restricted_or_offline", f"Origin {base} unreachable", {})
    return _res(
        "active_sitemap_and_feed_harvester",
        "ok" if feeds_hit else "not_found",
        f"Parsed {len(feeds_hit)} sitemap/feed(s) {feeds_hit} · {len(urls_found)} URL(s) · {len(authors)} author(s)",
        {"matched_endpoints": feeds_hit, "sample_urls": urls_found[:25], "authors": sorted(authors)[:15]},
    )


# ============================================================================
# 13. OPENAPI/SWAGGER, GRAPHQL, AI-PLUGIN & llms.txt SPEC DISCOVERY
# ============================================================================

def active_api_openapi_and_graphql_discovery(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    base = f"https://{_url_host(host)}"
    probes = [
        ("openapi_json", "/openapi.json"),
        ("swagger_json", "/swagger.json"),
        ("api_docs", "/v1/openapi.json"),
        ("ai_plugin", "/.well-known/ai-plugin.json"),
        ("llms_txt", "/llms.txt"),
        ("agents_json", "/.well-known/agents.json"),
        ("graphql_typename", "/graphql?query=%7B__typename%7D"),
    ]

    discovered: dict = {}
    reachable = 0
    for key, rel in probes:
        _, st, hdrs, raw, _ = _raw_http_request(base + rel, max_hops=2, max_bytes=120_000)
        if st == 0:
            continue
        reachable += 1
        if st != 200 or not raw:
            continue
        txt = raw.decode("utf-8", errors="replace").strip()
        if "<html" in txt[:250].lower():
            continue
        if key == "llms_txt" and len(txt) > 20:
            discovered[key] = {"preview": txt[:400]}
            continue
        try:
            j = json.loads(txt)
        except Exception:
            continue
        if key in ("openapi_json", "swagger_json", "api_docs") and ("openapi" in j or "swagger" in j):
            info = j.get("info") or {}
            discovered[key] = {
                "title": info.get("title"),
                "version": info.get("version"),
                "path_count": len(j.get("paths") or {}),
                "sample_paths": list((j.get("paths") or {}).keys())[:15],
            }
        elif key == "graphql_typename" and ("data" in j or "errors" in j):
            discovered["graphql_endpoint"] = {"url": base + "/graphql", "response_keys": list(j.keys())}
        elif isinstance(j, dict):
            discovered[key] = {k: j[k] for k in list(j.keys())[:8]}

    if reachable == 0:
        return _res("active_api_openapi_and_graphql_discovery", "restricted_or_offline", f"Origin {base} unreachable", {})
    return _res(
        "active_api_openapi_and_graphql_discovery",
        "ok" if discovered else "not_found",
        f"Discovered {len(discovered)} public API/AI spec(s): {list(discovered.keys())}",
        discovered,
    )


# ============================================================================
# 14. NON-DESTRUCTIVE EXPOSED /.git/HEAD, /.DS_Store & POLICY CHECK
# ============================================================================

def active_exposed_vcs_and_env_check(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    base = f"https://{_url_host(host)}"
    checks = [
        ("git_head", "/.git/HEAD", lambda b: b.startswith((b"ref: refs/", b"ref: "))),
        ("svn_entries", "/.svn/wc.db", lambda b: b.startswith(b"SQLite format 3")),
        ("ds_store", "/.DS_Store", lambda b: len(b) >= 8 and b[4:8] == b"Bud1"),
        ("crossdomain_xml", "/crossdomain.xml", lambda b: b"<cross-domain-policy" in b[:400]),
        ("clientaccesspolicy", "/clientaccesspolicy.xml", lambda b: b"<access-policy" in b[:400]),
    ]

    exposures: dict = {}
    reachable = 0
    for name, rel, validator in checks:
        _, st, _, raw, _ = _raw_http_request(base + rel, max_hops=1, max_bytes=16_384)
        if st == 0:
            continue
        reachable += 1
        if st == 200 and raw and validator(raw):
            exposures[name] = {
                "path": rel,
                "preview": raw[:120].decode("utf-8", errors="replace").strip(),
            }

    if reachable == 0:
        return _res("active_exposed_vcs_and_env_check", "restricted_or_offline", f"Origin {base} unreachable", {})
    return _res(
        "active_exposed_vcs_and_env_check",
        "ok",
        f"Audited 5 metadata/VCS paths on {host} — verified exposures: {list(exposures.keys()) or 'none'}",
        {"host": host, "verified_exposures": exposures},
    )


# ============================================================================
# 15. LIVE FIRST-PARTY JS BUNDLE API ENDPOINT & CLOUD BUCKET CARVER
# ============================================================================

def active_js_bundle_cloud_and_endpoint_carver(selector_type: str, value: str) -> dict:
    page_url = _target_url(selector_type, value)
    _, st, _, raw_html, err = _raw_http_request(page_url, max_hops=3, max_bytes=200_000)
    if st == 0:
        return _res("active_js_bundle_cloud_and_endpoint_carver", "restricted_or_offline", f"Origin unreachable ({err})", {"url": page_url})

    html = raw_html.decode("utf-8", errors="replace")
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, flags=re.IGNORECASE)
    js_urls = [urllib.parse.urljoin(page_url, s) for s in srcs][:4]

    api_routes: set[str] = set()
    cloud_assets: set[str] = set()
    tech_tokens: dict[str, list[str]] = {}
    combined_corpus = [html]

    for jurl in js_urls:
        _, jst, _, jraw, _ = _raw_http_request(jurl, max_hops=2, max_bytes=220_000)
        if jst == 200 and jraw:
            combined_corpus.append(jraw.decode("utf-8", errors="replace"))

    blob = "\n".join(combined_corpus)
    for m in re.findall(r'["\'](/(?:api|v1|v2|v3|graphql|internal|oauth|auth)/[A-Za-z0-9_./-]{2,64})["\']', blob):
        api_routes.add(m)
    for m in re.findall(
        r"https?://[a-z0-9._-]+(?:\.s3[a-z0-9.-]*\.amazonaws\.com|\.storage\.googleapis\.com|\.blob\.core\.windows\.net|\.supabase\.co|\.firebaseio\.com)",
        blob,
        flags=re.IGNORECASE,
    ):
        cloud_assets.add(m.lower())

    sentry = sorted(set(re.findall(r"https://[a-f0-9]{16,32}@[a-z0-9.-]+\.ingest\.sentry\.io/\d+", blob)))
    stripe_pk = sorted(set(re.findall(r"\bpk_live_[0-9a-zA-Z]{20,36}\b", blob)))
    firebase_proj = sorted(set(re.findall(r'projectId\s*:\s*["\']([a-z0-9-]{6,32})["\']', blob)))
    if sentry:
        tech_tokens["sentry_dsns"] = sentry[:5]
    if stripe_pk:
        tech_tokens["stripe_publishable_keys"] = stripe_pk[:5]
    if firebase_proj:
        tech_tokens["firebase_projects"] = firebase_proj[:5]

    return _res(
        "active_js_bundle_cloud_and_endpoint_carver",
        "ok",
        f"Scanned {len(js_urls)} JS bundle(s) · {len(api_routes)} API route(s) · {len(cloud_assets)} cloud asset(s)",
        {
            "scanned_js_bundles": js_urls,
            "api_endpoints": sorted(api_routes)[:30],
            "cloud_storage_and_baas": sorted(cloud_assets)[:20],
            "client_telemetry_identifiers": tech_tokens,
        },
    )


# ============================================================================
# 16. LIVE /favicon.ico SHODAN MURMURHASH3 (mmh3) & SHA-256 EXTRACTOR
# ============================================================================

def active_favicon_hash_extractor(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    _, st, hdrs, raw, err = _raw_http_request(f"https://{_url_host(host)}/favicon.ico", max_hops=3)
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
# 17. LIVE WEBPAGE OPENGRAPH, JSON-LD `sameAs` SOCIAL GRAPH & CONTACTS
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
    url = _target_url(selector_type, value)
    _, st, _, raw, err = _raw_http_request(url, max_hops=4)
    if st == 0:
        return _res("active_url_jsonld_opengraph", "restricted_or_offline", f"Live HTML fetch unreachable ({err})", {"url": url})

    home_html = raw.decode("utf-8", errors="replace")
    carved = carve_webpage_intelligence(home_html, base_url=url)

    # Also spider up to 3 same-host /contact, /about, /team, /doctors subpages when authorized!
    crawled_subpages: list[str] = []
    sub_candidates = list(carved.get("contact_subpages") or [])
    if not sub_candidates and selector_type == "domain":
        sub_candidates = [_target_url(selector_type, value, path="/contact"), _target_url(selector_type, value, path="/about")]

    all_emails = set(carved["emails"])
    all_phones = set(carved["phones"])
    social_by_key = {f"{s['platform']}:{s['handle'].lower()}": s for s in carved["social_profiles"]}
    same_as = list(carved["schema_same_as_links"])
    schema_entities = list(carved["schema_entities"])
    pivots = list(carved["pivots"])

    for sub_u in sub_candidates[:3]:
        _, sub_st, _, sub_raw, _ = _raw_http_request(sub_u, max_hops=2, max_bytes=200_000)
        if sub_st == 200 and sub_raw:
            crawled_subpages.append(sub_u)
            sub_carved = carve_webpage_intelligence(sub_raw.decode("utf-8", errors="replace"), base_url=sub_u)
            all_emails.update(sub_carved["emails"])
            all_phones.update(sub_carved["phones"])
            for s in sub_carved["social_profiles"]:
                social_by_key.setdefault(f"{s['platform']}:{s['handle'].lower()}", s)
            for u_sa in sub_carved["schema_same_as_links"]:
                if u_sa not in same_as:
                    same_as.append(u_sa)
            schema_entities.extend(sub_carved["schema_entities"])
            pivots.extend(sub_carved["pivots"])

    og_subset = carved["meta_tags"]
    social_list = list(social_by_key.values())[:30]

    return _res(
        "active_url_jsonld_opengraph",
        "ok",
        f"Crawled {1 + len(crawled_subpages)} page(s) · {len(all_emails)} email(s) · {len(all_phones)} phone(s) · {len(social_list)} social profile(s) · {len(schema_entities)} schema record(s)",
        {
            "title": carved.get("title"),
            "description": carved.get("description"),
            "crawled_pages": [url] + crawled_subpages,
            "meta_tags": og_subset,
            "emails": sorted(all_emails)[:25],
            "phones": sorted(all_phones)[:25],
            "social_profiles": social_list,
            "schema_same_as_links": same_as[:25],
            "schema_entities": schema_entities[:15],
            "tracking_ids": carved["tracking_ids"],
        },
        pivots[:25],
    )


# ============================================================================
# 18. ACTIVE AWS S3, GCS & AZURE BLOB PUBLIC BUCKET PERMUTATION PROBE
# ============================================================================

def active_cloud_bucket_permutation_probe(selector_type: str, value: str) -> dict:
    raw = _extract_host(selector_type, value) if selector_type == "domain" else value.strip().lower()
    slug = re.sub(r"[^a-z0-9-]+", "-", raw.split(".")[0]).strip("-")[:32]
    if len(slug) < 3:
        return _res("active_cloud_bucket_permutation_probe", "not_found", "Slug too short for bucket permutation", {})

    candidates = [
        ("aws_s3", slug, f"https://{slug}.s3.amazonaws.com/?max-keys=1"),
        ("aws_s3", f"{slug}-assets", f"https://{slug}-assets.s3.amazonaws.com/?max-keys=1"),
        ("aws_s3", f"{slug}-public", f"https://{slug}-public.s3.amazonaws.com/?max-keys=1"),
        ("gcp_gcs", slug, f"https://storage.googleapis.com/{slug}/?maxResults=1"),
        ("azure_blob", slug, f"https://{slug.replace('-', '')}.blob.core.windows.net/?comp=list"),
    ]

    hits = []
    reachable = 0
    for provider, bname, burl in candidates:
        _, st, _, body, _ = _raw_http_request(burl, max_hops=1, max_bytes=8192)
        if st == 0:
            continue
        reachable += 1
        txt = body.decode("utf-8", errors="replace")
        if st == 200 and "<ListBucketResult" in txt:
            hits.append({"provider": provider, "bucket": bname, "access": "PUBLIC_LISTABLE", "url": burl})
        elif st == 403:
            hits.append({"provider": provider, "bucket": bname, "access": "EXISTS_PRIVATE_403", "url": burl})

    if reachable == 0:
        return _res("active_cloud_bucket_permutation_probe", "restricted_or_offline", "Cloud storage endpoints unreachable from current network", {"slug": slug})
    return _res(
        "active_cloud_bucket_permutation_probe",
        "ok" if hits else "not_found",
        f"Probed {len(candidates)} S3/GCS/Azure bucket permutations for '{slug}' -> {len(hits)} hit(s)",
        {"base_slug": slug, "buckets": hits},
    )


# ============================================================================
# 19. EXPANDED 20-PORT NON-INTRUSIVE TCP PORT & SERVICE BANNER SCANNER
# ============================================================================

COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (465, "SMTPS"),
    (587, "Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (9200, "Elasticsearch"),
]


def active_tcp_service_banner_probe(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)

    def _check_port(item: tuple[int, str]):
        port, proto = item
        try:
            with socket.create_connection((host, port), timeout=1.8) as s:
                s.settimeout(1.2)
                banner = ""
                if port in (21, 22, 23, 25, 110, 143, 587, 3306):
                    try:
                        raw_b = s.recv(160)
                        banner = re.sub(r"[^\x20-\x7e]+", " ", raw_b.decode("utf-8", errors="replace")).strip()[:120]
                    except Exception:
                        pass
                return {"port": port, "service": proto, "state": "open", "banner": banner or None}
        except ConnectionRefusedError:
            return {"port": port, "service": proto, "state": "closed"}
        except Exception as exc:
            return {"port": port, "service": proto, "state": "filtered_or_blocked", "detail": str(exc)[:60]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_check_port, COMMON_PORTS))

    open_ports = [r for r in results if r["state"] == "open"]
    all_blocked = all(r["state"] == "filtered_or_blocked" for r in results)
    if all_blocked:
        return _res("active_tcp_service_banner_probe", "restricted_or_offline", f"Direct TCP probes to {host} blocked by sandbox/firewall", {"host": host})

    return _res(
        "active_tcp_service_banner_probe",
        "ok",
        f"Scanned 20 TCP ports on {host} -> Open: {[r['port'] for r in open_ports]} · Banners: {[r['banner'] for r in open_ports if r.get('banner')]}",
        {"host": host, "open_ports": open_ports},
    )


# ============================================================================
# 20. LIVE SSH-2.0 BANNER & RFC 4253 KEXINIT HOST-KEY FINGERPRINTER
# ============================================================================

def _parse_ssh_namelists(payload: bytes, count: int = 4) -> list[list[str]]:
    out: list[list[str]] = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(payload):
            break
        nlen = struct.unpack("!I", payload[pos : pos + 4])[0]
        pos += 4
        if pos + nlen > len(payload):
            break
        s = payload[pos : pos + nlen].decode("ascii", errors="ignore")
        out.append([x for x in s.split(",") if x])
        pos += nlen
    return out


def active_ssh_hostkey_and_kex_probe(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    try:
        with socket.create_connection((host, 22), timeout=2.5) as s:
            s.settimeout(2.2)
            banner_bytes = b""
            while b"\n" not in banner_bytes and len(banner_bytes) < 256:
                chunk = s.recv(128)
                if not chunk:
                    break
                banner_bytes += chunk
            banner = banner_bytes.splitlines()[0].decode("utf-8", errors="replace").strip() if banner_bytes else ""
            s.sendall(b"SSH-2.0-OSINT_Audit_2026\r\n")
            pkt = s.recv(4096)
    except Exception as exc:
        return _res("active_ssh_hostkey_and_kex_probe", "restricted_or_offline", f"TCP/22 SSH unreachable on '{host}' ({exc})", {"host": host})

    kex_algs: list[str] = []
    host_key_types: list[str] = []
    ciphers_c2s: list[str] = []
    # Locate SSH_MSG_KEXINIT (byte 0x14 = 20) after packet_length(4) + padding_length(1)
    idx = pkt.find(b"\x14")
    if idx >= 5 and idx + 17 < len(pkt):
        lists = _parse_ssh_namelists(pkt[idx + 17 :], count=4)
        if len(lists) >= 1:
            kex_algs = lists[0][:10]
        if len(lists) >= 2:
            host_key_types = lists[1][:10]
        if len(lists) >= 3:
            ciphers_c2s = lists[2][:10]

    if not banner.startswith("SSH-") and not host_key_types:
        return _res("active_ssh_hostkey_and_kex_probe", "restricted_or_offline", f"TCP/22 returned no SSH banner on '{host}'", {"host": host})

    os_hint = None
    for distro in ("Ubuntu", "Debian", "FreeBSD", "CentOS", "RHEL", "Fedora", "Alpine", "Windows"):
        if distro.lower() in banner.lower():
            os_hint = distro
            break

    return _res(
        "active_ssh_hostkey_and_kex_probe",
        "ok",
        f"SSH Banner='{banner}' · OS={os_hint or 'generic'} · HostKeys={host_key_types[:4]}",
        {
            "host": host,
            "ssh_banner": banner,
            "os_distro_hint": os_hint,
            "host_key_algorithms": host_key_types,
            "kex_algorithms": kex_algs,
            "encryption_ciphers": ciphers_c2s,
        },
    )


# ============================================================================
# 21. LIVE MAIL SERVER SMTP BANNER, EHLO & STARTTLS CERT INSPECTOR
# ============================================================================

def active_smtp_ehlo_starttls_inspector(selector_type: str, value: str) -> dict:
    host = _extract_host(selector_type, value)
    mx_targets = [host]
    if selector_type in ("domain", "email"):
        mx_ans = _doh_query(host, "MX")
        parsed_mx = []
        for a in mx_ans:
            parts = (a.get("data") or "").split()
            if parts:
                parsed_mx.append(parts[-1].rstrip(".").lower())
        if parsed_mx:
            mx_targets = parsed_mx[:2]

    for mx in mx_targets:
        for port in (25, 587):
            try:
                with socket.create_connection((mx, port), timeout=2.5) as s:
                    s.settimeout(2.2)
                    greeting = s.recv(512).decode("utf-8", errors="replace").strip()
                    if not greeting:
                        continue
                    s.sendall(b"EHLO osint.example.org\r\n")
                    ehlo_raw = s.recv(2048).decode("utf-8", errors="replace")
                    caps = [ln[4:].strip() for ln in ehlo_raw.splitlines() if len(ln) > 4]
                    tls_sans: list[str] = []
                    if any("STARTTLS" in c.upper() for c in caps):
                        s.sendall(b"STARTTLS\r\n")
                        st_resp = s.recv(256).decode("utf-8", errors="replace")
                        if st_resp.startswith("220"):
                            ctx = ssl.create_default_context()
                            with ctx.wrap_socket(s, server_hostname=mx) as ts:
                                cert = ts.getpeercert() or {}
                                tls_sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:15]
                    return _res(
                        "active_smtp_ehlo_starttls_inspector",
                        "ok",
                        f"SMTP on {mx}:{port} · Banner='{greeting[:70]}' · STARTTLS SANs={tls_sans[:4]}",
                        {
                            "mx_host": mx,
                            "port": port,
                            "banner": greeting,
                            "ehlo_capabilities": caps,
                            "vrfy_advertised": any(c.upper().startswith("VRFY") for c in caps),
                            "starttls_cert_sans": tls_sans,
                        },
                    )
            except Exception:
                continue

    return _res(
        "active_smtp_ehlo_starttls_inspector",
        "restricted_or_offline",
        f"Outbound TCP 25/587 to MX {mx_targets} blocked or closed",
        {"tested_mx_hosts": mx_targets},
    )


# ============================================================================
# 22. DIRECT 16-PLATFORM LIVE HTTP/API USERNAME EXISTENCE & PROFILE VERIFIER
# ============================================================================

USERNAME_PROBES = [
    ("GitHub", "https://api.github.com/users/{u}", "json_key", "login"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={u}", "json_nonempty_list", ""),
    ("PyPI", "https://pypi.org/user/{u}/", "status_200_text", "projects"),
    ("npm", "https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=1", "json_key", "objects"),
    ("Codeberg", "https://codeberg.org/api/v1/users/{u}", "json_key", "username"),
    ("DockerHub", "https://hub.docker.com/v2/users/{u}/", "json_key", "username"),
    ("HuggingFace", "https://huggingface.co/api/users/{u}/overview", "status_200", ""),
    ("Dev.to", "https://dev.to/api/users/by_username?url={u}", "json_key", "username"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "status_200_text", '"code":0'),
    ("Bluesky_ATProto", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", "json_key", "did"),
    ("Mastodon_Social", "https://mastodon.social/api/v1/accounts/lookup?acct={u}", "json_key", "id"),
    ("Crates.io", "https://crates.io/api/v1/users/{u}", "json_key", "user"),
    ("Packagist", "https://packagist.org/users/{u}/packages.json", "json_key", "packages"),
    ("Reddit", "https://www.reddit.com/user/{u}/about.json", "json_key", "data"),
    ("Telegram_Public", "https://t.me/{u}", "status_200_text", "tgme_page_title"),
    ("Linktree", "https://linktr.ee/{u}", "status_200_text", "__NEXT_DATA__"),
]


def active_username_live_platform_probe(selector_type: str, value: str) -> dict:
    handle = value.strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9_.-]{2,40}$", handle):
        return _res("active_username_live_platform_probe", "not_found", "Invalid username handle format", {})

    def _probe_one(spec: tuple[str, str, str, str]):
        platform, tmpl, check_kind, marker = spec
        url = tmpl.format(u=urllib.parse.quote(handle))
        _, st, _, body, _ = _raw_http_request(url, max_hops=2, max_bytes=65_536)
        if st == 0:
            return platform, "unreachable", url
        txt = body.decode("utf-8", errors="replace")
        if st == 200:
            if check_kind == "status_200":
                return platform, "confirmed", url
            if check_kind == "status_200_text" and marker in txt:
                return platform, "confirmed", url
            if check_kind.startswith("json_"):
                try:
                    j = json.loads(txt)
                    if check_kind == "json_nonempty_list" and isinstance(j, list) and len(j) > 0:
                        return platform, "confirmed", url
                    if check_kind == "json_key" and isinstance(j, dict) and marker in j:
                        if marker == "objects" and not j.get("objects"):
                            return platform, "not_found", url
                        return platform, "confirmed", url
                except Exception:
                    pass
        return platform, "not_found", url

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(_probe_one, USERNAME_PROBES))

    confirmed = [{"platform": p, "url": u} for p, status, u in outcomes if status == "confirmed"]
    reachable = sum(1 for _, status, _ in outcomes if status != "unreachable")
    if reachable == 0:
        return _res("active_username_live_platform_probe", "restricted_or_offline", "Outbound platform probes blocked", {"username": handle})

    pivots = [{"type": "url", "value": c["url"]} for c in confirmed[:6]]
    return _res(
        "active_username_live_platform_probe",
        "ok" if confirmed else "not_found",
        f"Verified '{handle}' across {reachable}/16 live platforms -> Confirmed on {[c['platform'] for c in confirmed]}",
        {"username": handle, "reachable_platforms": reachable, "confirmed_accounts": confirmed},
        pivots,
    )


# ============================================================================
# DISPATCH REGISTRY
# ============================================================================

MODULE_DISPATCH = {
    "active_dns_live_resolver": active_dns_live_resolver,
    "active_dns_zone_transfer_axfr": active_dns_zone_transfer_axfr,
    "active_dns_srv_and_federation": active_dns_srv_and_federation,
    "active_subdomain_takeover_cname_audit": active_subdomain_takeover_cname_audit,
    "active_tls_cert_inspector": active_tls_cert_inspector,
    "active_tls_protocol_alpn_matrix": active_tls_protocol_alpn_matrix,
    "active_jarm_tls_fingerprint": active_jarm_tls_fingerprint,
    "active_http_fingerprint_and_headers": active_http_fingerprint_and_headers,
    "active_http_methods_cors_and_waf": active_http_methods_cors_and_waf,
    "active_wellknown_and_robots_harvester": active_wellknown_and_robots_harvester,
    "active_mobile_app_and_fediverse_links": active_mobile_app_and_fediverse_links,
    "active_sitemap_and_feed_harvester": active_sitemap_and_feed_harvester,
    "active_api_openapi_and_graphql_discovery": active_api_openapi_and_graphql_discovery,
    "active_exposed_vcs_and_env_check": active_exposed_vcs_and_env_check,
    "active_js_bundle_cloud_and_endpoint_carver": active_js_bundle_cloud_and_endpoint_carver,
    "active_favicon_hash_extractor": active_favicon_hash_extractor,
    "active_url_jsonld_opengraph": active_url_jsonld_opengraph,
    "active_cloud_bucket_permutation_probe": active_cloud_bucket_permutation_probe,
    "active_tcp_service_banner_probe": active_tcp_service_banner_probe,
    "active_ssh_hostkey_and_kex_probe": active_ssh_hostkey_and_kex_probe,
    "active_smtp_ehlo_starttls_inspector": active_smtp_ehlo_starttls_inspector,
    "active_username_live_platform_probe": active_username_live_platform_probe,
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(applicable))) as pool:
        fut_pairs = [(m, pool.submit(MODULE_DISPATCH[m], sel_type, value)) for m in applicable]
        results = []
        for m, fut in fut_pairs:
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append(
                    _res(
                        m,
                        "restricted_or_offline",
                        f"Active probe skipped ({exc})",
                        {"selector_type": sel_type, "value": value, "error": str(exc)},
                    )
                )
        return results

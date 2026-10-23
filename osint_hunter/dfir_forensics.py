"""DFIR Pocket-Knife 2.0 — Pure-Python Zero-Network File & Token Forensics.

Provides 100% stdlib, zero-outbound-packet parsers for:
  1. Raw Email (.eml) headers, hop delays, SPF/DKIM/DMARC & attachment hashes
  2. Packet Captures (.pcap & .pcapng) — DNS QNAMEs, TLS ClientHello SNI & HTTP hosts
  3. Browser HTTP Archives (.har) — domains, server IPs, endpoints & auth headers
  4. MP4 / MOV Video Containers — QuickTime mvhd UTC timestamps & ISO-6709 ©xyz GPS
  5. PNG / WebP / C2PA & AI Image Provenance — C2PA JUMBF, ComfyUI & Stable Diffusion prompts
  6. Google Search `ei=` URL Parameter Chronolocation Decoder
  7. OpenSSH Public Keys (`ssh-rsa`/`ssh-ed25519`/`ecdsa`) & PEM X.509 Fingerprinter
"""

from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import ipaddress
import json
import re
import socket
import struct
import urllib.parse
import zlib
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

MAC_HFS_EPOCH_OFFSET = 2082844800  # Seconds between 1904-01-01 and 1970-01-01
ISO6709_RE = re.compile(r"([+-]\d{1,2}\.\d+)([+-]\d{1,3}\.\d+)")
IPV4_IN_HEADER_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_SIMPLE_RE = re.compile(r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,18}\b")
URL_SIMPLE_RE = re.compile(r"https?://[^\s<>\"')\]}]+")
SSH_PUBKEY_RE = re.compile(
    r"\b((?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com)\s+"
    r"([A-Za-z0-9+/=]{32,})(?:\s+([^\r\n]{1,160}))?)"
)
PEM_CERT_RE = re.compile(
    r"-----BEGIN (CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----"
)


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


# ============================================================================
# 1. RAW EMAIL (.eml) HEADER, HOP-DELAY & SPOOFING FORENSICS
# ============================================================================

def analyze_eml_bytes(data: bytes) -> dict[str, Any]:
    """Dissect an RFC 5322 .eml message: Received hops, SPF/DKIM/DMARC, spoofing & attachments."""
    msg = email.message_from_bytes(data, policy=email.policy.default)

    from_addrs = [addr.lower() for _, addr in getaddresses(msg.get_all("From", [])) if "@" in addr]
    to_addrs = [addr.lower() for _, addr in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", [])) if "@" in addr]
    reply_to = [addr.lower() for _, addr in getaddresses(msg.get_all("Reply-To", [])) if "@" in addr]
    return_path = [addr.lower() for _, addr in getaddresses(msg.get_all("Return-Path", [])) if "@" in addr]

    msg_id = str(msg.get("Message-ID", "")).strip()
    msg_id_domain = msg_id.split("@", 1)[1].rstrip(">").lower() if "@" in msg_id else None
    raw_date = str(msg.get("Date", "")).strip()
    date_utc = None
    sender_tz_offset = None
    if raw_date:
        try:
            dt = parsedate_to_datetime(raw_date)
            if dt.tzinfo is not None:
                off_sec = dt.utcoffset().total_seconds()  # type: ignore[union-attr]
                sign = "+" if off_sec >= 0 else "-"
                abs_m = int(abs(off_sec) // 60)
                sender_tz_offset = f"{sign}{abs_m // 60:02d}:{abs_m % 60:02d}"
                date_utc = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # Parse Received headers bottom-to-top (originating MTA -> final recipient MTA)
    received_raw = list(reversed([str(h) for h in msg.get_all("Received", [])]))
    hops: list[dict[str, Any]] = []
    prev_dt: datetime | None = None
    public_relay_ips: list[str] = []

    for idx, rline in enumerate(received_raw, 1):
        compact = " ".join(rline.split())
        from_m = re.search(r"\bfrom\s+([^\s;()]+)", compact, re.IGNORECASE)
        by_m = re.search(r"\bby\s+([^\s;()]+)", compact, re.IGNORECASE)
        hop_ips = [ip for ip in IPV4_IN_HEADER_RE.findall(compact) if _is_public_ip(ip)]
        for hip in hop_ips:
            if hip not in public_relay_ips:
                public_relay_ips.append(hip)

        hop_dt = None
        if ";" in compact:
            tail_ts = compact.rsplit(";", 1)[1].strip()
            try:
                parsed_h = parsedate_to_datetime(tail_ts)
                if parsed_h.tzinfo is not None:
                    hop_dt = parsed_h.astimezone(timezone.utc)
            except Exception:
                pass

        delay_sec = None
        if hop_dt and prev_dt:
            delay_sec = round((hop_dt - prev_dt).total_seconds(), 2)
        if hop_dt:
            prev_dt = hop_dt

        hops.append(
            {
                "hop": idx,
                "from_host": from_m.group(1) if from_m else None,
                "by_host": by_m.group(1) if by_m else None,
                "public_ips": hop_ips,
                "timestamp_utc": hop_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if hop_dt else None,
                "transit_delay_seconds": delay_sec,
            }
        )

    for hdr in ("X-Originating-IP", "X-Sender-IP", "X-Real-IP"):
        for val in msg.get_all(hdr, []):
            for ip_cand in IPV4_IN_HEADER_RE.findall(str(val)):
                if _is_public_ip(ip_cand) and ip_cand not in public_relay_ips:
                    public_relay_ips.insert(0, ip_cand)

    auth_blob = " ; ".join(str(x) for x in msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", []))
    auth_verdicts = {}
    for mech in ("spf", "dkim", "dmarc"):
        am = re.search(rf"\b{mech}=([a-zA-Z0-9_-]+)", auth_blob, re.IGNORECASE)
        if am:
            auth_verdicts[mech] = am.group(1).lower()

    spoofing_flags: list[str] = []
    if from_addrs and reply_to and set(from_addrs) != set(reply_to):
        spoofing_flags.append(f"From ({from_addrs[0]}) differs from Reply-To ({reply_to[0]})")
    if from_addrs and return_path:
        f_dom = from_addrs[0].split("@", 1)[1]
        rp_dom = return_path[0].split("@", 1)[1]
        if f_dom != rp_dom:
            spoofing_flags.append(f"Header From domain ({f_dom}) differs from Return-Path domain ({rp_dom})")
    for mech, verd in auth_verdicts.items():
        if verd in ("fail", "softfail", "permerror", "temperror"):
            spoofing_flags.append(f"{mech.upper()} authentication returned '{verd}'")
    if any((h.get("transit_delay_seconds") or 0) < -5 for h in hops):
        spoofing_flags.append("Negative hop transit delay detected (MTA clock skew or forged Received header)")

    attachments: list[dict[str, Any]] = []
    carved_urls: set[str] = set()
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = part.get_content_disposition()
        fname = part.get_filename()
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        if fname or disp == "attachment":
            attachments.append(
                {
                    "filename": fname or "unnamed_part",
                    "content_type": ctype,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        elif ctype in ("text/plain", "text/html") and payload:
            txt = payload.decode("utf-8", errors="ignore")
            for u in URL_SIMPLE_RE.findall(txt):
                carved_urls.add(u.rstrip(".,;:)>\"'"))

    pivots: list[dict[str, str]] = []
    for em in sorted(set(from_addrs + reply_to + return_path)):
        pivots.append({"type": "email", "value": em, "reason": "eml_header_address"})
    for ip_c in public_relay_ips[:8]:
        pivots.append({"type": "ip", "value": ip_c, "reason": "eml_received_or_originating_ip"})
    if msg_id_domain and "." in msg_id_domain:
        pivots.append({"type": "domain", "value": msg_id_domain, "reason": "eml_message_id_fqdn"})
    for att in attachments[:5]:
        pivots.append({"type": "file_hash", "value": att["sha256"], "reason": f"eml_attachment:{att['filename']}"})

    return {
        "format": "RFC5322_EML",
        "subject": str(msg.get("Subject", "")),
        "from": from_addrs,
        "to_cc": to_addrs[:15],
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": msg_id,
        "message_id_domain": msg_id_domain,
        "date_utc": date_utc,
        "sender_timezone_offset": sender_tz_offset,
        "timezone_offsets": [sender_tz_offset] if sender_tz_offset else [],
        "mailer_user_agent": str(msg.get("X-Mailer") or msg.get("User-Agent") or ""),
        "authentication_verdicts": auth_verdicts,
        "spoofing_and_anomaly_flags": spoofing_flags,
        "received_hops": hops,
        "public_relay_ips": public_relay_ips,
        "attachments": attachments,
        "body_urls": sorted(carved_urls)[:25],
        "discovered_pivots": pivots,
    }


# ============================================================================
# 2. PURE-PYTHON PCAP & PCAPNG NETWORK FORENSIC CARVER (DNS, TLS SNI, HTTP)
# ============================================================================

def _parse_dns_qname(dns_payload: bytes) -> str | None:
    if len(dns_payload) < 17:
        return None
    flags = struct.unpack("!H", dns_payload[2:4])[0]
    qdcount = struct.unpack("!H", dns_payload[4:6])[0]
    # Standard query (QR == 0) with 1..4 questions
    if (flags & 0x8000) != 0 or not (1 <= qdcount <= 4):
        return None
    idx = 12
    labels: list[str] = []
    while idx < len(dns_payload):
        ln = dns_payload[idx]
        idx += 1
        if ln == 0:
            break
        if ln > 63 or idx + ln > len(dns_payload) or len(labels) > 12:
            return None
        lbl = dns_payload[idx : idx + ln].decode("ascii", errors="ignore")
        if not lbl or not all(c.isalnum() or c in "-_" for c in lbl):
            return None
        labels.append(lbl.lower())
        idx += ln
    if len(labels) >= 2:
        return ".".join(labels)
    return None


def _parse_tls_client_hello_sni(tcp_payload: bytes) -> str | None:
    # TLS Record: ContentType 0x16 (Handshake), Version 0x0301..0x0304, Length, HandshakeType 0x01 (ClientHello)
    if len(tcp_payload) < 43 or tcp_payload[0] != 0x16 or tcp_payload[5] != 0x01:
        return None
    try:
        pos = 9 + 2 + 32  # Skip TLS record(5) + Handshake hdr(4) + ClientVersion(2) + Random(32)
        if pos >= len(tcp_payload):
            return None
        sess_len = tcp_payload[pos]
        pos += 1 + sess_len
        if pos + 2 > len(tcp_payload):
            return None
        cs_len = struct.unpack("!H", tcp_payload[pos : pos + 2])[0]
        pos += 2 + cs_len
        if pos + 1 > len(tcp_payload):
            return None
        comp_len = tcp_payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(tcp_payload):
            return None
        ext_total = struct.unpack("!H", tcp_payload[pos : pos + 2])[0]
        pos += 2
        end_ext = min(len(tcp_payload), pos + ext_total)
        while pos + 4 <= end_ext:
            ext_type, ext_len = struct.unpack("!HH", tcp_payload[pos : pos + 4])
            pos += 4
            if ext_type == 0x0000 and pos + ext_len <= end_ext and ext_len >= 5:
                # ServerNameListLength(2), NameType(1)==0, HostNameLength(2)
                name_type = tcp_payload[pos + 2]
                name_len = struct.unpack("!H", tcp_payload[pos + 3 : pos + 5])[0]
                if name_type == 0 and pos + 5 + name_len <= end_ext:
                    sni = tcp_payload[pos + 5 : pos + 5 + name_len].decode("ascii", errors="ignore").lower()
                    if "." in sni:
                        return sni
            pos += ext_len
    except Exception:
        return None
    return None


def _iter_pcap_frames(data: bytes):
    """Yield (link_type, timestamp_sec_or_none, raw_frame_bytes) for classic PCAP and PCAPNG."""
    if len(data) < 24:
        return
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be in (0xA1B2C3D4, 0xA1B23C4D):
        endian = ">"
        nano = magic_be == 0xA1B23C4D
    elif magic_be in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = "<"
        nano = magic_be == 0x4D3CB2A1
    elif magic_be == 0x0A0D0D0A:
        # PCAPNG container
        pos = 0
        endian = "<"
        link_types: list[int] = [1]
        while pos + 12 <= len(data):
            btype = struct.unpack(endian + "I", data[pos : pos + 4])[0]
            if btype == 0x0A0D0D0A and pos + 12 <= len(data):
                bom = data[pos + 8 : pos + 12]
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                link_types = []
            blen = struct.unpack(endian + "I", data[pos + 4 : pos + 8])[0]
            if blen < 12 or pos + blen > len(data):
                break
            body = data[pos + 8 : pos + blen - 4]
            if btype == 0x00000001 and len(body) >= 4:  # Interface Description Block
                lt = struct.unpack(endian + "H", body[:2])[0]
                link_types.append(lt)
            elif btype == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block
                iface_id, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack(endian + "IIIII", body[:20])
                lt = link_types[iface_id] if iface_id < len(link_types) else 1
                ts_us = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                yield lt, ts_us, body[20 : 20 + cap_len]
            elif btype == 0x00000003 and len(body) >= 4:  # Simple Packet Block
                yield (link_types[0] if link_types else 1), None, body[4:]
            pos += blen
        return
    else:
        return

    link_type = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        if pos + incl_len > len(data):
            break
        ts = ts_sec + (ts_sub / (1e9 if nano else 1e6))
        yield link_type, ts, data[pos : pos + incl_len]
        pos += incl_len


def analyze_pcap_bytes(data: bytes) -> dict[str, Any]:
    """Carve DNS queries, TLS SNI hostnames, HTTP hosts/URIs, and public IPs from PCAP/PCAPNG."""
    packet_count = 0
    public_ips: set[str] = set()
    dns_queries: set[str] = set()
    tls_sni_hosts: set[str] = set()
    http_requests: list[dict[str, str]] = []
    user_agents: set[str] = set()
    ts_min: float | None = None
    ts_max: float | None = None

    for link_type, ts, frame in _iter_pcap_frames(data):
        packet_count += 1
        if packet_count > 25_000:
            break
        if ts and 946684800 <= ts <= 2051222400:
            ts_min = ts if ts_min is None else min(ts_min, ts)
            ts_max = ts if ts_max is None else max(ts_max, ts)

        # Strip L2 header to reach IP packet
        ip_pkt = b""
        if link_type == 1 and len(frame) >= 14:  # Ethernet
            eth_type = struct.unpack("!H", frame[12:14])[0]
            offset = 14
            if eth_type == 0x8100 and len(frame) >= 18:  # 802.1Q VLAN
                eth_type = struct.unpack("!H", frame[16:18])[0]
                offset = 18
            if eth_type in (0x0800, 0x86DD):
                ip_pkt = frame[offset:]
        elif link_type == 101:  # Raw IP
            ip_pkt = frame
        elif link_type == 113 and len(frame) >= 16:  # Linux cooked SLL
            ip_pkt = frame[16:]
        elif link_type == 0 and len(frame) >= 4:  # BSD loopback
            ip_pkt = frame[4:]

        if len(ip_pkt) < 20:
            continue
        ver = ip_pkt[0] >> 4
        proto = 0
        l4_pkt = b""
        if ver == 4 and len(ip_pkt) >= 20:
            ihl = (ip_pkt[0] & 0x0F) * 4
            if len(ip_pkt) < ihl:
                continue
            proto = ip_pkt[9]
            src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt[12:16])
            dst_ip = socket.inet_ntop(socket.AF_INET, ip_pkt[16:20])
            for ip_c in (src_ip, dst_ip):
                if _is_public_ip(ip_c):
                    public_ips.add(ip_c)
            l4_pkt = ip_pkt[ihl:]
        elif ver == 6 and len(ip_pkt) >= 40:
            proto = ip_pkt[6]
            src_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt[24:40])
            for ip_c in (src_ip, dst_ip):
                if _is_public_ip(ip_c):
                    public_ips.add(ip_c)
            l4_pkt = ip_pkt[40:]

        if proto == 17 and len(l4_pkt) >= 8:  # UDP
            sport, dport = struct.unpack("!HH", l4_pkt[:4])
            udp_body = l4_pkt[8:]
            if 53 in (sport, dport) or 5353 in (sport, dport):
                qn = _parse_dns_qname(udp_body)
                if qn:
                    dns_queries.add(qn)
        elif proto == 6 and len(l4_pkt) >= 20:  # TCP
            sport, dport = struct.unpack("!HH", l4_pkt[:4])
            doff = ((l4_pkt[12] >> 4) & 0x0F) * 4
            if len(l4_pkt) <= doff:
                continue
            tcp_body = l4_pkt[doff:]
            if tcp_body and tcp_body[0] == 0x16:
                sni = _parse_tls_client_hello_sni(tcp_body)
                if sni:
                    tls_sni_hosts.add(sni)
            elif tcp_body[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                hdr_txt = tcp_body[:2048].decode("latin-1", errors="ignore")
                lines = hdr_txt.split("\r\n")
                req_line = lines[0]
                host_val = ""
                auth_scheme = ""
                for hl in lines[1:25]:
                    low = hl.lower()
                    if low.startswith("host:"):
                        host_val = hl.split(":", 1)[1].strip().lower()
                    elif low.startswith("user-agent:"):
                        user_agents.add(hl.split(":", 1)[1].strip()[:120])
                    elif low.startswith("authorization:"):
                        auth_scheme = hl.split(":", 1)[1].strip().split(" ", 1)[0]
                if host_val and len(http_requests) < 40:
                    parts = req_line.split(" ")
                    path = parts[1] if len(parts) >= 2 else "/"
                    http_requests.append(
                        {
                            "method": parts[0],
                            "url": f"http://{host_val}{path}",
                            "host": host_val,
                            "auth_scheme": auth_scheme,
                        }
                    )

    pivots: list[dict[str, str]] = []
    for d in sorted(dns_queries | tls_sni_hosts)[:15]:
        pivots.append({"type": "domain", "value": d.split(":")[0], "reason": "pcap_dns_or_tls_sni"})
    for ip_c in sorted(public_ips)[:10]:
        pivots.append({"type": "ip", "value": ip_c, "reason": "pcap_public_endpoint"})

    return {
        "format": "PCAP_OR_PCAPNG",
        "packets_inspected": packet_count,
        "capture_start_utc": datetime.fromtimestamp(ts_min, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts_min else None,
        "capture_end_utc": datetime.fromtimestamp(ts_max, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts_max else None,
        "public_ips": sorted(public_ips)[:40],
        "dns_queries": sorted(dns_queries)[:50],
        "tls_sni_hostnames": sorted(tls_sni_hosts)[:50],
        "http_requests": http_requests[:25],
        "http_user_agents": sorted(user_agents)[:15],
        "discovered_pivots": pivots,
    }


# ============================================================================
# 3. BROWSER HTTP ARCHIVE (.har) FORENSIC CARVER
# ============================================================================

def analyze_har_bytes(data: bytes) -> dict[str, Any]:
    """Extract domains, server IPs, API endpoints, User-Agents & auth leaks from W3C .har files."""
    obj = json.loads(data.decode("utf-8", errors="replace"))
    entries = (obj.get("log") or {}).get("entries") or []
    domains: set[str] = set()
    server_ips: set[str] = set()
    endpoints: list[str] = []
    auth_headers_found: list[str] = []
    user_agents: set[str] = set()
    timestamps: list[str] = []

    for ent in entries[:2000]:
        st_dt = ent.get("startedDateTime")
        if isinstance(st_dt, str) and st_dt:
            timestamps.append(st_dt)
        sip = str(ent.get("serverIPAddress") or "").strip("[]")
        if sip and _is_public_ip(sip):
            server_ips.add(sip)
        req = ent.get("request") or {}
        url = str(req.get("url") or "")
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
            clean_ep = f"{req.get('method', 'GET')} {parsed.scheme}://{parsed.netloc}{parsed.path}"
            if clean_ep not in endpoints and len(endpoints) < 40:
                endpoints.append(clean_ep)
        for hdr in req.get("headers") or []:
            hname = str(hdr.get("name") or "").lower()
            hval = str(hdr.get("value") or "")
            if hname == "user-agent" and hval:
                user_agents.add(hval[:120])
            elif hname in ("authorization", "x-api-key", "api-key") and hval:
                scheme = hval.split(" ", 1)[0] if " " in hval else hname
                tag = f"{hname}:{scheme} on {url[:60]}"
                if tag not in auth_headers_found and len(auth_headers_found) < 15:
                    auth_headers_found.append(tag)

    timestamps.sort()
    pivots = [{"type": "domain", "value": d, "reason": "har_request_host"} for d in sorted(domains)[:12]]
    pivots.extend({"type": "ip", "value": ip, "reason": "har_server_ip"} for ip in sorted(server_ips)[:8])
    return {
        "format": "W3C_HAR",
        "total_entries": len(entries),
        "first_request_utc": timestamps[0] if timestamps else None,
        "last_request_utc": timestamps[-1] if timestamps else None,
        "unique_domains": sorted(domains)[:50],
        "public_server_ips": sorted(server_ips)[:30],
        "sample_endpoints": endpoints,
        "user_agents": sorted(user_agents)[:10],
        "auth_headers_detected": auth_headers_found,
        "discovered_pivots": pivots,
    }


# ============================================================================
# 4. MP4 / MOV QUICKTIME CONTAINER & ©xyz GPS FORENSICS
# ============================================================================

def analyze_mp4_mov_bytes(data: bytes) -> dict[str, Any]:
    """Parse ISO BMFF / QuickTime boxes (`ftyp`, `mvhd`, `©xyz`) for UTC creation time & GPS."""
    major_brand = None
    creation_utc = None
    modification_utc = None
    duration_seconds = None
    gps_coords = None

    def _walk_boxes(buf: bytes, depth: int = 0) -> None:
        nonlocal major_brand, creation_utc, modification_utc, duration_seconds, gps_coords
        if depth > 6:
            return
        pos = 0
        n = len(buf)
        while pos + 8 <= n:
            size = struct.unpack(">I", buf[pos : pos + 4])[0]
            btype = buf[pos + 4 : pos + 8]
            hdr_len = 8
            if size == 1 and pos + 16 <= n:
                size = struct.unpack(">Q", buf[pos + 8 : pos + 16])[0]
                hdr_len = 16
            elif size == 0:
                size = n - pos
            if size < hdr_len or pos + size > n:
                break
            payload = buf[pos + hdr_len : pos + size]

            if btype == b"ftyp" and len(payload) >= 4:
                major_brand = payload[:4].decode("ascii", errors="ignore").strip()
            elif btype == b"mvhd" and len(payload) >= 20:
                ver = payload[0]
                if ver == 0 and len(payload) >= 20:
                    ctime, mtime, scale, dur = struct.unpack(">IIII", payload[4:20])
                elif ver == 1 and len(payload) >= 32:
                    ctime, mtime, scale, dur = struct.unpack(">QQIQ", payload[4:32])
                else:
                    ctime = mtime = scale = dur = 0
                if ctime > MAC_HFS_EPOCH_OFFSET:
                    unix_c = ctime - MAC_HFS_EPOCH_OFFSET
                    if 631152000 <= unix_c <= 2051222400:
                        creation_utc = datetime.fromtimestamp(unix_c, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if mtime > MAC_HFS_EPOCH_OFFSET:
                    unix_m = mtime - MAC_HFS_EPOCH_OFFSET
                    if 631152000 <= unix_m <= 2051222400:
                        modification_utc = datetime.fromtimestamp(unix_m, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if scale > 0 and dur > 0:
                    duration_seconds = round(dur / float(scale), 2)
            elif btype in (b"\xa9xyz", b"loci") and payload:
                txt = payload.decode("latin-1", errors="ignore")
                gm = ISO6709_RE.search(txt)
                if gm:
                    lat, lon = float(gm.group(1)), float(gm.group(2))
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        gps_coords = f"{lat:.6f},{lon:.6f}"
            elif btype in (b"moov", b"trak", b"mdia", b"minf", b"udta", b"ilst"):
                _walk_boxes(payload, depth + 1)
            elif btype == b"meta" and len(payload) > 4:
                # QuickTime `meta` may or may not have a 4-byte version/flags fullbox header
                _walk_boxes(payload[4:], depth + 1)
                _walk_boxes(payload, depth + 1)

            pos += size

    _walk_boxes(data)
    # Fallback scan for ISO-6709 GPS string in XMP/udta tail if custom DJI/GoPro atom was used
    if not gps_coords:
        idx = data.find(b"\xa9xyz")
        if idx != -1:
            gm = ISO6709_RE.search(data[idx : idx + 64].decode("latin-1", errors="ignore"))
            if gm:
                gps_coords = f"{float(gm.group(1)):.6f},{float(gm.group(2)):.6f}"

    c2pa_detected = any(sig in data for sig in (b"c2pa", b"c2pa.claim", b"jumb"))
    pivots = []
    if gps_coords:
        pivots.append({"type": "coordinates", "value": gps_coords, "reason": "mp4_quicktime_iso6709_gps"})

    return {
        "format": "MP4_MOV_BMFF",
        "major_brand": major_brand,
        "creation_utc_iso": creation_utc,
        "modification_utc_iso": modification_utc,
        "duration_seconds": duration_seconds,
        "gps_coordinates": gps_coords,
        "c2pa_jumbf_present": c2pa_detected,
        "discovered_pivots": pivots,
    }


# ============================================================================
# 5. PNG / WEBP / C2PA CONTENT CREDENTIALS & AI GENERATION PROMPT DETECTOR
# ============================================================================

AI_TOOL_SIGNATURES: dict[str, bytes] = {
    "Adobe Firefly / C2PA": b"Firefly",
    "OpenAI DALL-E / C2PA": b"OpenAI",
    "Google SynthID / DeepMind": b"SynthID",
    "Midjourney": b"Midjourney",
    "Stable Diffusion (A1111/Forge)": b"Negative prompt:",
    "ComfyUI Node Graph": b"class_type",
    "Black Forest Labs Flux": b"flux",
    "Leica Content Credentials": b"Leica",
}


def analyze_png_webp_c2pa_bytes(data: bytes) -> dict[str, Any]:
    """Extract PNG tEXt/zTXt/iTXt/tIME/caBX chunks, C2PA claims & AI diffusion prompts."""
    width = height = None
    png_modify_utc = None
    text_chunks: dict[str, str] = {}
    chunk_types: list[str] = []

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        while pos + 8 <= len(data):
            clen = struct.unpack(">I", data[pos : pos + 4])[0]
            ctype = data[pos + 4 : pos + 8].decode("latin-1", errors="ignore")
            if pos + 12 + clen > len(data):
                break
            cbody = data[pos + 8 : pos + 8 + clen]
            if len(chunk_types) < 30:
                chunk_types.append(ctype)

            if ctype == "IHDR" and len(cbody) >= 8:
                width, height = struct.unpack(">II", cbody[:8])
            elif ctype == "tIME" and len(cbody) == 7:
                yr, mo, dy, hh, mm, ss = struct.unpack(">HBBBBB", cbody)
                if 1990 <= yr <= 2035 and 1 <= mo <= 12 and 1 <= dy <= 31:
                    png_modify_utc = f"{yr:04d}-{mo:02d}-{dy:02d}T{hh:02d}:{mm:02d}:{ss:02d}Z"
            elif ctype == "tEXt" and b"\x00" in cbody:
                k, v = cbody.split(b"\x00", 1)
                text_chunks[k.decode("latin-1", errors="ignore")] = v.decode("utf-8", errors="replace")[:2000]
            elif ctype == "zTXt" and b"\x00" in cbody:
                k, rest = cbody.split(b"\x00", 1)
                if len(rest) > 1 and rest[0] == 0:
                    try:
                        inflated = zlib.decompress(rest[1:])
                        text_chunks[k.decode("latin-1", errors="ignore")] = inflated.decode("utf-8", errors="replace")[:2000]
                    except Exception:
                        pass
            elif ctype == "iTXt" and b"\x00" in cbody:
                parts = cbody.split(b"\x00", 5)
                if len(parts) >= 6:
                    comp_flag = parts[1][:1]
                    raw_txt = parts[5]
                    if comp_flag == b"\x01":
                        try:
                            raw_txt = zlib.decompress(raw_txt)
                        except Exception:
                            pass
                    text_chunks[parts[0].decode("latin-1", errors="ignore")] = raw_txt.decode("utf-8", errors="replace")[:2000]

            pos += 12 + clen

    c2pa_markers = [
        m.decode("ascii")
        for m in (b"c2pa", b"c2pa.claim", b"c2pa.assertions", b"caBX", b"jumb", b"trainedAlgorithmicMedia", b"compositeWithTrainedAlgorithmicMedia")
        if m in data
    ]
    matched_ai_vendors = [label for label, needle in AI_TOOL_SIGNATURES.items() if needle in data]

    ai_generation_type = None
    if "parameters" in text_chunks:
        ai_generation_type = "Stable Diffusion (parameters chunk)"
    elif "prompt" in text_chunks or "workflow" in text_chunks:
        ai_generation_type = "ComfyUI (prompt/workflow JSON chunk)"
    elif b"trainedAlgorithmicMedia" in data:
        ai_generation_type = "IPTC / C2PA Trained Algorithmic Media (AI-Generated)"

    return {
        "dimensions": f"{width}x{height}" if width and height else None,
        "png_chunk_types": chunk_types,
        "png_last_modified_utc": png_modify_utc,
        "embedded_text_metadata": text_chunks,
        "c2pa_content_credentials_detected": bool(c2pa_markers),
        "c2pa_markers": c2pa_markers,
        "ai_provenance_classification": ai_generation_type,
        "ai_or_camera_signatures": matched_ai_vendors,
    }


# ============================================================================
# 6. GOOGLE SEARCH `ei=` URL PARAMETER CHRONOLOCATION DECODER
# ============================================================================

def decode_google_ei_parameter(raw: str) -> dict[str, Any] | None:
    """Decode Google Search `ei=` parameter into exact server-side UTC search timestamp."""
    s = (raw or "").strip()
    ei_val = None
    if "ei=" in s:
        m = re.search(r"[?&]ei=([A-Za-z0-9_-]{6,64})", s)
        if m:
            ei_val = m.group(1)
    elif s.lower().startswith("ei="):
        ei_val = s.split("=", 1)[1].strip()

    if not ei_val:
        return None
    pad = "=" * ((4 - len(ei_val) % 4) % 4)
    try:
        raw_bytes = base64.urlsafe_b64decode(ei_val + pad)
    except Exception:
        return None
    if len(raw_bytes) < 4:
        return None

    unix_sec = struct.unpack("<I", raw_bytes[:4])[0]
    if not (1072915200 <= unix_sec <= 2051222400):  # 2004 .. 2035
        return None
    dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
    return {
        "decoder": "google_ei_chronolocation",
        "ei_parameter": ei_val,
        "search_unix_epoch": unix_sec,
        "search_utc_iso": dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "forensic_note": "Google's `ei` query parameter encodes the exact 32-bit little-endian UTC Unix second the SERP was generated.",
    }


# ============================================================================
# 7. OPENSSH PUBLIC KEY & PEM X.509 CERTIFICATE OFFLINE FINGERPRINTER
# ============================================================================

def decode_ssh_pubkey_or_pem(raw: str) -> dict[str, Any] | None:
    """Compute SHA256/MD5 fingerprints, key bit-lengths & comments from OpenSSH pubkeys or PEM certs."""
    s = (raw or "").strip()

    sm = SSH_PUBKEY_RE.search(s)
    if sm:
        b64_blob = sm.group(2)
        comment = (sm.group(3) or "").strip() or None
        try:
            wire = base64.b64decode(b64_blob, validate=True)
        except Exception:
            wire = b""
        if len(wire) >= 12:
            ktype_len = struct.unpack(">I", wire[:4])[0]
            wire_ktype = wire[4 : 4 + ktype_len].decode("ascii", errors="ignore") if 4 + ktype_len <= len(wire) else ""
            rsa_bits = None
            if wire_ktype == "ssh-rsa" and 4 + ktype_len + 4 < len(wire):
                pos = 4 + ktype_len
                exp_len = struct.unpack(">I", wire[pos : pos + 4])[0]
                pos += 4 + exp_len
                if pos + 4 <= len(wire):
                    mod_len = struct.unpack(">I", wire[pos : pos + 4])[0]
                    mod_bytes = wire[pos + 4 : pos + 4 + mod_len].lstrip(b"\x00")
                    rsa_bits = len(mod_bytes) * 8

            sha256_b64 = base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
            md5_hex = ":".join(f"{b:02x}" for b in hashlib.md5(wire).digest())
            comment_email = None
            if comment:
                em = EMAIL_SIMPLE_RE.search(comment)
                if em:
                    comment_email = em.group(0).lower()
            return {
                "decoder": "openssh_public_key",
                "key_type": wire_ktype,
                "rsa_modulus_bits": rsa_bits,
                "fingerprint_sha256": f"SHA256:{sha256_b64}",
                "fingerprint_md5": f"MD5:{md5_hex}",
                "comment": comment,
                "leaked_email_in_comment": comment_email,
            }

    pm = PEM_CERT_RE.search(s)
    if pm:
        pem_kind = pm.group(1)
        b64_body = re.sub(r"\s+", "", pm.group(2))
        try:
            der = base64.b64decode(b64_body)
            sha256_hex = hashlib.sha256(der).hexdigest()
            return {
                "decoder": "pem_der_fingerprint",
                "pem_block_type": pem_kind,
                "der_size_bytes": len(der),
                "sha256_fingerprint": sha256_hex,
                "censys_search_dork": f"https://search.censys.io/certificates/{sha256_hex}" if pem_kind == "CERTIFICATE" else None,
            }
        except Exception:
            return None

    return None

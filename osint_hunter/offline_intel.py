"""Zero-network deterministic OSINT decoders & local binary forensic parsers."""

from __future__ import annotations

import base64
import email
import hashlib
import ipaddress
import json
import re
import struct
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .classify import (
    DOMAIN_RE,
    EMAIL_RE,
    EVM_RE,
    IPV4_RE,
    NOISE_DOMAINS,
    PROMPT_STOPWORDS,
    URL_RE,
    VIN_TRANSLITERATION,
    VIN_WEIGHTS,
    extract_selectors,
    is_valid_imo,
)
from .paths import DATA_DIR

with (DATA_DIR / "intel_tables.json").open("r", encoding="utf-8") as _fh:
    INTEL_TABLES = json.load(_fh)

VIN_YEAR_MAP = {
    "A": "2010 / 1980", "B": "2011 / 1981", "C": "2012 / 1982", "D": "2013 / 1983",
    "E": "2014 / 1984", "F": "2015 / 1985", "G": "2016 / 1986", "H": "2017 / 1987",
    "J": "2018 / 1988", "K": "2019 / 1989", "L": "2020 / 1990", "M": "2021 / 1991",
    "N": "2022 / 1992", "P": "2023 / 1993", "R": "2024 / 1994", "S": "2025 / 1995",
    "T": "2026 / 1996", "V": "2027 / 1997", "W": "2028 / 1998", "X": "2029 / 1999",
    "Y": "2000", "1": "2001", "2": "2002", "3": "2003", "4": "2004",
    "5": "2005", "6": "2006", "7": "2007", "8": "2008", "9": "2009",
}


def decode_phone(e164: str) -> dict:
    digits = re.sub(r"\D", "", e164)
    countries = INTEL_TABLES["e164_countries"]
    cc = None
    country = "Unknown ITU Prefix"
    for length in (3, 2, 1):
        prefix = digits[:length]
        if prefix in countries:
            cc = prefix
            country = countries[prefix]
            break

    national = digits[len(cc):] if cc else digits
    region_or_carrier = None
    if cc == "1" and len(national) >= 3:
        npa = national[:3]
        region_or_carrier = INTEL_TABLES["nanpa_area_codes"].get(npa, f"NANPA Area Code {npa}")
    elif cc == "966" and len(national) >= 2:
        p2 = national[:2]
        region_or_carrier = INTEL_TABLES["saudi_mobile_prefixes"].get(p2, f"Saudi National Prefix {p2}")
    elif cc and cc in INTEL_TABLES.get("regional_mobile_prefixes", {}):
        cmap = INTEL_TABLES["regional_mobile_prefixes"][cc]
        for plen in (3, 2, 1):
            if len(national) >= plen and national[:plen] in cmap:
                region_or_carrier = cmap[national[:plen]]
                break

    return {
        "e164": f"+{digits}",
        "country_code": f"+{cc}" if cc else None,
        "country": country,
        "national_number": national,
        "carrier_or_region_hint": region_or_carrier,
        "digit_length": len(digits),
        "messaging_pivots": {
            "whatsapp_deeplink": f"https://wa.me/{digits}",
            "telegram_deeplink": f"https://t.me/+{digits}",
        },
        "dork_formats": [
            f"\"+{digits}\"",
            f"\"{digits}\"",
            f"\"+{cc} {national}\"" if cc else f"\"{digits}\"",
        ],
    }


def decode_aircraft_hex(hex6: str) -> dict:
    h = hex6.strip().upper()
    val = int(h, 16)
    country = "Unallocated / Unknown ICAO Block"
    military_flag = False
    military_unit = None

    for blk in INTEL_TABLES["icao_hex_blocks"]:
        if int(blk["start"], 16) <= val <= int(blk["end"], 16):
            country = blk["country"]
            for m_start, m_end, m_desc in blk.get("mil_ranges", []):
                if int(m_start, 16) <= val <= int(m_end, 16):
                    military_flag = True
                    military_unit = m_desc
            break

    return {
        "icao24_hex": h,
        "registration_country": country,
        "is_military_or_gov_block": military_flag,
        "military_block_detail": military_unit,
        "live_tracking_links": {
            "adsb_exchange": f"https://globe.adsbexchange.com/?icao={h.lower()}",
            "airplanes_live": f"https://globe.airplanes.live/?icao={h.lower()}",
            "planespotters": f"https://www.planespotters.net/hex/{h}",
        },
    }


def decode_vessel_identifier(raw: str) -> dict:
    digits = re.sub(r"\D", "", raw)
    upper = raw.upper()
    if "IMO" in upper or len(digits) == 7:
        valid = is_valid_imo(digits)
        return {
            "identifier_type": "IMO",
            "imo_number": f"IMO {digits}",
            "imo_checksum_valid": valid,
            "note": "IMO hull numbers stay permanently welded to the vessel across name, owner, and flag changes.",
            "registry_links": {
                "equasis_inspection": "https://www.equasis.org/",
                "marinetraffic": f"https://www.marinetraffic.com/en/ais/details/ships/imo:{digits}",
                "vesselfinder": f"https://www.vesselfinder.com/vessels/details/{digits}",
            },
        }

    mids = INTEL_TABLES["maritime_mid"]
    station_type = "Standard Shipborne AIS Transponder"
    mid = digits[:3]
    if digits.startswith("00"):
        station_type = "Coastal Base Station"
        mid = digits[2:5]
    elif digits.startswith("111"):
        station_type = "Search & Rescue (SAR) Aircraft"
        mid = digits[3:6]
    elif digits.startswith("99"):
        station_type = "AIS Aid-to-Navigation (Buoy / Lighthouse)"
        mid = digits[2:5]

    flag = mids.get(mid, f"Unknown MID ({mid})")
    shadow_watch = any(k in flag for k in ("Cameroon", "Gabon", "Comoros", "Palau", "Tanzania", "Sierra Leone"))
    return {
        "identifier_type": "MMSI",
        "mmsi": digits,
        "mid_code": mid,
        "flag_state": flag,
        "station_type": station_type,
        "shadow_fleet_high_watch_flag": shadow_watch,
        "registry_links": {
            "itu_mars": "https://www.itu.int/en/ITU-R/terrestrial/mars/Pages/default.aspx",
            "marinetraffic": f"https://www.marinetraffic.com/en/ais/details/ships/mmsi:{digits}",
            "vesselfinder": f"https://www.vesselfinder.com/?mmsi={digits}",
        },
    }


def decode_vin(vin: str) -> dict:
    v = vin.strip().upper()
    wmi = v[:3]
    vds = v[3:9]
    vis = v[9:]
    year_char = v[9]
    plant_char = v[10]
    serial = v[11:]

    total = sum(VIN_TRANSLITERATION.get(ch, 0) * VIN_WEIGHTS[i] for i, ch in enumerate(v))
    rem = total % 11
    expected_chk = "X" if rem == 10 else str(rem)
    chk_valid = v[8] == expected_chk

    first = v[0]
    region = {
        "1": "United States", "4": "United States", "5": "United States", "7": "United States",
        "2": "Canada", "3": "Mexico", "J": "Japan", "K": "South Korea", "L": "China",
        "S": "United Kingdom", "V": "France / Spain", "W": "Germany", "X": "Europe / Russia",
        "Y": "Sweden / Finland", "Z": "Italy",
    }.get(first, "International ISO 3779 Region")

    return {
        "vin": v,
        "wmi": wmi,
        "manufacturer": INTEL_TABLES["vin_wmi"].get(wmi, f"WMI {wmi} ({region})"),
        "country_region": region,
        "vds_descriptor": vds,
        "vis_identifier": vis,
        "model_year_estimate": VIN_YEAR_MAP.get(year_char, "Unknown"),
        "assembly_plant_code": plant_char,
        "production_serial": serial,
        "north_america_check_digit_valid": chk_valid,
        "salvage_and_gov_links": {
            "nhtsa_vpic_json": f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{v}?format=json",
            "bidfax_auction_photos": f"https://en.bidfax.info/search?q={v}",
        },
    }


def decode_mac_bssid(mac: str) -> dict:
    norm = mac.upper().replace("-", ":")
    octets = norm.split(":")
    oui = ":".join(octets[:3])
    first_byte = int(octets[0], 16)
    is_multicast = bool(first_byte & 0b00000001)
    is_locally_administered = bool(first_byte & 0b00000010)

    # EUI-64 SLAAC IPv6 interface ID (flip 7th bit of first byte, insert FF:FE)
    flipped = first_byte ^ 0x02
    eui64_iid = f"{flipped:02x}{octets[1].lower()}:{octets[2].lower()}ff:fe{octets[3].lower()}:{octets[4].lower()}{octets[5].lower()}"

    vendor = INTEL_TABLES["oui_vendors"].get(oui)
    if not vendor and is_locally_administered:
        vendor = "Randomized / Locally Administered MAC (iOS / Android / Modern OS Privacy MAC or Virtual NIC)"
    elif not vendor:
        vendor = f"Unlisted IEEE OUI ({oui}) — query WiGLE / Wireshark OUI DB"

    return {
        "bssid_mac": norm,
        "oui_prefix": oui,
        "vendor": vendor,
        "locally_administered_randomized": is_locally_administered,
        "multicast_group_address": is_multicast,
        "ipv6_slaac_link_local": f"fe80::{eui64_iid}",
        "pivots": {
            "wigle_lookup": f"https://wigle.net/search?netid={norm}",
        },
    }


def decode_ip_offline(ip_str: str) -> dict:
    ip_obj = ipaddress.ip_address(ip_str)
    info = {
        "ip": str(ip_obj),
        "version": f"IPv{ip_obj.version}",
        "is_private_rfc1918": ip_obj.is_private,
        "is_global_routable": ip_obj.is_global,
        "is_multicast": ip_obj.is_multicast,
        "reverse_ptr_name": ip_obj.reverse_pointer,
    }
    # Check EUI-64 embedded MAC in IPv6!
    if ip_obj.version == 6:
        packed = ip_obj.packed
        if packed[11] == 0xFF and packed[12] == 0xFE:
            mac_b = [packed[8] ^ 0x02, packed[9], packed[10], packed[13], packed[14], packed[15]]
            embedded_mac = ":".join(f"{b:02X}" for b in mac_b)
            info["embedded_eui64_mac"] = embedded_mac
            info["embedded_mac_intel"] = decode_mac_bssid(embedded_mac)
    return info


def decode_crypto_address(addr: str) -> dict:
    a = addr.strip()
    if a.endswith(".eth"):
        chain = "Ethereum Name Service (ENS)"
        explorers = {
            "ens_app": f"https://app.ens.domains/{a}",
            "web3_bio": f"https://web3.bio/{a}",
        }
    elif EVM_RE.fullmatch(a):
        chain = "EVM Compatible (Ethereum / Arbitrum / Base / Optimism / Polygon / BSC)"
        is_mixed_case = a != a.lower() and a != a.upper()
        explorers = {
            "etherscan": f"https://etherscan.io/address/{a}",
            "blockscan_multichain": f"https://blockscan.com/address/{a}",
            "arkham": f"https://platform.arkhamintelligence.com/explorer/address/{a}",
            "debank_portfolio": f"https://debank.com/profile/{a}",
            "web3_bio": f"https://web3.bio/{a}",
        }
        return {
            "address": a,
            "ecosystem": chain,
            "has_eip55_mixed_case": is_mixed_case,
            "ofac_oracle_contract": "0x40C57923924B5c5c5455c48D93317139ADDaC8fb",
            "explorers": explorers,
        }
    elif a.startswith(("bc1p",)):
        chain = "Bitcoin Taproot (P2TR Bech32m)"
        explorers = {"mempool_space": f"https://mempool.space/address/{a}", "oxt_me": f"https://oxt.me/address/{a}"}
    elif a.startswith(("bc1q",)):
        chain = "Bitcoin Native SegWit (Bech32)"
        explorers = {"mempool_space": f"https://mempool.space/address/{a}", "oxt_me": f"https://oxt.me/address/{a}"}
    elif a.startswith(("1", "3")):
        chain = "Bitcoin Legacy / P2SH"
        explorers = {"mempool_space": f"https://mempool.space/address/{a}", "blockchair": f"https://blockchair.com/bitcoin/address/{a}"}
    elif a.startswith("T"):
        chain = "TRON (TRC-20 USDT High-Volume Network)"
        explorers = {"tronscan": f"https://tronscan.org/#/address/{a}", "oklink": f"https://www.oklink.com/trx/address/{a}"}
    else:
        chain = "Multi-Chain Address Candidate"
        explorers = {"blockchair": f"https://blockchair.com/search?q={a}"}

    return {"address": a, "ecosystem": chain, "explorers": explorers}


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT structure"}

    def _b64(seg: str):
        pad = seg + "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(pad.encode("ascii")).decode("utf-8", errors="replace"))

    header = _b64(parts[0])
    payload = _b64(parts[1])
    timestamps = {}
    for k in ("iat", "exp", "nbf", "auth_time"):
        if isinstance(payload.get(k), (int, float)):
            timestamps[f"{k}_utc"] = datetime.fromtimestamp(payload[k], tz=timezone.utc).isoformat()

    pivots = []
    for k, v in payload.items():
        if isinstance(v, str):
            if "@" in v and EMAIL_RE.fullmatch(v):
                pivots.append({"type": "email", "value": v.lower()})
            elif v.startswith("http"):
                pivots.append({"type": "url", "value": v})

    return {
        "header": header,
        "payload": payload,
        "decoded_timestamps": timestamps,
        "extracted_pivots": pivots,
    }


def parse_pgp_armored_keys(armored_text: str) -> dict:
    """Pure-Python RFC 4880 OpenPGP packet parser extracting User IDs & key creation UTC dates."""
    uids: list[str] = []
    creation_dates: list[str] = []
    emails: list[str] = []

    blocks = re.findall(
        r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
        armored_text,
        flags=re.DOTALL,
    )
    for blk in blocks:
        lines = [ln.strip() for ln in blk.splitlines() if ln.strip() and not ln.startswith("-----") and ":" not in ln]
        body_lines = [ln for ln in lines if not ln.startswith("=")]
        try:
            raw = base64.b64decode("".join(body_lines))
        except Exception:
            continue

        idx = 0
        n = len(raw)
        while idx < n:
            ctb = raw[idx]
            idx += 1
            if not (ctb & 0x80):
                break
            if ctb & 0x40:  # New packet format
                tag = ctb & 0x3F
                if idx >= n:
                    break
                l0 = raw[idx]
                idx += 1
                if l0 < 192:
                    plen = l0
                elif l0 < 224 and idx < n:
                    plen = ((l0 - 192) << 8) + raw[idx] + 192
                    idx += 1
                elif l0 == 255 and idx + 4 <= n:
                    plen = struct.unpack(">I", raw[idx : idx + 4])[0]
                    idx += 4
                else:
                    break
            else:  # Old packet format
                tag = (ctb >> 2) & 0x0F
                ltype = ctb & 0x03
                if ltype == 0 and idx < n:
                    plen = raw[idx]
                    idx += 1
                elif ltype == 1 and idx + 2 <= n:
                    plen = struct.unpack(">H", raw[idx : idx + 2])[0]
                    idx += 2
                elif ltype == 2 and idx + 4 <= n:
                    plen = struct.unpack(">I", raw[idx : idx + 4])[0]
                    idx += 4
                else:
                    break

            body = raw[idx : idx + plen]
            idx += plen

            if tag in (6, 14) and len(body) >= 5 and body[0] == 4:
                ts = struct.unpack(">I", body[1:5])[0]
                if 700000000 < ts < 2200000000:
                    creation_dates.append(datetime.fromtimestamp(ts, tz=timezone.utc).isoformat())
            elif tag == 13:  # User ID Packet!
                uid_str = body.decode("utf-8", errors="replace").strip()
                if uid_str and uid_str not in uids:
                    uids.append(uid_str)
                for em in EMAIL_RE.findall(uid_str):
                    if em.lower() not in emails:
                        emails.append(em.lower())

    return {
        "pgp_key_blocks_found": len(blocks),
        "user_ids": uids,
        "extracted_emails": emails,
        "key_creation_timestamps_utc": sorted(set(creation_dates)),
    }


def _parse_jpeg_exif(data: bytes) -> dict:
    """Minimal pure-Python JPEG APP1 EXIF & GPS IFD parser."""
    if not data.startswith(b"\xff\xd8"):
        return {}
    pos = 2
    exif_out: dict = {}
    while pos + 4 < len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if marker == 0xE1 and data[pos + 4 : pos + 10] == b"Exif\x00\x00":
            tiff = data[pos + 10 : pos + 2 + seg_len]
            if len(tiff) < 8:
                break
            endian = "<" if tiff[:2] == b"II" else ">"
            ifd0_off = struct.unpack(endian + "I", tiff[4:8])[0]

            def read_ifd(offset: int) -> dict[int, object]:
                entries: dict[int, object] = {}
                if offset + 2 > len(tiff):
                    return entries
                cnt = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
                for i in range(cnt):
                    e_off = offset + 2 + i * 12
                    if e_off + 12 > len(tiff):
                        break
                    tag, ftype, count, val_raw = struct.unpack(endian + "HHII", tiff[e_off : e_off + 12])
                    type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}
                    total_bytes = count * type_sizes.get(ftype, 1)
                    if total_bytes <= 4:
                        raw_bytes = tiff[e_off + 8 : e_off + 8 + total_bytes]
                    else:
                        if val_raw + total_bytes > len(tiff):
                            continue
                        raw_bytes = tiff[val_raw : val_raw + total_bytes]
                    if ftype == 2:  # ASCII
                        entries[tag] = raw_bytes.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
                    elif ftype == 4 and count == 1:
                        entries[tag] = struct.unpack(endian + "I", raw_bytes)[0]
                    elif ftype == 5 and count >= 1:
                        rats = []
                        for r_i in range(count):
                            num, den = struct.unpack(endian + "II", raw_bytes[r_i * 8 : (r_i + 1) * 8])
                            rats.append(num / den if den else 0.0)
                        entries[tag] = rats
                return entries

            ifd0 = read_ifd(ifd0_off)
            tag_names = {0x010F: "camera_make", 0x0110: "camera_model", 0x0131: "software", 0x0132: "datetime", 0x013B: "artist"}
            for t_id, label in tag_names.items():
                if t_id in ifd0 and ifd0[t_id]:
                    exif_out[label] = ifd0[t_id]

            # SubExif IFD (0x8769)
            if 0x8769 in ifd0 and isinstance(ifd0[0x8769], int):
                sub = read_ifd(ifd0[0x8769])
                if 0x9003 in sub:
                    exif_out["datetime_original"] = sub[0x9003]
                if 0xA431 in sub:
                    exif_out["body_serial_number"] = sub[0xA431]
                if 0xA434 in sub:
                    exif_out["lens_model"] = sub[0xA434]

            # GPS IFD (0x8825)
            if 0x8825 in ifd0 and isinstance(ifd0[0x8825], int):
                gps = read_ifd(ifd0[0x8825])
                if 2 in gps and 4 in gps and isinstance(gps[2], list) and isinstance(gps[4], list):
                    lat_dms = gps[2]
                    lon_dms = gps[4]
                    lat = lat_dms[0] + lat_dms[1] / 60.0 + lat_dms[2] / 3600.0
                    lon = lon_dms[0] + lon_dms[1] / 60.0 + lon_dms[2] / 3600.0
                    if gps.get(1) == "S":
                        lat = -lat
                    if gps.get(3) == "W":
                        lon = -lon
                    exif_out["gps_coordinates"] = f"{lat:.6f},{lon:.6f}"
            break
        if marker in (0xDA, 0xD9):
            break
        pos += 2 + seg_len
    return exif_out


_NON_DOMAIN_FILE_EXTS = {
    "txt", "csv", "tsv", "json", "xml", "html", "htm", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "png", "jpg", "jpeg", "gif", "webp", "svg", "mp4", "mov", "mp3", "wav",
    "zip", "rar", "7z", "tar", "gz", "exe", "dll", "apk", "ipa", "eml", "pcap", "har", "py", "js", "css",
}

_LIST_HEADER_WORDS = PROMPT_STOPWORDS | {
    "id", "name", "email", "emails", "phone", "phones", "mobile", "number", "url", "urls",
    "link", "links", "domain", "domains", "host", "ip", "ips", "wallet", "notes", "note",
    "status", "date", "time", "type", "value", "source", "description", "title", "subject",
    "true", "false", "null", "none", "yes", "no",
}


def _decode_smart_text(raw: bytes, limit: int = 524_288) -> str:
    chunk = raw[:limit]
    if not chunk:
        return ""
    if chunk.startswith((b"\xff\xfe", b"\xfe\xff")):
        return chunk.decode("utf-16", errors="ignore")
    if chunk.startswith(b"\xef\xbb\xbf"):
        return chunk[3:].decode("utf-8", errors="ignore")
    probe = chunk[:200]
    if len(probe) >= 8 and probe[1::2].count(0) > len(probe) // 3:
        return chunk.decode("utf-16-le", errors="ignore")
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        return chunk.decode("cp1256", errors="ignore")


def _extract_pdf_text_and_links(data: bytes) -> tuple[str, list[str]]:
    """Decompress PDF FlateDecode streams and carve visible text literals + /URI annotations."""
    text_chunks: list[str] = []
    uris: list[str] = []

    raw_latin = data[:524_288].decode("latin-1", errors="ignore")
    for um in re.findall(r"/URI\s*\(([^)]{4,300})\)", raw_latin):
        uris.append(um.replace(r"\(", "(").replace(r"\)", ")"))

    streams = re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, flags=re.DOTALL)[:80]
    for st_bytes in streams:
        decomp = None
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                decomp = zlib.decompress(st_bytes.strip(b"\r\n"), wbits)
                break
            except Exception:
                continue
        buf = decomp if decomp is not None else st_bytes[:32_768]
        s_lat = buf.decode("latin-1", errors="ignore")
        for um in re.findall(r"/URI\s*\(([^)]{4,300})\)", s_lat):
            uris.append(um.replace(r"\(", "(").replace(r"\)", ")"))
        # Literal PDF strings (...) inside text blocks
        lits = []
        for lit in re.findall(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)", s_lat):
            cleaned = (
                lit.replace(r"\n", "\n")
                .replace(r"\r", " ")
                .replace(r"\t", " ")
                .replace(r"\(", "(")
                .replace(r"\)", ")")
                .replace("\\\\", "\\")
            )
            raw_b = cleaned.encode("latin-1", errors="ignore")
            if raw_b.startswith((b"\xfe\xff", b"\xff\xfe")):
                cleaned = raw_b.decode("utf-16", errors="ignore")
            if cleaned.strip():
                lits.append(cleaned)
        if lits:
            text_chunks.append(" ".join(lits))

    if uris:
        text_chunks.append("\n".join(uris))
    return "\n".join(text_chunks), sorted(set(uris))[:30]


def _html_to_searchable_text(txt: str) -> str:
    if "<" not in txt or ">" not in txt:
        return txt
    # Keep href/mailto/tel values visible before stripping HTML tags
    expanded = re.sub(
        r"""href\s*=\s*["']([^"']{4,300})["']""",
        lambda m: f" {m.group(1)} ",
        txt,
        flags=re.IGNORECASE,
    )
    expanded = re.sub(r"\b(?:mailto|tel):", " ", expanded, flags=re.IGNORECASE)
    expanded = re.sub(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", " ", expanded, flags=re.IGNORECASE | re.DOTALL)
    expanded = re.sub(r"<br\s*/?>|</(?:p|div|li|tr|h[1-6])>", "\n", expanded, flags=re.IGNORECASE)
    return re.sub(r"<[^>]+>", " ", expanded)


def analyze_local_file(file_path: str) -> dict:
    p = Path(file_path)
    data = p.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    magic = "Binary / Text"
    ext_low = p.suffix.lower()
    if data.startswith(b"\xff\xd8\xff"):
        magic = "JPEG Image"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        magic = "PNG Image"
    elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        magic = "WebP Image"
    elif data.startswith(b"%PDF-"):
        magic = "PDF Document"
    elif data.startswith(b"PK\x03\x04"):
        magic = "ZIP / Office OpenXML (DOCX/XLSX/PPTX/APK/JAR)"
    elif len(data) >= 4 and data[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
        magic = "PCAP / PCAPNG Packet Capture"
    elif len(data) >= 12 and data[4:8] in (b"ftyp", b"moov", b"mdat", b"wide"):
        magic = "MP4 / MOV QuickTime Video"
    elif ext_low in (".eml", ".msg") or (b"Received:" in data[:4096] and b"From:" in data[:4096]):
        magic = "RFC 5322 Email (.eml)"
    elif ext_low == ".har":
        magic = "W3C Browser HTTP Archive (.har)"
    elif b"\x00" not in data[:4096] or data.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        magic = "Plain / Structured Text"

    metadata: dict = {}
    content_pivots: list[dict] = []
    seen_pivots: set[tuple[str, str]] = set()
    extracted_text_parts: list[str] = []

    def _push_pivot(ptype: str, pval: str) -> None:
        v = (pval or "").strip()
        if not v:
            return
        if ptype == "domain":
            v_low = v.lower().rstrip(".").removeprefix("www.")
            ext_part = v_low.rsplit(".", 1)[-1] if "." in v_low else ""
            if v_low in NOISE_DOMAINS or ext_part in _NON_DOMAIN_FILE_EXTS or not DOMAIN_RE.fullmatch(v_low):
                return
            v = v_low
        key = (ptype, v.lower())
        if key not in seen_pivots:
            seen_pivots.add(key)
            content_pivots.append({"type": ptype, "value": v})

    from .dfir_forensics import (
        analyze_eml_bytes,
        analyze_har_bytes,
        analyze_mp4_mov_bytes,
        analyze_pcap_bytes,
        analyze_png_webp_c2pa_bytes,
        decode_ssh_pubkey_or_pem,
    )

    if magic == "JPEG Image":
        metadata["exif"] = _parse_jpeg_exif(data)
        c2pa_info = analyze_png_webp_c2pa_bytes(data)
        if c2pa_info.get("c2pa_content_credentials_detected") or c2pa_info.get("ai_or_camera_signatures"):
            metadata["c2pa_and_ai_provenance"] = c2pa_info
        if "gps_coordinates" in metadata["exif"]:
            _push_pivot("coordinates", metadata["exif"]["gps_coordinates"])
        artist = (metadata["exif"].get("artist") or "").strip()
        if artist and len(artist) <= 60:
            extracted_text_parts.append(f"Author: {artist}")
        xmp_m = re.search(rb"<x:xmpmeta[^>]*>.*?</x:xmpmeta>", data[:262_144], flags=re.DOTALL)
        if xmp_m:
            extracted_text_parts.append(_html_to_searchable_text(xmp_m.group(0).decode("utf-8", errors="ignore")))

    elif magic in ("PNG Image", "WebP Image"):
        img_f = analyze_png_webp_c2pa_bytes(data)
        metadata["image_forensics_and_c2pa"] = img_f
        for tk, tv in (img_f.get("text_chunks") or {}).items():
            if isinstance(tv, str) and len(tv) <= 4000:
                extracted_text_parts.append(f"{tk}: {tv}")

    elif magic == "MP4 / MOV QuickTime Video":
        mp4_res = analyze_mp4_mov_bytes(data)
        metadata["video_container_forensics"] = mp4_res
        for pv in mp4_res.get("discovered_pivots", []):
            _push_pivot(pv["type"], pv["value"])

    elif magic == "RFC 5322 Email (.eml)":
        eml_res = analyze_eml_bytes(data)
        metadata["eml_forensics"] = eml_res
        for pv in eml_res.get("discovered_pivots", []):
            _push_pivot(pv["type"], pv["value"])
        try:
            msg = email.message_from_bytes(data)
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    payload_b = part.get_payload(decode=True)
                    if payload_b:
                        extracted_text_parts.append(_html_to_searchable_text(_decode_smart_text(payload_b, 200_000)))
        except Exception:
            pass

    elif magic == "PCAP / PCAPNG Packet Capture":
        pcap_res = analyze_pcap_bytes(data)
        metadata["pcap_forensics"] = pcap_res
        for pv in pcap_res.get("discovered_pivots", []):
            _push_pivot(pv["type"], pv["value"])

    elif magic == "W3C Browser HTTP Archive (.har)":
        try:
            har_res = analyze_har_bytes(data)
            metadata["har_forensics"] = har_res
            for pv in har_res.get("discovered_pivots", []):
                _push_pivot(pv["type"], pv["value"])
        except Exception as exc:
            metadata["har_parse_error"] = str(exc)

    elif magic.startswith("ZIP") and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p, "r") as zf:
            names = zf.namelist()
            metadata["archive_file_count"] = len(names)
            if "docProps/core.xml" in names:
                try:
                    root = ET.fromstring(zf.read("docProps/core.xml"))
                    office_meta = {}
                    for elem in root.iter():
                        tag_short = elem.tag.split("}")[-1]
                        if elem.text and elem.text.strip():
                            office_meta[tag_short] = elem.text.strip()
                    metadata["office_core_properties"] = office_meta
                    for k in ("creator", "lastModifiedBy"):
                        val = office_meta.get(k)
                        if val and len(val) <= 39 and " " not in val:
                            _push_pivot("username", val)
                        elif val and 2 <= len(val.split()) <= 4:
                            _push_pivot("person_name", val)
                except Exception:
                    pass
            if "docProps/app.xml" in names:
                try:
                    aroot = ET.fromstring(zf.read("docProps/app.xml"))
                    for elem in aroot.iter():
                        if elem.tag.split("}")[-1] == "Company" and elem.text and elem.text.strip():
                            comp = elem.text.strip()
                            metadata["office_company"] = comp
                            _push_pivot("company", comp)
                except Exception:
                    pass

            for member in names[:60]:
                m_low = member.lower()
                try:
                    info = zf.getinfo(member)
                    if info.file_size > 2_000_000:
                        continue
                    if (
                        m_low.startswith(("word/document", "word/header", "word/footer", "xl/sharedstrings", "xl/worksheets/sheet", "ppt/slides/slide"))
                        and m_low.endswith(".xml")
                    ) or m_low == "content.xml":
                        xroot = ET.fromstring(zf.read(member))
                        txt_vals = [el.text.strip() for el in xroot.iter() if el.text and el.text.strip()]
                        if txt_vals:
                            extracted_text_parts.append("\n".join(txt_vals))
                    elif m_low.endswith(".rels"):
                        rels_txt = zf.read(member).decode("utf-8", errors="ignore")
                        for tgt in re.findall(r'Target="((?:https?://|mailto:|tel:)[^"]{4,300})"', rels_txt, flags=re.IGNORECASE):
                            extracted_text_parts.append(tgt.removeprefix("mailto:").removeprefix("tel:"))
                    elif m_low.endswith((".txt", ".csv", ".tsv", ".json", ".md", ".html", ".htm", ".vcf", ".eml")):
                        extracted_text_parts.append(_html_to_searchable_text(_decode_smart_text(zf.read(member), 250_000)))
                except Exception:
                    continue

    elif magic == "PDF Document":
        head_str = data[:65536].decode("latin-1", errors="ignore")
        for key in ("Author", "Creator", "Producer", "Title", "Subject", "CreationDate", "ModDate"):
            m = re.search(rf"/{key}\s*\(([^)]{{1,200}})\)", head_str)
            if m:
                val_clean = m.group(1).strip()
                metadata[f"pdf_{key.lower()}"] = val_clean
                if key == "Author" and val_clean:
                    if "@" in val_clean or " " not in val_clean:
                        extracted_text_parts.append(val_clean)
                    elif 2 <= len(val_clean.split()) <= 4:
                        _push_pivot("person_name", val_clean)
        pdf_txt, pdf_uris = _extract_pdf_text_and_links(data)
        if pdf_uris:
            metadata["pdf_embedded_links"] = pdf_uris
        if pdf_txt:
            extracted_text_parts.append(pdf_txt)

    elif magic == "Plain / Structured Text":
        raw_txt = _decode_smart_text(data, 524_288)
        extracted_text_parts.append(_html_to_searchable_text(raw_txt))

    # Carve embedded emails, URLs, IPv4s, SSH/PEM keys, and all 24 OSINT selectors from readable content
    sample_str = "\n".join(extracted_text_parts) if extracted_text_parts else _decode_smart_text(data, 524_288)
    ssh_pem_info = decode_ssh_pubkey_or_pem(sample_str)
    if ssh_pem_info:
        metadata["key_or_cert_forensics"] = ssh_pem_info

    for sel in extract_selectors(sample_str, check_local_file=False):
        if sel["type"] != "keyword":
            _push_pivot(sel["type"], sel["value"])

    # For structured/text lists (.txt, .csv, .tsv, .vcf, .docx, .xlsx, .pdf), also inspect clean single-token lines/cells
    # so bare target lists (e.g. one username or phone per line without '@') are captured accurately.
    if magic in ("Plain / Structured Text", "ZIP / Office OpenXML (DOCX/XLSX/PPTX/APK/JAR)", "PDF Document"):
        is_list_ext = ext_low in (".txt", ".csv", ".tsv", ".vcf", ".list")
        checked = 0
        for raw_ln in sample_str.splitlines():
            if checked >= 150:
                break
            cells = [c.strip(" \"'`,;\t\r") for c in (raw_ln.split(",") if ext_low == ".csv" else [raw_ln])]
            for cell in cells:
                if not cell or len(cell) < 3 or len(cell) > 90:
                    continue
                if cell.lower() in _LIST_HEADER_WORDS:
                    continue
                checked += 1
                # Label: Value pairs (e.g. "Name: ...", "Clinic: ...", "Phone: +966 55 ...")
                if cell.count(":") == 1 and not cell.lower().startswith(("http:", "https:")):
                    k_part, v_part = [x.strip() for x in cell.split(":", 1)]
                    kl = k_part.lower()
                    if kl in ("phone", "mobile", "tel", "whatsapp", "number"):
                        digs = re.sub(r"\D", "", v_part)
                        if digs.startswith("00"):
                            digs = digs[2:]
                        if 9 <= len(digs) <= 15 and digs[0] != "0":
                            _push_pivot("phone", f"+{digs}")
                        continue
                    if kl in ("name", "full name", "person", "owner", "doctor", "author") and 2 <= len(v_part.split()) <= 5:
                        _push_pivot("person_name", v_part)
                        continue
                    if kl in ("company", "organization", "org", "clinic", "business", "employer") and len(v_part) >= 3:
                        _push_pivot("company", v_part)
                        continue
                # Bare single-token handles / phones on target-list lines
                if " " not in cell:
                    ext_sfx = cell.rsplit(".", 1)[-1].lower() if "." in cell else ""
                    if ext_sfx in _NON_DOMAIN_FILE_EXTS:
                        continue
                    if re.fullmatch(r"\+?[1-9][\d\s().-]{8,18}\d", cell):
                        digs = re.sub(r"\D", "", cell)
                        if 10 <= len(digs) <= 15:
                            _push_pivot("phone", f"+{digs}")
                        continue
                    if is_list_ext and re.fullmatch(r"[a-zA-Z0-9_.-]{3,39}", cell) and not cell.isdigit():
                        if not re.fullmatch(r"\d+(?:\.\d+)+", cell):
                            for s2 in extract_selectors(cell, check_local_file=False):
                                if s2["type"] != "keyword":
                                    _push_pivot(s2["type"], s2["value"])
                    elif re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]*(?:[._-][a-zA-Z0-9]+)+", cell) and not DOMAIN_RE.fullmatch(cell.lower()):
                        # Distinct handle with separators (e.g. dr.abo3tab, user_name) inside docs
                        _push_pivot("username", cell)

    carved_emails = [pv["value"] for pv in content_pivots if pv["type"] == "email"][:20] or sorted(set(e.lower() for e in EMAIL_RE.findall(sample_str)))[:15]
    carved_urls = [pv["value"] for pv in content_pivots if pv["type"] == "url"][:20] or sorted(set(URL_RE.findall(sample_str)))[:15]
    carved_wallets = [pv["value"] for pv in content_pivots if pv["type"] == "crypto_address"][:15] or sorted(set(EVM_RE.findall(sample_str)))[:10]
    carved_ips = [pv["value"] for pv in content_pivots if pv["type"] == "ip"][:15] or sorted(set(IPV4_RE.findall(sample_str)))[:10]

    for em in carved_emails[:10]:
        _push_pivot("email", em)
    for w in carved_wallets[:10]:
        _push_pivot("crypto_address", w)

    # Include content selectors first; append file_hash for non-text binary triage
    pivots: list[dict] = list(content_pivots[:45])
    if magic != "Plain / Structured Text" or not pivots:
        pivots.append({"type": "file_hash", "value": sha256})

    return {
        "file_name": p.name,
        "absolute_path": str(p.resolve()),
        "size_bytes": len(data),
        "detected_format": magic,
        "hashes": {"sha256": sha256, "sha1": sha1, "md5": md5},
        "extracted_metadata": metadata,
        "carved_artifacts": {
            "emails": carved_emails,
            "urls": carved_urls,
            "evm_wallets": carved_wallets,
            "ipv4s": carved_ips,
        },
        "content_selectors": content_pivots[:45],
        "extracted_text_sample": sample_str[:16_384],
        "discovered_pivots": pivots,
    }


# ============================================================================
# ADVANCED CHRONOLOCATION, IDENTIFIER & BANKING FORENSIC DECODERS
# ============================================================================

IBAN_LENGTHS: dict[str, tuple[int, str]] = {
    "SA": (24, "Saudi Arabia"), "AE": (23, "United Arab Emirates"), "KW": (30, "Kuwait"),
    "QA": (29, "Qatar"), "BH": (22, "Bahrain"), "OM": (23, "Oman"), "EG": (29, "Egypt"),
    "JO": (30, "Jordan"), "LB": (28, "Lebanon"), "TR": (26, "Turkey"), "IQ": (23, "Iraq"),
    "GB": (22, "United Kingdom"), "DE": (22, "Germany"), "FR": (27, "France"),
    "CH": (21, "Switzerland"), "LI": (21, "Liechtenstein"), "LU": (20, "Luxembourg"),
    "NL": (18, "Netherlands"), "BE": (16, "Belgium"), "AT": (20, "Austria"),
    "ES": (24, "Spain"), "IT": (27, "Italy"), "PT": (25, "Portugal"), "IE": (22, "Ireland"),
    "SE": (24, "Sweden"), "NO": (15, "Norway"), "DK": (18, "Denmark"), "FI": (18, "Finland"),
    "PL": (28, "Poland"), "CZ": (24, "Czechia"), "CY": (28, "Cyprus"), "MT": (31, "Malta"),
    "GR": (27, "Greece"), "RO": (24, "Romania"), "BG": (22, "Bulgaria"), "HU": (28, "Hungary"),
    "EE": (20, "Estonia"), "LV": (21, "Latvia"), "LT": (20, "Lithuania"), "UA": (29, "Ukraine"),
    "PK": (24, "Pakistan"), "BR": (29, "Brazil"),
}

TIKTOK_VIDEO_RE = re.compile(r"tiktok\.com/(?:@([a-zA-Z0-9._-]+)/)?(?:video|photo)/(\d{18,20})")
UUID_RE = re.compile(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})\b")
MONGO_OID_RE = re.compile(r"\b([0-9a-fA-F]{24})\b")
ULID_RE = re.compile(r"\b([0-7][0-9A-HJKMNP-TV-Z]{25})\b")
IBAN_CANDIDATE_RE = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,29})\b")
SNOWFLAKE_RE = re.compile(r"\b(\d{17,19})\b")

CROCKFORD_B32 = {ch: idx for idx, ch in enumerate("0123456789ABCDEFGHJKMNPQRSTVWXYZ")}


def decode_tiktok_id_or_url(raw: str) -> dict | None:
    """Extract exact UTC upload timestamp from a TikTok URL or 19-digit video/photo ID (id >> 32)."""
    s = (raw or "").strip()
    m = TIKTOK_VIDEO_RE.search(s)
    handle = None
    vid_str = None
    if m:
        handle = m.group(1)
        vid_str = m.group(2)
    elif re.fullmatch(r"\d{19}", s):
        vid_str = s
    if not vid_str:
        return None

    vid = int(vid_str)
    unix_sec = vid >> 32
    if not (1451606400 <= unix_sec <= 1956528000):  # 2016-01-01 .. 2032-01-01
        return None
    dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
    return {
        "decoder": "tiktok_chronolocation",
        "post_id": vid_str,
        "author_handle": handle,
        "upload_unix_epoch": unix_sec,
        "upload_utc_iso": dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lower_32bit_worker_seq": vid & 0xFFFFFFFF,
        "forensic_note": "TikTok encodes the exact server-side UTC upload second in the upper 32 bits of the 64-bit post ID.",
    }


def decode_snowflake_id(raw: str) -> dict | None:
    """Decode 17–19 digit Discord or X/Twitter Snowflake IDs into exact millisecond UTC creation timestamps."""
    s = re.sub(r"\D", "", (raw or "").strip())
    if not (17 <= len(s) <= 19):
        return None
    val = int(s)
    candidates = []
    for platform, epoch_ms, min_yr in (
        ("Discord", 1420070400000, 2015),
        ("X / Twitter", 1288834974657, 2010),
    ):
        ts_ms = (val >> 22) + epoch_ms
        yr = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).year
        if min_yr <= yr <= 2031:
            dt_iso = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            candidates.append(
                {
                    "platform": platform,
                    "created_utc_iso": dt_iso,
                    "unix_ms": ts_ms,
                    "worker_id": (val & 0x3E0000) >> 17,
                    "process_id": (val & 0x1F000) >> 12,
                    "increment": val & 0xFFF,
                }
            )
    if not candidates:
        return None
    return {
        "decoder": "snowflake_chronolocation",
        "snowflake_id": s,
        "possible_interpretations": candidates,
    }


def decode_uuid_or_ulid(raw: str) -> dict | None:
    """Extract embedded UTC timestamps & hardware MAC addresses from UUIDv1/v6/v7, ULIDs, and MongoDB ObjectIds."""
    s = (raw or "").strip()

    # 1. Standard RFC 4122 / RFC 9562 UUID
    um = UUID_RE.search(s)
    if um:
        u_str = um.group(1).lower()
        hex32 = u_str.replace("-", "")
        ver = int(hex32[12], 16)
        out: dict = {"decoder": "uuid_forensics", "uuid": u_str, "version": ver}
        if ver == 1:
            time_low = int(hex32[0:8], 16)
            time_mid = int(hex32[8:12], 16)
            time_hi = int(hex32[12:16], 16) & 0x0FFF
            greg_100ns = (time_hi << 48) | (time_mid << 32) | time_low
            unix_ts = (greg_100ns - 0x01B21DD213814000) / 1e7
            dt_iso = datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            node_hex = hex32[20:32].upper()
            mac_fmt = ":".join(node_hex[i : i + 2] for i in range(0, 12, 2))
            mac_info = decode_mac_bssid(mac_fmt)
            out.update(
                {
                    "created_utc_iso": dt_iso,
                    "embedded_node_mac": mac_fmt,
                    "node_mac_vendor": mac_info.get("vendor"),
                    "is_multicast_random_node": bool(int(node_hex[:2], 16) & 0x01),
                    "forensic_note": "UUIDv1 leaks exact 100ns creation time and the generating machine's 48-bit MAC address.",
                }
            )
        elif ver == 7:
            unix_ms = int(hex32[0:12], 16)
            dt_iso = datetime.fromtimestamp(unix_ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            out.update(
                {
                    "created_utc_iso": dt_iso,
                    "unix_ms": unix_ms,
                    "forensic_note": "UUIDv7 (RFC 9562) encodes exact millisecond UTC creation time in its top 48 bits.",
                }
            )
        elif ver == 6:
            greg_100ns = (int(hex32[0:12], 16) << 12) | (int(hex32[12:16], 16) & 0x0FFF)
            unix_ts = (greg_100ns - 0x01B21DD213814000) / 1e7
            out["created_utc_iso"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        elif ver == 4:
            out["forensic_note"] = "UUIDv4 is cryptographically random (122 random bits; no embedded timestamp/MAC)."
        return out

    # 2. 26-char Crockford Base32 ULID
    if ULID_RE.fullmatch(s.upper()):
        u_up = s.upper()
        ts_ms = 0
        for ch in u_up[:10]:
            ts_ms = (ts_ms << 5) | CROCKFORD_B32[ch]
        yr = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).year
        if 2010 <= yr <= 2035:
            dt_iso = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            return {
                "decoder": "ulid_forensics",
                "ulid": u_up,
                "created_utc_iso": dt_iso,
                "unix_ms": ts_ms,
            }

    # 3. 24-hex MongoDB ObjectId
    if MONGO_OID_RE.fullmatch(s):
        unix_sec = int(s[:8], 16)
        yr = datetime.fromtimestamp(unix_sec, tz=timezone.utc).year
        if 2009 <= yr <= 2035:
            return {
                "decoder": "mongodb_objectid_forensics",
                "object_id": s.lower(),
                "created_utc_iso": datetime.fromtimestamp(unix_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "machine_process_hex": s[8:18].lower(),
                "counter": int(s[18:24], 16),
            }

    return None


def decode_iban(raw: str) -> dict | None:
    """Validate ISO 13616 IBAN MOD-97-10 checksum and extract country & banking institution metadata."""
    compact = re.sub(r"[\s-]+", "", (raw or "").strip()).upper()
    if not IBAN_CANDIDATE_RE.fullmatch(compact):
        return None
    cc = compact[:2]
    if cc not in IBAN_LENGTHS:
        return None
    exp_len, country_name = IBAN_LENGTHS[cc]
    if len(compact) != exp_len:
        return None

    rearranged = compact[4:] + compact[:4]
    numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    mod97_valid = int(numeric_str) % 97 == 1

    bank_code = compact[4:6] if cc == "SA" else compact[4:8]
    bank_name = INTEL_TABLES.get("sama_bank_codes_sa", {}).get(bank_code) if cc == "SA" else None

    return {
        "decoder": "iban_iso13616",
        "iban": compact,
        "country_code": cc,
        "country": country_name,
        "check_digits": compact[2:4],
        "mod97_valid": mod97_valid,
        "bank_identifier": bank_code,
        "bank_name": bank_name,
        "bban": compact[4:],
    }


def universal_forensic_decode(raw_input: str) -> dict:
    """Run EVERY zero-network deterministic decoder matching any token inside `raw_input`."""
    from .classify import extract_selectors

    text = (raw_input or "").strip()
    decoded_items: list[dict] = []

    # 1. TikTok URL / Post ID timestamp & Google Search `ei=` chronolocation & SSH/PEM keys
    from .dfir_forensics import decode_google_ei_parameter, decode_ssh_pubkey_or_pem

    tt = decode_tiktok_id_or_url(text)
    if tt:
        decoded_items.append(tt)

    gei = decode_google_ei_parameter(text)
    if gei:
        decoded_items.append(gei)

    ssh_or_pem = decode_ssh_pubkey_or_pem(text)
    if ssh_or_pem:
        decoded_items.append(ssh_or_pem)

    # 2. UUIDv1/v6/v7, ULID, MongoDB ObjectId
    for tok in re.split(r"[\s,;()\"'<>]+", text):
        if not tok:
            continue
        u_res = decode_uuid_or_ulid(tok)
        if u_res:
            decoded_items.append(u_res)
        ib_res = decode_iban(tok)
        if ib_res and ib_res["mod97_valid"]:
            decoded_items.append(ib_res)

    # Check multi-group spaced IBAN (e.g. "SA03 8000 0000 6080 1016 7519")
    ib_spaced = decode_iban(text)
    if ib_spaced and ib_spaced["mod97_valid"] and not any(d.get("iban") == ib_spaced["iban"] for d in decoded_items):
        decoded_items.append(ib_spaced)

    # 3. Discord / X Snowflake IDs (when not already decoded as TikTok)
    for sf in SNOWFLAKE_RE.findall(text):
        if tt and tt.get("post_id") == sf:
            continue
        sf_res = decode_snowflake_id(sf)
        if sf_res:
            decoded_items.append(sf_res)

    # 4. Standard OSINT typed selectors (Phone, Aircraft ICAO, Vessel IMO/MMSI, VIN, MAC/BSSID, JWT, Local File)
    for sel in extract_selectors(text):
        st, sv = sel["type"], sel["value"]
        if st == "phone":
            decoded_items.append({"decoder": "phone_itu_e164", **decode_phone(sv)})
        elif st == "aircraft_hex":
            decoded_items.append({"decoder": "aircraft_icao24", **decode_aircraft_hex(sv)})
        elif st == "vessel_imo":
            decoded_items.append({"decoder": "maritime_ais_imo", **decode_vessel_identifier(sv)})
        elif st == "vin":
            decoded_items.append({"decoder": "vehicle_iso3779_vin", **decode_vin(sv)})
        elif st == "mac_bssid":
            decoded_items.append({"decoder": "ieee_mac_bssid", **decode_mac_bssid(sv)})
        elif st == "jwt_token":
            decoded_items.append({"decoder": "jwt_token", **decode_jwt(sv)})
        elif st == "local_file":
            decoded_items.append({"decoder": "local_binary_forensics", **analyze_local_file(sv)})

    return {
        "input": text,
        "decoded_count": len(decoded_items),
        "results": decoded_items,
    }

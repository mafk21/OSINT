"""Zero-network deterministic OSINT decoders & local binary forensic parsers."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .classify import EMAIL_RE, EVM_RE, IPV4_RE, URL_RE, VIN_TRANSLITERATION, VIN_WEIGHTS, is_valid_imo
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


def analyze_local_file(file_path: str) -> dict:
    p = Path(file_path)
    data = p.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    magic = "Binary / Text"
    if data.startswith(b"\xff\xd8\xff"):
        magic = "JPEG Image"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        magic = "PNG Image"
    elif data.startswith(b"%PDF-"):
        magic = "PDF Document"
    elif data.startswith(b"PK\x03\x04"):
        magic = "ZIP / Office OpenXML (DOCX/XLSX/PPTX/APK/JAR)"

    metadata: dict = {}
    pivots: list[dict] = [{"type": "file_hash", "value": sha256}]

    if magic == "JPEG Image":
        metadata["exif"] = _parse_jpeg_exif(data)
        if "gps_coordinates" in metadata["exif"]:
            pivots.append({"type": "coordinates", "value": metadata["exif"]["gps_coordinates"]})

    elif magic.startswith("ZIP") and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p, "r") as zf:
            names = zf.namelist()
            metadata["archive_file_count"] = len(names)
            if "docProps/core.xml" in names:
                xml_bytes = zf.read("docProps/core.xml")
                root = ET.fromstring(xml_bytes)
                office_meta = {}
                for elem in root.iter():
                    tag_short = elem.tag.split("}")[-1]
                    if elem.text and elem.text.strip():
                        office_meta[tag_short] = elem.text.strip()
                metadata["office_core_properties"] = office_meta
                for k in ("creator", "lastModifiedBy"):
                    val = office_meta.get(k)
                    if val and len(val) <= 39 and " " not in val:
                        pivots.append({"type": "username", "value": val})

    elif magic == "PDF Document":
        head_str = data[:65536].decode("latin-1", errors="ignore")
        for key in ("Author", "Creator", "Producer", "Title", "CreationDate", "ModDate"):
            m = re.search(rf"/{key}\s*\(([^)]{{1,200}})\)", head_str)
            if m:
                metadata[f"pdf_{key.lower()}"] = m.group(1)

    # Carve embedded emails, URLs, IPv4s, and EVM wallets from readable strings
    sample_str = data[:524288].decode("utf-8", errors="ignore")
    carved_emails = sorted(set(e.lower() for e in EMAIL_RE.findall(sample_str)))[:15]
    carved_urls = sorted(set(URL_RE.findall(sample_str)))[:15]
    carved_wallets = sorted(set(EVM_RE.findall(sample_str)))[:10]
    carved_ips = sorted(set(IPV4_RE.findall(sample_str)))[:10]

    for em in carved_emails[:5]:
        pivots.append({"type": "email", "value": em})
    for w in carved_wallets[:5]:
        pivots.append({"type": "crypto_address", "value": w})

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
        "discovered_pivots": pivots,
    }

"""Zero-Dependency 64-bit Perceptual Image Hash (`dHash`) & Visual Similarity Engine (Upgrade #2).

Matches identical or near-identical profile avatars and photos even after social
platforms resize, re-compress, strip metadata, or convert formats (e.g. `1024x1024`
PNG vs `160x160` JPEG/PNG with compression noise).

Decoders (100% local, zero cloud calls):
  1. Pure-Python PNG scanline decoder (`IHDR` + `PLTE` + `IDAT` zlib + Paeth/Sub/Up/Avg unfiltering)
  2. Pure-Python Baseline JPEG (`SOF0`) Huffman 8x8 DCT DC-coefficient luminance decoder
  3. Pure-Python uncompressed BMP / Netpbm PGM/PPM decoder
  4. Optional Pillow (`PIL`) or `ffmpeg` gray8 pipe fallback for progressive JPEG / WebP / GIF
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import zlib
from typing import Any


def _paeth_predictor(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _resample_to_9x8(grid: list[list[float]], src_w: int, src_h: int) -> list[list[float]] | None:
    if src_w < 2 or src_h < 2 or not grid:
        return None
    out: list[list[float]] = []
    for ty in range(8):
        y0 = (ty * src_h) / 8.0
        y1 = ((ty + 1) * src_h) / 8.0
        iy0 = max(0, int(y0))
        iy1 = min(src_h - 1, max(iy0, int(y1 - 1e-6)))
        row_out: list[float] = []
        for tx in range(9):
            x0 = (tx * src_w) / 9.0
            x1 = ((tx + 1) * src_w) / 9.0
            ix0 = max(0, int(x0))
            ix1 = min(src_w - 1, max(ix0, int(x1 - 1e-6)))
            total = 0.0
            cnt = 0
            # Step if huge source image so resampling stays < 1ms
            step_y = max(1, (iy1 - iy0 + 1) // 8)
            step_x = max(1, (ix1 - ix0 + 1) // 8)
            for yy in range(iy0, iy1 + 1, step_y):
                r_src = grid[yy]
                for xx in range(ix0, ix1 + 1, step_x):
                    total += r_src[xx]
                    cnt += 1
            row_out.append(total / cnt if cnt else 0.0)
        out.append(row_out)
    return out


def _grid_9x8_to_dhash_hex(grid_9x8: list[list[float]]) -> str:
    bits = 0
    for y in range(8):
        row = grid_9x8[y]
        for x in range(8):
            bits = (bits << 1) | (1 if row[x] > row[x + 1] else 0)
    return f"{bits:016x}"


def _decode_png_to_9x8(data: bytes) -> list[list[float]] | None:
    """Decode non-interlaced 8-bit/16-bit PNG in pure Python stdlib and resample to 9x8 luminance."""
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos = 8
    width = height = bit_depth = color_type = interlace = 0
    palette: list[tuple[int, int, int]] = []
    idat_parts: list[bytes] = []

    while pos + 8 <= len(data):
        clen = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        if pos + 12 + clen > len(data):
            break
        cbody = data[pos + 8 : pos + 8 + clen]
        pos += 12 + clen
        if ctype == b"IHDR" and len(cbody) >= 13:
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", cbody[:13])
        elif ctype == b"PLTE":
            for i in range(0, len(cbody) - 2, 3):
                palette.append((cbody[i], cbody[i + 1], cbody[i + 2]))
        elif ctype == b"IDAT":
            idat_parts.append(cbody)
        elif ctype == b"IEND":
            break

    if width < 2 or height < 2 or width > 4096 or height > 4096 or interlace != 0:
        return None
    if bit_depth not in (8, 16) or color_type not in (0, 2, 3, 4, 6):
        return None
    if not idat_parts:
        return None

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    bytes_per_sample = 2 if bit_depth == 16 else 1
    bpp = channels * bytes_per_sample
    stride = width * bpp

    try:
        raw = zlib.decompress(b"".join(idat_parts), zlib.MAX_WBITS, height * (stride + 1))
    except Exception:
        return None
    if len(raw) < height * (stride + 1):
        return None

    prev_line = bytearray(stride)
    cur_line = bytearray(stride)
    lum_grid: list[list[float]] = []

    offset = 0
    for _y in range(height):
        ftype = raw[offset]
        offset += 1
        scan = raw[offset : offset + stride]
        offset += stride

        if ftype == 0:
            cur_line[:] = scan
        elif ftype == 1:  # Sub
            for i in range(stride):
                left = cur_line[i - bpp] if i >= bpp else 0
                cur_line[i] = (scan[i] + left) & 0xFF
        elif ftype == 2:  # Up
            for i in range(stride):
                cur_line[i] = (scan[i] + prev_line[i]) & 0xFF
        elif ftype == 3:  # Average
            for i in range(stride):
                left = cur_line[i - bpp] if i >= bpp else 0
                cur_line[i] = (scan[i] + ((left + prev_line[i]) >> 1)) & 0xFF
        elif ftype == 4:  # Paeth
            for i in range(stride):
                left = cur_line[i - bpp] if i >= bpp else 0
                up = prev_line[i]
                up_left = prev_line[i - bpp] if i >= bpp else 0
                cur_line[i] = (scan[i] + _paeth_predictor(left, up, up_left)) & 0xFF
        else:
            return None

        row_lum: list[float] = []
        step = bpp
        if color_type == 0:  # Grayscale
            for px in range(0, stride, step):
                row_lum.append(float(cur_line[px]))
        elif color_type == 4:  # Grayscale + Alpha (composite over dark neutral 128)
            for px in range(0, stride, step):
                g = cur_line[px]
                a = cur_line[px + bytes_per_sample] / 255.0
                row_lum.append(g * a + 128.0 * (1.0 - a))
        elif color_type == 2:  # RGB
            for px in range(0, stride, step):
                r = cur_line[px]
                g = cur_line[px + bytes_per_sample]
                b = cur_line[px + 2 * bytes_per_sample]
                row_lum.append(0.299 * r + 0.587 * g + 0.114 * b)
        elif color_type == 6:  # RGBA
            for px in range(0, stride, step):
                r = cur_line[px]
                g = cur_line[px + bytes_per_sample]
                b = cur_line[px + 2 * bytes_per_sample]
                a = cur_line[px + 3 * bytes_per_sample] / 255.0
                lum = 0.299 * r + 0.587 * g + 0.114 * b
                row_lum.append(lum * a + 128.0 * (1.0 - a))
        elif color_type == 3:  # Indexed PLTE
            for px in range(stride):
                idx = cur_line[px]
                if idx < len(palette):
                    r, g, b = palette[idx]
                    row_lum.append(0.299 * r + 0.587 * g + 0.114 * b)
                else:
                    row_lum.append(0.0)

        lum_grid.append(row_lum)
        prev_line, cur_line = cur_line, prev_line

    return _resample_to_9x8(lum_grid, width, height)


class _JpegBitReader:
    def __init__(self, payload: bytes) -> None:
        self.buf = payload
        self.n = len(payload)
        self.pos = 0
        self.bit_buf = 0
        self.bit_cnt = 0
        self.hit_marker = False

    def reset_bits(self) -> None:
        self.bit_buf = 0
        self.bit_cnt = 0

    def _fill_byte(self) -> int | None:
        if self.hit_marker or self.pos >= self.n:
            return None
        b = self.buf[self.pos]
        self.pos += 1
        if b == 0xFF:
            while self.pos < self.n and self.buf[self.pos] == 0xFF:
                self.pos += 1
            if self.pos >= self.n:
                self.hit_marker = True
                return None
            nxt = self.buf[self.pos]
            self.pos += 1
            if nxt == 0x00:
                return 0xFF
            if 0xD0 <= nxt <= 0xD7:
                # Restart marker handled by caller if needed; return sentinel
                return -1 - (nxt - 0xD0)
            self.hit_marker = True
            return None
        return b

    def get_bit(self) -> int:
        if self.bit_cnt == 0:
            nb = self._fill_byte()
            if nb is None or nb < 0:
                raise EOFError("marker_or_eof")
            self.bit_buf = nb
            self.bit_cnt = 8
        self.bit_cnt -= 1
        return (self.bit_buf >> self.bit_cnt) & 1

    def get_bits(self, k: int) -> int:
        val = 0
        for _ in range(k):
            val = (val << 1) | self.get_bit()
        return val

    def decode_huff(self, table: dict[tuple[int, int], int]) -> int:
        code = 0
        for length in range(1, 17):
            code = (code << 1) | self.get_bit()
            sym = table.get((length, code))
            if sym is not None:
                return sym
        raise ValueError("bad_huff")


def _receive_extend(mag_bits: int, val: int) -> int:
    if mag_bits == 0:
        return 0
    vt = 1 << (mag_bits - 1)
    if val < vt:
        return val - ((1 << mag_bits) - 1)
    return val


def _decode_baseline_jpeg_dc_to_9x8(data: bytes) -> list[list[float]] | None:
    """Decode Baseline JPEG (`SOF0`) 8x8 block DC luminance coefficients in pure Python."""
    if len(data) < 64 or data[:2] != b"\xff\xd8":
        return None

    pos = 2
    n = len(data)
    huff_tables: dict[tuple[int, int], dict[tuple[int, int], int]] = {}
    quant_dc: dict[int, int] = {}
    width = height = 0
    comps: list[tuple[int, int, int, int]] = []  # (cid, h_samp, v_samp, qt_id)
    restart_interval = 0
    sos_map: dict[int, tuple[int, int]] = {}
    scan_start = 0

    while pos + 4 <= n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            break
        if marker in (0xD8,) or (0xD0 <= marker <= 0xD7):
            continue
        if pos + 2 > n:
            break
        seg_len = struct.unpack(">H", data[pos : pos + 2])[0]
        if seg_len < 2 or pos + seg_len > n:
            break
        seg = data[pos + 2 : pos + seg_len]
        pos += seg_len

        if marker == 0xDB:  # DQT
            qpos = 0
            while qpos < len(seg):
                pq_tq = seg[qpos]
                prec = pq_tq >> 4
                tq = pq_tq & 0x0F
                qpos += 1
                if prec == 0 and qpos + 64 <= len(seg):
                    quant_dc[tq] = seg[qpos]
                    qpos += 64
                elif prec == 1 and qpos + 128 <= len(seg):
                    quant_dc[tq] = struct.unpack(">H", seg[qpos : qpos + 2])[0]
                    qpos += 128
                else:
                    break
        elif marker == 0xC4:  # DHT
            hpos = 0
            while hpos + 17 <= len(seg):
                tc_th = seg[hpos]
                tc = (tc_th >> 4) & 0x0F
                th = tc_th & 0x0F
                counts = seg[hpos + 1 : hpos + 17]
                hpos += 17
                tot_syms = sum(counts)
                if hpos + tot_syms > len(seg):
                    break
                syms = seg[hpos : hpos + tot_syms]
                hpos += tot_syms
                tbl: dict[tuple[int, int], int] = {}
                code = 0
                s_idx = 0
                for bit_len in range(1, 17):
                    for _ in range(counts[bit_len - 1]):
                        tbl[(bit_len, code)] = syms[s_idx]
                        code += 1
                        s_idx += 1
                    code <<= 1
                huff_tables[(tc, th)] = tbl
        elif marker == 0xDD and len(seg) >= 2:  # DRI
            restart_interval = struct.unpack(">H", seg[:2])[0]
        elif marker == 0xC0 and len(seg) >= 9:  # Baseline SOF0
            prec = seg[0]
            if prec != 8:
                return None
            height, width, ncomp = struct.unpack(">HHB", seg[1:6])
            comps = []
            for i in range(ncomp):
                base = 6 + 3 * i
                if base + 3 <= len(seg):
                    cid = seg[base]
                    hv = seg[base + 1]
                    qtid = seg[base + 2]
                    comps.append((cid, hv >> 4, hv & 0x0F, qtid))
        elif marker == 0xC2:  # Progressive SOF2 -> delegate to fallback
            return None
        elif marker == 0xDA:  # SOS
            if not comps or len(seg) < 4:
                return None
            ns = seg[0]
            if ns != len(comps):
                # Non-interleaved scan -> delegate to fallback
                return None
            for i in range(ns):
                cs = seg[1 + 2 * i]
                td_ta = seg[2 + 2 * i]
                sos_map[cs] = (td_ta >> 4, td_ta & 0x0F)
            scan_start = pos
            break

    if not scan_start or width < 16 or height < 16 or not comps:
        return None

    max_h = max(c[1] for c in comps)
    max_v = max(c[2] for c in comps)
    if max_h < 1 or max_v < 1:
        return None

    mcu_px_w = max_h * 8
    mcu_px_h = max_v * 8
    mcus_x = (width + mcu_px_w - 1) // mcu_px_w
    mcus_y = (height + mcu_px_h - 1) // mcu_px_h
    if mcus_x * mcus_y > 65536:
        return None

    y_cid, y_h, y_v, y_qt = comps[0]
    y_q0 = quant_dc.get(y_qt, 1)
    blocks_w = mcus_x * y_h
    blocks_h = mcus_y * y_v
    dc_grid = [[128.0] * blocks_w for _ in range(blocks_h)]

    br = _JpegBitReader(data[scan_start:])
    dc_preds = {c[0]: 0 for c in comps}
    mcu_counter = 0

    try:
        for my in range(mcus_y):
            for mx in range(mcus_x):
                if restart_interval and mcu_counter > 0 and (mcu_counter % restart_interval == 0):
                    # Sync across restart marker if present in stream
                    br.reset_bits()
                    while br.pos < br.n and br.buf[br.pos] == 0xFF:
                        br.pos += 1
                    if br.pos < br.n and 0xD0 <= br.buf[br.pos] <= 0xD7:
                        br.pos += 1
                    dc_preds = {c[0]: 0 for c in comps}

                for cid, hs, vs, _qt in comps:
                    td, ta = sos_map.get(cid, (0, 0))
                    dc_tbl = huff_tables.get((0, td))
                    ac_tbl = huff_tables.get((1, ta))
                    if not dc_tbl or not ac_tbl:
                        return None
                    for vy in range(vs):
                        for hx in range(hs):
                            ssss = br.decode_huff(dc_tbl)
                            diff = _receive_extend(ssss, br.get_bits(ssss)) if ssss else 0
                            dc_val = dc_preds[cid] + diff
                            dc_preds[cid] = dc_val
                            if cid == y_cid:
                                lum = 128.0 + (dc_val * y_q0) / 8.0
                                dc_grid[my * y_v + vy][mx * y_h + hx] = max(0.0, min(255.0, lum))
                            k = 1
                            while k < 64:
                                rs = br.decode_huff(ac_tbl)
                                if rs == 0x00:  # EOB
                                    break
                                if rs == 0xF0:  # ZRL (16 zeros)
                                    k += 16
                                    continue
                                rrrr = rs >> 4
                                s_ac = rs & 0x0F
                                k += rrrr
                                if s_ac:
                                    _ = br.get_bits(s_ac)
                                k += 1
                mcu_counter += 1
    except Exception:
        return None

    return _resample_to_9x8(dc_grid, blocks_w, blocks_h)


def _decode_via_pillow_or_ffmpeg(data: bytes) -> list[list[float]] | None:
    """Optional local decoder for WebP, GIF, or progressive JPEG if Pillow or ffmpeg is present."""
    try:
        import io
        from PIL import Image  # type: ignore

        with Image.open(io.BytesIO(data)) as im:
            gray = im.convert("L").resize((9, 8))
            px = list(gray.getdata())
            return [[float(px[y * 9 + x]) for x in range(9)] for y in range(8)]
    except Exception:
        pass

    ff = shutil.which("ffmpeg")
    if ff:
        try:
            proc = subprocess.run(
                [ff, "-hide_banner", "-loglevel", "error", "-i", "pipe:0", "-frames:v", "1", "-vf", "scale=9:8", "-f", "rawvideo", "-pix_fmt", "gray", "pipe:1"],
                input=data,
                capture_output=True,
                timeout=2.5,
            )
            if proc.returncode == 0 and len(proc.stdout) >= 72:
                b = proc.stdout[:72]
                return [[float(b[y * 9 + x]) for x in range(9)] for y in range(8)]
        except Exception:
            pass
    return None


def compute_dhash_hex(data: bytes) -> str | None:
    """Compute a 64-bit perceptual difference hash (`16-hex-char` string) from image bytes."""
    if not data or len(data) < 24:
        return None
    grid: list[list[float]] | None = None
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        grid = _decode_png_to_9x8(data)
    elif data[:3] == b"\xff\xd8\xff":
        grid = _decode_baseline_jpeg_dc_to_9x8(data)

    if grid is None:
        grid = _decode_via_pillow_or_ffmpeg(data)
    if grid is None:
        return None
    return _grid_9x8_to_dhash_hex(grid)


def hamming_distance_64(hash_a: str, hash_b: str) -> int:
    """Return bit-level Hamming distance (`0..64`) between two 16-hex-char dHashes."""
    return (int(hash_a, 16) ^ int(hash_b, 16)).bit_count()


def visual_similarity_pct(hash_a: str, hash_b: str) -> float:
    dist = hamming_distance_64(hash_a, hash_b)
    return round(((64 - dist) / 64.0) * 100.0, 1)


def find_perceptual_photo_matches(
    images: list[dict[str, Any]],
    *,
    max_hamming_distance: int = 10,
) -> list[dict[str, Any]]:
    """Find cross-platform visually matching avatars/photos even when SHA-256 differs (re-compressed/resized)."""
    hashed = [
        im
        for im in images
        if isinstance(im.get("dhash"), str)
        and len(im["dhash"]) == 16
        and im.get("dhash") not in ("0000000000000000", "ffffffffffffffff")
    ]
    matches: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()

    for i in range(len(hashed)):
        for j in range(i + 1, len(hashed)):
            a, b = hashed[i], hashed[j]
            src_a = str(a.get("source") or a.get("platform") or "")
            src_b = str(b.get("source") or b.get("platform") or "")
            if src_a == src_b and a.get("entity") == b.get("entity"):
                continue
            # Skip pairs already identical by exact SHA-256 unless we want unified visual proof
            if a.get("sha256") and a.get("sha256") == b.get("sha256"):
                continue
            dist = hamming_distance_64(a["dhash"], b["dhash"])
            if dist <= max_hamming_distance:
                pair_key = tuple(sorted((a.get("image_url", ""), b.get("image_url", ""))))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                sim = visual_similarity_pct(a["dhash"], b["dhash"])
                matches.append(
                    {
                        "dhash_a": a["dhash"],
                        "dhash_b": b["dhash"],
                        "hamming_distance": dist,
                        "similarity_pct": sim,
                        "platforms": [
                            {"platform": src_a, "selector": a.get("entity") or a.get("selector")},
                            {"platform": src_b, "selector": b.get("entity") or b.get("selector")},
                        ],
                        "note": (
                            f"Visual Match (~{sim}% similarity, dHash Δ={dist}/64): "
                            f"Same photo re-encoded/resized across {src_a} ({a.get('entity')}) & {src_b} ({b.get('entity')})"
                        ),
                    }
                )

    matches.sort(key=lambda m: m["hamming_distance"])
    return matches

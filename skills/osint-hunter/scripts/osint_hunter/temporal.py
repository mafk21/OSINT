"""Pattern-of-Life, Author Timezone Leak & Circadian Sleep-Window Profiler.

Walks multi-stage OSINT hunt telemetry non-destructively to extract:
  1. Explicit UTC timezone offsets (+HH:MM / -HH:MM) from Git commits, emails & headers
  2. 24-hour UTC human-activity histogram & inferred sleep-window / waking timezone
  3. Chronological forensic timeline separating human actions from registry/cert dates
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

TZ_REGION_HINTS: dict[str, str] = {
    "-10:00": "Hawaii / Polynesia",
    "-09:00": "Alaska",
    "-08:00": "US/Canada Pacific (PST)",
    "-07:00": "US/Canada Mountain / Pacific DST",
    "-06:00": "US/Canada Central / Mexico",
    "-05:00": "US/Canada Eastern / Colombia / Peru",
    "-04:00": "US Eastern DST / Atlantic / Venezuela / Chile",
    "-03:00": "Brazil / Argentina / Uruguay",
    "+00:00": "UTC / UK / Ireland / Portugal / West Africa (or server-normalized UTC)",
    "+01:00": "Central Europe (CET) / UK BST / West-Central Africa",
    "+02:00": "Eastern Europe (EET) / CEST / Egypt / South Africa / Levant",
    "+03:00": "Saudi Arabia / GCC (Qatar, Kuwait, Bahrain) / Iraq / Jordan / Turkey / East Africa / Moscow",
    "+03:30": "Iran",
    "+04:00": "UAE / Oman / Caucasus (Georgia, Armenia, Azerbaijan)",
    "+04:30": "Afghanistan",
    "+05:00": "Pakistan / Uzbekistan / Kazakhstan",
    "+05:30": "India / Sri Lanka (IST)",
    "+05:45": "Nepal",
    "+06:00": "Bangladesh / Kyrgyzstan",
    "+07:00": "Thailand / Vietnam / Indonesia (WIB)",
    "+08:00": "China / Singapore / Malaysia / Taiwan / Hong Kong / Western Australia",
    "+09:00": "Japan / South Korea",
    "+09:30": "Central Australia",
    "+10:00": "Eastern Australia (AEST)",
    "+11:00": "Eastern Australia DST / Pacific",
    "+12:00": "New Zealand (NZST)",
    "+13:00": "New Zealand DST",
}

ISO_TS_RE = re.compile(
    r"\b(20\d{2}|19[89]\d)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b"
)
GIT_OFFSET_LINE_RE = re.compile(
    r"^(?:Date:\s+|[a-zA-Z0-9 ._-]+\s+<[^>\s]+>\s+\d{9,11}\s+)([+-]\d{4})\b"
)
RFC2822_OFFSET_RE = re.compile(
    r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+20\d{2}\s+"
    r"\d{2}:\d{2}:\d{2}\s+([+-]\d{4})\b"
)

HUMAN_ACTIVITY_KEYS = {
    "created_utc_iso",
    "upload_utc_iso",
    "created_utc",
    "commit_date",
    "authored_date",
    "published_at",
    "pushed_at",
    "updated_at",
    "date_utc",
    "search_utc_iso",
    "creation_utc_iso",
}

INFRA_LIFECYCLE_MODULES = {
    "crtsh_ct_logs",
    "iana_rdap",
    "wayback_cdx",
    "active_tls_cert_inspector",
}


def _norm_offset(raw_off: str) -> str | None:
    s = raw_off.strip()
    if s == "Z":
        return "+00:00"
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", s)
    if not m:
        return None
    sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3))
    if hh > 14 or mm >= 60:
        return None
    return f"{sign}{hh:02d}:{mm:02d}"


def _parse_iso_to_utc(ts_str: str) -> tuple[datetime | None, str | None]:
    m = ISO_TS_RE.search(ts_str)
    if not m:
        return None, None
    full = m.group(0)
    raw_tz = m.group(7)
    norm_tz = _norm_offset(raw_tz) if raw_tz else None
    try:
        clean = full.replace(" ", "T")
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        elif raw_tz and len(raw_tz) == 5 and ":" not in raw_tz:
            clean = clean[:-5] + raw_tz[:3] + ":" + raw_tz[3:]
        elif not raw_tz:
            clean = clean + "+00:00"
        dt = datetime.fromisoformat(clean)
        dt_utc = dt.astimezone(timezone.utc)
        if not (1990 <= dt_utc.year <= 2035):
            return None, None
        return dt_utc, norm_tz
    except Exception:
        return None, None


def _estimate_sleep_window(hourly_counts: list[int]) -> dict[str, Any] | None:
    """Given 24 UTC hour buckets, find the quietest 7-hour window and infer local timezone."""
    total = sum(hourly_counts)
    if total < 3:
        return None

    # Sliding 7-hour window on circular 24-hour clock
    best_start = 0
    best_sum = None
    for start_h in range(24):
        win_sum = sum(hourly_counts[(start_h + k) % 24] for k in range(7))
        # Tie-break by preferring windows centered furthest from peak hour
        if best_sum is None or win_sum < best_sum:
            best_sum = win_sum
            best_start = start_h

    end_h = (best_start + 7) % 24
    # Assume typical human sleep midpoint is ~03:30 local time.
    # sleep_mid_utc + offset = 3.5 (mod 24) => offset = 3.5 - sleep_mid_utc
    sleep_mid_utc = (best_start + 3.5) % 24
    raw_offset = 3.5 - sleep_mid_utc
    while raw_offset <= -12:
        raw_offset += 24
    while raw_offset > 14:
        raw_offset -= 24
    rounded_off = int(round(raw_offset))
    sign = "+" if rounded_off >= 0 else "-"
    off_str = f"{sign}{abs(rounded_off):02d}:00"
    confidence = "MODERATE" if total >= 8 else "LOW_SAMPLE"

    return {
        "sleep_window_utc": f"{best_start:02d}:00–{end_h:02d}:00 UTC",
        "quietest_7h_window_utc": f"{best_start:02d}:00–{end_h:02d}:00 UTC",
        "events_in_sleep_window": best_sum,
        "total_human_events": total,
        "inferred_utc_offset": off_str,
        "probable_regions": TZ_REGION_HINTS.get(off_str, "Global"),
        "confidence": confidence,
    }


def build_temporal_profile(report: dict) -> dict:
    """Analyze all timestamps & UTC offsets across a multi-stage OSINT report."""
    tz_counter: Counter[str] = Counter()
    tz_evidence: dict[str, list[str]] = {}
    hourly_human = [0] * 24
    timeline_map: dict[tuple[str, str, str], dict] = {}

    def _record_tz(off: str | None, source_desc: str) -> None:
        if not off:
            return
        tz_counter[off] += 1
        bucket = tz_evidence.setdefault(off, [])
        if source_desc not in bucket and len(bucket) < 5:
            bucket.append(source_desc)

    def _record_event(dt_utc: datetime, cat: str, mod: str, entity: str, label: str) -> None:
        iso_str = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        key = (iso_str, mod, label[:80])
        if key not in timeline_map:
            timeline_map[key] = {
                "timestamp_utc": iso_str,
                "category": cat,
                "module": mod,
                "entity": entity,
                "event": label[:140],
            }
            if cat == "human_activity":
                # Exclude exact 00:00:00 date-only artifacts from circadian hour bucketing
                if not (dt_utc.hour == 0 and dt_utc.minute == 0 and dt_utc.second == 0):
                    hourly_human[dt_utc.hour] += 1

    def _walk(obj: Any, mod: str, entity: str, key_hint: str = "") -> None:
        if isinstance(obj, dict):
            # Explicit timezone offset fields (e.g. from .eml or commit carvers)
            for tz_k in ("timezone_offsets", "commit_timezones", "commit_timezone_offsets", "author_tz_offsets"):
                vals = obj.get(tz_k)
                if isinstance(vals, list):
                    for v in vals:
                        no = _norm_offset(str(v))
                        if no:
                            _record_tz(no, f"{mod} ({entity})")
                elif isinstance(vals, dict):
                    for v, cnt in vals.items():
                        no = _norm_offset(str(v))
                        if no:
                            for _ in range(max(1, min(int(cnt), 20))):
                                _record_tz(no, f"{mod} ({entity})")
            if isinstance(obj.get("sender_timezone_offset"), str):
                no = _norm_offset(obj["sender_timezone_offset"])
                if no:
                    _record_tz(no, f"{mod}:sender_tz ({entity})")

            # Unix epoch fields on Reddit / HN / PGP / TikTok
            for ep_k in ("created_utc", "upload_unix_epoch", "created"):
                ep_v = obj.get(ep_k)
                if isinstance(ep_v, (int, float)) and 946684800 <= ep_v <= 2051222400:
                    dt_u = datetime.fromtimestamp(float(ep_v), tz=timezone.utc)
                    cat = "infrastructure_lifecycle" if mod in INFRA_LIFECYCLE_MODULES else "human_activity"
                    _record_event(dt_u, cat, mod, entity, f"{ep_k} recorded")

            for k, v in obj.items():
                _walk(v, mod, entity, key_hint=str(k))

        elif isinstance(obj, list):
            for item in obj[:60]:
                _walk(item, mod, entity, key_hint=key_hint)

        elif isinstance(obj, str) and len(obj) <= 600:
            # Check RFC 2822 / Git offset strings
            for rm in RFC2822_OFFSET_RE.finditer(obj):
                no = _norm_offset(rm.group(1))
                if no:
                    _record_tz(no, f"{mod}:{key_hint} ({entity})")
                try:
                    dt_p = parsedate_to_datetime(rm.group(0))
                    if dt_p.tzinfo is not None:
                        _record_event(dt_p.astimezone(timezone.utc), "human_activity", mod, entity, f"{key_hint or 'header'} timestamp")
                except Exception:
                    pass

            gm = GIT_OFFSET_LINE_RE.search(obj)
            if gm:
                no = _norm_offset(gm.group(1))
                if no:
                    _record_tz(no, f"{mod}:git_patch ({entity})")

            dt_u, norm_tz = _parse_iso_to_utc(obj)
            if dt_u is not None:
                if norm_tz and norm_tz != "+00:00":
                    _record_tz(norm_tz, f"{mod}:{key_hint} ({entity})")
                is_human = (
                    key_hint in HUMAN_ACTIVITY_KEYS
                    or ("commit" in mod or "tiktok" in mod or "snowflake" in mod or "reddit" in mod or "github" in mod or "eml" in mod)
                ) and mod not in INFRA_LIFECYCLE_MODULES
                cat = "human_activity" if is_human else "infrastructure_lifecycle"
                _record_event(dt_u, cat, mod, entity, f"{key_hint or 'artifact'}: {obj[:60]}")

    for wave in report.get("wave_results", []):
        ent = f"{wave.get('type')}:{wave.get('value')}"
        for col in wave.get("collector_outputs", []):
            if col.get("status") != "ok":
                continue
            mod = str(col.get("module", "collector"))
            _walk(col.get("data"), mod, ent)

    non_zero_tz = {k: v for k, v in tz_counter.items() if k != "+00:00"}
    tz_summary = [
        {
            "utc_offset": off,
            "occurrences": cnt,
            "probable_regions": TZ_REGION_HINTS.get(off, "Unknown Region"),
            "sources": tz_evidence.get(off, []),
        }
        for off, cnt in sorted(tz_counter.items(), key=lambda x: (-x[1], x[0]))
    ]

    sorted_timeline = sorted(timeline_map.values(), key=lambda x: x["timestamp_utc"])
    sleep_est = _estimate_sleep_window(hourly_human)
    peak_hour_utc = max(range(24), key=lambda h: hourly_human[h]) if sum(hourly_human) > 0 else None
    tz_offsets_dict = {off: cnt for off, cnt in sorted(tz_counter.items(), key=lambda x: (-x[1], x[0]))}
    likely_regions = [TZ_REGION_HINTS[off] for off in tz_offsets_dict if off in TZ_REGION_HINTS and off != "+00:00"]
    if not likely_regions and sleep_est and sleep_est.get("probable_regions"):
        likely_regions = [sleep_est["probable_regions"]]
    shift_anomalies = (
        [f"Multiple distinct non-UTC timezone offsets observed ({', '.join(sorted(non_zero_tz.keys()))}) — indicates travel, VPN/proxy rotation, or multi-operator access"]
        if len(non_zero_tz) >= 2
        else []
    )

    return {
        "total_timestamps_extracted": len(sorted_timeline),
        "human_activity_events": sum(hourly_human),
        "human_activity_events_count": sum(hourly_human),
        "inferred_timezone_offsets": tz_offsets_dict,
        "likely_geographic_regions": likely_regions,
        "explicit_timezone_leaks": tz_summary,
        "timezone_shift_detected": len(non_zero_tz) >= 2,
        "timezone_shift_anomalies": shift_anomalies,
        "hourly_activity_utc": {f"{h:02d}:00": hourly_human[h] for h in range(24)},
        "hourly_utc_histogram": {f"{h:02d}": hourly_human[h] for h in range(24)},
        "peak_activity_hour_utc": f"{peak_hour_utc:02d}:00 UTC" if peak_hour_utc is not None else None,
        "circadian_sleep_estimate": sleep_est,
        "estimated_sleep_window_utc": sleep_est,
        "first_seen_utc": sorted_timeline[0]["timestamp_utc"] if sorted_timeline else None,
        "latest_activity_utc": sorted_timeline[-1]["timestamp_utc"] if sorted_timeline else None,
        "chronological_timeline": sorted_timeline[:50],
    }

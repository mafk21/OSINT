---
name: osint-hunter
description: Autonomous OSINT recon and investigation engine. Use whenever the user provides a username, handle, email, phone number, domain, IP, ASN, URL, crypto wallet, 17-char VIN, aircraft ICAO hex, vessel IMO or MMSI, Wi-Fi BSSID, file hash, JWT, or local file to investigate. Executes 35+ passive collectors and offline decoders immediately on Turn 1 with zero clarifying questions, and enforces a mandatory human permission gate before running Active OSINT probes.
license: MIT
compatibility: Python 3.9+ standard library only (zero pip dependencies). Works standalone from any working directory in Claude Code, Codex, Cursor, Claude.ai, and 75+ agents.
---

# Autonomous OSINT Hunter (`osint-hunter`)

This skill bundles a complete, zero-dependency Python 3 OSINT execution engine (`scripts/hunt.py` + `scripts/osint_hunter/`) and offline lookup tables (`data/`). You can execute it from **any directory** without cloning the main repository.

## Locating `hunt.py`

Resolve the bundled `scripts/hunt.py` relative to this `SKILL.md` file (or via `${CLAUDE_SKILL_DIR}` when set):

```bash
HUNT_PY="${CLAUDE_SKILL_DIR:+${CLAUDE_SKILL_DIR}/scripts/hunt.py}"
if [ -z "$HUNT_PY" ] || [ ! -f "$HUNT_PY" ]; then
  for d in "./skills/osint-hunter" "$HOME/.claude/skills/osint-hunter" "$HOME/.codex/skills/osint-hunter" "$HOME/.agents/skills/osint-hunter" ".agents/skills/osint-hunter" ".claude/skills/osint-hunter" ".codex/skills/osint-hunter" "$HOME/.cursor/skills/osint-hunter" "/mnt/skills/user/osint-hunter" "/mnt/skills/private/osint-hunter"; do
    [ -f "$d/scripts/hunt.py" ] && HUNT_PY="$d/scripts/hunt.py" && break
  done
fi
```

---

## Law 1: Passive OSINT — Immediate Turn-1 Execution (Zero Questions)

When the user supplies **any target** (handle, email, phone, domain, IP, ASN, URL, wallet, VIN, aircraft hex, vessel IMO/MMSI, BSSID, SHA-256, JWT, or local file):

1. **DO NOT ask clarifying questions.** Do not ask "Would you like me to investigate?" or "Which tools should I use?".
2. **Immediately run Passive OSINT** on Turn 1:
   ```bash
   python3 "$HUNT_PY" "<target_or_prompt>" --depth 2
   ```
3. **Zero packets are sent to target-owned infrastructure** in Passive Mode. All 35+ collectors query passive public APIs (GitHub commit/SSH/PGP packet carving, npm/PyPI, DoH, `crt.sh`, RDAP, Wayback CDX, Shodan InternetDB, RIPEstat, Nominatim, Bitcoin/EVM RPC) and deterministic offline decoders (ITU E.164, ICAO 24-bit military/country hex, ITU MID/IMO checksum, ISO 3779 VIN, IEEE OUI/BSSID, JWT, EXIF GPS, PDF/DOCX/ZIP metadata).
4. Present a structured **Intelligence Dossier** citing `./cases/<case_id>/` (`dossier.md`, `report.json`, `graph.json`, `stix2_bundle.json`, `manifest.sha256`), entity pivots discovered, and target-forged search dorks.

---

## Law 2: Active OSINT — ALWAYS Ask User Permission Before Every Run (Hard Gate)

Active OSINT sends **direct TCP/TLS/HTTP/DNS packets** to target infrastructure (`:443` X.509 SANs, live HTTP/CSP/analytics headers, `/robots.txt`, `/.well-known/security.txt`, OpenID tenant config, Shodan `mmh3` `/favicon.ico` hash, OpenGraph/JSON-LD `sameAs`, TCP service banners).

**Even if the user explicitly asks for "active recon", "deep scan", or "live probe", you MUST ask for confirmation before EVERY single active run:**

1. **Step 1 — Prepare Single-Use Authorization Token (Sends ZERO Packets)**:
   ```bash
   python3 "$HUNT_PY" "<target>" --prepare-active
   ```
2. **Step 2 — Stop & Ask the User for Explicit Permission**:
   Use your platform's question/confirmation UI (e.g. `ask_user`) or ask clearly in chat, disclosing:
   - Exact target host(s) / IP(s) to be contacted directly
   - Planned active probing modules (from `--prepare-active` output)
   - OPSEC warning (target servers/WAF/IDS will log this machine's egress IP and TLS fingerprint)
3. **Step 3 — Execute ONLY After Explicit User Approval**:
   ```bash
   python3 "$HUNT_PY" "<target>" --active --request-id ACT-XXXXXXXX --user-approved "<verbatim_user_reply>"
   ```
   Each `ACT-XXXXXXXX` token is **single-use**, **target-bound**, and expires in 15 minutes. A new active run always requires a fresh `--prepare-active` + fresh user approval.

For full collector and active-gate details, read `references/ACTIVE_GATE_AND_MODULES.md`.

---
name: osint-hunter
description: Autonomous multi-stage OSINT recon, DFIR forensics, and investigation engine. Use whenever the user provides a username, handle, email, phone number, domain, IP, ASN, URL, crypto wallet, 17-char VIN, aircraft ICAO hex, vessel IMO or MMSI, Wi-Fi BSSID, file hash, JWT, or local file (.eml, .pcap, .har, .mp4, .png, .jpg, .pdf, .docx) to investigate. Executes 45+ passive collectors and 18 offline decoders immediately on Turn 1 with zero clarifying questions, analyzes every stage to recursively hunt all newly discovered clues until surface convergence, and enforces a mandatory human permission gate before running 22 Active OSINT probes.
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

## Law 1 & Law 2: Immediate Passive Start + Exhaustive Multi-Stage Surface Expansion

When the user supplies **any target** (handle, email, phone, domain, IP, ASN, URL, wallet, VIN, aircraft hex, vessel IMO/MMSI, BSSID, SHA-256, JWT, or local file):

1. **DO NOT ask clarifying questions.** Never stop after finding just 1 profile or 1 clue in a stage.
2. **Stage 1 — Exhaustive Seed Hunt** (runs up to 4 stages automatically across all collectors & handle variants, 0 packets sent to target servers):
   ```bash
   python3 "$HUNT_PY" "<target_or_prompt>" --depth 4
   ```
3. **Stage 2..N — Ingest Web/Search Findings & Hunt EVERY Newly Carved Clue Until Convergence**:
   - Run **all** forged search dorks (`report["forged_dorks"]`) via `web_search` / `fetch_page` to gather every bio, Linktree, WhatsApp `wa.me` phone, email, real name, company/clinic, and domain in Stage 1.
   - Feed **all** gathered text/snippets back into the case analyzer so it carves **every** new clue and hunts **all** of them across subsequent stages:
     ```bash
     python3 "$HUNT_PY" --resume-case <CASE_ID> --ingest-file <stage_findings.txt>
     ```
   - Repeat for any newly forged Stage-2/3 dorks until a stage yields **0 new unvisited target leads (`converged: true`)**.
   - Need zero-network DFIR, media provenance, or chronolocation decoding (`.eml`, `.pcap`/`.pcapng`, `.har`, `.mp4`/`.mov`, PNG/WebP C2PA & ComfyUI/SD, Google `ei=`, SSH/PEM, TikTok URL/ID, Discord/X Snowflake, UUIDv1/v6/v7, ULID, MongoDB ObjectId, IBAN, phone, VIN, ICAO24, IMO/MMSI, MAC)? Run `python3 "$HUNT_PY" --decode "<file_or_token>"`.
   - Need attack-surface drift, cross-case link analysis, or IDN Punycode typosquats? Run `--diff-last`, `--compare-cases <A> <B>`, or `--typosquats`.
4. Present the unified **Multi-Stage Intelligence Dossier** citing `./cases/<case_id>/` (`dossier.md`, `report.html`, `report.json`, `entities.csv`, `graph.gexf`, `graph.graphml`, `neo4j.cypher`, `obsidian/`, `stix2_bundle.json`, `manifest.sha256`).

---

## Law 3: Active OSINT — ALWAYS Ask User Permission Before Every Run (Hard Gate)

Active OSINT sends **direct TCP/TLS/HTTP/DNS/SMTP/SSH packets** across **22 built-in live probes** to target infrastructure.

**Even if the user explicitly asks for "full OSINT", "active recon", or "deep scan", you MUST ask for confirmation before EVERY single active run:**

1. **Step 1 — Prepare Single-Use Authorization Token Across the Full Discovered Surface (Sends ZERO Packets)**:
   ```bash
   python3 "$HUNT_PY" --prepare-active --from-case <CASE_ID>
   ```
   *(Or `python3 "$HUNT_PY" "<target>" --prepare-active`.)*
2. **Step 2 — Stop & Ask the User for Explicit Permission**:
   Use your platform's question/confirmation UI (e.g. `ask_user`) or ask clearly in chat, disclosing:
   - Single-use Request ID (`ACT-XXXXXXXX`) & all discovered target hosts/IPs/handles in scope
   - Planned active probing modules (from `--prepare-active` output)
   - OPSEC warning (target servers/WAF/IDS will log this machine's egress IP and TLS fingerprint)
3. **Step 3 — Execute ONLY After Explicit User Approval**:
   ```bash
   python3 "$HUNT_PY" "<target_from_plan>" --active --request-id ACT-XXXXXXXX --user-approved "<verbatim_user_reply>"
   ```
   Each `ACT-XXXXXXXX` token is **single-use**, **target-bound**, and expires in 15 minutes. A new active run always requires a fresh `--prepare-active` + fresh user approval.

For full collector and active-gate details, read `references/ACTIVE_GATE_AND_MODULES.md`.

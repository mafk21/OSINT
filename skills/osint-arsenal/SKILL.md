---
name: osint-arsenal
description: Search and pivot across 540 verified OSINT tools, 20 intelligence disciplines, 24 input-to-output selector chains, 56 Google/Shodan/Censys/FOFA/GitHub dorks, 12 investigation playbooks, and 2026 dead or hijacked tool graveyard warnings. Use when selecting OSINT tools for any clue, planning investigation tradecraft, generating search engine dorks, or checking working replacements for retired tools.
license: MIT
compatibility: Python 3.9+ standard library only (zero pip dependencies). Also includes Markdown reference sheets for non-shell environments.
---

# OSINT 540-Tool Arsenal, Pivot Advisor & Dork Forge (`osint-arsenal`)

This skill bundles the complete validated **540-tool OSINT Monster Database**, **12 multi-hop playbooks**, **56 search dorks**, and **2026 Graveyard warnings** inside `data/` + `scripts/osint.py`.

## Locating `osint.py`

```bash
OSINT_PY="${CLAUDE_SKILL_DIR:+${CLAUDE_SKILL_DIR}/scripts/osint.py}"
if [ -z "$OSINT_PY" ] || [ ! -f "$OSINT_PY" ]; then
  for d in "./skills/osint-arsenal" "$HOME/.claude/skills/osint-arsenal" "$HOME/.codex/skills/osint-arsenal" "$HOME/.agents/skills/osint-arsenal" ".agents/skills/osint-arsenal" ".claude/skills/osint-arsenal" ".codex/skills/osint-arsenal" "$HOME/.cursor/skills/osint-arsenal" "/mnt/skills/user/osint-arsenal" "/mnt/skills/private/osint-arsenal"; do
    [ -f "$d/scripts/osint.py" ] && OSINT_PY="$d/scripts/osint.py" && break
  done
fi
```

## Core Commands

```bash
# 1. Selector Pivot ("I have X, what passive free tools give me Y?")
python3 "$OSINT_PY" pivot email --passive --free
python3 "$OSINT_PY" pivot username --no-auth --tier S
python3 "$OSINT_PY" pivot domain --passive --limit 15

# 2. Full-Text Tool Search Across 540 Verified Tools
python3 "$OSINT_PY" search telegram --passive
python3 "$OSINT_PY" search satellite --free --no-auth
python3 "$OSINT_PY" search --category geoint-maps-satellites --tier S

# 3. Forge Target-Parameterized Google / Shodan / Censys / FOFA / GitHub Dorks
python3 "$OSINT_PY" dorks --target example.com
python3 "$OSINT_PY" dorks --engine Shodan --target example.com

# 4. Multi-Hop Investigation Playbooks & 2026 Dead/Hijacked Tool Graveyard
python3 "$OSINT_PY" workflows
python3 "$OSINT_PY" graveyard
python3 "$OSINT_PY" stats
```

## Supported Selector Types for `pivot`

`username`, `email`, `phone`, `person_name`, `domain`, `ip`, `asn`, `url`, `image`, `video`, `audio`, `coordinates`, `company`, `crypto_address`, `file_hash`, `vessel_imo`, `aircraft_hex`, `vin`, `mac_bssid`, `repo_code`, `onion_url`, `document`, `rf_frequency`, `keyword`.

## Bundled Markdown References (No-Shell Fallback)

If bash execution is unavailable, read directly from this skill directory:
- `references/PIVOT_CHEATSHEET.md` — Top specialist passive S-Tier starting stacks per selector
- `references/WORKFLOWS_QUICKREF.md` — 12 multi-hop OSINT investigation playbooks
- `references/GRAVEYARD_2026.md` — Retired, paywalled, and hijacked OSINT domains to avoid (including the `telegago.com` hijack warning)

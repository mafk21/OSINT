# 🧩 Agent Skills & Plugin Setup Guide (Claude, Codex, Cursor & 75+ Agents)

[⬅️ Back to Main Atlas](../README.md) · [`skills/osint-hunter`](../skills/osint-hunter/SKILL.md) · [`skills/osint-arsenal`](../skills/osint-arsenal/SKILL.md)

You do **not** need to clone or work inside this repository to use **OSINT Monster Database**. Both skills in [`skills/`](../skills/) bundle their own zero-dependency Python 3 runtime and compact intelligence datasets so they work **globally from any folder**.

---

## 📦 Included Skills

| Skill | Folder & Zip | What It Gives Your Agent |
| :--- | :--- | :--- |
| **`osint-hunter`** | [`skills/osint-hunter/`](../skills/osint-hunter/) · [`osint-hunter-skill.zip`](../releases/osint-hunter-skill.zip) | **Autonomous Recon Engine**: Runs 35+ passive collectors & offline decoders immediately on Turn 1 (zero questions), writes STIX 2.1 + SHA-256 dossiers, and enforces a mandatory human permission gate (`ACT-XXXXXXXX`) before Active OSINT probing. |
| **`osint-arsenal`** | [`skills/osint-arsenal/`](../skills/osint-arsenal/) · [`osint-arsenal-skill.zip`](../releases/osint-arsenal-skill.zip) | **540-Tool Tradecraft & Dork Forge**: Searches all 540 verified tools, maps 24 `Input → Output` selector pivots, runs 12 playbooks, forges 56 Google/Shodan/Censys/FOFA/GitHub dorks, and flags 2026 hijacked/dead tools. |

---

## 1️⃣ Universal One-Liner (`npx skills` — 75+ Coding Agents)

Works with **Claude Code**, **OpenAI Codex**, **Cursor**, **OpenCode**, **Windsurf**, **Cline**, **GitHub Copilot**, **Goose**, **Roo**, **Kiro**, and 70+ other agents:

```bash
# Install both skills globally (auto-detects your installed agents)
npx skills add mafk21/OSINT -g

# Or target specific agents explicitly:
npx skills add mafk21/OSINT -g -a claude-code -a codex -a cursor

# Or install only one skill:
npx skills add mafk21/OSINT -g --skill osint-hunter
npx skills add mafk21/OSINT -g --skill osint-arsenal
```

---

## 2️⃣ Claude Code (Native `/plugin` Marketplace)

Inside any **Claude Code** session, register this repository as a plugin marketplace and install in two slash commands:

```text
/plugin marketplace add mafk21/OSINT
/plugin install osint-monster@osint-monster
```

*(Prefer installing just one? Run `/plugin install osint-hunter@osint-monster` or `/plugin install osint-arsenal@osint-monster`.)*

---

## 3️⃣ OpenAI Codex (CLI & Codex App)

### Method A — Codex Built-in `$skill-installer`
Paste either or both commands directly into **Codex**:

```text
$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-hunter
$skill-installer install https://github.com/mafk21/OSINT/tree/main/skills/osint-arsenal
```
*(Restart Codex after installation so it picks up the newly installed skills + `agents/openai.yaml` metadata.)*

### Method B — `npx skills` Targeting Codex
```bash
npx skills add mafk21/OSINT -g -a codex
```

### Method C — Codex Plugin Manifest
This repo also ships native OpenAI Codex plugin manifests ([`.codex-plugin/plugin.json`](../.codex-plugin/plugin.json) and [`.agents/plugins/marketplace.json`](../.agents/plugins/marketplace.json)) bundling both `./skills/` and `./.mcp.json`.

---

## 4️⃣ Claude.ai Web & Claude Desktop (Drag-and-Drop `.zip` Upload)

For **Claude Pro, Max, Team, and Enterprise** users on **claude.ai** or **Claude Desktop**:

1. Download the pre-packaged skill archives from [`releases/`](../releases/):
   - [**`releases/osint-hunter-skill.zip`**](../releases/osint-hunter-skill.zip)
   - [**`releases/osint-arsenal-skill.zip`**](../releases/osint-arsenal-skill.zip)
2. Open Claude → **Settings → Capabilities → Skills** (ensure Code Execution is enabled).
3. Click **Upload skill** and select each `.zip` file.
4. Start any chat and drop a handle, domain, email, VIN, aircraft hex, or investigation question!

---

## 5️⃣ Zero-Node Pure-Python Local Installer (`install_skills.py`)

Don't want to use Node/`npx`? Run the zero-dependency Python installer from a local clone:

```bash
# Install globally to ~/.claude/skills, ~/.codex/skills, ~/.cursor/skills & ~/.agents/skills
python3 scripts/install_skills.py --all

# Or install only to Claude Code or Codex
python3 scripts/install_skills.py --claude
python3 scripts/install_skills.py --codex

# Or install into a specific case/project folder
python3 scripts/install_skills.py --project ~/investigations/case-2026

# Check installation status or uninstall cleanly
python3 scripts/install_skills.py --list
python3 scripts/install_skills.py --uninstall --all
```

---

## 6️⃣ Alternative: Global MCP Server Registration

If you also want native Model Context Protocol tools (`osint_passive_hunt`, `osint_prepare_active_hunt`, `osint_execute_active_hunt`, `osint_search_arsenal`, `osint_forge_dorks`) exposed directly to your agent:

```bash
# Claude Code global MCP registration
claude mcp add --scope user osint-monster -- python3 /absolute/path/to/OSINT/scripts/mcp_server.py

# OpenAI Codex global MCP registration
codex mcp add osint-monster -- python3 /absolute/path/to/OSINT/scripts/mcp_server.py
```

---

## 🛡️ How the Two-Law Safety Doctrine Works Inside Skills

- **`🟢 Passive Mode` (Default — Zero Questions)**: Give Claude or Codex any target (`"Investigate @torvalds and +966501234567"`). The `osint-hunter` skill immediately runs passive collection on Turn 1 without asking clarifying questions and writes a forensic bundle into `./cases/<case_id>/`.
- **`🔴 Active Mode` (Hard-Gated — Always Asks First)**: Even if you say `"Run active recon on example.com"`, the skill **cannot** send direct packets until it first runs `--prepare-active`, shows you the exact hosts + OPSEC exposure, waits for your explicit approval, and consumes a single-use `ACT-XXXXXXXX` token.

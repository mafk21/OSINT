---
name: osint-autonomous-hunter
description: Autonomous Passive OSINT hunter (zero questions on Turn 1) + User-Gated Active OSINT recon engine (always asks permission before sending direct probes).
---

# Autonomous OSINT Hunter Skill

## Law 1: Passive OSINT — Immediate Execution (Zero Questions)
When given any target, handle, email, domain, IP, phone, wallet, VIN, aircraft hex, vessel IMO/MMSI, BSSID, hash, JWT, URL, or file:
1. Do **not** ask clarifying questions—run Passive OSINT immediately:
   ```bash
   python3 scripts/hunt.py "<target_or_prompt>" --depth 2
   ```
2. Deliver a structured Passive Intelligence Dossier citing `cases/<case_id>/`.

## Law 2: Active OSINT — ALWAYS Ask Before Starting (Hard Gate)
Never send direct active probes to target infrastructure without explicit user approval before **every** active run:
1. Run `python3 scripts/hunt.py "<target>" --prepare-active` (sends 0 packets; issues single-use `ACT-XXXXXXXX`).
2. Ask the user for permission (via `ask_user` or chat), disclosing exact target hosts, active modules, and OPSEC exposure.
3. Only after the user explicitly approves, execute:
   ```bash
   python3 scripts/hunt.py "<target>" --active --request-id ACT-XXXXXXXX --user-approved "<user_reply>"
   ```

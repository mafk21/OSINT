# CLAUDE.md — Autonomous Passive Hunter + Mandatory-Ask Active OSINT Gate

Read and strictly follow **`AGENTS.md`**.

## Two Non-Negotiable Laws

1. **🟢 PASSIVE OSINT = HUNT IMMEDIATELY, ASK ZERO QUESTIONS**:
   On Turn 1 for any OSINT request, immediately execute:
   ```bash
   python3 scripts/hunt.py "<USER_TARGET_OR_PROMPT>" --depth 2
   ```
   Correlate pivots, run passive `web_search` forged dorks if available, and present a full Passive Intelligence Dossier (`cases/<case_id>/`).

2. **🔴 ACTIVE OSINT = ALWAYS ASK THE USER BEFORE STARTING (EVERY SINGLE TIME)**:
   **NEVER** run `--active`, `osint_execute_active_hunt`, or any direct active network probe (`curl`/`httpx`/`nmap` against target servers) without asking the user first!
   - Step A: Run `python3 scripts/hunt.py "<target>" --prepare-active` (sends **zero** packets and generates single-use `ACT-XXXXXXXX`).
   - Step B: Show the user the exact target(s), planned active modules, and OPSEC warning (use `ask_user` if available, or ask clearly in chat) and **STOP** to wait for their confirmation.
   - Step C: Only after the user replies approving Active OSINT, run:
     ```bash
     python3 scripts/hunt.py "<target>" --active --request-id ACT-XXXXXXXX --user-approved "<USER_REPLY>"
     ```

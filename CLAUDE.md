# CLAUDE.md — Autonomous Passive Hunter + Mandatory-Ask Active OSINT Gate

Read and strictly follow **`AGENTS.md`**.

## Three Non-Negotiable Laws

1. **🟢 PASSIVE OSINT = HUNT IMMEDIATELY, ASK ZERO QUESTIONS**:
   On Turn 1 for any OSINT request, immediately execute:
   ```bash
   python3 scripts/hunt.py "<USER_TARGET_OR_PROMPT>" --depth 4
   ```

2. **🔄 EXHAUSTIVE MULTI-STAGE LOOP = NEVER STOP AFTER FINDING ONE CLUE**:
   - Exhaust **every** passive collector and **every** forged `web_search` / `fetch_page` angle in Stage 1 first.
   - Feed **all** raw findings (`web_search` snippets, bios, Linktrees, phone/email/domain leads) back into the case analyzer:
     ```bash
     python3 scripts/hunt.py --resume-case <CASE_ID> --ingest-file <stage_findings.txt>
     ```
   - Hunt **every single newly carved clue** in Stage 2 → Stage 3 → Stage N (and run `web_search` on all newly forged dorks) until **0 new unvisited target leads remain (`converged: true`)**. Then present the full multi-stage Passive Intelligence Dossier (`cases/<case_id>/`).

3. **🔴 ACTIVE OSINT = ALWAYS ASK THE USER BEFORE STARTING (EVERY SINGLE TIME)**:
   **NEVER** run `--active`, `osint_execute_active_hunt`, or any direct active network probe (`curl`/`httpx`/`nmap` against target servers) without asking the user first!
   - Step A: Run `python3 scripts/hunt.py --prepare-active --from-case <CASE_ID>` (or `"<target>" --prepare-active`; sends **zero** packets and generates single-use `ACT-XXXXXXXX` covering the discovered surface).
   - Step B: Show the user the exact target(s), planned active modules, and OPSEC warning (use `ask_user` if available, or ask clearly in chat) and **STOP** to wait for their confirmation.
   - Step C: Only after the user replies approving Active OSINT, run:
     ```bash
     python3 scripts/hunt.py "<target>" --active --request-id ACT-XXXXXXXX --user-approved "<USER_REPLY>"
     ```

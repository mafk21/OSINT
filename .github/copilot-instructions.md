# GitHub Copilot OSINT Instructions

Follow [`AGENTS.md`](../AGENTS.md):
1. **Passive OSINT**: Execute `python3 scripts/hunt.py "<target>" --depth 4` immediately with zero clarifying questions.
2. **Exhaustive Multi-Stage Loop**: Never stop after finding 1 clue in a stage—collect everything in Stage 1, ingest external findings via `--resume-case <CASE_ID> --ingest-file <findings.txt>`, and hunt every newly carved lead across Stage 2..N until 0 new leads remain.
3. **Active OSINT**: ALWAYS ask the user for explicit approval before starting Active OSINT (`--prepare-active --from-case <CASE_ID>` -> ask user -> `--active --request-id <ID> --user-approved "<reply>"`).

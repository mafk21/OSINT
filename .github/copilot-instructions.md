# GitHub Copilot OSINT Instructions

Follow [`AGENTS.md`](../AGENTS.md):
1. **Passive OSINT**: Execute `python3 scripts/hunt.py "<target>" --depth 2` immediately with zero clarifying questions.
2. **Active OSINT**: ALWAYS ask the user for explicit approval before starting Active OSINT (`--prepare-active` -> ask user -> `--active --request-id <ID> --user-approved "<reply>"`).

# Contributing to the OSINT Monster Database

Contributions of verified, high-signal, actively maintained OSINT tools, dorks, workflows, and graveyard updates are welcome!

## Architecture: Single Source of Truth

All Markdown tables (`README.md`, `categories/*.md`, `docs/PIVOT_MATRIX.md`, `docs/WORKFLOWS.md`, `docs/DORKS_ARSENAL.md`, `docs/GRAVEYARD_2026.md`), flat exports (`data/tools.csv`, `data/tools.jsonl`), the relational database (`data/osint.sqlite`), and the web bundle (`web/data.js`) are **100% deterministically generated** from the JSON files in `data/`:

- `data/tools.json` — Tool entries conforming strictly to `data/schema.json`
- `data/categories.json` — 20 intelligence discipline definitions
- `data/workflows.json` — Step-by-step investigation playbooks
- `data/dorks.json` — Search engine dork operators
- `data/graveyard.json` — Retired/hijacked tools and verified replacements

**Do not hand-edit generated Markdown tables or exports**—edit the JSON source files in `data/` and run `python3 scripts/build.py`.

---

## Quality Bar for New Tools

1. **Alive & Verifiable**: Must be live, functional, and actively maintained (if a famous tool died or was hijacked, add it to `data/graveyard.json` instead!).
2. **Genuine OSINT Value**: No generic consumer bookmarks, dead forks, or thin wrappers that duplicate upstream tools without adding capability.
3. **Accurate OPSEC Classification**:
   - `"Passive"` — Never sends network packets directly to the target.
   - `"Active"` — Directly probes, crawls, or queries target infrastructure.
   - `"Hybrid"` — Supports both passive and active execution modes.
4. **Actionable `quick_start`**: Include a real CLI invocation, API `curl` one-liner, or concrete analyst tradecraft tip.

---

## Adding a Tool in 3 Steps

1. Append your entry to `data/tools.json` following `data/schema.json`:
   ```json
   {
     "id": "your-tool-slug",
     "name": "Your Tool Name",
     "url": "https://example.org/",
     "github": "owner/repo",
     "category": "domain-dns-asm",
     "subcategory": "Subdomain & Asset Discovery",
     "description": "Clear, technical 1-2 sentence explanation of what it collects and why analysts use it.",
     "type": "CLI",
     "pricing": "Free / Open Source",
     "opsec": "Passive",
     "auth_required": false,
     "inputs": ["domain"],
     "outputs": ["subdomains", "dns_records"],
     "platforms": ["Linux", "macOS", "Go"],
     "tags": ["subdomains", "passive-dns", "golang"],
     "tier": "A",
     "quick_start": "your-tool -d example.com --passive"
   }
   ```
2. Run the strict validator (zero external dependencies, Python 3.9+):
   ```bash
   python3 scripts/validate.py
   ```
3. Rebuild all Markdown docs, CSV/JSONL/SQLite exports, and the Web Explorer bundle:
   ```bash
   python3 scripts/build.py
   ```

#!/usr/bin/env python3
"""Zero-dependency Agent Skills Installer & Zip Packager for OSINT Monster Database.

Installs the self-contained `osint-hunter` and `osint-arsenal` skills globally or into a
project directory for Claude Code, OpenAI Codex, Cursor, Windsurf, GitHub Copilot, OpenCode,
and universal `.agents/skills` hosts — no Node.js required.

Examples:
    python3 scripts/install_skills.py --all
    python3 scripts/install_skills.py --claude --codex
    python3 scripts/install_skills.py --project ~/my-investigation
    python3 scripts/install_skills.py --list
    python3 scripts/install_skills.py --uninstall --all
"""

from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_SRC = ROOT / "skills"
RELEASES_DIR = ROOT / "releases"

SKILL_NAMES = ("osint-hunter", "osint-arsenal")

GLOBAL_TARGETS = {
    "agents": Path.home() / ".agents" / "skills",
    "claude": Path.home() / ".claude" / "skills",
    "codex": Path.home() / ".codex" / "skills",
    "cursor": Path.home() / ".cursor" / "skills",
    "windsurf": Path.home() / ".codeium" / "windsurf" / "skills",
    "copilot": Path.home() / ".copilot" / "skills",
    "opencode": Path.home() / ".config" / "opencode" / "skills",
}

PROJECT_SUBDIRS = {
    "agents": ".agents/skills",
    "claude": ".claude/skills",
    "codex": ".codex/skills",
    "cursor": ".cursor/skills",
}

FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)


def _ignore_junk(_src: str, names: list[str]) -> set[str]:
    return {n for n in names if n in {"__pycache__", ".DS_Store"} or n.endswith(".pyc")}


def build_deterministic_skill_zip(skill_dir: Path, out_zip: Path) -> Path:
    """Create a byte-for-byte deterministic zip archive (<skill-name>/SKILL.md...) for Claude.ai upload."""
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(
        p
        for p in skill_dir.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.name != ".DS_Store"
        and not p.name.endswith(".pyc")
    )
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file_path in files:
            arcname = file_path.relative_to(skill_dir.parent).as_posix()
            info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_ZIP_DT)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if file_path.suffix == ".py" else 0o644) << 16
            zf.writestr(info, file_path.read_bytes())
    return out_zip


def install_to_dir(dest_skills_root: Path, selected_skills: list[str]) -> list[Path]:
    installed: list[Path] = []
    dest_skills_root.mkdir(parents=True, exist_ok=True)
    for sname in selected_skills:
        src = SKILLS_SRC / sname
        if not (src / "SKILL.md").is_file():
            raise FileNotFoundError(f"Skill source missing: {src / 'SKILL.md'} (run `python3 scripts/build.py` first)")
        dst = dest_skills_root / sname
        if dst.is_symlink() or dst.is_file():
            dst.unlink()
        elif dst.is_dir():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, ignore=_ignore_junk)
        installed.append(dst)
    return installed


def uninstall_from_dir(dest_skills_root: Path, selected_skills: list[str]) -> list[Path]:
    removed: list[Path] = []
    for sname in selected_skills:
        dst = dest_skills_root / sname
        if dst.is_symlink() or dst.is_file():
            dst.unlink()
            removed.append(dst)
        elif dst.is_dir():
            shutil.rmtree(dst)
            removed.append(dst)
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="install_skills.py",
        description="Install self-contained OSINT Monster Skills for Claude Code, Codex, Cursor & more",
    )
    parser.add_argument("--all", action="store_true", help="Target Claude Code, Codex, Cursor, and universal ~/.agents/skills")
    parser.add_argument("--claude", action="store_true", help="Install for Claude Code (~/.claude/skills)")
    parser.add_argument("--codex", action="store_true", help="Install for OpenAI Codex (~/.codex/skills & ~/.agents/skills)")
    parser.add_argument("--cursor", action="store_true", help="Install for Cursor (~/.cursor/skills)")
    parser.add_argument("--windsurf", action="store_true", help="Install for Windsurf (~/.codeium/windsurf/skills)")
    parser.add_argument("--copilot", action="store_true", help="Install for GitHub Copilot (~/.copilot/skills)")
    parser.add_argument("--opencode", action="store_true", help="Install for OpenCode (~/.config/opencode/skills)")
    parser.add_argument("--project", help="Install into a specific project directory instead of global user home")
    parser.add_argument("--skill", action="append", choices=SKILL_NAMES, help="Install only specific skill(s)")
    parser.add_argument("--list", action="store_true", help="List available skills and current install status")
    parser.add_argument("--uninstall", action="store_true", help="Remove installed OSINT skills from selected targets")
    parser.add_argument("--package", action="store_true", help="Rebuild releases/*.zip archives for Claude.ai web upload")
    args = parser.parse_args()

    selected_skills = args.skill or list(SKILL_NAMES)

    if args.list:
        print("Available OSINT Monster Skills:")
        for sname in SKILL_NAMES:
            smd = SKILLS_SRC / sname / "SKILL.md"
            status = "READY" if smd.is_file() else "MISSING"
            print(f"  • {sname:<16} [{status}]  ({SKILLS_SRC / sname})")
        print("\nGlobal Agent Skill Directories:")
        for agent, root_dir in GLOBAL_TARGETS.items():
            present = [s for s in SKILL_NAMES if (root_dir / s / "SKILL.md").is_file()]
            tag = ", ".join(present) if present else "not installed"
            print(f"  • {agent:<10} -> {str(root_dir):<42} ({tag})")
        return 0

    if args.package:
        for sname in selected_skills:
            zpath = build_deterministic_skill_zip(SKILLS_SRC / sname, RELEASES_DIR / f"{sname}-skill.zip")
            print(f"Packaged: {zpath} ({zpath.stat().st_size // 1024} KB)")
        if not (args.all or args.claude or args.codex or args.cursor or args.windsurf or args.copilot or args.opencode or args.project):
            return 0

    chosen_targets: list[tuple[str, Path]] = []
    if args.project:
        proj = Path(args.project).expanduser().resolve()
        agents = []
        if args.claude:
            agents.append("claude")
        if args.codex:
            agents.extend(["codex", "agents"])
        if args.cursor:
            agents.append("cursor")
        if args.all or not agents:
            agents = ["agents", "claude", "codex", "cursor"]
        seen = set()
        for a in agents:
            if a not in seen:
                seen.add(a)
                chosen_targets.append((f"project:{a}", proj / PROJECT_SUBDIRS[a]))
    else:
        agents = []
        if args.all:
            agents.extend(["agents", "claude", "codex", "cursor"])
        else:
            if args.claude:
                agents.append("claude")
            if args.codex:
                agents.extend(["codex", "agents"])
            if args.cursor:
                agents.append("cursor")
            if args.windsurf:
                agents.append("windsurf")
            if args.copilot:
                agents.append("copilot")
            if args.opencode:
                agents.append("opencode")
        if not agents:
            # Sensible default when run with no flags: Claude Code + Codex + Universal .agents
            agents = ["agents", "claude", "codex"]
        seen = set()
        for a in agents:
            if a not in seen:
                seen.add(a)
                chosen_targets.append((a, GLOBAL_TARGETS[a]))

    if args.uninstall:
        for label, target_dir in chosen_targets:
            removed = uninstall_from_dir(target_dir, selected_skills)
            for r in removed:
                print(f"[REMOVED] ({label}) {r}")
        return 0

    for label, target_dir in chosen_targets:
        installed = install_to_dir(target_dir, selected_skills)
        for p in installed:
            print(f"[INSTALLED] ({label}) {p}")

    print("\nReady! Restart or open Claude Code / Codex / Cursor in ANY directory and give it a target.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

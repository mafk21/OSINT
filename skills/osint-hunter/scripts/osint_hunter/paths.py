"""Portable path resolution for both Repository Mode and Standalone Installed Skill Mode."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
PKG_PARENT = PKG_DIR.parent

# Detect whether running inside the full OSINT repository or as a standalone Agent Skill
IS_REPO_MODE = (PKG_PARENT / "AGENTS.md").exists() and (PKG_PARENT / "data" / "tools.json").exists()


def resolve_data_dir() -> Path:
    env_dir = os.environ.get("OSINT_DATA_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    candidates = [
        PKG_PARENT / "data",
        PKG_PARENT.parent / "data",
        PKG_DIR / "data",
    ]
    for cand in candidates:
        if (cand / "intel_tables.json").exists():
            return cand
    return PKG_PARENT / "data"


def _ensure_writable_dir(preferred: Path, fallback_name: str) -> Path:
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".write_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return preferred
    except OSError:
        fb = Path(tempfile.gettempdir()) / fallback_name
        fb.mkdir(parents=True, exist_ok=True)
        return fb


def get_cases_dir(override: str | Path | None = None) -> Path:
    if override:
        return _ensure_writable_dir(Path(override).expanduser().resolve(), "osint-cases")
    env_dir = os.environ.get("OSINT_CASES_DIR")
    if env_dir:
        return _ensure_writable_dir(Path(env_dir).expanduser().resolve(), "osint-cases")
    if IS_REPO_MODE:
        return _ensure_writable_dir(PKG_PARENT / "cases", "osint-cases")
    # Standalone Skill Mode: write into ./cases inside user's active working directory
    return _ensure_writable_dir(Path.cwd() / "cases", "osint-cases")


def get_state_dir() -> Path:
    env_dir = os.environ.get("OSINT_STATE_DIR")
    if env_dir:
        return _ensure_writable_dir(Path(env_dir).expanduser().resolve(), "osint-hunter-state")
    if IS_REPO_MODE:
        return _ensure_writable_dir(PKG_PARENT / "cases", "osint-hunter-state")
    # Standalone Skill Mode: persist single-use ACT-XXXXXXXX tokens in user cache across turns
    return _ensure_writable_dir(Path.home() / ".cache" / "osint-hunter", "osint-hunter-state")


DATA_DIR = resolve_data_dir()

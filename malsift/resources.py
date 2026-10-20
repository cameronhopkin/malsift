"""Access to files shipped inside the package (config, prompts, YARA rules, seccomp).

Everything MalSift needs at runtime lives under ``malsift/data`` and is declared as
package data, so a plain ``pip install .`` (non-editable) works the same as a dev checkout.
"""
from __future__ import annotations

from importlib.resources import as_file, files
from pathlib import Path


def data_dir() -> Path:
    """Filesystem path of the packaged ``data`` directory."""
    res = files("malsift").joinpath("data")
    # Installed packages are plain directories for every supported install method, but
    # go through as_file() so zip-style importers still yield a real path.
    with as_file(res) as p:
        return Path(p)


def config_dir() -> Path:
    return data_dir() / "config"


def prompts_dir() -> Path:
    return data_dir() / "prompts"


def rules_dir() -> Path:
    return data_dir() / "rules"


def seccomp_profile() -> Path:
    return data_dir() / "seccomp" / "analyzer.json"


def read_prompt(name: str) -> str | None:
    p = prompts_dir() / name
    return p.read_text(encoding="utf-8") if p.is_file() else None

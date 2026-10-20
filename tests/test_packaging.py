"""Bug 6 regression: config, prompts, rules and seccomp ship inside the package."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from malsift import resources
from malsift.config import load_config

ROOT = Path(__file__).resolve().parent.parent


def test_resources_resolve_inside_package():
    pkg = Path(__import__("malsift").__file__).parent
    for p in (
        resources.config_dir() / "default.yaml",
        resources.prompts_dir() / "analyze.txt",
        resources.prompts_dir() / "deep.txt",
        resources.rules_dir() / "example.yar",
        resources.rules_dir() / "poison_indicators.yar",
        resources.seccomp_profile(),
    ):
        assert p.is_file(), p
        assert pkg in p.parents


@pytest.mark.skipif(not os.environ.get("MALSIFT_EXPECT_INSTALLED"), reason="CI non-editable install job only")
def test_running_against_installed_copy():
    assert "site-packages" in __import__("malsift").__file__


def test_default_config_is_loaded_from_package():
    cfg = load_config()
    assert any(s.endswith("default.yaml") for s in cfg.sources)


@pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / "pyproject.toml").is_file(),
    reason="needs a source checkout",
)
def test_wheel_contains_package_data(tmp_path):
    pytest.importorskip("setuptools")
    pytest.importorskip("wheel")
    src = tmp_path / "src"
    shutil.copytree(
        ROOT, src,
        ignore=shutil.ignore_patterns(".git", ".venv", "*.egg-info", "build", "dist", "__pycache__"),
    )
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "-q",
         "-w", str(tmp_path / "dist"), str(src)],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    whl = next((tmp_path / "dist").glob("malsift-*.whl"))
    names = set(zipfile.ZipFile(whl).namelist())
    for required in (
        "malsift/data/config/default.yaml",
        "malsift/data/prompts/analyze.txt",
        "malsift/data/prompts/deep.txt",
        "malsift/data/rules/example.yar",
        "malsift/data/rules/poison_indicators.yar",
        "malsift/data/seccomp/analyzer.json",
    ):
        assert required in names, required

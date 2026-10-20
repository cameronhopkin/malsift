"""Bug 4 regression: high_entropy_cutoff is honored; per-window entropy + region map."""
from __future__ import annotations

import random

from malsift.cli import main
from malsift.config import load_config
from malsift.static_analysis import analyze_file


def _layered(tmp_path):
    rnd = random.Random(1)
    data = b"\x00" * 2048 + rnd.randbytes(4096) + b"A" * 1024
    p = tmp_path / "layered.bin"
    p.write_bytes(data)
    return p


def test_cutoff_from_config_is_used(tmp_path):
    p = tmp_path / "text.bin"
    p.write_bytes(b"abcdefgh" * 64)  # entropy 3.0
    cfg = load_config()
    assert analyze_file(p, cfg).to_dict()["high_entropy"] is False
    cfg.set(2.5, "static", "high_entropy_cutoff")
    d = analyze_file(p, cfg).to_dict()
    assert d["high_entropy"] is True
    assert d["high_entropy_cutoff"] == 2.5


def test_cutoff_from_local_yaml(tmp_path):
    cdir = tmp_path / "cfgdir"
    cdir.mkdir()
    (cdir / "local.yaml").write_text("static:\n  high_entropy_cutoff: 2.0\n")
    cfg = load_config(cdir)
    assert cfg.get("static", "high_entropy_cutoff") == 2.0


def test_entropy_windows_and_region_map(tmp_path):
    cfg = load_config()
    d = analyze_file(_layered(tmp_path), cfg).to_dict()
    assert d["entropy_block"] == 1024
    assert len(d["entropy_windows"]) == 7
    assert d["entropy_windows"][2]["offset"] == 2048
    assert d["entropy_windows"][0]["entropy"] == 0.0
    assert d["high_entropy_regions"] == [
        {
            "start": 2048,
            "end": 6144,
            "length": 4096,
            "max_entropy": d["high_entropy_regions"][0]["max_entropy"],
            "mean_entropy": d["high_entropy_regions"][0]["mean_entropy"],
        }
    ]
    assert d["high_entropy_regions"][0]["max_entropy"] >= 7.0


def test_small_windows_configurable(tmp_path):
    cfg = load_config()
    cfg.set(256, "static", "entropy_block")
    d = analyze_file(_layered(tmp_path), cfg).to_dict()
    assert len(d["entropy_windows"]) == 28 and d["entropy_windows"][1]["offset"] == 256


def test_region_map_follows_cutoff(tmp_path):
    cfg = load_config()
    cfg.set(7.99, "static", "high_entropy_cutoff")
    d = analyze_file(_layered(tmp_path), cfg).to_dict()
    assert d["high_entropy_regions"] == []


def test_cli_cutoff_flag(tmp_path, capsys):
    import json

    out = tmp_path / "out"
    rc = main(["analyze", str(_layered(tmp_path)), "--no-llm", "--quiet", "--out", str(out),
               "--high-entropy-cutoff", "0.5"])
    assert rc == 0
    rep = json.loads(next(out.glob("*.json")).read_text())
    assert rep["static"]["high_entropy_cutoff"] == 0.5
    assert rep["static"]["high_entropy_regions"][0]["start"] == 2048

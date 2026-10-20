"""Optional capa / radare2 integration: detected when installed, skipped when not."""
from __future__ import annotations

import json
import os
import stat
import sys

from malsift import integrations
from malsift.pipeline import PipelineOptions, run


def _fake_tool(dirpath, name, payload_by_flag):
    script = dirpath / name
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"P = {json.dumps(payload_by_flag)!r}\n"
        "P = json.loads(P)\n"
        "flag = sys.argv[1]\n"
        "print(json.dumps(P.get(flag, {})))\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)


def _enable(cfg):
    cfg.set("auto", "integrations", "capa")
    cfg.set("auto", "integrations", "radare2")


def test_skipped_when_not_installed(tmp_path, monkeypatch, cfg):
    _enable(cfg)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    s = tmp_path / "s.bin"
    s.write_bytes(b"MZ")
    rep = run(s, cfg, PipelineOptions(use_llm=False))
    assert rep["integrations"]["capa"] == {"available": False, "ran": False, "skipped_reason": "capa not installed"}
    assert rep["integrations"]["radare2"]["ran"] is False


def test_disabled_in_config(tmp_path, cfg):
    cfg.set("off", "integrations", "capa")  # (also the test default via MALSIFT_CAPA=off)
    assert integrations.run_all(tmp_path, cfg)["capa"]["skipped_reason"] == "disabled in config"


def test_capa_and_rabin2_results_parsed(tmp_path, monkeypatch, cfg, fake_llm):
    _enable(cfg)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _fake_tool(bindir, "capa", {"--json": {
        "meta": {"version": "9.9"},
        "rules": {
            "check for debugger via API": {"meta": {"namespace": "anti-analysis/anti-debugging",
                                                    "attack": [{"id": "T1622"}]}},
            "contain loop": {"meta": {"lib": True}},
        },
    }})
    _fake_tool(bindir, "rabin2", {
        "-Ij": {"info": {"arch": "x86", "bits": 64, "bintype": "pe", "stripped": True}},
        "-ij": [{"libname": "KERNEL32.dll", "name": "GetTickCount"}],
        "-Sj": [{"name": ".text", "size": 4096, "perm": "-r-x"}],
    })
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    s = tmp_path / "s.bin"
    s.write_bytes(b"MZ")
    rep = run(s, cfg, PipelineOptions(use_llm=True))
    capa = rep["integrations"]["capa"]
    assert capa["ran"] and capa["version"] == "9.9"
    assert capa["capabilities"] == [{"name": "check for debugger via API",
                                     "namespace": "anti-analysis/anti-debugging", "attack": ["T1622"]}]
    assert capa["attack_techniques"] == ["T1622"]
    r2 = rep["integrations"]["radare2"]
    assert r2["info"]["bintype"] == "pe"
    assert r2["imports"] == ["KERNEL32.dll!GetTickCount"]
    assert r2["sections"][0]["name"] == ".text"
    assert "check for debugger via API" in fake_llm[0]["user"]


def test_capa_failure_is_reported(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "capa"
    script.write_text(f"#!{sys.executable}\nimport sys\nsys.stderr.write('unsupported format\\n')\nsys.exit(14)\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    res = integrations.run_capa(tmp_path / "x.bin")
    assert res["ran"] and res["error"] == "unsupported format"


def test_env_toggle(monkeypatch):
    from malsift.config import load_config

    monkeypatch.setenv("MALSIFT_CAPA", "auto")
    assert load_config().get("integrations", "capa") == "auto"
    monkeypatch.setenv("MALSIFT_CAPA", "off")
    assert load_config().get("integrations", "capa") == "off"

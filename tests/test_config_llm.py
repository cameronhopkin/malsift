"""Triage/deep endpoints and MALSIFT_* environment overrides."""
from __future__ import annotations

import pytest

from malsift.config import load_config
from malsift.pipeline import PipelineOptions, run


def test_env_overrides():
    cfg = load_config(environ={
        "MALSIFT_TRIAGE_URL": "http://10.0.0.5:8000/v1",
        "MALSIFT_DEEP_URL": "http://10.0.0.6:8000/v1",
        "MALSIFT_MODEL_TRIAGE": "small-model",
        "MALSIFT_MODEL_DEEP": "big-model",
        "MALSIFT_API_KEY": "test-key-not-real",
        "MALSIFT_TIMEOUT_S": "30",
    })
    assert cfg.get("llm", "triage", "endpoint") == "http://10.0.0.5:8000/v1"
    assert cfg.get("llm", "deep", "endpoint") == "http://10.0.0.6:8000/v1"
    assert cfg.get("llm", "triage", "model") == "small-model"
    assert cfg.get("llm", "deep", "model") == "big-model"
    assert cfg.get("llm", "api_key") == "test-key-not-real"
    assert cfg.get("llm", "timeout_s") == 30


def test_env_beats_local_yaml(tmp_path):
    (tmp_path / "local.yaml").write_text("llm:\n  triage:\n    model: from-yaml\n")
    cfg = load_config(tmp_path, environ={"MALSIFT_MODEL_TRIAGE": "from-env"})
    assert cfg.get("llm", "triage", "model") == "from-env"
    cfg = load_config(tmp_path, environ={})
    assert cfg.get("llm", "triage", "model") == "from-yaml"


def test_config_dir_env(tmp_path):
    (tmp_path / "local.yaml").write_text("report:\n  format: both\n")
    cfg = load_config(environ={"MALSIFT_CONFIG_DIR": str(tmp_path)})
    assert cfg.get("report", "format") == "both"


def test_invalid_env_value():
    with pytest.raises(ValueError):
        load_config(environ={"MALSIFT_TIMEOUT_S": "soon"})


def test_legacy_flat_llm_keys(tmp_path):
    (tmp_path / "local.yaml").write_text("llm:\n  endpoint: http://legacy:1/v1\n  model: old\n")
    cfg = load_config(tmp_path, environ={})
    assert cfg.get("llm", "triage", "endpoint") == "http://legacy:1/v1"
    assert cfg.get("llm", "deep", "endpoint") == "http://legacy:1/v1"
    assert cfg.get("llm", "triage", "model") == "old"


def _sample(tmp_path, evasive=False):
    p = tmp_path / "s.bin"
    p.write_bytes(b"MZ\x00hello world\x00" + (b"vboxservice.exe\x00" if evasive else b""))
    return p


def test_triage_only_by_default(tmp_path, cfg, fake_llm):
    rep = run(_sample(tmp_path), cfg, PipelineOptions(use_llm=True))
    assert [c["model"] for c in fake_llm] == ["qwen3-coder"]
    assert set(rep["llm"]["tiers"]) == {"triage"}


def test_deep_tier_uses_its_own_endpoint(tmp_path, cfg, fake_llm):
    cfg.set("http://deep-host:9/v1", "llm", "deep", "endpoint")
    rep = run(_sample(tmp_path), cfg, PipelineOptions(use_llm=True, deep=True, deep_model="big"))
    assert [(c["endpoint"], c["model"]) for c in fake_llm] == [
        ("http://127.0.0.1:11434/v1", "qwen3-coder"),
        ("http://deep-host:9/v1", "big"),
    ]
    assert "triage model notes" in fake_llm[1]["user"]
    assert rep["llm"]["summary"].startswith("summary from big")
    assert rep["llm"]["tiers"]["deep"]["reason"] == "requested (--deep)"


def test_deep_auto_escalation(tmp_path, cfg, fake_llm):
    cfg.set(True, "llm", "deep", "auto_escalate")
    run(_sample(tmp_path), cfg, PipelineOptions(use_llm=True))
    assert len(fake_llm) == 1  # nothing risky -> no escalation
    fake_llm.clear()
    rep = run(_sample(tmp_path, evasive=True), cfg, PipelineOptions(use_llm=True))
    assert len(fake_llm) == 2
    assert rep["llm"]["tiers"]["deep"]["reason"].startswith("auto-escalated")


def test_unreachable_endpoint_is_reported_not_raised(tmp_path, cfg):
    cfg.set("http://127.0.0.1:9/v1", "llm", "triage", "endpoint")
    cfg.set(2, "llm", "timeout_s")
    rep = run(_sample(tmp_path), cfg, PipelineOptions(use_llm=True))
    assert rep["llm"]["summary"] is None
    assert rep["llm"]["error"]

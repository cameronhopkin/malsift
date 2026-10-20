"""Configuration loading with safe defaults.

Precedence (low to high):

1. built-in defaults (below)
2. packaged ``malsift/data/config/default.yaml``
3. ``local.yaml`` from the config dir (``--config-dir``, ``$MALSIFT_CONFIG_DIR``, or
   ``./config`` in the current working directory)
4. ``MALSIFT_*`` environment variables
5. CLI flags
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import resources

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


DEFAULTS: dict[str, Any] = {
    "llm": {
        "api_key": "not-needed-for-local",
        "timeout_s": 120,
        "temperature": 0.1,
        # Fast first-pass model. Always used when the LLM step is enabled.
        "triage": {
            "endpoint": "http://127.0.0.1:11434/v1",
            "model": "qwen3-coder",
            "max_tokens": 1024,
        },
        # Larger second-pass model. Used with --deep, or automatically when
        # auto_escalate is true and the static facts show risk signals.
        "deep": {
            "endpoint": "http://127.0.0.1:11434/v1",
            "model": "gpt-oss:120b",
            "max_tokens": 2048,
            "auto_escalate": False,
        },
    },
    "static": {
        "string_min_len": 5,
        "max_strings": 2000,
        "entropy_block": 1024,
        "high_entropy_cutoff": 7.2,
        "max_entropy_windows": 4096,
        "max_script_bytes": 2_000_000,
    },
    "yara": {
        # "fail": a rule file with a syntax error aborts the run with the file and error.
        # "warn": the broken file is skipped with a loud warning; the rest still run.
        "on_error": "fail",
    },
    "evasion": {
        # Weighted score at/above which --fail-on-hit trips.
        "fail_threshold": 3,
    },
    "guard": {
        # When True, injection-shaped strings/lines are neutralized (metadata-only marker).
        "neutralize_injection": True,
        # When True, a registered high-risk classifier may hard-quarantine an item.
        "enable_hard_quarantine": True,
    },
    "payloads": {
        "min_base64_len": 80,
        "min_hex_len": 64,
    },
    "integrations": {
        # "auto": use if installed, skip quietly if not. "off": never run.
        "capa": "auto",
        "radare2": "auto",
        "timeout_s": 120,
    },
    "isolation": {
        "image": "malsift-analyzer:latest",
        "memory": "1g",
        "cpus": "1.0",
        "pids_limit": 128,
        "tmpfs_size": "64m",
        "timeout_s": 300,
    },
    "report": {
        "out_dir": "reports",
        "format": "json",
        "defang_iocs": True,
    },
}

# Environment overrides: variable -> config key path (and type converter).
ENV_OVERRIDES: dict[str, tuple[tuple[str, ...], type]] = {
    "MALSIFT_TRIAGE_URL": (("llm", "triage", "endpoint"), str),
    "MALSIFT_DEEP_URL": (("llm", "deep", "endpoint"), str),
    "MALSIFT_MODEL_TRIAGE": (("llm", "triage", "model"), str),
    "MALSIFT_MODEL_DEEP": (("llm", "deep", "model"), str),
    "MALSIFT_API_KEY": (("llm", "api_key"), str),
    "MALSIFT_TIMEOUT_S": (("llm", "timeout_s"), int),
    "MALSIFT_REPORT_DIR": (("report", "out_dir"), str),
    "MALSIFT_REPORT_FORMAT": (("report", "format"), str),
    "MALSIFT_HIGH_ENTROPY_CUTOFF": (("static", "high_entropy_cutoff"), float),
    "MALSIFT_YARA_ON_ERROR": (("yara", "on_error"), str),
    "MALSIFT_ISOLATION_IMAGE": (("isolation", "image"), str),
    "MALSIFT_CAPA": (("integrations", "capa"), str),
    "MALSIFT_RADARE2": (("integrations", "radare2"), str),
}


@dataclass
class Config:
    data: dict[str, Any] = field(default_factory=lambda: _deep_copy(DEFAULTS))
    sources: list[str] = field(default_factory=list)

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def set(self, value: Any, *keys: str) -> None:
        node = self.data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value


def _deep_copy(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        out[k] = _deep_copy(v) if isinstance(v, dict) else v
    return out


def _merge(base: dict[str, Any], over: dict[str, Any]) -> None:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v


def _legacy_llm_keys(loaded: dict[str, Any]) -> None:
    """Map the 0.2.0 flat ``llm.endpoint``/``llm.model`` keys onto both tiers."""
    llm = loaded.get("llm")
    if not isinstance(llm, dict):
        return
    for flat in ("endpoint", "model", "max_tokens"):
        if flat in llm:
            val = llm.pop(flat)
            for tier in ("triage", "deep"):
                tier_cfg = llm.setdefault(tier, {})
                if isinstance(tier_cfg, dict) and flat not in tier_cfg:
                    # model/max_tokens only seed the triage tier; the deep tier keeps its
                    # own bigger defaults unless set explicitly.
                    if flat == "endpoint" or tier == "triage":
                        tier_cfg[flat] = val


def _load_yaml(cfg: Config, path: Path) -> None:
    if yaml is None or not path.is_file():
        return
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if isinstance(loaded, dict):
        _legacy_llm_keys(loaded)
        _merge(cfg.data, loaded)
        cfg.sources.append(str(path))


def apply_env(cfg: Config, environ: dict[str, str] | None = None) -> None:
    env = os.environ if environ is None else environ
    for var, (keys, conv) in ENV_OVERRIDES.items():
        raw = env.get(var)
        if raw is None or raw == "":
            continue
        try:
            cfg.set(conv(raw), *keys)
        except ValueError as e:
            raise ValueError(f"invalid value for {var}: {raw!r} ({e})") from e
        cfg.sources.append(f"env:{var}")


def load_config(
    config_dir: str | os.PathLike[str] | None = None,
    environ: dict[str, str] | None = None,
) -> Config:
    env = os.environ if environ is None else environ
    cfg = Config()
    _load_yaml(cfg, resources.config_dir() / "default.yaml")

    if config_dir:
        user_dir: Path | None = Path(config_dir)
    elif env.get("MALSIFT_CONFIG_DIR"):
        user_dir = Path(env["MALSIFT_CONFIG_DIR"])
    else:
        user_dir = Path.cwd() / "config"
    if user_dir is not None:
        # An explicit directory may carry its own default.yaml (0.2.0 layout) as well.
        if config_dir and (user_dir / "default.yaml").resolve() != (
            resources.config_dir() / "default.yaml"
        ).resolve():
            _load_yaml(cfg, user_dir / "default.yaml")
        _load_yaml(cfg, user_dir / "local.yaml")

    apply_env(cfg, env)
    return cfg

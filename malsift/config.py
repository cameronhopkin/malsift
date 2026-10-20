"""Configuration loading with safe defaults.

Config precedence (low to high): built-in defaults -> config/default.yaml ->
config/local.yaml -> CLI overrides.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


DEFAULTS: dict[str, Any] = {
    "llm": {
        "endpoint": "http://127.0.0.1:11434/v1",
        "model": "qwen3-coder",
        "api_key": "not-needed-for-local",
        "timeout_s": 120,
        "max_tokens": 1024,
        "temperature": 0.1,
    },
    "static": {
        "string_min_len": 5,
        "max_strings": 2000,
        "entropy_block": 256,
        "high_entropy_cutoff": 7.2,
    },
    "guard": {
        # When True, injection-shaped regions are neutralized (metadata-only marker).
        "neutralize_injection": True,
        # When True, a registered high-risk classifier may hard-quarantine a region.
        "enable_hard_quarantine": True,
    },
    "report": {
        "out_dir": "reports",
    },
}


@dataclass
class Config:
    data: dict[str, Any] = field(default_factory=lambda: _deep_copy(DEFAULTS))

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


def load_config(config_dir: str | os.PathLike[str] | None = None) -> Config:
    cfg = Config()
    base = Path(config_dir) if config_dir else Path(__file__).resolve().parent.parent / "config"
    if yaml is None:
        return cfg
    for name in ("default.yaml", "local.yaml"):
        p = base / name
        if p.is_file():
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                _merge(cfg.data, loaded)
    return cfg

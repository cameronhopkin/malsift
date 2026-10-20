"""Optional third-party static analyzers: capa and radare2.

Both are detected at runtime. If a tool is not installed (or disabled in config) the
report says so and the run continues. Both tools only *parse* the sample; neither
executes it. They still parse untrusted input, so prefer running them inside the
isolated analyzer container (``--isolate docker``).

* capa (Mandiant): ``capa --json <sample>``. MalSift records the matched capability
  names, namespaces and the ATT&CK IDs capa attaches to them.
* radare2: ``rabin2 -j`` (shipped with radare2) for binary info, imports and sections.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

MAX_ITEMS = 300


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(  # fixed argv, no shell
        cmd, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL
    )
    return proc.returncode, proc.stdout, proc.stderr


def _skipped(reason: str, available: bool = False) -> dict[str, Any]:
    return {"available": available, "ran": False, "skipped_reason": reason}


def run_capa(sample: Path, mode: str = "auto", timeout: int = 120) -> dict[str, Any]:
    if mode == "off":
        return _skipped("disabled in config")
    exe = shutil.which("capa")
    if exe is None:
        return _skipped("capa not installed")
    try:
        rc, out, err = _run([exe, "--json", str(sample)], timeout)
    except subprocess.TimeoutExpired:
        return {**_skipped(f"timed out after {timeout}s", True), "error": "timeout"}
    except OSError as e:
        return {**_skipped(str(e), True), "error": str(e)}
    if rc != 0 or not out.strip():
        msg = (err.strip().splitlines() or [f"exit code {rc}"])[-1][:300]
        return {"available": True, "ran": True, "error": msg, "capabilities": []}
    try:
        doc = json.loads(out)
    except json.JSONDecodeError as e:
        return {"available": True, "ran": True, "error": f"unparseable JSON: {e}", "capabilities": []}

    caps: list[dict[str, Any]] = []
    attack: set[str] = set()
    for name, rule in (doc.get("rules") or {}).items():
        meta = rule.get("meta", {}) if isinstance(rule, dict) else {}
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue  # library helper rules are noise
        ids = []
        for a in meta.get("attack") or []:
            tid = a.get("id") if isinstance(a, dict) else None
            if tid:
                ids.append(tid)
                attack.add(tid)
        caps.append({"name": name, "namespace": meta.get("namespace"), "attack": ids})
        if len(caps) >= MAX_ITEMS:
            break
    return {
        "available": True,
        "ran": True,
        "version": (doc.get("meta") or {}).get("version"),
        "capabilities": caps,
        "attack_techniques": sorted(attack),
    }


def _rabin2_json(exe: str, flag: str, sample: Path, timeout: int) -> Any:
    rc, out, _err = _run([exe, flag, str(sample)], timeout)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def run_radare2(sample: Path, mode: str = "auto", timeout: int = 120) -> dict[str, Any]:
    if mode == "off":
        return _skipped("disabled in config")
    exe = shutil.which("rabin2")
    if exe is None:
        return _skipped("radare2 (rabin2) not installed")
    try:
        info = _rabin2_json(exe, "-Ij", sample, timeout)
        imports = _rabin2_json(exe, "-ij", sample, timeout)
        sections = _rabin2_json(exe, "-Sj", sample, timeout)
    except subprocess.TimeoutExpired:
        return {**_skipped(f"timed out after {timeout}s", True), "error": "timeout"}
    except OSError as e:
        return {**_skipped(str(e), True), "error": str(e)}

    def _list(doc: Any, key: str) -> list:
        if isinstance(doc, dict):
            doc = doc.get(key, [])
        return doc if isinstance(doc, list) else []

    bin_info = (info or {}).get("info", info) if isinstance(info, dict) else None
    keep = ("arch", "bits", "bintype", "class", "os", "machine", "compiler", "lang",
            "stripped", "static", "canary", "nx", "pic", "signed")
    return {
        "available": True,
        "ran": True,
        "info": {k: bin_info.get(k) for k in keep if k in bin_info} if isinstance(bin_info, dict) else None,
        "imports": [
            f"{i.get('libname') or '?'}!{i.get('name')}" for i in _list(imports, "imports")[:MAX_ITEMS]
            if isinstance(i, dict)
        ],
        "sections": [
            {"name": s.get("name"), "size": s.get("size"), "perm": s.get("perm")}
            for s in _list(sections, "sections")[:MAX_ITEMS]
            if isinstance(s, dict)
        ],
    }


def run_all(sample: Path, cfg) -> dict[str, Any]:
    timeout = int(cfg.get("integrations", "timeout_s", default=120))
    return {
        "capa": run_capa(sample, str(cfg.get("integrations", "capa", default="auto")), timeout),
        "radare2": run_radare2(sample, str(cfg.get("integrations", "radare2", default="auto")), timeout),
    }

"""Static analysis over raw sample bytes.

Everything here operates on bytes the analyst has chosen to examine. It extracts
descriptive facts (type, hashes, entropy, strings, structure, signature hits). It does
not execute the sample.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import magic  # python-magic
except ImportError:  # pragma: no cover
    magic = None

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None


ASCII_STRING_TMPL = rb"[\x20-\x7e]{%d,}"
UTF16_STRING_TMPL = rb"(?:[\x20-\x7e]\x00){%d,}"


@dataclass
class StaticResult:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    filetype: str
    entropy: float
    entropy_windows: list[float] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    pe: dict[str, Any] | None = None
    yara_matches: list[str] = field(default_factory=list)
    yara_details: list[dict[str, Any]] = field(default_factory=list)
    yara_errors: list[str] = field(default_factory=list)
    high_entropy_cutoff: float = 7.2
    entropy_block: int = 1024
    entropy_windows_truncated: bool = False

    @property
    def high_entropy(self) -> bool:
        return self.entropy >= self.high_entropy_cutoff

    def high_entropy_regions(self) -> list[dict[str, Any]]:
        return high_entropy_regions(
            self.entropy_windows, self.entropy_block, self.high_entropy_cutoff, self.size
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "hashes": {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256},
            "filetype": self.filetype,
            "entropy": round(self.entropy, 4),
            "high_entropy": self.high_entropy,
            "high_entropy_cutoff": self.high_entropy_cutoff,
            "entropy_block": self.entropy_block,
            "entropy_windows": [
                {"offset": i * self.entropy_block, "entropy": round(e, 3)}
                for i, e in enumerate(self.entropy_windows)
            ],
            "entropy_windows_truncated": self.entropy_windows_truncated,
            "high_entropy_regions": self.high_entropy_regions(),
            "strings_sampled": len(self.strings),
            "pe": self.pe,
            "yara_matches": self.yara_matches,
            "yara_details": self.yara_details,
            "yara_errors": self.yara_errors,
        }


def _hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _windowed_entropy(data: bytes, block: int, max_windows: int) -> tuple[list[float], bool]:
    """Entropy per fixed-size window. Returns (values, truncated)."""
    if block <= 0:
        return [], False
    starts = range(0, len(data), block)
    truncated = max_windows > 0 and len(starts) > max_windows
    if truncated:
        starts = starts[:max_windows]
    return [shannon_entropy(data[i : i + block]) for i in starts], truncated


def high_entropy_regions(
    windows: list[float], block: int, cutoff: float, size: int
) -> list[dict[str, Any]]:
    """Merge consecutive windows at/above ``cutoff`` into regions with byte offsets."""
    regions: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    vals: list[float] = []
    for i, e in enumerate(windows):
        if e >= cutoff:
            if cur is None:
                cur = {"start": i * block}
                vals = []
            vals.append(e)
            cur["end"] = min((i + 1) * block, size)
        elif cur is not None:
            cur.update(max_entropy=round(max(vals), 3), mean_entropy=round(sum(vals) / len(vals), 3))
            regions.append(cur)
            cur = None
    if cur is not None:
        cur.update(max_entropy=round(max(vals), 3), mean_entropy=round(sum(vals) / len(vals), 3))
        regions.append(cur)
    for r in regions:
        r["length"] = r["end"] - r["start"]
    return regions


def _filetype(data: bytes, path: Path) -> str:
    if magic is not None:
        try:
            return magic.from_buffer(data[:4096])
        except Exception:
            pass
    # Minimal fallback by magic bytes.
    if data[:2] == b"MZ":
        return "PE executable (fallback id)"
    if data[:4] == b"\x7fELF":
        return "ELF executable (fallback id)"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "Mach-O (fallback id)"
    return f"unknown (first bytes: {data[:4].hex()})"


def extract_strings(data: bytes, min_len: int, limit: int) -> list[str]:
    out: list[str] = []
    for tmpl in (ASCII_STRING_TMPL, UTF16_STRING_TMPL):
        rx = re.compile(tmpl % min_len)
        for m in rx.finditer(data):
            try:
                out.append(m.group().decode("ascii", errors="ignore").replace("\x00", ""))
            except Exception:
                continue
            if len(out) >= limit:
                return out
    return out


def _analyze_pe(data: bytes) -> dict[str, Any] | None:
    if pefile is None or data[:2] != b"MZ":
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception as e:  # malformed PE is itself a signal, not a crash
        return {"parse_error": str(e)}

    imports: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("ascii", "ignore") if entry.dll else "?"
        for imp in entry.imports:
            name = imp.name.decode("ascii", "ignore") if imp.name else f"ord{imp.ordinal}"
            imports.append(f"{dll}!{name}")
            if len(imports) >= 400:
                break

    sections = [
        {
            "name": s.Name.decode("ascii", "ignore").rstrip("\x00"),
            "vsize": s.Misc_VirtualSize,
            "rsize": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
        }
        for s in pe.sections
    ]
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", None),
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "sections": sections,
        "imports_sampled": imports,
    }


class RuleCompileError(RuntimeError):
    """One or more YARA rule files failed to compile."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("YARA rule compilation failed:\n  " + "\n  ".join(errors))


@dataclass
class CompiledRules:
    rules: Any | None
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    available: bool = True


def compile_rules(rules_dir: str | Path, on_error: str = "fail") -> CompiledRules:
    """Compile every .yar/.yara file under ``rules_dir`` up front.

    Each file is compiled on its own first so a syntax error is reported with its file
    name and line. ``on_error="fail"`` raises RuleCompileError; ``on_error="warn"`` skips
    the broken files (recording the errors) and compiles the rest. A missing directory or
    a missing yara module is reported, never silently ignored.
    """
    if on_error not in ("fail", "warn"):
        raise ValueError(f"yara on_error must be 'fail' or 'warn', got {on_error!r}")
    if yara is None:
        return CompiledRules(None, errors=["yara-python is not installed; YARA scanning disabled"], available=False)
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        err = f"rules directory not found: {rules_dir}"
        if on_error == "fail":
            raise RuleCompileError([err])
        return CompiledRules(None, errors=[err])

    paths = sorted([*rules_dir.rglob("*.yar"), *rules_dir.rglob("*.yara")])
    good: dict[str, str] = {}
    errors: list[str] = []
    for p in paths:
        ns = p.relative_to(rules_dir).with_suffix("").as_posix().replace("/", "_")
        try:
            yara.compile(filepath=str(p))
        except yara.SyntaxError as e:
            errors.append(f"{p}: {e}")
            continue
        except yara.Error as e:
            errors.append(f"{p}: {e}")
            continue
        good[ns] = str(p)

    if errors and on_error == "fail":
        raise RuleCompileError(errors)
    if not good:
        return CompiledRules(None, files=[], errors=errors)
    try:
        compiled = yara.compile(filepaths=good)
    except yara.Error as e:  # e.g. duplicate rule identifiers across files
        errs = [*errors, f"{rules_dir}: {e}"]
        if on_error == "fail":
            raise RuleCompileError(errs) from e
        return CompiledRules(None, files=[], errors=errs)
    return CompiledRules(compiled, files=sorted(good.values()), errors=errors)


def _yara_scan(data: bytes, rules: Any | None) -> tuple[list[dict[str, Any]], list[str]]:
    if isinstance(rules, CompiledRules):
        rules = rules.rules
    if rules is None:
        return [], []
    try:
        matches = rules.match(data=data, timeout=60)
    except Exception as e:  # noqa: BLE001 - surface, don't swallow
        return [], [f"yara scan error: {e}"]
    out = []
    for m in matches:
        meta = dict(getattr(m, "meta", {}) or {})
        out.append(
            {
                "rule": str(m.rule),
                "namespace": str(getattr(m, "namespace", "")),
                "tags": list(getattr(m, "tags", []) or []),
                "severity": str(meta.get("severity", "unknown")).lower(),
                "description": str(meta.get("description", "")),
            }
        )
    return out, []


def analyze_file(path: str | Path, cfg, rules: Any | None = None) -> StaticResult:
    path = Path(path)
    return analyze_bytes(path.read_bytes(), path, cfg, rules=rules)


def analyze_bytes(data: bytes, path: str | Path, cfg, rules: Any | None = None) -> StaticResult:
    path = Path(path)
    md5, sha1, sha256 = _hashes(data)
    min_len = int(cfg.get("static", "string_min_len", default=5))
    limit = int(cfg.get("static", "max_strings", default=2000))
    block = int(cfg.get("static", "entropy_block", default=1024))
    cutoff = float(cfg.get("static", "high_entropy_cutoff", default=7.2))
    max_windows = int(cfg.get("static", "max_entropy_windows", default=4096))
    windows, truncated = _windowed_entropy(data, block, max_windows)
    yara_details, yara_errors = _yara_scan(data, rules)
    if isinstance(rules, CompiledRules):
        yara_errors = [*rules.errors, *yara_errors]
    return StaticResult(
        path=str(path),
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        filetype=_filetype(data, path),
        entropy=shannon_entropy(data),
        entropy_windows=windows,
        entropy_windows_truncated=truncated,
        strings=extract_strings(data, min_len, limit),
        pe=_analyze_pe(data),
        yara_matches=[d["rule"] for d in yara_details],
        yara_details=yara_details,
        yara_errors=yara_errors,
        high_entropy_cutoff=cutoff,
        entropy_block=block,
    )

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "hashes": {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256},
            "filetype": self.filetype,
            "entropy": round(self.entropy, 4),
            "high_entropy": self.entropy >= 7.2,
            "strings_sampled": len(self.strings),
            "pe": self.pe,
            "yara_matches": self.yara_matches,
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


def _windowed_entropy(data: bytes, block: int) -> list[float]:
    if block <= 0:
        return []
    return [shannon_entropy(data[i : i + block]) for i in range(0, len(data), block)][:512]


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


def compile_rules(rules_dir: str | Path) -> Any | None:
    if yara is None:
        return None
    rules_dir = Path(rules_dir)
    files = {p.stem: str(p) for p in rules_dir.glob("*.yar")}
    files.update({p.stem: str(p) for p in rules_dir.glob("*.yara")})
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except Exception:
        return None


def _yara_scan(data: bytes, rules: Any | None) -> list[str]:
    if rules is None:
        return []
    try:
        return [str(m.rule) for m in rules.match(data=data, timeout=60)]
    except Exception:
        return []


def analyze_file(path: str | Path, cfg, rules: Any | None = None) -> StaticResult:
    path = Path(path)
    data = path.read_bytes()
    md5, sha1, sha256 = _hashes(data)
    min_len = int(cfg.get("static", "string_min_len", default=5))
    limit = int(cfg.get("static", "max_strings", default=2000))
    block = int(cfg.get("static", "entropy_block", default=256))
    return StaticResult(
        path=str(path),
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        filetype=_filetype(data, path),
        entropy=shannon_entropy(data),
        entropy_windows=_windowed_entropy(data, block),
        strings=extract_strings(data, min_len, limit),
        pe=_analyze_pe(data),
        yara_matches=_yara_scan(data, rules),
    )

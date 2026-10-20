"""Comment stripping.

The model is asked to reason about what code *does*, which lives in executing statements,
not in comments. Comments are also the primary carrier for adversarial prompt-injection
bait. We strip common comment forms before anything reaches the LLM. Detection (YARA,
strings, entropy) already ran on the raw bytes, so stripping here loses no coverage.

This is deliberately conservative: it removes comment *regions* for a handful of common
languages. It is not a parser and does not need to be.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# (name, regex). DOTALL where the comment can span lines.
_BLOCK_PATTERNS = [
    ("c_block", re.compile(r"/\*.*?\*/", re.DOTALL)),
    ("html", re.compile(r"<!--.*?-->", re.DOTALL)),
    ("py_docstring_d", re.compile(r'"""(?:.*?)"""', re.DOTALL)),
    ("py_docstring_s", re.compile(r"'''(?:.*?)'''", re.DOTALL)),
]
_LINE_PATTERNS = [
    ("c_line", re.compile(r"//[^\n]*")),
    ("hash_line", re.compile(r"(?m)#[^\n]*")),
    ("dash_line", re.compile(r"--[^\n]*")),
]

_PLACEHOLDER = "[comment removed]"


@dataclass
class PreprocessResult:
    text: str
    removed_regions: int
    removed_bytes: int


def strip_comments(text: str) -> PreprocessResult:
    removed = 0
    removed_bytes = 0

    def _sub(pattern: re.Pattern[str], s: str) -> str:
        nonlocal removed, removed_bytes

        def repl(m: re.Match[str]) -> str:
            nonlocal removed, removed_bytes
            removed += 1
            removed_bytes += len(m.group())
            return _PLACEHOLDER

        return pattern.sub(repl, s)

    for _name, pat in _BLOCK_PATTERNS:
        text = _sub(pat, text)
    for _name, pat in _LINE_PATTERNS:
        text = _sub(pat, text)

    return PreprocessResult(text=text, removed_regions=removed, removed_bytes=removed_bytes)

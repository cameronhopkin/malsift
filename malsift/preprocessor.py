"""Script detection and language-aware comment stripping.

The model is asked to reason about what code *does*, which lives in executing statements,
not in comments. Comments are also a common carrier for adversarial prompt-injection bait,
so for **scripts** we strip comments before anything reaches the LLM. Detection (YARA,
strings, entropy, IOC extraction) already ran on the raw bytes, so stripping loses no
coverage.

Two rules keep this from destroying evidence:

* Only files detected as a script in a known language are stripped. Strings extracted
  from binaries are never comment-stripped: a ``//`` inside ``http://host/path`` or a
  ``--no-sandbox`` flag is an indicator, not a comment.
* Stripping is language-aware. A small scanner tracks string literals and only treats a
  comment token as a comment where that language allows one (``#`` must start a word in
  shell/PowerShell, ``//`` right after ``:`` is a URL, ``REM`` only starts a line, ...).

It is deliberately small and conservative. It is not a parser and does not need to be.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_PLACEHOLDER = "[comment removed]"


@dataclass(frozen=True)
class _Syntax:
    line: tuple[str, ...] = ()
    block: tuple[tuple[str, str], ...] = ()
    quotes: tuple[str, ...] = ()
    escape: str | None = "\\"
    # Comment token must sit at line start or after whitespace / one of these chars.
    word_start_only: bool = False
    word_start_chars: str = ""
    # Tokens that only open a comment at the start of a line (after indentation).
    line_start_only: tuple[str, ...] = ()
    case_insensitive_line_start: bool = False
    # Triple-quoted string that begins a line is a docstring (Python).
    docstrings: bool = False
    # Quote chars whose literal may span newlines.
    multiline_quotes: tuple[str, ...] = ()


SYNTAX: dict[str, _Syntax] = {
    "python": _Syntax(
        line=("#",), quotes=('"""', "'''", '"', "'"), docstrings=True,
        multiline_quotes=('"""', "'''"),
    ),
    "shell": _Syntax(
        line=("#",), quotes=('"', "'"), word_start_only=True, word_start_chars=";|&(){}",
        multiline_quotes=('"', "'"),
    ),
    "powershell": _Syntax(
        line=("#",), block=(("<#", "#>"),), quotes=('"', "'"), escape="`",
        word_start_only=True, word_start_chars=";|&(){}", multiline_quotes=('"', "'"),
    ),
    "javascript": _Syntax(
        line=("//",), block=(("/*", "*/"),), quotes=('"', "'", "`"), multiline_quotes=("`",),
    ),
    "php": _Syntax(
        line=("//", "#"), block=(("/*", "*/"),), quotes=('"', "'"), word_start_only=False,
    ),
    "vbscript": _Syntax(
        line=("'",), quotes=('"',), escape=None, line_start_only=("rem ", "rem\t"),
        case_insensitive_line_start=True,
    ),
    "batch": _Syntax(
        quotes=('"',), escape=None,
        line_start_only=("rem ", "rem\t", "@rem ", "::"), case_insensitive_line_start=True,
    ),
    "html": _Syntax(block=(("<!--", "-->"),), escape=None),
}

LANGUAGES = tuple(SYNTAX)

_EXTENSIONS = {
    ".py": "python", ".pyw": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".js": "javascript", ".jse": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".php": "php", ".phtml": "php",
    ".vbs": "vbscript", ".vbe": "vbscript", ".vba": "vbscript", ".bas": "vbscript",
    ".bat": "batch", ".cmd": "batch",
    ".html": "html", ".htm": "html", ".hta": "html", ".svg": "html",
}

_MAGIC_HINTS = (
    ("python script", "python"),
    ("shell script", "shell"),
    ("bourne-again", "shell"),
    ("powershell", "powershell"),
    ("javascript", "javascript"),
    ("node script", "javascript"),
    ("php script", "php"),
    ("html document", "html"),
    ("dos batch", "batch"),
)

_SHEBANG = re.compile(rb"^#!\s*\S*?(?:/env\s+)?(python[\d.]*|bash|sh|zsh|ksh|dash|node|pwsh|php)\b")
_SHEBANG_MAP = {
    "bash": "shell", "sh": "shell", "zsh": "shell", "ksh": "shell", "dash": "shell",
    "node": "javascript", "pwsh": "powershell", "php": "php",
}

# Content heuristics: (language, pattern). A language needs >= 2 distinct hits.
_HEURISTICS: list[tuple[str, re.Pattern[str]]] = [
    ("python", re.compile(r"(?m)^\s*(?:import \w|from [\w.]+ import |def \w+\(|class \w+[(:])")),
    ("python", re.compile(r"(?m)^if __name__ == ['\"]__main__['\"]")),
    ("powershell", re.compile(r"(?i)\$env:|\bparam\s*\(|\b(?:invoke|new|get|set)-[a-z]+\b")),
    ("powershell", re.compile(r"(?i)-executionpolicy|\[system\.[a-z.]+\]::")),
    ("javascript", re.compile(r"\bfunction\s*\w*\s*\(|\b(?:var|let|const)\s+\w+\s*=")),
    ("javascript", re.compile(r"\bWScript\.|\bActiveXObject\b|\bdocument\.|=>\s*\{")),
    ("vbscript", re.compile(r"(?im)^\s*(?:dim|sub|function|set)\s+\w+")),
    ("vbscript", re.compile(r"(?i)\bCreateObject\s*\(|\bEnd\s+(?:Sub|Function|If)\b")),
    ("batch", re.compile(r"(?im)^\s*@?echo\s+off\b")),
    ("batch", re.compile(r"(?im)^\s*(?:set\s+\w+=|goto\s+:?\w+|call\s+:\w+|if\s+(?:not\s+)?exist)")),
    ("html", re.compile(r"(?i)<!doctype html|<html[\s>]")),
    ("html", re.compile(r"(?i)<(?:body|head|script|div)[\s>]")),
    ("php", re.compile(r"<\?php\b")),
    ("php", re.compile(r"\$_(?:GET|POST|REQUEST|SERVER)\b")),
]


def looks_binary(data: bytes) -> bool:
    head = data[:8192]
    if not head:
        return False
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return False
    if b"\x00" in head:
        return True
    ctrl = sum(1 for b in head if b < 9 or 13 < b < 32)
    return ctrl / len(head) > 0.05


def decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", errors="replace")


def detect_script_language(data: bytes, filetype: str = "", path: str | Path | None = None) -> str | None:
    """Return the script language of a sample, or None if it is not a known script.

    Binaries (NUL bytes / control chars, or an executable magic) are never scripts.
    """
    ft = (filetype or "").lower()
    if any(k in ft for k in ("executable", "pe32", "elf", "mach-o", "archive", "image data")):
        return None
    if looks_binary(data):
        return None

    m = _SHEBANG.match(data[:256])
    if m:
        interp = m.group(1).decode()
        return "python" if interp.startswith("python") else _SHEBANG_MAP.get(interp)

    if path is not None:
        lang = _EXTENSIONS.get(Path(path).suffix.lower())
        if lang:
            return lang

    for hint, lang in _MAGIC_HINTS:
        if hint in ft:
            return lang

    text = decode_text(data[:65536])
    hits: dict[str, set[int]] = {}
    for i, (lang, rx) in enumerate(_HEURISTICS):
        if rx.search(text):
            hits.setdefault(lang, set()).add(i)
    best = max(hits.items(), key=lambda kv: len(kv[1]), default=None)
    if best and len(best[1]) >= 2:
        return best[0]
    return None


@dataclass
class PreprocessResult:
    text: str
    removed_regions: int
    removed_bytes: int
    language: str | None = None
    kinds: dict[str, int] = field(default_factory=dict)


def _startswith(text: str, i: int, tok: str, ci: bool = False) -> bool:
    chunk = text[i : i + len(tok)]
    return chunk.lower() == tok if ci else chunk == tok


def strip_comments(text: str, language: str) -> PreprocessResult:
    """Strip comments from script ``text`` written in ``language``.

    Comment regions become ``[comment removed]``; block comments keep their newlines so
    line numbers stay stable. String literals are left intact.
    """
    syn = SYNTAX.get(language)
    if syn is None:
        raise ValueError(f"unsupported script language: {language!r}")

    out: list[str] = []
    removed = 0
    removed_bytes = 0
    kinds: dict[str, int] = {}
    i = 0
    n = len(text)
    at_line_start = True
    quotes = sorted(syn.quotes, key=len, reverse=True)

    def _drop(kind: str, chunk: str) -> None:
        nonlocal removed, removed_bytes
        removed += 1
        removed_bytes += len(chunk)
        kinds[kind] = kinds.get(kind, 0) + 1
        out.append(_PLACEHOLDER + "\n" * chunk.count("\n"))

    while i < n:
        ch = text[i]

        if at_line_start and ch in " \t":
            out.append(ch)
            i += 1
            continue

        # Line-start-only comment tokens (REM, ::).
        if at_line_start and syn.line_start_only:
            tok = next(
                (t for t in syn.line_start_only
                 if _startswith(text, i, t, syn.case_insensitive_line_start)),
                None,
            )
            if tok is None and syn.case_insensitive_line_start:
                # "REM" alone on a line.
                for t in syn.line_start_only:
                    bare = t.rstrip()
                    if _startswith(text, i, bare, True) and text[i + len(bare) : i + len(bare) + 1] in ("\n", "\r", ""):
                        tok = bare
                        break
            if tok is not None:
                end = text.find("\n", i)
                end = n if end == -1 else end
                _drop("line", text[i:end])
                i = end
                continue

        # Docstrings: a triple-quoted literal that starts a line.
        if syn.docstrings and at_line_start:
            tq = next((q for q in ('"""', "'''") if text.startswith(q, i)), None)
            if tq:
                end = text.find(tq, i + 3)
                end = n if end == -1 else end + 3
                _drop("docstring", text[i:end])
                i = end
                at_line_start = False
                continue

        # Block comments.
        blk = next((b for b in syn.block if text.startswith(b[0], i)), None)
        if blk is not None:
            end = text.find(blk[1], i + len(blk[0]))
            end = n if end == -1 else end + len(blk[1])
            _drop("block", text[i:end])
            i = end
            at_line_start = False
            continue

        # Line comments.
        lc = next((t for t in syn.line if text.startswith(t, i)), None)
        if lc is not None:
            prev = text[i - 1] if i > 0 else "\n"
            ok = True
            if syn.word_start_only and not (prev.isspace() or prev in syn.word_start_chars):
                ok = False
            if lc == "//" and prev == ":":  # scheme://host is a URL, not a comment
                ok = False
            if ok:
                end = text.find("\n", i)
                end = n if end == -1 else end
                _drop("line", text[i:end])
                i = end
                continue

        # String literals: copy verbatim.
        q = next((q for q in quotes if text.startswith(q, i)), None)
        if q is not None:
            j = i + len(q)
            multiline = q in syn.multiline_quotes
            while j < n:
                if syn.escape and text[j] == syn.escape and len(q) == 1:
                    j += 2
                    continue
                if text.startswith(q, j):
                    j += len(q)
                    break
                if text[j] == "\n" and not multiline:
                    break  # unterminated single-line literal: stop at end of line
                j += 1
            out.append(text[i:j])
            i = j
            at_line_start = False
            continue

        out.append(ch)
        at_line_start = ch == "\n"
        i += 1

    return PreprocessResult(
        text="".join(out),
        removed_regions=removed,
        removed_bytes=removed_bytes,
        language=language,
        kinds=kinds,
    )

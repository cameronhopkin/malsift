"""Content guard.

Malware authors embed text whose only purpose is to hijack an LLM analyzer: fake system
prompts, "ignore previous instructions", fabricated role headers, delimiter spoofing, and
padded decoys meant to trip content policies so the model refuses and triage stalls.

The guard keys on the *structure* of such injections, never on subject matter. There is no
dictionary of sensitive topics in this repo and there must never be one. Two outcomes:

Guarding is per item: each extracted string, or each line of a script, is judged on its
own so one planted string cannot hide its neighbours.

  - NEUTRALIZE: injection-shaped item replaced with a metadata-only marker so the
    pipeline keeps moving. The raw content is never forwarded to the model or the report.
  - QUARANTINE: if a host-supplied high-risk classifier flags an item, it is recorded as
    a hash + reason only. The content itself is never surfaced.

A deployer wires in their own classifier via register_classifier(). None ships here.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

# Structural signatures of prompt-injection attempts. These match *shape*, not topic.
_INJECTION_SIGNATURES = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"),
    re.compile(r"(?i)disregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|message|instructions)"),
    re.compile(r"(?i)you\s+are\s+now\s+(?:a|an|in)\b"),
    re.compile(r"(?i)\bnew\s+instructions?\s*:"),
    re.compile(r"(?i)^\s*(?:system|assistant|user)\s*:", re.MULTILINE),
    re.compile(r"(?i)<\|?(?:system|im_start|im_end|endoftext)\|?>"),
    re.compile(r"(?i)\[/?INST\]"),
    re.compile(r"(?i)###\s*(?:system|instruction|response)\b"),
    re.compile(r"(?i)do\s+not\s+(?:analyze|respond|comply|continue)"),
    re.compile(r"(?i)refuse\s+to\s+(?:analyze|answer|help)"),
]

# An item is "suspicious" if it trips >=1 signature; score is the count.
_HighRiskClassifier = Callable[[str], "tuple[bool, str] | None"]
_classifiers: list[_HighRiskClassifier] = []


def register_classifier(fn: _HighRiskClassifier) -> None:
    """Register a host-supplied high-risk classifier.

    fn(region_text) -> (True, reason) to hard-quarantine, or None/(False, _) to pass.
    The classifier must return a reason string only, never the flagged content.
    """
    _classifiers.append(fn)


def clear_classifiers() -> None:
    _classifiers.clear()


@dataclass
class GuardMarker:
    kind: str  # "neutralized" | "quarantined"
    sha256: str
    reason: str
    span: tuple[int, int]


@dataclass
class GuardResult:
    text: str
    markers: list[GuardMarker] = field(default_factory=list)

    @property
    def neutralized(self) -> int:
        return sum(1 for m in self.markers if m.kind == "neutralized")

    @property
    def quarantined(self) -> int:
        return sum(1 for m in self.markers if m.kind == "quarantined")


def _injection_score(region: str) -> int:
    return sum(1 for sig in _INJECTION_SIGNATURES if sig.search(region))


def _run_classifiers(region: str) -> tuple[bool, str] | None:
    for fn in _classifiers:
        try:
            verdict = fn(region)
        except Exception:
            continue
        if verdict and verdict[0]:
            return True, str(verdict[1])
    return None


def _guard_item(
    item: str, span: tuple[int, int], *, neutralize: bool, hard_quarantine: bool
) -> tuple[str, GuardMarker | None]:
    """Guard one unit (a single extracted string, or a single line of script text)."""
    if not item.strip():
        return item, None
    digest = hashlib.sha256(item.encode("utf-8", "ignore")).hexdigest()

    quarantine = _run_classifiers(item) if hard_quarantine else None
    if quarantine:
        marker = GuardMarker("quarantined", digest, quarantine[1], span)
        return f"[quarantined item sha256={digest[:16]} reason={quarantine[1]}]", marker

    score = _injection_score(item)
    if score and neutralize:
        marker = GuardMarker("neutralized", digest, f"injection_signatures={score}", span)
        return f"[neutralized injection-shaped item sha256={digest[:16]}]", marker

    return item, None


def scan_strings(
    strings: list[str], *, neutralize: bool = True, hard_quarantine: bool = True
) -> tuple[list[str], list[GuardMarker]]:
    """Guard a list of extracted strings, evaluating EACH string on its own.

    Strings pulled out of a binary are independent artifacts. Joining them and guarding
    the blob lets one planted string take every neighbouring indicator down with it, which
    is exactly the stall attack the guard exists to stop. Only the offending string is
    replaced; the span is the string's index in the input list.
    """
    out: list[str] = []
    markers: list[GuardMarker] = []
    for idx, s in enumerate(strings):
        text, marker = _guard_item(
            s, (idx, idx + 1), neutralize=neutralize, hard_quarantine=hard_quarantine
        )
        out.append(text)
        if marker:
            markers.append(marker)
    return out, markers


def scan(text: str, *, neutralize: bool = True, hard_quarantine: bool = True) -> GuardResult:
    """Guard free text (e.g. a script view) line by line.

    Each line is evaluated independently, so a planted line is neutralized without
    taking the surrounding code or indicators with it. Spans are character offsets.
    """
    markers: list[GuardMarker] = []
    out_parts: list[str] = []
    for match in re.finditer(r"[^\n]*(?:\n|\Z)", text):
        line = match.group()
        if not line:
            continue
        body = line[:-1] if line.endswith("\n") else line
        nl = "\n" if line.endswith("\n") else ""
        guarded, marker = _guard_item(
            body,
            (match.start(), match.start() + len(body)),
            neutralize=neutralize,
            hard_quarantine=hard_quarantine,
        )
        out_parts.append(guarded + nl)
        if marker:
            markers.append(marker)
    return GuardResult(text="".join(out_parts), markers=markers)

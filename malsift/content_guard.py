"""Content guard.

Malware authors embed text whose only purpose is to hijack an LLM analyzer: fake system
prompts, "ignore previous instructions", fabricated role headers, delimiter spoofing, and
padded decoys meant to trip content policies so the model refuses and triage stalls.

The guard keys on the *structure* of such injections, never on subject matter. There is no
dictionary of sensitive topics in this repo and there must never be one. Two outcomes:

  - NEUTRALIZE: injection-shaped region replaced with a metadata-only marker so the
    pipeline keeps moving. The raw content is never forwarded to the model or the report.
  - QUARANTINE: if a host-supplied high-risk classifier flags a region, it is recorded as
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

# A region is "suspicious" if it trips >=1 signature; score is the count.
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


def scan(text: str, *, neutralize: bool = True, hard_quarantine: bool = True) -> GuardResult:
    """Scan text region-by-region (split on blank lines) and guard suspicious regions."""
    markers: list[GuardMarker] = []
    out_parts: list[str] = []

    # Split into regions but keep offsets for marker spans.
    for match in re.finditer(r".*?(?:\n\s*\n|\Z)", text, re.DOTALL):
        region = match.group()
        if not region:
            continue
        start, end = match.start(), match.end()
        digest = hashlib.sha256(region.encode("utf-8", "ignore")).hexdigest()

        quarantine = _run_classifiers(region) if hard_quarantine else None
        if quarantine:
            markers.append(GuardMarker("quarantined", digest, quarantine[1], (start, end)))
            out_parts.append(f"[quarantined region sha256={digest[:16]} reason={quarantine[1]}]")
            continue

        score = _injection_score(region)
        if score and neutralize:
            markers.append(
                GuardMarker("neutralized", digest, f"injection_signatures={score}", (start, end))
            )
            out_parts.append(f"[neutralized injection-shaped region sha256={digest[:16]}]")
            continue

        out_parts.append(region)

    return GuardResult(text="".join(out_parts), markers=markers)

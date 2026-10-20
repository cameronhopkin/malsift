"""End-to-end triage pipeline.

Order matters for safety:
  1. static analysis on raw bytes (full coverage, nothing stripped)
  2. evasion indicator detection (reads static facts)
  3. preprocess: strip comments from any text view of the sample
  4. content guard: neutralize/quarantine injection-shaped regions
  5. LLM triage: sanitized context only
  6. report
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import content_guard, evasion, report, static_analysis
from .llm_client import LLMClient
from .preprocessor import strip_comments

_PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts"


@dataclass
class PipelineOptions:
    use_llm: bool = True
    endpoint: str | None = None
    model: str | None = None


def _load_prompt() -> str:
    p = _PROMPT_DIR / "analyze.txt"
    if p.is_file():
        return p.read_text(encoding="utf-8")
    return (
        "You are a malware-analysis assistant. Given sanitized static-analysis facts, "
        "describe likely behavior, suggest a family, and list MITRE ATT&CK technique IDs "
        "(T####) as leads. Be concise and do not speculate beyond the evidence."
    )


def _sanitized_text_view(static: static_analysis.StaticResult, cfg) -> tuple[str, dict[str, Any]]:
    """Build the text the model may see: strings joined, comments stripped, guarded."""
    raw = "\n".join(static.strings)
    pre = strip_comments(raw)
    g = content_guard.scan(
        pre.text,
        neutralize=bool(cfg.get("guard", "neutralize_injection", default=True)),
        hard_quarantine=bool(cfg.get("guard", "enable_hard_quarantine", default=True)),
    )
    guard_meta = {
        "neutralized": g.neutralized,
        "quarantined": g.quarantined,
        "comments_removed": pre.removed_regions,
        "markers": [
            {"kind": m.kind, "sha256": m.sha256[:16], "reason": m.reason} for m in g.markers
        ],
    }
    return g.text, guard_meta


def run(path: str | Path, cfg, opts: PipelineOptions, rules=None) -> dict[str, Any]:
    static = static_analysis.analyze_file(path, cfg, rules=rules)
    ev = evasion.detect(static.strings, static.pe)
    sanitized_text, guard_meta = _sanitized_text_view(static, cfg)

    llm_summary: str | None = None
    llm_error: str | None = None
    if opts.use_llm:
        client = LLMClient(
            endpoint=opts.endpoint or cfg.get("llm", "endpoint"),
            model=opts.model or cfg.get("llm", "model"),
            api_key=cfg.get("llm", "api_key", default="not-needed-for-local"),
            timeout_s=int(cfg.get("llm", "timeout_s", default=120)),
            max_tokens=int(cfg.get("llm", "max_tokens", default=1024)),
            temperature=float(cfg.get("llm", "temperature", default=0.1)),
        )
        user_ctx = _build_llm_context(static, ev, sanitized_text)
        resp = client.chat(system=_load_prompt(), user=user_ctx)
        if resp.ok:
            llm_summary = resp.content
        else:
            llm_error = resp.error

    return report.build_report(
        static=static.to_dict(),
        evasion=ev.to_dict(),
        guard=guard_meta,
        llm_summary=llm_summary,
        llm_error=llm_error,
    )


def _build_llm_context(static: static_analysis.StaticResult, ev: evasion.EvasionReport,
                       sanitized_text: str) -> str:
    lines = [
        f"filetype: {static.filetype}",
        f"size: {static.size}",
        f"entropy: {round(static.entropy, 3)}",
        f"yara_matches: {', '.join(static.yara_matches) or 'none'}",
        f"anti_analysis_score: {ev.score}",
        f"anti_debug_apis: {', '.join(ev.anti_debug_apis) or 'none'}",
        f"vm_artifacts: {', '.join(ev.vm_artifacts) or 'none'}",
    ]
    if static.pe and "imports_sampled" in static.pe:
        imps = static.pe["imports_sampled"][:60]
        lines.append("imports (sampled): " + ", ".join(imps))
    lines.append("")
    lines.append("sanitized strings (comments stripped, injection-shaped regions neutralized):")
    lines.append(sanitized_text[:8000])
    return "\n".join(lines)

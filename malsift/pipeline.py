"""End-to-end triage pipeline.

The pipeline is split in two halves so the half that parses untrusted bytes can run in
the hardened analyzer container (``--isolate docker``) while the half that talks to the
model runs on the host:

``extract()``  (runs on the host, or isolated in the container)
  1. static analysis on raw bytes: type, hashes, entropy map, strings, PE, YARA
  2. optional capa / radare2
  3. IOC extraction on the RAW strings / script text (before any sanitizing)
  4. evasion indicator detection + sandbox masking hints
  5. scripts only (by detected file type): payload-blob isolation, then
     language-aware comment stripping

``analyze()``  (always on the host; consumes the extraction JSON)
  6. content guard: each extracted string (or script line) judged on its own
  7. LLM: triage tier, optional deep tier, sanitized context only
  8. report
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import (
    content_guard,
    evasion,
    integrations,
    ioc,
    payloads,
    preprocessor,
    report,
    resources,
    static_analysis,
)
from .llm_client import LLMClient

EXTRACTION_SCHEMA = 1

_FALLBACK_PROMPT = (
    "You are a malware-analysis assistant. Given sanitized static-analysis facts, "
    "describe likely behavior, suggest a family, and list MITRE ATT&CK technique IDs "
    "(T####) as leads. Be concise and do not speculate beyond the evidence."
)


@dataclass
class PipelineOptions:
    use_llm: bool = True
    endpoint: str | None = None  # triage endpoint override
    model: str | None = None  # triage model override
    deep: bool = False  # force the deep tier
    deep_endpoint: str | None = None
    deep_model: str | None = None
    isolation: dict[str, Any] | None = None  # filled in by the CLI


def _load_prompt(name: str = "analyze.txt") -> str:
    return resources.read_prompt(name) or _FALLBACK_PROMPT


# --------------------------------------------------------------------------------------
# Half 1: extraction over untrusted bytes
# --------------------------------------------------------------------------------------


def extract(path: str | Path, cfg, rules=None, *, run_integrations: bool = True) -> dict[str, Any]:
    """Everything that parses the sample. Output is plain JSON-serializable data."""
    path = Path(path)
    data = path.read_bytes()
    static = static_analysis.analyze_bytes(data, path, cfg, rules=rules)

    language = preprocessor.detect_script_language(data, static.filetype, path)
    script: dict[str, Any] | None = None
    ioc_sources: list[str] = list(static.strings)
    if language:
        max_bytes = int(cfg.get("static", "max_script_bytes", default=2_000_000))
        raw_text = preprocessor.decode_text(data[:max_bytes])
        ioc_sources.append(raw_text)
        iso_text, blobs = payloads.isolate(
            raw_text,
            min_base64_len=int(cfg.get("payloads", "min_base64_len", default=80)),
            min_hex_len=int(cfg.get("payloads", "min_hex_len", default=64)),
        )
        pre = preprocessor.strip_comments(iso_text, language)
        script = {
            "language": language,
            "truncated": len(data) > max_bytes,
            "text": pre.text,  # comment-stripped, blobs replaced; guarded later on the host
            "comments_removed": pre.removed_regions,
            "comment_bytes_removed": pre.removed_bytes,
            "payload_blobs": [b.to_dict() for b in blobs],
        }

    # IOC extraction runs on raw material, before any sanitizing.
    iocs = ioc.extract(ioc_sources)
    ev = evasion.detect(static.strings + ([raw_text] if language else []), static.pe)
    integ = integrations.run_all(path, cfg) if run_integrations else {}

    sd = static.to_dict()
    sd["script_language"] = language
    return {
        "schema": EXTRACTION_SCHEMA,
        "static": sd,
        "strings": static.strings,
        "script": script,
        "iocs": iocs.to_dict(defang=False),
        "evasion": ev.to_dict(),
        "integrations": integ,
    }


# --------------------------------------------------------------------------------------
# Half 2: guard + model + report (host)
# --------------------------------------------------------------------------------------


def _guard(extraction: dict[str, Any], cfg) -> tuple[str, dict[str, Any]]:
    neutralize = bool(cfg.get("guard", "neutralize_injection", default=True))
    hard_q = bool(cfg.get("guard", "enable_hard_quarantine", default=True))
    script = extraction.get("script")
    if script:
        g = content_guard.scan(script["text"], neutralize=neutralize, hard_quarantine=hard_q)
        view, markers, unit = g.text, g.markers, "script_line"
    else:
        guarded, markers = content_guard.scan_strings(
            list(extraction.get("strings") or []), neutralize=neutralize, hard_quarantine=hard_q
        )
        view, unit = "\n".join(guarded), "string"
    meta = {
        "unit": unit,
        "neutralized": sum(1 for m in markers if m.kind == "neutralized"),
        "quarantined": sum(1 for m in markers if m.kind == "quarantined"),
        "comments_removed": script["comments_removed"] if script else 0,
        "payload_blobs_isolated": len(script["payload_blobs"]) if script else 0,
        "markers": [
            {"kind": m.kind, "sha256": m.sha256[:16], "reason": m.reason, "span": list(m.span)}
            for m in markers
        ],
    }
    return view, meta


def _risk_signals(extraction: dict[str, Any], guard_meta: dict[str, Any], cfg) -> list[str]:
    sig = []
    if extraction["evasion"]["score"] >= int(cfg.get("evasion", "fail_threshold", default=3)):
        sig.append("anti-analysis indicators")
    if report.significant_yara(extraction["static"].get("yara_details", [])):
        sig.append("yara hits")
    if guard_meta["neutralized"] or guard_meta["quarantined"]:
        sig.append("injection bait")
    if extraction["static"].get("high_entropy_regions"):
        sig.append("high-entropy regions")
    if extraction.get("script") and extraction["script"]["payload_blobs"]:
        sig.append("embedded payload blobs")
    return sig


def _client(cfg, tier: str, endpoint: str | None, model: str | None) -> LLMClient:
    return LLMClient(
        endpoint=endpoint or cfg.get("llm", tier, "endpoint"),
        model=model or cfg.get("llm", tier, "model"),
        api_key=cfg.get("llm", "api_key", default="not-needed-for-local"),
        timeout_s=int(cfg.get("llm", "timeout_s", default=120)),
        max_tokens=int(cfg.get("llm", tier, "max_tokens", default=1024)),
        temperature=float(cfg.get("llm", "temperature", default=0.1)),
    )


def analyze(extraction: dict[str, Any], cfg, opts: PipelineOptions) -> dict[str, Any]:
    sanitized_view, guard_meta = _guard(extraction, cfg)
    defang = bool(cfg.get("report", "defang_iocs", default=True))
    iocs_report = _reformat_iocs(extraction["iocs"], defang)

    tiers: dict[str, Any] = {}
    if opts.use_llm:
        ctx = build_llm_context(extraction, sanitized_view, iocs_report)
        client = _client(cfg, "triage", opts.endpoint, opts.model)
        resp = client.chat(system=_load_prompt("analyze.txt"), user=ctx)
        tiers["triage"] = {
            "endpoint": client.endpoint, "model": client.model,
            "summary": resp.content if resp.ok else None, "error": resp.error,
        }
        signals = _risk_signals(extraction, guard_meta, cfg)
        auto = bool(cfg.get("llm", "deep", "auto_escalate", default=False)) and bool(signals)
        if opts.deep or auto:
            deep_ctx = ctx
            if resp.ok:
                deep_ctx += "\n\ntriage model notes (untrusted model output, verify):\n" + resp.content[:4000]
            dclient = _client(cfg, "deep", opts.deep_endpoint, opts.deep_model)
            dresp = dclient.chat(system=_load_prompt("deep.txt"), user=deep_ctx)
            tiers["deep"] = {
                "endpoint": dclient.endpoint, "model": dclient.model,
                "reason": "requested (--deep)" if opts.deep else "auto-escalated: " + ", ".join(signals),
                "summary": dresp.content if dresp.ok else None, "error": dresp.error,
            }

    return report.build_report(
        static=extraction["static"],
        evasion=extraction["evasion"],
        guard=guard_meta,
        iocs=iocs_report,
        payloads=(extraction.get("script") or {}).get("payload_blobs", []),
        integrations=extraction.get("integrations") or {},
        llm_tiers=tiers,
        isolation=opts.isolation or {"mode": "none"},
    )


def _reformat_iocs(raw: dict[str, Any], defang: bool) -> dict[str, Any]:
    s = ioc.IOCSet(
        urls=list(raw.get("urls", [])),
        ips=[dict(i) for i in raw.get("ips", [])],
        domains=list(raw.get("domains", [])),
        paths=list(raw.get("paths", [])),
    )
    return s.to_dict(defang=defang)


def run(path: str | Path, cfg, opts: PipelineOptions, rules=None) -> dict[str, Any]:
    """Extract and analyze in-process (no isolation)."""
    return analyze(extract(path, cfg, rules=rules), cfg, opts)


def build_llm_context(extraction: dict[str, Any], sanitized_view: str, iocs: dict[str, Any]) -> str:
    st = extraction["static"]
    ev = extraction["evasion"]
    lines = [
        f"filetype: {st['filetype']}",
        f"script_language: {st.get('script_language') or 'n/a'}",
        f"size: {st['size']}",
        f"entropy: {st['entropy']} (cutoff {st.get('high_entropy_cutoff')})",
        "high_entropy_regions: "
        + (", ".join(f"{r['start']}-{r['end']}@{r['max_entropy']}" for r in st.get("high_entropy_regions", [])[:20]) or "none"),
        f"yara_matches: {', '.join(st.get('yara_matches', [])) or 'none'}",
        f"anti_analysis_score: {ev['score']}",
        f"anti_debug_apis: {', '.join(ev['anti_debug_apis']) or 'none'}",
        f"vm_artifacts: {', '.join(ev['vm_artifacts']) or 'none'}",
        f"analysis_tool_watch: {', '.join(ev['analysis_tool_watch']) or 'none'}",
        f"low_weight_signals: {', '.join(ev.get('low_weight_signals', [])) or 'none'}",
    ]
    pe = st.get("pe")
    if pe and "imports_sampled" in pe:
        lines.append("imports (sampled): " + ", ".join(pe["imports_sampled"][:60]))
    integ = extraction.get("integrations") or {}
    capa = integ.get("capa") or {}
    if capa.get("capabilities"):
        lines.append("capa capabilities: " + "; ".join(c["name"] for c in capa["capabilities"][:60]))
    for kind in ("urls", "domains", "ips", "paths"):
        vals = iocs.get(kind) or []
        if vals:
            shown = [v["value"] if isinstance(v, dict) else v for v in vals[:40]]
            tag = " (defanged)" if iocs.get("defanged") else ""
            lines.append(f"ioc_{kind}{tag}: " + ", ".join(shown))
    script = extraction.get("script")
    if script and script["payload_blobs"]:
        lines.append(
            "payload blobs (contents withheld): "
            + "; ".join(
                f"#{b['index']} {b['kind']} len={b['length']} decoded_magic={b.get('decoded_magic') or '-'}"
                for b in script["payload_blobs"][:40]
            )
        )
    lines.append("")
    if script:
        lines.append(
            "sanitized script logic (comments stripped, payload blobs replaced by hash markers, "
            "injection-shaped lines neutralized):"
        )
    else:
        lines.append("sanitized strings (one per line; injection-shaped strings neutralized):")
    lines.append(sanitized_view[:8000])
    return "\n".join(lines)

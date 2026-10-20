"""Report assembly and rendering.

Produces a machine-readable dict (JSON file), an optional Markdown report, and a human
console summary. MITRE ATT&CK technique IDs are extracted from the model's free text as
*leads*; they are the model's suggestions, not ground truth.

Reports are built only from already-sanitized data: no raw strings, no guarded content,
no payload blob contents. IOCs are defanged unless ``report.defang_iocs`` is false.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover
    Console = None  # type: ignore

_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
FORMATS = ("json", "md", "both")
INFO_SEVERITIES = {"info", "informational", "none"}


def extract_attack_ids(text: str) -> list[str]:
    seen: list[str] = []
    for m in _ATTACK_RE.findall(text or ""):
        if m not in seen:
            seen.append(m)
    return seen


def significant_yara(details: list[dict[str, Any]]) -> list[str]:
    """Rule names whose ``meta.severity`` is above informational."""
    return [d["rule"] for d in details or [] if d.get("severity", "unknown") not in INFO_SEVERITIES]


def build_report(
    static: dict[str, Any],
    evasion: dict[str, Any],
    guard: dict[str, Any],
    llm_tiers: dict[str, Any] | None = None,
    iocs: dict[str, Any] | None = None,
    payloads: list[dict[str, Any]] | None = None,
    integrations: dict[str, Any] | None = None,
    isolation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tiers = llm_tiers or {}
    final = tiers.get("deep") or tiers.get("triage") or {}
    summary = final.get("summary")
    error = None if summary else (final.get("error") if final else None)
    attack = []
    for t in ("triage", "deep"):
        for tid in extract_attack_ids((tiers.get(t) or {}).get("summary") or ""):
            if tid not in attack:
                attack.append(tid)
    return {
        "malsift_version": __import__("malsift").__version__,
        "generated_utc": datetime.now(UTC).isoformat(),
        "isolation": isolation or {"mode": "none"},
        "static": static,
        "evasion": evasion,
        "iocs": iocs or {},
        "payload_blobs": payloads or [],
        "integrations": integrations or {},
        "content_guard": guard,
        "llm": {
            "summary": summary,
            "error": error,
            "attack_techniques": attack,
            "tiers": tiers,
        },
    }


def _basename(report: dict[str, Any]) -> str:
    sha = report.get("static", {}).get("hashes", {}).get("sha256", "nohash")[:16]
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"malsift_{stamp}_{sha}"


def write_report(report: dict[str, Any], out_dir: str | Path, fmt: str = "json") -> list[Path]:
    """Write the report as JSON, Markdown, or both. Returns the written paths."""
    if fmt not in FORMATS:
        raise ValueError(f"report format must be one of {FORMATS}, got {fmt!r}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = _basename(report)
    paths: list[Path] = []
    if fmt in ("json", "both"):
        p = out_dir / f"{base}.json"
        p.write_text(json.dumps(report, indent=2), encoding="utf-8")
        paths.append(p)
    if fmt in ("md", "both"):
        p = out_dir / f"{base}.md"
        p.write_text(render_markdown(report), encoding="utf-8")
        paths.append(p)
    return paths


# --------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------


def _md(text: Any) -> str:
    """Escape a value for a Markdown table cell / inline text."""
    s = str(text) if text is not None else "-"
    s = s.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    s = s.replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")
    return s or "-"


def _code(text: Any) -> str:
    s = str(text).replace("`", "'").replace("\n", " ")
    return f"`{s}`"


def render_markdown(report: dict[str, Any]) -> str:
    st = report["static"]
    ev = report["evasion"]
    guard = report["content_guard"]
    llm = report["llm"]
    iso = report.get("isolation") or {}
    iocs = report.get("iocs") or {}
    h = st["hashes"]
    out: list[str] = []
    w = out.append

    w(f"# MalSift report: {_code(Path(st['path']).name)}\n")
    w(f"Generated {report['generated_utc']} by MalSift {report['malsift_version']}.\n")
    if iso.get("mode") == "docker":
        w(f"**Isolation:** parsing ran in the hardened container `{_md(iso.get('image'))}` "
          "(no network, read-only, all capabilities dropped, seccomp). The content guard and "
          "model call ran on the host over the extracted data.\n")
    else:
        w("**Isolation:** none. The sample was parsed directly on the analysis host.\n")

    w("## Summary\n")
    w("| Field | Value |\n|---|---|")
    w(f"| File type | {_md(st['filetype'])} |")
    w(f"| Script language | {_md(st.get('script_language') or 'n/a')} |")
    w(f"| Size | {st['size']} bytes |")
    w(f"| MD5 | {_code(h['md5'])} |")
    w(f"| SHA-1 | {_code(h['sha1'])} |")
    w(f"| SHA-256 | {_code(h['sha256'])} |")
    w(f"| Entropy | {st['entropy']} ({'HIGH' if st['high_entropy'] else 'normal'}, cutoff {st.get('high_entropy_cutoff')}) |")
    w(f"| YARA | {_md(', '.join(st.get('yara_matches', [])) or 'none')} |")
    w(f"| Anti-analysis score | {ev['score']} |")
    w("")

    regions = st.get("high_entropy_regions") or []
    w("## High-entropy regions\n")
    if regions:
        w("| Start | End | Length | Max | Mean |\n|---:|---:|---:|---:|---:|")
        for r in regions[:200]:
            w(f"| {r['start']} | {r['end']} | {r['length']} | {r['max_entropy']} | {r['mean_entropy']} |")
    else:
        w(f"None at or above {st.get('high_entropy_cutoff')} (window {st.get('entropy_block')} bytes).")
    w("")

    if st.get("yara_details") or st.get("yara_errors"):
        w("## YARA\n")
        for d in st.get("yara_details", []):
            w(f"- {_code(d['rule'])} ({_md(d.get('severity'))}): {_md(d.get('description'))}")
        for e in st.get("yara_errors", []):
            w(f"- **error:** {_md(e)}")
        w("")

    w("## Anti-analysis indicators\n")
    w("| Category | Hits |\n|---|---|")
    w(f"| Anti-debug APIs | {_md(', '.join(ev['anti_debug_apis']) or '-')} |")
    w(f"| VM artifacts | {_md(', '.join(ev['vm_artifacts']) or '-')} |")
    w(f"| Tool watching | {_md(', '.join(ev['analysis_tool_watch']) or '-')} |")
    counted = "counted" if ev.get("low_weight_counted") else "not counted alone"
    w(f"| Low-weight signals ({counted}) | {_md(', '.join(ev.get('low_weight_signals', [])) or '-')} |")
    w("")
    if ev.get("sandbox_hints"):
        w("### Sandbox configuration hints (dynamic tier)\n")
        for hint in ev["sandbox_hints"]:
            w(f"- **{_md(hint['category'])}:** {_md(hint['recommendation'])}")
        w("")

    w("## Indicators of compromise\n")
    if iocs.get("defanged"):
        w("_Defanged for safe sharing._\n")
    any_ioc = False
    for kind, label in (("urls", "URLs"), ("domains", "Domains"), ("ips", "IP addresses"), ("paths", "File paths")):
        vals = iocs.get(kind) or []
        if not vals:
            continue
        any_ioc = True
        w(f"**{label}**\n")
        for v in vals[:200]:
            if isinstance(v, dict):
                w(f"- {_code(v['value'])} ({_md(v.get('scope'))})")
            else:
                w(f"- {_code(v)}")
        w("")
    if not any_ioc:
        w("None extracted.\n")

    blobs = report.get("payload_blobs") or []
    if blobs:
        w("## Isolated payload blobs\n")
        w("Contents withheld from the model and this report.\n")
        w("| # | Kind | Offset | Length | SHA-256 (text) | Decoded size | Decoded magic |\n|---:|---|---:|---:|---|---:|---|")
        for b in blobs[:200]:
            w(f"| {b['index']} | {b['kind']} | {b['offset']} | {b['length']} | {_code(b['sha256'][:16])} | "
              f"{b.get('decoded_size') or '-'} | {_md(b.get('decoded_magic') or '-')} |")
        w("")

    integ = report.get("integrations") or {}
    if integ:
        w("## External analyzers\n")
        capa = integ.get("capa") or {}
        if capa.get("ran"):
            w(f"**capa** ({len(capa.get('capabilities', []))} capabilities)"
              + (f", error: {_md(capa['error'])}" if capa.get("error") else ""))
            for c in capa.get("capabilities", [])[:100]:
                att = f" [{', '.join(c['attack'])}]" if c.get("attack") else ""
                w(f"- {_md(c['name'])}{att}")
        else:
            w(f"**capa:** skipped ({_md(capa.get('skipped_reason', 'not run'))})")
        w("")
        r2 = integ.get("radare2") or {}
        if r2.get("ran"):
            info = r2.get("info") or {}
            w("**radare2:** " + _md(", ".join(f"{k}={v}" for k, v in info.items()) or "no info")
              + f"; {len(r2.get('imports', []))} imports, {len(r2.get('sections', []))} sections")
        else:
            w(f"**radare2:** skipped ({_md(r2.get('skipped_reason', 'not run'))})")
        w("")

    w("## Content guard\n")
    w(f"Unit: {guard.get('unit', 'string')}. {guard['neutralized']} neutralized, "
      f"{guard['quarantined']} quarantined, {guard['comments_removed']} comments stripped, "
      f"{guard.get('payload_blobs_isolated', 0)} payload blobs isolated.\n")

    w("## Model analysis\n")
    tiers = llm.get("tiers") or {}
    if not tiers:
        w("Not run (--no-llm).\n")
    for name in ("triage", "deep"):
        t = tiers.get(name)
        if not t:
            continue
        w(f"### {name.title()} ({_md(t.get('model'))})\n")
        if t.get("reason"):
            w(f"_{_md(t['reason'])}_\n")
        if t.get("summary"):
            # Model output is untrusted text: fence it so it renders literally.
            body = t["summary"].replace("```", "'''")
            w("```text\n" + body + "\n```\n")
        else:
            w(f"Skipped: {_md(t.get('error'))}\n")
    if llm.get("attack_techniques"):
        w("**ATT&CK leads (model suggestions, verify):** " + ", ".join(llm["attack_techniques"]) + "\n")
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------------------


def render_console(report: dict[str, Any]) -> None:
    static = report["static"]
    ev = report["evasion"]
    guard = report["content_guard"]
    llm = report["llm"]
    iso = report.get("isolation") or {}

    if Console is None:  # plain fallback
        print(json.dumps(report, indent=2))
        return

    console = Console(highlight=False)
    if iso.get("mode") != "docker":
        console.print(
            "[bold yellow]warning:[/bold yellow] analysis ran directly on this host (no "
            "isolation). Use --isolate docker for untrusted samples."
        )
    h = static["hashes"]
    meta = Table.grid(padding=(0, 2))
    meta.add_row("file", Text(static["path"]))
    meta.add_row("type", Text(static["filetype"]))
    if static.get("script_language"):
        meta.add_row("script", static["script_language"])
    meta.add_row("size", f"{static['size']} bytes")
    meta.add_row("sha256", h["sha256"])
    meta.add_row(
        "entropy",
        f"{static['entropy']} ({'HIGH' if static['high_entropy'] else 'normal'}, "
        f"cutoff {static.get('high_entropy_cutoff')}, "
        f"{len(static.get('high_entropy_regions') or [])} high regions)",
    )
    meta.add_row("yara", ", ".join(static["yara_matches"]) or "none")
    meta.add_row("isolation", str(iso.get("mode", "none")))
    console.print(Panel(meta, title="MalSift triage", border_style="cyan"))
    for err in static.get("yara_errors") or []:
        console.print("[bold red]YARA error:[/bold red] " + err.replace("[", "\\["))

    ev_table = Table(title="Anti-analysis indicators", show_header=True, header_style="bold")
    ev_table.add_column("category")
    ev_table.add_column("hits")
    ev_table.add_row("anti-debug APIs", ", ".join(ev["anti_debug_apis"]) or "-")
    ev_table.add_row("VM artifacts", ", ".join(ev["vm_artifacts"]) or "-")
    ev_table.add_row("tool watching", ", ".join(ev["analysis_tool_watch"]) or "-")
    ev_table.add_row("low-weight", ", ".join(ev.get("low_weight_signals", [])) or "-")
    ev_table.add_row("score", str(ev["score"]))
    console.print(ev_table)

    counts = (report.get("iocs") or {}).get("counts") or {}
    if counts:
        console.print("[dim]IOCs:[/dim] " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    console.print(
        f"[dim]content guard:[/dim] {guard['neutralized']} neutralized, "
        f"{guard['quarantined']} quarantined, {guard['comments_removed']} comments stripped, "
        f"{guard.get('payload_blobs_isolated', 0)} payload blobs isolated"
    )

    if llm["summary"]:
        console.print(Panel(Text(llm["summary"]), title="LLM behavior summary", border_style="green"))
        if llm["attack_techniques"]:
            console.print("[bold]ATT&CK leads:[/bold] " + ", ".join(llm["attack_techniques"]))
    elif llm["error"]:
        console.print(f"[yellow]LLM step skipped:[/yellow] {llm['error']}")
    else:
        console.print("[dim]LLM step not run (--no-llm).[/dim]")

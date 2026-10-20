"""Report assembly and rendering.

Produces a machine-readable dict (and JSON file) plus a human console summary. MITRE
ATT&CK technique IDs are extracted from the model's free text as *leads*; they are the
model's suggestions, not ground truth.
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
except ImportError:  # pragma: no cover
    Console = None  # type: ignore

_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_attack_ids(text: str) -> list[str]:
    seen: list[str] = []
    for m in _ATTACK_RE.findall(text or ""):
        if m not in seen:
            seen.append(m)
    return seen


def build_report(
    static: dict[str, Any],
    evasion: dict[str, Any],
    guard: dict[str, Any],
    llm_summary: str | None,
    llm_error: str | None,
) -> dict[str, Any]:
    return {
        "malsift_version": __import__("malsift").__version__,
        "generated_utc": datetime.now(UTC).isoformat(),
        "static": static,
        "evasion": evasion,
        "content_guard": guard,
        "llm": {
            "summary": llm_summary,
            "error": llm_error,
            "attack_techniques": extract_attack_ids(llm_summary or ""),
        },
    }


def write_report(report: dict[str, Any], out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sha = report.get("static", {}).get("hashes", {}).get("sha256", "nohash")[:16]
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"malsift_{stamp}_{sha}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def render_console(report: dict[str, Any]) -> None:
    static = report["static"]
    ev = report["evasion"]
    guard = report["content_guard"]
    llm = report["llm"]

    if Console is None:  # plain fallback
        print(json.dumps(report, indent=2))
        return

    console = Console()
    h = static["hashes"]
    meta = Table.grid(padding=(0, 2))
    meta.add_row("file", static["path"])
    meta.add_row("type", static["filetype"])
    meta.add_row("size", f"{static['size']} bytes")
    meta.add_row("sha256", h["sha256"])
    meta.add_row("entropy", f"{static['entropy']} ({'HIGH' if static['high_entropy'] else 'normal'})")
    meta.add_row("yara", ", ".join(static["yara_matches"]) or "none")
    console.print(Panel(meta, title="MalSift triage", border_style="cyan"))

    ev_table = Table(title="Anti-analysis indicators", show_header=True, header_style="bold")
    ev_table.add_column("category")
    ev_table.add_column("hits")
    ev_table.add_row("anti-debug APIs", ", ".join(ev["anti_debug_apis"]) or "-")
    ev_table.add_row("VM artifacts", ", ".join(ev["vm_artifacts"]) or "-")
    ev_table.add_row("tool watching", ", ".join(ev["analysis_tool_watch"]) or "-")
    ev_table.add_row("score", str(ev["score"]))
    console.print(ev_table)

    console.print(
        f"[dim]content guard:[/dim] {guard['neutralized']} neutralized, "
        f"{guard['quarantined']} quarantined, {guard['comments_removed']} comments stripped"
    )

    if llm["summary"]:
        console.print(Panel(llm["summary"], title="LLM behavior summary", border_style="green"))
        if llm["attack_techniques"]:
            console.print("[bold]ATT&CK leads:[/bold] " + ", ".join(llm["attack_techniques"]))
    elif llm["error"]:
        console.print(f"[yellow]LLM step skipped:[/yellow] {llm['error']}")
    else:
        console.print("[dim]LLM step not run (--no-llm).[/dim]")

"""MalSift command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .pipeline import PipelineOptions, run
from .report import render_console, write_report
from .static_analysis import compile_rules


def _cmd_analyze(args: argparse.Namespace) -> int:
    sample = Path(args.sample)
    if not sample.is_file():
        print(f"error: sample not found: {sample}", file=sys.stderr)
        return 2

    cfg = load_config(args.config_dir)
    rules_dir = args.rules or (Path(__file__).resolve().parent.parent / "rules")
    rules = compile_rules(rules_dir)

    opts = PipelineOptions(
        use_llm=not args.no_llm,
        endpoint=args.endpoint,
        model=args.model,
    )
    report = run(sample, cfg, opts, rules=rules)

    if not args.quiet:
        render_console(report)

    if not args.no_write:
        out_dir = args.out or cfg.get("report", "out_dir", default="reports")
        path = write_report(report, out_dir)
        if not args.quiet:
            print(f"\nreport written: {path}")

    # Non-zero exit if the sample looks evasive or trips yara, to help CI/automation.
    evasive = report["evasion"]["score"] > 0 or report["static"]["yara_matches"]
    return 1 if (args.fail_on_hit and evasive) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="malsift",
        description="Defensive malware triage: static analysis + local-LLM summary with an "
        "adversarial content guard.",
    )
    p.add_argument("--version", action="version", version=f"malsift {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze a single sample")
    a.add_argument("sample", help="path to the sample to analyze")
    a.add_argument("--endpoint", help="OpenAI-compatible endpoint (default: local Ollama)")
    a.add_argument("--model", help="model name to request")
    a.add_argument("--no-llm", action="store_true", help="static analysis only, no model call")
    a.add_argument("--rules", help="directory of .yar/.yara rules")
    a.add_argument("--config-dir", help="directory holding default.yaml/local.yaml")
    a.add_argument("--out", help="report output directory")
    a.add_argument("--no-write", action="store_true", help="do not write a JSON report")
    a.add_argument("--quiet", action="store_true", help="suppress console output")
    a.add_argument("--fail-on-hit", action="store_true",
                   help="exit non-zero if evasive indicators or yara hits are found")
    a.set_defaults(func=_cmd_analyze)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""MalSift command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, isolation, resources
from .config import load_config
from .pipeline import PipelineOptions, analyze, extract
from .report import FORMATS, render_console, significant_yara, write_report
from .static_analysis import RuleCompileError, compile_rules


def _warn(msg: str) -> None:
    print(f"\n!!! WARNING: {msg}\n", file=sys.stderr)


def _compile(args: argparse.Namespace, cfg):
    on_error = args.rules_on_error or str(cfg.get("yara", "on_error", default="fail"))
    rules_dir = Path(args.rules) if args.rules else resources.rules_dir()
    rules = compile_rules(rules_dir, on_error=on_error)
    for err in rules.errors:
        _warn(f"YARA rule problem (skipped): {err}")
    return rules


def _cmd_extract(args: argparse.Namespace) -> int:
    """Extraction half only; prints JSON to stdout. Used inside the analyzer container."""
    sample = Path(args.sample)
    if not sample.is_file():
        print(f"error: sample not found: {sample}", file=sys.stderr)
        return 2
    cfg = load_config(args.config_dir)
    if args.config_json:
        try:
            overrides = json.loads(args.config_json)
        except json.JSONDecodeError as e:
            print(f"error: --config-json is not valid JSON: {e}", file=sys.stderr)
            return 2
        for section, values in overrides.items():
            if section in isolation.EXTRACTION_SECTIONS and isinstance(values, dict):
                for key, val in values.items():
                    cfg.set(val, section, key)
    try:
        rules = _compile(args, cfg)
    except RuleCompileError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    json.dump(extract(sample, cfg, rules=rules), sys.stdout)
    sys.stdout.write("\n")
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    sample = Path(args.sample)
    if not sample.is_file():
        print(f"error: sample not found: {sample}", file=sys.stderr)
        return 2

    try:
        cfg = load_config(args.config_dir)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.rules_on_error:
        cfg.set(args.rules_on_error, "yara", "on_error")
    if args.high_entropy_cutoff is not None:
        cfg.set(args.high_entropy_cutoff, "static", "high_entropy_cutoff")
    fmt = args.format or str(cfg.get("report", "format", default="json"))
    if fmt not in FORMATS:
        print(f"error: report format must be one of {FORMATS}", file=sys.stderr)
        return 2

    opts = PipelineOptions(
        use_llm=not args.no_llm,
        endpoint=args.endpoint,
        model=args.model,
        deep=args.deep,
        deep_endpoint=args.deep_endpoint,
        deep_model=args.deep_model,
    )

    if args.isolate == "docker":
        try:
            extraction, iso_meta = isolation.run_extract_in_docker(
                sample,
                cfg,
                rules_dir=Path(args.rules) if args.rules else None,
            )
        except isolation.IsolationError as e:
            print(f"error: {e}", file=sys.stderr)
            return 4
    else:
        try:
            rules = _compile(args, cfg)
        except RuleCompileError as e:
            print(f"error: {e}", file=sys.stderr)
            print("Fix the rule, or pass --rules-on-error warn to skip broken files.", file=sys.stderr)
            return 3
        if not args.quiet:
            _warn(
                "analysis is running directly on this host with no isolation. Untrusted "
                "samples are parsed by libmagic, pefile, YARA and any installed capa/radare2. "
                "Use --isolate docker (see README) for a hardened, network-less container."
            )
        extraction = extract(sample, cfg, rules=rules)
        iso_meta = isolation.describe("none")

    opts.isolation = iso_meta
    report = analyze(extraction, cfg, opts)

    if not args.quiet:
        render_console(report)

    if not args.no_write:
        out_dir = args.out or cfg.get("report", "out_dir", default="reports")
        paths = write_report(report, out_dir, fmt)
        if not args.quiet:
            for p in paths:
                print(f"report written: {p}")

    # Non-zero exit for automation when the sample shows meaningful anti-analysis
    # indicators or trips a YARA rule above informational severity.
    threshold = int(cfg.get("evasion", "fail_threshold", default=3))
    hit = report["evasion"]["score"] >= threshold or bool(
        significant_yara(report["static"].get("yara_details", []))
    )
    return 1 if (args.fail_on_hit and hit) else 0


def _add_common(a: argparse.ArgumentParser) -> None:
    a.add_argument("sample", help="path to the sample")
    a.add_argument("--rules", help="directory of .yar/.yara rules (default: packaged rules)")
    a.add_argument("--rules-on-error", choices=["fail", "warn"],
                   help="what to do when a YARA rule file fails to compile (default: fail)")
    a.add_argument("--config-dir", help="directory holding local.yaml (default: ./config or $MALSIFT_CONFIG_DIR)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="malsift",
        description="Defensive malware triage: static analysis + local-LLM summary with an "
        "adversarial content guard.",
    )
    p.add_argument("--version", action="version", version=f"malsift {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze a single sample")
    _add_common(a)
    a.add_argument("--endpoint", help="triage-tier OpenAI-compatible endpoint (default: local Ollama)")
    a.add_argument("--model", help="triage-tier model name")
    a.add_argument("--deep", action="store_true", help="also run the deep-tier model")
    a.add_argument("--deep-endpoint", help="deep-tier endpoint")
    a.add_argument("--deep-model", help="deep-tier model name")
    a.add_argument("--no-llm", action="store_true", help="static analysis only, no model call")
    a.add_argument("--isolate", choices=["none", "docker"], default="none",
                   help="run sample parsing in the hardened analyzer container (default: none)")
    a.add_argument("--high-entropy-cutoff", type=float, help="override static.high_entropy_cutoff")
    a.add_argument("--out", help="report output directory")
    a.add_argument("--format", choices=list(FORMATS), help="report format (default: json)")
    a.add_argument("--no-write", action="store_true", help="do not write a report file")
    a.add_argument("--quiet", action="store_true", help="suppress console output")
    a.add_argument("--fail-on-hit", action="store_true",
                   help="exit 1 if the anti-analysis score reaches evasion.fail_threshold or a "
                   "YARA rule above informational severity matches")
    a.set_defaults(func=_cmd_analyze)

    e = sub.add_parser(
        "extract",
        help="run only the byte-parsing half and print JSON (used inside the analyzer container)",
    )
    _add_common(e)
    e.add_argument("--config-json", help="JSON overrides for the static/payloads/yara/integrations "
                   "sections (passed by --isolate docker)")
    e.set_defaults(func=_cmd_extract)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

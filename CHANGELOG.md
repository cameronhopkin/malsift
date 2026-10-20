# Changelog

## 0.3.0 (unreleased)

### Fixed
- **CI**: removed the `apt-get install libyara9` step (the package does not exist on
  Ubuntu 24.04 runners, and the `yara-python` wheel bundles libyara). Fixed the same
  package name in the README.
- **Content guard**: extracted strings are now guarded one at a time (and script text
  line by line). Previously strings were joined with single newlines and split on blank
  lines, so a single injection string neutralized the entire string set before it reached
  the model.
- **Comment stripping**: only applied to files detected as scripts, never to strings
  extracted from binaries, and now language-aware (string literals, URLs, `--flags` and
  `#fragments` survive). Previously `http://host/beacon` became `http:[comment removed]`.
- **Evasion detection**: whole-token matching with exact tool/VM artifact names
  (`.idata` no longer matches "ida", words containing "xen" no longer match Xen). Common
  runtime APIs (GetTickCount, QueryPerformanceCounter, IsDebuggerPresent, ...) are
  low-weight and only count alongside a strong signal. `--fail-on-hit` uses a weighted
  threshold and ignores `info`-severity YARA rules, so ordinary PEs no longer trip it.
- **Entropy**: `static.high_entropy_cutoff` is honored (was hardcoded to 7.2). Reports
  now include per-window entropy and a merged high-entropy region map. Default
  `entropy_block` raised from 256 to 1024 bytes so random data can actually reach the
  cutoff.
- **YARA**: rules are compiled up front, file by file. Syntax errors fail the run with
  the file and compiler error (`yara.on_error: fail`, default) or are skipped with a loud
  warning and listed in the report (`warn`). Scan errors are reported instead of being
  swallowed.
- **Packaging**: config, prompts, YARA rules and the seccomp profile moved into
  `malsift/data/` and are declared as package data, so a regular `pip install .` works.
  CI now tests a non-editable install.

### Restored (from the June design)
- Hardened static-analysis container: `Dockerfile.analyzer`, `docker-compose.yml` and a
  default-deny seccomp profile; `malsift analyze --isolate docker` runs all byte parsing
  inside it. README now states exactly what runs isolated and what runs on the host, and
  MalSift warns when analysis runs on the host.
- `setup.sh` for venv setup and dependency checks.
- Optional capa and radare2 (`rabin2`) integration, auto-detected, results in the report.
- Markdown reports (`--format json|md|both`).
- Separate triage and deep model endpoints (`--deep`, optional auto-escalation) and
  `MALSIFT_*` environment variable overrides.
- IOC extraction (URLs, IPs, domains, file paths) on raw strings before sanitizing, with
  defanging in reports.
- Script payload isolation (base64 / hex / `\xNN` / `0x..` blobs recorded by hash, never
  sent to the model) and the structural `poison_indicators.yar` rule set.
- Sandbox masking hints for the dynamic tier in the evasion report.

### Changed
- `malsift extract` subcommand prints the extraction JSON (used inside the container).
- Report schema additions: `isolation`, `iocs`, `payload_blobs`, `integrations`,
  `static.entropy_windows`, `static.high_entropy_regions`, `static.yara_details`,
  `static.yara_errors`, `evasion.low_weight_signals`, `evasion.sandbox_hints`,
  `llm.tiers`.
- `preprocessor.strip_comments()` now requires a language argument.

## 0.2.0
- Initial public release.

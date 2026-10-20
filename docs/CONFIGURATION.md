# Configuration guide

MalSift reads configuration in this order (later wins):

1. built-in defaults
2. the packaged `malsift/data/config/default.yaml` (ships inside the wheel)
3. `local.yaml` from the config directory: `--config-dir DIR`, else `$MALSIFT_CONFIG_DIR`,
   else `./config/` in the current working directory (`config/local.yaml` is gitignored).
   An explicit `--config-dir` may also hold its own `default.yaml`.
4. `MALSIFT_*` environment variables
5. CLI flags

Copy the keys you need from `malsift/data/config/default.yaml` into `config/local.yaml`.

## Environment variables

| Variable | Config key | Notes |
|---|---|---|
| `MALSIFT_TRIAGE_URL` | `llm.triage.endpoint` | OpenAI-compatible base URL for the triage model |
| `MALSIFT_DEEP_URL` | `llm.deep.endpoint` | Base URL for the deep model |
| `MALSIFT_MODEL_TRIAGE` | `llm.triage.model` | |
| `MALSIFT_MODEL_DEEP` | `llm.deep.model` | |
| `MALSIFT_API_KEY` | `llm.api_key` | Bearer token, if your gateway needs one. Prefer this over writing a key into YAML. |
| `MALSIFT_TIMEOUT_S` | `llm.timeout_s` | integer |
| `MALSIFT_HIGH_ENTROPY_CUTOFF` | `static.high_entropy_cutoff` | float |
| `MALSIFT_YARA_ON_ERROR` | `yara.on_error` | `fail` or `warn` |
| `MALSIFT_REPORT_DIR` | `report.out_dir` | |
| `MALSIFT_REPORT_FORMAT` | `report.format` | `json`, `md` or `both` |
| `MALSIFT_ISOLATION_IMAGE` | `isolation.image` | analyzer image tag |
| `MALSIFT_CAPA` | `integrations.capa` | `auto` or `off` |
| `MALSIFT_RADARE2` | `integrations.radare2` | `auto` or `off` |
| `MALSIFT_CONFIG_DIR` | (location) | directory holding `local.yaml` |

An invalid value (e.g. a non-integer timeout) is an error, not silently ignored.

## LLM

MalSift has two model tiers. Both speak the OpenAI `/v1/chat/completions` contract.

| Key | Meaning |
|-----|---------|
| `llm.triage.endpoint` / `llm.triage.model` / `llm.triage.max_tokens` | Fast first pass. Runs whenever the LLM step is enabled. CLI: `--endpoint`, `--model`. |
| `llm.deep.endpoint` / `llm.deep.model` / `llm.deep.max_tokens` | Larger second pass that also sees the triage note. CLI: `--deep`, `--deep-endpoint`, `--deep-model`. |
| `llm.deep.auto_escalate` | When true, the deep tier also runs automatically if the static facts show risk signals (anti-analysis score at the fail threshold, a YARA hit above `info`, neutralized bait, high-entropy regions, or embedded payload blobs). |
| `llm.api_key` | Shared by both tiers. Usually unused locally. |
| `llm.timeout_s` / `llm.temperature` | Request tuning. Keep temperature low for triage. |

The 0.2.0 flat keys `llm.endpoint` / `llm.model` still work: `endpoint` seeds both
tiers, `model` seeds the triage tier.

Run `malsift analyze <file> --no-llm` to skip the model entirely (static-only).

## Static analysis

| Key | Meaning |
|-----|---------|
| `static.string_min_len` | Minimum printable run length for string extraction. |
| `static.max_strings` | Cap on extracted strings (bounds memory/time). |
| `static.entropy_block` | Window size in bytes for the entropy map. Default 1024. Smaller windows cannot reach high entropy even for random data (a 256-byte window of random bytes averages about 7.2 bits), so keep it at 1024 or more when using a cutoff near 7.2. |
| `static.high_entropy_cutoff` | Entropy at/above which the whole file is flagged high-entropy **and** at/above which windows are merged into `high_entropy_regions`. CLI: `--high-entropy-cutoff`. |
| `static.max_entropy_windows` | Cap on windows in the report (`entropy_windows_truncated` tells you when it was hit). |
| `static.max_script_bytes` | Max bytes of a script decoded for preprocessing. |

The report includes `entropy_windows` (`offset`, `entropy` per window) and
`high_entropy_regions` (`start`, `end`, `length`, `max_entropy`, `mean_entropy`).

## YARA

| Key | Meaning |
|-----|---------|
| `yara.on_error` | `fail` (default): any rule file that does not compile aborts the run with the file name and compiler error (exit code 3). `warn`: the broken file is skipped, a warning is printed, and the error is listed under `static.yara_errors` in the report. CLI: `--rules-on-error`. |

Rules come from the packaged `malsift/data/rules/` unless you pass `--rules DIR`
(searched recursively for `.yar`/`.yara`). `--fail-on-hit` ignores matches whose
`meta.severity` is `info`, so the example rules never trip it.

`poison_indicators.yar` detects prompt-injection *structure* (instruction-override
phrasing, chat-template role markers, spoofed prompt delimiters) in raw bytes, ASCII and
UTF-16. It contains no topic keywords.

## Evasion detection

| Key | Meaning |
|-----|---------|
| `evasion.fail_threshold` | Weighted score at/above which `--fail-on-hit` trips. Strong indicators (exact VM artifacts, analysis-tool process names, deliberate anti-debug APIs) weigh 3. Low-weight signals that appear in most compiled programs (GetTickCount, QueryPerformanceCounter, IsDebuggerPresent, OutputDebugString, GetSystemFirmwareTable, SystemBiosVersion) weigh 1 and only count when a strong indicator is also present. |

`evasion.sandbox_hints` in the report lists, per category found, what to mask in a
dynamic-analysis VM (SMBIOS vendor strings, guest tools, timing consistency, debugger
attachment). They are configuration recommendations for your sandbox, not code.

## Content guard

| Key | Meaning |
|-----|---------|
| `guard.neutralize_injection` | Replace injection-shaped items with metadata-only markers. Items are individual extracted strings (binaries) or individual lines (scripts). |
| `guard.enable_hard_quarantine` | Allow a registered high-risk classifier to quarantine an item. |

To add hard-quarantine behavior, register your own classifier at startup:

```python
from malsift import content_guard

def my_classifier(item: str):
    # return (True, "reason") to quarantine; None to pass.
    # Return a reason only. Never return or log the flagged content.
    ...

content_guard.register_classifier(my_classifier)
```

No subject-matter dictionary ships with MalSift, by design. Keep any classifier you add
metadata-only.

## Script payload isolation

| Key | Meaning |
|-----|---------|
| `payloads.min_base64_len` | Minimum length of a base64 run treated as an embedded payload. |
| `payloads.min_hex_len` | Minimum length (hex characters) of hex / `\xNN` / `0x..` runs. |

Each blob is recorded in `payload_blobs` (kind, offset, length, SHA-256 of the text and,
when it decodes, SHA-256/size/entropy/leading magic of the decoded bytes) and replaced in
the model's view by a marker. Blob contents are never sent to the model or written to the
report.

## Optional analyzers

| Key | Meaning |
|-----|---------|
| `integrations.capa` | `auto` (use `capa` if on `PATH`) or `off`. |
| `integrations.radare2` | `auto` (use `rabin2` if on `PATH`) or `off`. |
| `integrations.timeout_s` | Per-tool timeout. |

## Isolation

| Key | Meaning |
|-----|---------|
| `isolation.image` | Image used by `--isolate docker`. Build it with `docker build -f Dockerfile.analyzer -t malsift-analyzer:latest .` |
| `isolation.memory` / `isolation.cpus` / `isolation.pids_limit` / `isolation.tmpfs_size` | Container limits. |
| `isolation.timeout_s` | Wall-clock limit for the isolated extraction. |

With `--isolate docker`, a `--rules` directory is mounted read-only into the container,
and the host's effective `static`, `payloads`, `yara` and `integrations` settings
(after `local.yaml`, `MALSIFT_*` and CLI flags) are passed to it, so isolated and host
runs use the same thresholds.

## Reports

| Key | Meaning |
|-----|---------|
| `report.out_dir` | Output directory (`--out`). |
| `report.format` | `json`, `md` or `both` (`--format`). |
| `report.defang_iocs` | Defang URLs, domains and IPs in reports and in the model context (default true). |

## Dynamic detonation (optional, stub)

Disabled until you provision it. See `malsift/sandbox/firecracker.py` and the safety
requirements in `DISCLAIMER.md`. You must supply your own kernel and rootfs and set
`operator_opt_in=True` on a disposable, network-isolated host.

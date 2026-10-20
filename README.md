# MalSift

Self-hosted malware triage that pairs classic static analysis with a **local**
open-weight LLM, can parse untrusted samples inside a hardened, network-less container
(`--isolate docker`), and **quarantines adversarial "poison" content** that malware embeds
to derail LLM-based analyzers.

MalSift speaks the OpenAI `/v1/chat/completions` contract at the client layer, but it is
designed to point at a **local** inference endpoint (vLLM, Ollama, llama.cpp, TGI). Live
samples and their extracted artifacts never leave your environment. That is the correct
operational posture for malware work regardless of any model's content policy: custody,
reproducibility, air-gap operation, and cost.

> **This is a defensive analysis tool.** It summarizes and classifies samples you have
> lawful authority to analyze. It does not generate malware, exploits, or evasion code.
> Read [DISCLAIMER.md](DISCLAIMER.md) before you run it.

---

## Why this exists

Adversaries have started embedding fake "sensitive" text (bogus system prompts, fake
biological or policy-tripping content) inside samples, in non-executing comments,
specifically to make LLM-assisted triage **refuse or stall**. MalSift treats that text as
what it is: an attacker-controlled payload aimed at your analyzer. It:

1. **Detects injection-shaped text** by *structure* (instruction-override patterns,
   fake role headers, delimiter spoofing), not by subject matter. No topic keyword
   dictionaries ship in this repo. The same idea ships as a YARA rule set
   (`poison_indicators.yar`) so bait shows up as a detection, too.
2. **Neutralizes** anti-analysis bait so the pipeline keeps moving. Each extracted string
   (or each script line) is judged **on its own**, so one planted string cannot hide the
   URLs, paths and command lines around it. Only the offending item is replaced with a
   metadata-only marker.
3. **Hard-quarantines** anything a pluggable high-risk classifier (that *you* wire in)
   flags, surfacing a hash and a reason, never the content itself.

The model only ever sees sanitized facts: strings with bait neutralized and, for scripts,
comment-stripped logic with embedded payload blobs replaced by hash markers. Raw-byte
detection (YARA, entropy map, IOC extraction, evasion heuristics) runs first, on the
untouched bytes, for full coverage.

## How it works

```
                 ┌──────────── extract (host, or isolated container) ────────────┐
sample bytes ──▶ │ type, hashes, entropy map, strings, PE, YARA, capa, radare2   │
                 │ IOC extraction (raw)   evasion detection + sandbox hints      │
                 │ scripts only: payload-blob isolation → comment stripping      │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │ JSON
                 ┌──────────────── analyze (always on the host) ─────────────────┐
                 │ content guard (per string / per line) → LLM triage tier       │
                 │ → optional deep tier → report (JSON / Markdown / console)     │
                 └───────────────────────────────────────────────────────────────┘
```

What each stage does:

| Stage | Details |
|---|---|
| Static analysis | libmagic type, MD5/SHA-1/SHA-256, whole-file entropy plus a **per-window entropy map** and merged **high-entropy regions** (offsets), printable/UTF-16 strings, PE headers/sections/imports, YARA. |
| YARA | Rules are compiled up front. A broken rule **fails the run** with its file and error (or, with `--rules-on-error warn`, is skipped with a loud warning and listed in the report). |
| capa / radare2 | Optional. Used when installed (`capa`, `rabin2` on `PATH`), skipped with a note when not. Results land in the report. |
| IOC extraction | URLs, IPs, domains and file paths, taken from the **raw** strings/script text before any sanitizing. Defanged in reports by default. |
| Evasion detection | Whole-token matching on exact tool/VM artifact names (so `.idata` is not "IDA"); APIs found in almost every compiled program (GetTickCount, QueryPerformanceCounter, IsDebuggerPresent) are low-weight and only count alongside a stronger signal. Outputs **sandbox masking hints**: configuration recommendations for the dynamic tier (which VM vendor strings, timing behaviour, debugger presence to mask). |
| Script preprocessing | Only when the file is detected as a script (Python, PowerShell, JavaScript, VBScript, batch, shell, PHP, HTML). Encoded payload blobs (base64, hex, `\xNN`, `0x..` arrays) are recorded by hash and replaced with markers; then comments are stripped with a language-aware scanner that leaves string literals, URLs and `--flags` intact. Strings from binaries are never comment-stripped. |
| Content guard | Per extracted string, or per script line. |
| LLM | OpenAI-compatible. A **triage** endpoint/model always; a **deep** endpoint/model with `--deep` or automatic escalation. |

Dynamic detonation is an **optional, documented stub** (see
[`malsift/sandbox/`](malsift/sandbox/)). It targets Firecracker microVMs (separate guest
kernel) rather than shared-kernel containers, and requires you to supply an
environment-specific kernel and rootfs. It is intentionally not turnkey.

## Isolation: what runs where

By default (`--isolate none`) **everything runs directly on your host**: libmagic,
pefile, YARA, capa and radare2 parse the untrusted file in your user account. MalSift
prints a warning when you run this way. That is fine for CI and for samples you already
trust to be inert; for real malware use the container:

```bash
docker build -f Dockerfile.analyzer -t malsift-analyzer:latest .   # or ./setup.sh --docker
malsift analyze ./samples/suspect.bin --isolate docker
```

With `--isolate docker`:

| Runs **inside** the container | Runs **on the host** |
|---|---|
| file typing, hashing, entropy, strings, PE parsing, YARA, capa/radare2 (if added to the image), IOC extraction, evasion detection, script comment stripping and payload isolation | reading the container's JSON output, the content guard, the LLM call(s), writing reports |

The container runs with: `--network none`, read-only root filesystem, `--cap-drop ALL`,
`no-new-privileges`, a default-deny **seccomp allowlist**
([`malsift/data/seccomp/analyzer.json`](malsift/data/seccomp/analyzer.json): no sockets,
ptrace, mount, namespaces, bpf, keyring, module loading), non-root UID 10001, a small
`noexec` tmpfs, memory/CPU/PID/file-descriptor limits, and the sample directory mounted
**read-only**. The same settings are in [`docker-compose.yml`](docker-compose.yml):

```bash
SAMPLE=suspect.bin docker compose run --rm analyzer > extraction.json
```

Limits, stated plainly: a container shares the host kernel. This boundary is meant for
**static parsing** of hostile files (parser bugs in libmagic, pefile, YARA). The sample
is never executed by MalSift. Do not treat the container as a detonation sandbox; dynamic
execution belongs in a microVM on a disposable host.

## Prerequisites

| Need | Why |
|------|-----|
| Python 3.11+ | Runtime |
| `libmagic` | File-type identification (`python-magic`); MalSift falls back to magic bytes without it |
| `yara-python` | Signature matching. The PyPI wheel **bundles libyara**, so no system YARA package is needed |
| A local OpenAI-compatible LLM endpoint | Behavior summarization (optional; `--no-llm` skips it) |
| Docker | Optional, for `--isolate docker` |
| capa, radare2 | Optional extra analyzers, used automatically when on `PATH` |

System libs (Debian/Ubuntu): `sudo apt-get install -y libmagic1`
System libs (macOS/Homebrew): `brew install libmagic`

## Quick start

```bash
./setup.sh                 # creates .venv, installs MalSift + dev tools, checks optional deps
source .venv/bin/activate  # (./setup.sh --user for a plain install, --docker to build the image)

# or by hand:
python3 -m venv .venv && source .venv/bin/activate
pip install .              # regular install; config, prompts, rules ship inside the package
# pip install -e ".[dev]"  # editable install for development

# static-only triage (no model needed), JSON + Markdown reports
malsift analyze ./samples/suspect.bin --no-llm --format both

# parse inside the hardened container
malsift analyze ./samples/suspect.bin --isolate docker

# full triage against a local model, plus a second pass on a bigger model
malsift analyze ./samples/suspect.bin \
  --endpoint http://127.0.0.1:11434/v1 --model qwen3-coder \
  --deep --deep-endpoint http://gpu-box:8000/v1 --deep-model gpt-oss:120b
```

Useful flags: `--format json|md|both`, `--fail-on-hit` (exit 1 when the weighted
anti-analysis score reaches `evasion.fail_threshold` or a YARA rule above `info`
severity matches), `--rules DIR`, `--rules-on-error fail|warn`,
`--high-entropy-cutoff N`, `--config-dir DIR`. Every setting can also come from
`MALSIFT_*` environment variables; see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Before you run: configuration checklist

**Required**
- Point the triage tier at *your* local inference server (`--endpoint`,
  `MALSIFT_TRIAGE_URL`, or `llm.triage.endpoint`). The default
  `http://127.0.0.1:11434/v1` assumes a local Ollama.
- Decide where samples are parsed: `--isolate docker` for untrusted samples.

**Optional**
- Point `--rules DIR` at your own `.yar` rules. The packaged rules are a benign example
  plus the structural `poison_indicators.yar`.
- Tune thresholds in `config/local.yaml` (entropy cutoff and window, string min length,
  evasion fail threshold). Copy keys from
  [`malsift/data/config/default.yaml`](malsift/data/config/default.yaml).
- Wire a high-risk content classifier via `content_guard.register_classifier(...)` if you
  want hard-quarantine behavior beyond structural injection detection.

**Required before detonation (dynamic tier only)**
- Supply a Firecracker kernel image and a rootfs. Without them the sandbox stays a stub
  and dynamic analysis is disabled. Never detonate on a host you cannot afford to lose.

## Usage notes

- **Never commit live samples.** `samples/` and `reports/` are gitignored, and a
  pre-commit hook rejects anything in `samples/` that is not `.gitkeep`.
- Output is JSON (machine), optional Markdown (`--format md|both`), plus a rich console
  summary. Reports land in `reports/` by default. Reports never contain raw strings,
  neutralized bait, or payload blob contents; IOCs are defanged (`hxxp[://]x[.]com`).
- MITRE ATT&CK technique IDs in reports are the model's suggestions; treat them as leads
  for an analyst, not ground truth.

## Project layout

```
malsift/
  malsift/              core package (pipeline, analyzers, guard, client, report, cli)
    data/config/        default.yaml (packaged)
    data/prompts/       triage + deep prompt templates
    data/rules/         YARA rules: benign example + poison_indicators.yar
    data/seccomp/       seccomp allowlist for the analyzer container
    sandbox/            Firecracker detonation stub (documented, not turnkey)
  Dockerfile.analyzer   hardened static-analysis image
  docker-compose.yml    same hardening as `--isolate docker`
  setup.sh              venv setup + dependency check
  tests/                safety-property and regression tests
  docs/                 CONFIGURATION.md
```

## Safety and licensing

- [LICENSE](LICENSE) — MIT. Keep the copyright and permission notice in copies.
- [NOTICE](NOTICE) — attribution.
- [DISCLAIMER.md](DISCLAIMER.md) — authorized use only, sample handling, detonation safety.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability in MalSift itself.

## License

MIT, Copyright (c) 2026 Cameron Hopkin. See [LICENSE](LICENSE).

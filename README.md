# MalSift

Self-hosted malware triage that pairs classic static analysis with a **local**
open-weight LLM, runs untrusted samples inside a hardened isolation boundary, and
**quarantines adversarial "poison" content** that malware embeds to derail LLM-based
analyzers.

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

1. **Detects injection-shaped regions** by *structure* (instruction-override patterns,
   fake role headers, delimiter spoofing), not by subject matter. No topic keyword
   dictionaries ship in this repo.
2. **Neutralizes** anti-analysis bait so the pipeline keeps moving, recording a
   metadata-only marker instead of the raw content.
3. **Hard-quarantines** anything a pluggable high-risk classifier (that *you* wire in)
   flags, surfacing a hash and a reason, never the content itself.

The model only ever sees sanitized, comment-stripped code and sanitized strings. Raw-byte
detection (YARA, entropy, evasion heuristics) runs underneath for full coverage.

## How it works

```
sample ──▶ static analysis ──▶ preprocessor ──▶ content guard ──▶ LLM triage ──▶ report
            (raw bytes)         (strip comments)  (neutralize /     (local,        (JSON +
            magic, strings,                        quarantine        sanitized      rich
            PE/ELF, entropy,                        bait)             input only)    console,
            YARA, evasion                                                            MITRE
            heuristics)                                                              ATT&CK)
```

Dynamic detonation is an **optional, documented stub** (see
[`malsift/sandbox/`](malsift/sandbox/)). It targets Firecracker microVMs (separate guest
kernel) rather than shared-kernel containers, and requires you to supply an
environment-specific kernel and rootfs. It is intentionally not turnkey.

## Prerequisites

| Need | Why |
|------|-----|
| Python 3.11+ | Runtime |
| `libmagic` | File-type identification (`python-magic`) |
| `libyara` / `yara-python` | Signature matching |
| A local OpenAI-compatible LLM endpoint | Behavior summarization (optional; `--no-llm` skips it) |

System libs (Debian/Ubuntu): `sudo apt-get install -y libmagic1 libyara9`
System libs (macOS/Homebrew): `brew install libmagic yara`

## Quick start

```bash
# always work in a venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

# static-only triage (no model needed)
malsift analyze ./samples/suspect.bin --no-llm

# full triage against a local model
malsift analyze ./samples/suspect.bin \
  --endpoint http://127.0.0.1:11434/v1 \
  --model qwen3-coder
```

## Before you run: configuration checklist

**Required**
- Point `--endpoint` at *your* local inference server. The default
  `http://127.0.0.1:11434/v1` assumes a local Ollama.
- Confirm `libmagic` and `libyara` are installed, or run with `--no-llm` and expect
  reduced coverage if a lib is missing.

**Optional**
- Drop your own `.yar` rules in `rules/`. The shipped rule is a benign example.
- Tune thresholds in `config/default.yaml` (entropy cutoff, string min length).
- Wire a high-risk content classifier via `content_guard.register_classifier(...)` if you
  want hard-quarantine behavior beyond structural injection detection.

**Required before detonation (dynamic tier only)**
- Supply a Firecracker kernel image and a rootfs. Without them the sandbox stays a stub
  and dynamic analysis is disabled. Never detonate on a host you cannot afford to lose.

## Usage notes

- **Never commit live samples.** `samples/` and `reports/` are gitignored, and a
  pre-commit hook rejects anything in `samples/` that is not `.gitkeep`.
- Output is JSON (machine) plus a rich console summary (human). Reports land in
  `reports/` by default.
- MITRE ATT&CK technique IDs in reports are the model's suggestions; treat them as leads
  for an analyst, not ground truth.

## Project layout

```
malsift/
  malsift/            core package (pipeline, analyzers, guard, client, report, cli)
    sandbox/          Firecracker detonation stub (documented, not turnkey)
  config/             default.yaml
  rules/              YARA rules (ship a benign example only)
  prompts/            LLM analysis prompt template
  tests/              safety-property tests
  docs/               CONFIGURATION.md
```

## Safety and licensing

- [LICENSE](LICENSE) — MIT. Keep the copyright and permission notice in copies.
- [NOTICE](NOTICE) — attribution.
- [DISCLAIMER.md](DISCLAIMER.md) — authorized use only, sample handling, detonation safety.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability in MalSift itself.

## License

MIT, Copyright (c) 2026 Cameron Hopkin. See [LICENSE](LICENSE).

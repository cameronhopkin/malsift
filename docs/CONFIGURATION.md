# Configuration guide

MalSift reads config in this order (later wins): built-in defaults ->
`config/default.yaml` -> `config/local.yaml` -> CLI flags. Copy `default.yaml` to
`local.yaml` for your environment; `local.yaml` is gitignored.

## LLM

| Key | Meaning |
|-----|---------|
| `llm.endpoint` | OpenAI-compatible base URL. Default `http://127.0.0.1:11434/v1` (local Ollama). Point it at your vLLM/llama.cpp/TGI server. |
| `llm.model` | Model name to request (e.g. `qwen3-coder`, `gpt-oss:120b`). |
| `llm.api_key` | Usually unused locally; set if your gateway requires a bearer token. |
| `llm.timeout_s` / `llm.max_tokens` / `llm.temperature` | Request tuning. Keep temperature low for triage. |

Run `malsift analyze <file> --no-llm` to skip the model entirely (static-only).

## Static analysis

| Key | Meaning |
|-----|---------|
| `static.string_min_len` | Minimum printable run length for string extraction. |
| `static.max_strings` | Cap on extracted strings (bounds memory/time). |
| `static.entropy_block` | Window size for windowed entropy. |
| `static.high_entropy_cutoff` | Entropy at/above which a file is flagged high-entropy (packing hint). |

Drop your own `.yar`/`.yara` files in `rules/` (or pass `--rules DIR`). The shipped rule
is a benign example; replace it.

## Content guard

| Key | Meaning |
|-----|---------|
| `guard.neutralize_injection` | Replace injection-shaped regions with metadata-only markers. |
| `guard.enable_hard_quarantine` | Allow a registered high-risk classifier to quarantine a region. |

To add hard-quarantine behavior, register your own classifier at startup:

```python
from malsift import content_guard

def my_classifier(region: str):
    # return (True, "reason") to quarantine; None to pass.
    # Return a reason only. Never return or log the flagged content.
    ...

content_guard.register_classifier(my_classifier)
```

No subject-matter dictionary ships with MalSift, by design. Keep any classifier you add
metadata-only.

## Dynamic detonation (optional, stub)

Disabled until you provision it. See `malsift/sandbox/firecracker.py` and the safety
requirements in `DISCLAIMER.md`. You must supply your own kernel and rootfs and set
`operator_opt_in=True` on a disposable, network-isolated host.

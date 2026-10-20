"""OpenAI-compatible chat client, pointed at a local endpoint by default.

Uses only the Python standard library (urllib) so the package has no hard HTTP dependency.
The client forwards *sanitized* analysis context only; raw sample bytes and guarded regions
never reach it.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class LLMResponse:
    ok: bool
    content: str
    error: str | None = None


class LLMClient:
    def __init__(self, endpoint: str, model: str, api_key: str = "not-needed-for-local",
                 timeout_s: int = 120, max_tokens: int = 1024, temperature: float = 0.1):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.temperature = temperature

    def chat(self, system: str, user: str) -> LLMResponse:
        url = f"{self.endpoint}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            return LLMResponse(ok=True, content=content)
        except urllib.error.URLError as e:
            return LLMResponse(ok=False, content="", error=f"endpoint unreachable: {e}")
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            return LLMResponse(ok=False, content="", error=f"unexpected response shape: {e}")
        except Exception as e:  # noqa: BLE001
            return LLMResponse(ok=False, content="", error=str(e))

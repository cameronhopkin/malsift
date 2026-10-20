"""Shared fixtures. Every fixture here is synthetic and benign: no live samples."""
from __future__ import annotations

import random

import pytest

from malsift import content_guard
from malsift.config import load_config


@pytest.fixture(autouse=True)
def _clean_classifiers():
    content_guard.clear_classifiers()
    yield
    content_guard.clear_classifiers()


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    # Keep the developer's own MALSIFT_* variables and ./config/local.yaml out of tests.
    import os

    for k in list(os.environ):
        if k.startswith("MALSIFT_"):
            monkeypatch.delenv(k, raising=False)
    # Don't call a real capa/radare2 that happens to be installed on the test host;
    # tests/test_integrations.py turns these back on with fake tools.
    monkeypatch.setenv("MALSIFT_CAPA", "off")
    monkeypatch.setenv("MALSIFT_RADARE2", "off")
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def cfg():
    return load_config()


@pytest.fixture
def fake_llm(monkeypatch):
    """Capture what would be sent to the model instead of calling a server."""
    from malsift import llm_client

    calls: list[dict] = []

    def chat(self, system, user):
        calls.append({"endpoint": self.endpoint, "model": self.model, "system": system, "user": user})
        return llm_client.LLMResponse(ok=True, content=f"summary from {self.model}: T1059 T1027")

    monkeypatch.setattr(llm_client.LLMClient, "chat", chat)
    return calls


def benign_pe_bytes() -> bytes:
    """A synthetic, non-executable PE-shaped blob with the strings a typical compiled
    program carries: ordinary section names (.text/.rdata/.idata) and the CRT-startup
    APIs that naive detectors mistake for anti-analysis."""
    rnd = random.Random(7)
    parts = [
        b"MZ",
        b"\x90" * 58,
        b"This program cannot be run in DOS mode.\r\n$",
        b"\x00" * 64,
        b"PE\x00\x00",
        b"\x00.text\x00\x00\x00.rdata\x00\x00.data\x00\x00\x00.idata\x00\x00.reloc\x00\x00",
        b"\x00KERNEL32.dll\x00GetTickCount\x00QueryPerformanceCounter\x00IsDebuggerPresent\x00",
        b"GetSystemTimeAsFileTime\x00GetCurrentProcessId\x00OutputDebugStringW\x00",
        b"\x00Microsoft Visual C++ Runtime Library\x00Invalid parameter passed\x00",
        b"\x00Xenial release notes\x00Validated input\x00",
        bytes(rnd.randrange(0, 40) for _ in range(512)),
    ]
    return b"".join(parts)

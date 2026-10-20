"""Bug 3 regression: token matching, low-weight common APIs, sandbox hints."""
from __future__ import annotations

from conftest import benign_pe_bytes

from malsift import evasion
from malsift.cli import main


def test_section_names_and_words_do_not_match_tools_or_vms():
    rep = evasion.detect([".idata", ".rdata", "Xenial", "validated", "idapro_notes", "vmwarehouse"], None)
    assert rep.analysis_tool_watch == []
    assert rep.vm_artifacts == []
    assert rep.score == 0


def test_exact_tool_and_vm_names_match():
    rep = evasion.detect(["C:\\Program Files\\IDA\\ida64.exe", "VBoxService.exe"], None)
    assert "ida64.exe" in rep.analysis_tool_watch
    assert "vboxservice.exe" in rep.vm_artifacts
    assert rep.score >= 6


def test_common_crt_apis_are_low_weight_only():
    pe = {"imports_sampled": [
        "KERNEL32.dll!GetTickCount", "KERNEL32.dll!QueryPerformanceCounter",
        "KERNEL32.dll!IsDebuggerPresent", "KERNEL32.dll!GetSystemTimeAsFileTime",
    ]}
    rep = evasion.detect([], pe)
    assert set(rep.low_weight_signals) >= {"GetTickCount", "QueryPerformanceCounter", "IsDebuggerPresent"}
    assert rep.anti_debug_apis == []
    assert rep.score == 0
    assert rep.to_dict()["low_weight_counted"] is False
    assert rep.sandbox_hints() == []


def test_low_weight_counts_in_combination():
    pe = {"imports_sampled": ["KERNEL32.dll!GetTickCount", "KERNEL32.dll!CheckRemoteDebuggerPresent"]}
    rep = evasion.detect([], pe)
    assert rep.anti_debug_apis == ["CheckRemoteDebuggerPresent"]
    assert rep.score == evasion.WEIGHT_STRONG + evasion.WEIGHT_LOW
    cats = {h["category"] for h in rep.sandbox_hints()}
    assert cats == {"debugger", "timing"}


def test_api_substrings_do_not_match():
    rep = evasion.detect(["MyCheckRemoteDebuggerPresentWrapperX", "GetTickCountXYZ"], None)
    assert rep.anti_debug_apis == [] and rep.low_weight_signals == []


def test_sandbox_hints_are_config_recommendations():
    rep = evasion.detect(["vmtoolsd.exe", "VBoxVBoxVBox"], None)
    hints = rep.to_dict()["sandbox_hints"]
    cats = {h["category"] for h in hints}
    assert {"vmware", "virtualbox"} <= cats
    for h in hints:
        assert h["recommendation"]  # plain-language configuration advice


def test_fail_on_hit_does_not_trip_on_typical_benign_pe(tmp_path):
    sample = tmp_path / "benign.exe"
    sample.write_bytes(benign_pe_bytes())
    rc = main(["analyze", str(sample), "--no-llm", "--no-write", "--quiet", "--fail-on-hit"])
    assert rc == 0


def test_fail_on_hit_trips_on_real_indicators(tmp_path):
    sample = tmp_path / "evasive.bin"
    sample.write_bytes(benign_pe_bytes() + b"\x00vboxservice.exe\x00CheckRemoteDebuggerPresent\x00")
    rc = main(["analyze", str(sample), "--no-llm", "--no-write", "--quiet", "--fail-on-hit"])
    assert rc == 1

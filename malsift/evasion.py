"""Anti-analysis indicator detection and sandbox-configuration hints.

This module *detects* whether a sample appears to look for a sandbox, debugger, or VM so
an analyst knows the sample may behave differently under observation. It reports
indicators found in the sample and, for each category found, a defensive *configuration
recommendation* for the dynamic-analysis tier (what to mask in the analysis VM so the
sample's environment checks see a realistic machine). It does not implement evasion and
ships no evasion code.

Matching rules (to keep false positives off ordinary binaries):

* Names are matched as whole tokens, never as substrings. ``ida`` is only matched as the
  exact process names ``ida.exe``/``ida64.exe``/``idaq.exe``/``idaq64.exe``, so the PE
  section ``.idata`` never hits; ``xen`` is only matched as specific Xen artifacts.
* APIs are matched against the import table and against whole strings/tokens.
* APIs present in nearly every compiled program's runtime startup code (GetTickCount,
  QueryPerformanceCounter, IsDebuggerPresent, ...) are LOW-weight signals. They are
  reported, but only add to the score when at least one stronger signal is present.

The indicator names are long-published, standard malware-analysis reference material
(documented by Cuckoo/CAPE, al-khaser test suites, and analysis courses). They are used
here only to flag their presence in a sample under review.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --- APIs ---------------------------------------------------------------------------
# Strong: rarely imported by ordinary programs; a deliberate debugger/thread-hiding check.
_STRONG_APIS = {
    "CheckRemoteDebuggerPresent": "debugger",
    "NtSetInformationThread": "debugger",
    "ZwSetInformationThread": "debugger",
    "NtQueryInformationProcess": "debugger",
    "ZwQueryInformationProcess": "debugger",
    "DbgUiRemoteBreakin": "debugger",
    "wine_get_unix_file_name": "vm",
}
# Low: present in most compiled programs (CRT startup, profilers, logging).
_LOW_APIS = {
    "GetTickCount": "timing",
    "GetTickCount64": "timing",
    "QueryPerformanceCounter": "timing",
    "IsDebuggerPresent": "debugger",
    "OutputDebugStringA": "debugger",
    "OutputDebugStringW": "debugger",
    "GetSystemFirmwareTable": "firmware",
    "NtQuerySystemInformation": "debugger",
}

# --- VM / sandbox artifacts (exact tokens, case-insensitive) --------------------------
_VM_ARTIFACTS = {
    # VMware
    "vmtoolsd.exe": "vmware", "vmwaretray.exe": "vmware", "vmwareuser.exe": "vmware",
    "vmmouse.sys": "vmware", "vmhgfs.sys": "vmware", "VMwareVMware": "vmware",
    "VMware Tools": "vmware", "VMware Virtual Platform": "vmware",
    # VirtualBox
    "vboxservice.exe": "virtualbox", "vboxtray.exe": "virtualbox",
    "VBoxGuest.sys": "virtualbox", "VBoxMouse.sys": "virtualbox", "VBoxSF.sys": "virtualbox",
    "VBoxVBoxVBox": "virtualbox", "VirtualBox Guest Additions": "virtualbox",
    "HARDWARE\\ACPI\\DSDT\\VBOX__": "virtualbox",
    # QEMU / KVM
    "qemu-ga.exe": "qemu", "QEMU HARDDISK": "qemu", "KVMKVMKVM": "qemu",
    # Xen
    "XenVMMXenVMM": "xen", "xenservice.exe": "xen",
    # Hyper-V
    "Microsoft Hv": "hyperv", "vmicheartbeat": "hyperv",
    # Parallels
    "prl_tools.exe": "parallels", "prl cc.exe": "parallels",
    # Sandboxes
    "SbieDll.dll": "sandboxie", "cuckoomon.dll": "cuckoo", "dbghelp_cuckoo": "cuckoo",
}
# Registry value commonly read by benign inventory software too: low weight.
_LOW_VM_ARTIFACTS = {
    "SystemBiosVersion": "firmware",
    "SystemManufacturer": "firmware",
}

# --- Analysis tools a sample may look for (exact process / window names) --------------
_TOOLS = {
    "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe", "x64dbg.exe", "x32dbg.exe",
    "ollydbg.exe", "windbg.exe", "immunitydebugger.exe", "wireshark.exe", "dumpcap.exe",
    "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe", "fiddler.exe",
    "tcpview.exe", "autoruns.exe", "regmon.exe", "filemon.exe", "processhacker.exe",
    "pestudio.exe", "httpdebugger.exe", "OLLYDBG", "WinDbgFrameClass",
}

WEIGHT_STRONG = 3
WEIGHT_LOW = 1

# Defensive sandbox-configuration recommendations, keyed by category.
SANDBOX_HINTS: dict[str, str] = {
    "vmware": "Mask VMware identity in the analysis VM: set SMBIOS/DMI vendor, product and "
    "BIOS strings to a physical-hardware profile, use a non-VMware MAC OUI, and keep VMware "
    "Tools processes/drivers out of the guest image (use hypervisor-side introspection).",
    "virtualbox": "Mask VirtualBox identity: replace VBOX ACPI/DSDT and SMBIOS strings with "
    "a physical-hardware profile, avoid installing Guest Additions in the detonation image, "
    "and use a non-VirtualBox MAC OUI.",
    "qemu": "Mask QEMU/KVM identity: set custom SMBIOS strings and disk model names, hide "
    "the KVM CPUID signature (e.g. -cpu host,kvm=off) and omit qemu-guest-agent from the guest.",
    "xen": "Mask Xen identity: hide the Xen CPUID leaf and PV drivers/services from the guest.",
    "hyperv": "Mask Hyper-V enlightenments/CPUID vendor and integration services in the guest.",
    "parallels": "Keep Parallels Tools out of the detonation image and mask its SMBIOS strings.",
    "sandboxie": "Do not run detonation under Sandboxie; use a full VM so SbieDll is absent.",
    "cuckoo": "Use an in-guest monitor that does not expose a well-known module name, or "
    "monitor from the hypervisor.",
    "firmware": "Populate firmware registry values (SystemBiosVersion, SystemManufacturer) "
    "with a realistic physical-hardware profile.",
    "debugger": "Observe without an attached user-mode debugger: rely on hypervisor or "
    "kernel-level tracing so debugger-presence checks see a normal process.",
    "timing": "Keep guest clocks and tick counters consistent: avoid accelerating Sleep() "
    "without also advancing GetTickCount/QPC/RDTSC, give the guest a realistic uptime, and "
    "let detonation run long enough for delayed execution.",
    "tools": "Do not run analysis tools inside the detonation guest under their default "
    "process/window names; collect telemetry from outside the guest.",
}


def _token_rx(name: str) -> re.Pattern[str]:
    # Whole-token match: not preceded/followed by an identifier character.
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", re.IGNORECASE)


_STRONG_API_RX = {n: _token_rx(n) for n in _STRONG_APIS}
_LOW_API_RX = {n: _token_rx(n) for n in _LOW_APIS}
_VM_RX = {n: _token_rx(n) for n in _VM_ARTIFACTS}
_LOW_VM_RX = {n: _token_rx(n) for n in _LOW_VM_ARTIFACTS}
_TOOL_RX = {n: _token_rx(n) for n in _TOOLS}


@dataclass
class EvasionReport:
    anti_debug_apis: list[str] = field(default_factory=list)
    vm_artifacts: list[str] = field(default_factory=list)
    analysis_tool_watch: list[str] = field(default_factory=list)
    low_weight_signals: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)
    low_categories: set[str] = field(default_factory=set)

    @property
    def strong_score(self) -> int:
        return WEIGHT_STRONG * (
            len(self.anti_debug_apis) + len(self.vm_artifacts) + len(self.analysis_tool_watch)
        )

    @property
    def score(self) -> int:
        """Weighted score. Low-weight signals only count alongside a stronger one."""
        if self.strong_score == 0:
            return 0
        return self.strong_score + WEIGHT_LOW * len(self.low_weight_signals)

    def sandbox_hints(self) -> list[dict[str, str]]:
        cats = set(self.categories)
        if self.strong_score:
            cats |= self.low_categories
        return [
            {"category": c, "recommendation": SANDBOX_HINTS[c]}
            for c in sorted(cats)
            if c in SANDBOX_HINTS
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "anti_debug_apis": self.anti_debug_apis,
            "vm_artifacts": self.vm_artifacts,
            "analysis_tool_watch": self.analysis_tool_watch,
            "low_weight_signals": self.low_weight_signals,
            "low_weight_counted": self.strong_score > 0,
            "sandbox_hints": self.sandbox_hints(),
        }


def _found(name: str, rx: re.Pattern[str], strings: list[str], imports: set[str]) -> bool:
    if name in imports:
        return True
    return any(rx.search(s) for s in strings)


def detect(strings: list[str], pe: dict | None) -> EvasionReport:
    rep = EvasionReport()

    imports: set[str] = set()
    if pe and isinstance(pe.get("imports_sampled"), list):
        for imp in pe["imports_sampled"]:
            imports.add(imp.split("!")[-1])  # format is "DLL!Name"

    for api, cat in _STRONG_APIS.items():
        if _found(api, _STRONG_API_RX[api], strings, imports):
            rep.anti_debug_apis.append(api)
            rep.categories.add(cat)
    for api, cat in _LOW_APIS.items():
        if _found(api, _LOW_API_RX[api], strings, imports):
            rep.low_weight_signals.append(api)
            rep.low_categories.add(cat)
    for art, cat in _VM_ARTIFACTS.items():
        if _found(art, _VM_RX[art], strings, set()):
            rep.vm_artifacts.append(art)
            rep.categories.add(cat)
    for art, cat in _LOW_VM_ARTIFACTS.items():
        if _found(art, _LOW_VM_RX[art], strings, set()):
            rep.low_weight_signals.append(art)
            rep.low_categories.add(cat)
    for tool in sorted(_TOOLS):
        if _found(tool, _TOOL_RX[tool], strings, set()):
            rep.analysis_tool_watch.append(tool)
            rep.categories.add("tools")
    return rep

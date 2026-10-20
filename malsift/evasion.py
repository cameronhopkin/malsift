"""Anti-analysis indicator detection.

This module *detects* whether a sample appears to look for a sandbox, debugger, or VM so
an analyst knows the sample may behave differently under observation. It reports
indicators found in the sample. It does not implement evasion and ships no evasion code.

The indicator names below are long-published, standard malware-analysis reference material
(the same API names and artifacts taught in every analysis course and documented by
Cuckoo/CAPE). They are used here only to flag their presence in a sample under review.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Windows API calls commonly used for anti-debug / timing / environment checks.
_ANTI_DEBUG_APIS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "GetTickCount",
    "QueryPerformanceCounter",
    "NtSetInformationThread",
}

# Strings/artifacts a sample may probe to decide it is inside an analysis VM.
_VM_ARTIFACT_STRINGS = {
    "vmware",
    "virtualbox",
    "vboxservice",
    "vboxtray",
    "qemu",
    "xen",
    "sandbox",
    "sbiedll",  # Sandboxie
    "wine_get_unix_file_name",
    "SystemBiosVersion",
    "HARDWARE\\ACPI\\DSDT\\VBOX__",
}

# Strings suggesting the sample inspects analysis tooling.
_TOOL_WATCH_STRINGS = {
    "wireshark",
    "procmon",
    "procexp",
    "ollydbg",
    "x64dbg",
    "ida",
    "fiddler",
    "tcpview",
}


@dataclass
class EvasionReport:
    anti_debug_apis: list[str] = field(default_factory=list)
    vm_artifacts: list[str] = field(default_factory=list)
    analysis_tool_watch: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return len(self.anti_debug_apis) + len(self.vm_artifacts) + len(self.analysis_tool_watch)

    def to_dict(self) -> dict[str, list[str] | int]:
        return {
            "score": self.score,
            "anti_debug_apis": self.anti_debug_apis,
            "vm_artifacts": self.vm_artifacts,
            "analysis_tool_watch": self.analysis_tool_watch,
        }


def detect(strings: list[str], pe: dict | None) -> EvasionReport:
    rep = EvasionReport()
    haystack = "\n".join(strings).lower()

    import_names: set[str] = set()
    if pe and isinstance(pe.get("imports_sampled"), list):
        for imp in pe["imports_sampled"]:
            # format is "DLL!Name"
            import_names.add(imp.split("!")[-1])

    for api in _ANTI_DEBUG_APIS:
        if api in import_names or api.lower() in haystack:
            rep.anti_debug_apis.append(api)

    for art in _VM_ARTIFACT_STRINGS:
        if art.lower() in haystack:
            rep.vm_artifacts.append(art)

    for tool in _TOOL_WATCH_STRINGS:
        if tool in haystack:
            rep.analysis_tool_watch.append(tool)

    return rep

"""Firecracker microVM detonation stub.

Why a microVM and not a container: a shared-kernel container is not a safe boundary for
detonating untrusted code. Firecracker gives each sample a separate guest kernel.

This ships as a STUB on purpose. It will refuse to run until an operator supplies a kernel
image and a rootfs and explicitly opts in. There is no bundled kernel/rootfs and no
network path is configured. See DISCLAIMER.md before completing this.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class SandboxNotConfigured(RuntimeError):
    """Raised when detonation is requested but the sandbox is not fully provisioned."""


@dataclass
class DetonationConfig:
    kernel_image: str | None = None       # path to a vmlinux you supply
    rootfs_image: str | None = None       # path to a rootfs you supply
    firecracker_bin: str = "firecracker"  # must be installed by the operator
    vcpus: int = 1
    mem_mib: int = 512
    timeout_s: int = 60
    # Networking is intentionally omitted. Detonation runs with no reachable network
    # unless an operator wires an isolated tap device themselves.
    operator_opt_in: bool = False

    def validate(self) -> None:
        if not self.operator_opt_in:
            raise SandboxNotConfigured(
                "Detonation is disabled. Set operator_opt_in=True only on a disposable, "
                "network-isolated host (see DISCLAIMER.md)."
            )
        for label, val in (("kernel_image", self.kernel_image), ("rootfs_image", self.rootfs_image)):
            if not val or not Path(val).is_file():
                raise SandboxNotConfigured(f"missing {label}; supply your own image path")


class FirecrackerSandbox:
    def __init__(self, config: DetonationConfig):
        self.config = config

    def detonate(self, sample_path: str) -> dict:
        """Placeholder. Validates provisioning and then stops.

        A complete implementation would: boot a Firecracker microVM from the supplied
        kernel/rootfs, copy the sample in over a vsock/drive, run it under observation
        (syscall/network capture) for timeout_s, then collect artifacts and destroy the VM.
        That final step is left to the operator because it is environment-specific and
        carries real risk.
        """
        self.config.validate()
        raise SandboxNotConfigured(
            "Sandbox provisioned but detonation body is intentionally left as a stub. "
            "Implement boot/observe/teardown for your environment."
        )

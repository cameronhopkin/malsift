"""Dynamic detonation tier (documented stub).

Deliberately not turnkey. Completing this requires supplying an environment-specific
Firecracker kernel and rootfs, and accepting the risk documented in DISCLAIMER.md.
"""
from .firecracker import DetonationConfig, FirecrackerSandbox, SandboxNotConfigured

__all__ = ["DetonationConfig", "FirecrackerSandbox", "SandboxNotConfigured"]

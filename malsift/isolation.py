"""Run the extraction half of the pipeline inside the hardened analyzer container.

What runs isolated (``--isolate docker``): everything that parses the sample's bytes:
file-type detection, hashing, entropy, string extraction, PE parsing, YARA, capa,
radare2, IOC extraction, evasion detection, script comment stripping and payload
isolation. The container has no network, a read-only root filesystem, all Linux
capabilities dropped, ``no-new-privileges``, a seccomp allowlist, a non-root user, a
small ``noexec`` tmpfs, and memory/CPU/PID limits. The sample directory is mounted
read-only.

What stays on the host: reading the container's JSON output, the content guard, the
LLM call(s) (the container has no network by design), and writing reports.

Containers share the host kernel. This boundary is appropriate for *static* parsing of
untrusted files; it is not a detonation sandbox. Dynamic execution belongs in a microVM
(see ``malsift/sandbox``).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import resources

CONTAINER_SAMPLES = "/samples"
CONTAINER_RULES = "/rules"
CONTAINER_USER = "10001:10001"


class IsolationError(RuntimeError):
    pass


def docker_available() -> bool:
    return shutil.which("docker") is not None


def build_docker_command(
    sample: Path,
    cfg,
    *,
    rules_dir: Path | None = None,
    seccomp: Path | None = None,
    docker: str = "docker",
) -> list[str]:
    """Return the ``docker run`` argv. Mirrors the ``analyzer`` service in docker-compose.yml."""
    sample = sample.resolve()
    seccomp = (seccomp or resources.seccomp_profile()).resolve()
    image = str(cfg.get("isolation", "image", default="malsift-analyzer:latest"))
    tmpfs_size = str(cfg.get("isolation", "tmpfs_size", default="64m"))
    cmd = [
        docker, "run", "--rm", "-i",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", f"seccomp={seccomp}",
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs_size}",
        "--user", CONTAINER_USER,
        "--memory", str(cfg.get("isolation", "memory", default="1g")),
        "--memory-swap", str(cfg.get("isolation", "memory", default="1g")),
        "--cpus", str(cfg.get("isolation", "cpus", default="1.0")),
        "--pids-limit", str(cfg.get("isolation", "pids_limit", default=128)),
        "--ulimit", "nofile=256:256",
        "--ipc", "none",
        "-v", f"{sample.parent}:{CONTAINER_SAMPLES}:ro",
    ]
    args = ["extract", f"{CONTAINER_SAMPLES}/{sample.name}"]
    if rules_dir is not None:
        cmd += ["-v", f"{rules_dir.resolve()}:{CONTAINER_RULES}:ro"]
        args += ["--rules", CONTAINER_RULES]
    # Hand the host's *effective* extraction settings (defaults + local.yaml + MALSIFT_*
    # env + CLI flags) to the container, so isolated and host runs behave identically.
    args += ["--config-json", json.dumps(extraction_config(cfg), separators=(",", ":"))]
    cmd += [image, *args]
    return cmd


EXTRACTION_SECTIONS = ("static", "payloads", "yara", "integrations")


def extraction_config(cfg) -> dict[str, Any]:
    return {k: cfg.get(k, default={}) for k in EXTRACTION_SECTIONS}


def run_extract_in_docker(
    sample: Path,
    cfg,
    *,
    rules_dir: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run ``malsift extract`` in the container. Returns (extraction, isolation_meta)."""
    if not docker_available():
        raise IsolationError(
            "--isolate docker requested but the docker CLI was not found. Install Docker or "
            "run with --isolate none (analysis then runs directly on this host)."
        )
    seccomp = resources.seccomp_profile()
    if not seccomp.is_file():
        raise IsolationError(f"seccomp profile missing: {seccomp}")
    cmd = build_docker_command(sample, cfg, rules_dir=rules_dir, seccomp=seccomp)
    timeout = int(cfg.get("isolation", "timeout_s", default=300))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as e:
        raise IsolationError(f"isolated extraction timed out after {timeout}s") from e
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.strip().splitlines()[-15:])
        raise IsolationError(
            f"isolated extraction failed (exit {proc.returncode}). Is the image built? "
            f"`docker build -f Dockerfile.analyzer -t {cfg.get('isolation', 'image')} .`\n{tail}"
        )
    try:
        extraction = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise IsolationError(f"isolated extraction returned invalid JSON: {e}") from e
    if not isinstance(extraction, dict) or "static" not in extraction:
        raise IsolationError("isolated extraction returned an unexpected document")
    # The container saw the sample under /samples; report the host path instead.
    extraction["static"]["path"] = str(sample)
    meta = describe("docker", image=str(cfg.get("isolation", "image")), seccomp=str(seccomp))
    return extraction, meta


def describe(mode: str, **extra: Any) -> dict[str, Any]:
    if mode == "docker":
        return {
            "mode": "docker",
            "isolated_steps": [
                "file type", "hashes", "entropy", "strings", "PE parsing", "YARA",
                "capa", "radare2", "IOC extraction", "evasion detection",
                "script comment stripping", "payload isolation",
            ],
            "host_steps": ["content guard", "LLM", "report writing"],
            "controls": [
                "network none", "read-only rootfs", "cap-drop ALL", "no-new-privileges",
                "seccomp allowlist", "non-root uid 10001", "noexec tmpfs", "memory/cpu/pids limits",
                "samples mounted read-only",
            ],
            **extra,
        }
    return {
        "mode": "none",
        "isolated_steps": [],
        "host_steps": ["all steps (sample parsed directly on the host)"],
        "warning": "No isolation: the sample was parsed by libraries running on the host.",
    }

#!/usr/bin/env python3
"""Pre-commit guard: refuse to commit anything under samples/ except .gitkeep.

Works both as a pre-commit framework hook (filenames passed as args) and as a plain
git hook (falls back to `git diff --cached`).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import PurePosixPath


def _staged_from_git() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True,
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def main(argv: list[str]) -> int:
    files = argv[1:] or _staged_from_git()
    offenders = []
    for f in files:
        p = PurePosixPath(f.replace("\\", "/"))
        parts = p.parts
        if "samples" in parts:
            idx = parts.index("samples")
            rest = parts[idx + 1:]
            if rest and rest != (".gitkeep",):
                offenders.append(f)
    if offenders:
        print("BLOCKED: refusing to commit files under samples/ (possible live malware):")
        for f in offenders:
            print(f"  - {f}")
        print("Move samples out of the repo. Only samples/.gitkeep may be tracked.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

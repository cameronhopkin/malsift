#!/usr/bin/env bash
# MalSift developer/analyst setup: creates .venv, installs MalSift, checks system libs.
#
#   ./setup.sh            # editable install with dev tools (pytest, ruff)
#   ./setup.sh --user     # regular (non-editable) install, no dev tools
#   ./setup.sh --docker   # also build the hardened analyzer image
set -euo pipefail

cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
MODE="dev"
BUILD_DOCKER=0
for arg in "$@"; do
  case "$arg" in
    --user) MODE="user" ;;
    --docker) BUILD_DOCKER=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

"$PYTHON" - <<'PY' || { echo "Python 3.11+ is required" >&2; exit 1; }
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
PY

if [ ! -d .venv ]; then
  echo "==> creating .venv"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null

if [ "$MODE" = "dev" ]; then
  echo "==> installing malsift (editable) with dev extras"
  python -m pip install -e ".[dev]"
else
  echo "==> installing malsift"
  python -m pip install .
fi

echo "==> checking optional system components"
python - <<'PY'
import shutil
def check(label, ok, hint):
    print(f"  [{'ok' if ok else '--'}] {label}" + ("" if ok else f"  ({hint})"))
try:
    import magic  # noqa: F401
    check("libmagic", True, "")
except Exception:
    check("libmagic", False, "apt install libmagic1 / brew install libmagic; file typing falls back to magic bytes")
try:
    import yara  # noqa: F401
    check("yara-python (bundles libyara)", True, "")
except Exception:
    check("yara-python", False, "pip install yara-python")
check("capa (optional)", shutil.which("capa") is not None, "https://github.com/mandiant/capa/releases")
check("radare2 / rabin2 (optional)", shutil.which("rabin2") is not None, "https://github.com/radareorg/radare2")
check("docker (optional, for --isolate docker)", shutil.which("docker") is not None, "https://docs.docker.com/get-docker/")
PY

if [ "$BUILD_DOCKER" = "1" ]; then
  echo "==> building malsift-analyzer:latest"
  docker build -f Dockerfile.analyzer -t malsift-analyzer:latest .
fi

if command -v pre-commit >/dev/null 2>&1 && [ -d .git ]; then
  pre-commit install >/dev/null && echo "==> pre-commit hook installed"
else
  echo "==> tip: pip install pre-commit && pre-commit install (blocks committing samples)"
fi

echo
echo "Done. Activate with:  source .venv/bin/activate"
echo "Try:                  malsift analyze <file> --no-llm --format both"

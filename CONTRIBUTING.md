# Contributing to MalSift

Thanks for helping improve defensive tooling.

## Ground rules

- **Defensive only.** PRs that add malware generation, exploit code, live samples, or
  turnkey evasion capability will be closed. MalSift analyzes samples; it does not create
  offensive capability.
- **No live samples, ever.** Not in code, tests, fixtures, or issues. Use synthetic
  reproductions or hashes.
- **No subject-matter keyword lists.** The content guard keys on injection *structure*,
  not topics. Keep it that way.

## Development

```bash
./setup.sh                 # or: python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
source .venv/bin/activate
ruff check .
pytest
# container tests (needs Docker):
docker build -f Dockerfile.analyzer -t malsift-analyzer:latest .
MALSIFT_DOCKER_TESTS=1 pytest tests/test_isolation.py
```

## Pull requests

1. Keep changes focused and covered by tests.
2. Run `ruff check .` and `pytest` locally (CI runs both).
3. If you touch the content guard, preprocessor, isolation or sandbox, add or update a
   safety-property test under `tests/`. Fixtures must be synthetic and benign.
4. Confirm the pre-commit hook is installed so you cannot commit a sample by accident.

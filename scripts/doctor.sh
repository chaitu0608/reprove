#!/usr/bin/env bash
# Reprove environment doctor — checks the local dev setup and repairs the one
# known macOS quirk: Python 3.14 skips .pth files that carry the UF_HIDDEN
# flag, which silently breaks editable installs.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -x ".venv/bin/python" ]; then
  echo "✗ no .venv found. Create it with:"
  echo "    python3 -m venv .venv && pip install -e '.[dev,mcp]'"
  exit 1
fi

if [ "$(uname)" = "Darwin" ]; then
  hidden=$(ls -lO .venv/lib/python*/site-packages/ 2>/dev/null | grep -c "hidden" || true)
  if [ "${hidden:-0}" -gt 0 ]; then
    echo "· repairing ${hidden} hidden file(s) in .venv (macOS UF_HIDDEN)"
    chflags -R nohidden .venv
  fi
fi

.venv/bin/python -c "import reprove; print('· reprove:', reprove.__file__)"

if command -v node >/dev/null 2>&1; then
  echo "· node: $(node --version)"
else
  echo "! node not found — dynamic exploit probes will be skipped"
fi

.venv/bin/python -m pytest tests/ -q
echo "✓ doctor: environment is healthy"

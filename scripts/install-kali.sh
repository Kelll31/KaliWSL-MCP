#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -x .venv-kali/bin/python ]; then
    python3 -m venv .venv-kali
fi
if [ -f requirements.lock ]; then
    .venv-kali/bin/python -m pip install -r requirements.lock
    .venv-kali/bin/python -m pip install --no-deps -e .
else
    .venv-kali/bin/python -m pip install -e .
fi
if [ "${1:-}" = "--dev" ]; then
    .venv-kali/bin/python -m pip install -e '.[dev]'
fi
if [ ! -f config.local.json ]; then
    cp config.example.json config.local.json
fi
.venv-kali/bin/python -m kali_mcp --config config.local.json --check

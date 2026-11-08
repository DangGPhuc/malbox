#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

export PYTHONPATH=backend
echo "[*] Starting malbox-ai Backend API on http://127.0.0.1:8000..."
exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

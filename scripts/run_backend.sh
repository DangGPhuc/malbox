#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

export PYTHONPATH=backend
HOST="${MALBOX_HOST:-$(python3 -c 'from app.core.config import settings; print(settings.HOST)' 2>/dev/null || echo 127.0.0.1)}"
PORT="${MALBOX_PORT:-$(python3 -c 'from app.core.config import settings; print(settings.PORT)' 2>/dev/null || echo 8000)}"

echo "[*] Starting malbox-ai Backend API on http://${HOST}:${PORT}..."
exec python3 -m uvicorn app.main:app --host "$HOST" --port "$PORT" --reload

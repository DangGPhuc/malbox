#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

CHECK_ONLY=false
FORCE_INSTALL=false

for arg in "$@"; do
    case "$arg" in
        --check-only)
            CHECK_ONLY=true
            ;;
        --force)
            FORCE_INSTALL=true
            ;;
        -h|--help)
            echo "Usage: bash setup.sh [--check-only] [--force]"
            echo "  --check-only  Offline readiness check without installing or modifying files."
            echo "  --force       Re-run install.sh even if environment appears configured."
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $arg"
            echo "Usage: bash setup.sh [--check-only] [--force]"
            exit 2
            ;;
    esac
done

echo "============================================================"
echo " MalBox Machine 1 (Kali Linux Client) - Setup & Readiness"
echo "============================================================"
echo "OS / Arch : $(uname -s) $(uname -r) / $(uname -m)"

if [ "$CHECK_ONLY" = true ]; then
    echo "Mode      : CHECK-ONLY (offline, non-modifying)"
    if [ -x "$VENV_PYTHON" ]; then
        PY_EXEC="$VENV_PYTHON"
    elif command -v python3 >/dev/null 2>&1; then
        PY_EXEC="$(command -v python3)"
    else
        echo "[ERROR] Neither .venv nor system python3 was found."
        exit 1
    fi
    exec "$PY_EXEC" "${SCRIPT_DIR}/readiness.py" --mode check-only
fi

echo "Mode      : SETUP (idempotent)"

NEEDS_INSTALL=false
if [ "$FORCE_INSTALL" = true ]; then
    NEEDS_INSTALL=true
elif [ ! -x "$VENV_PYTHON" ]; then
    NEEDS_INSTALL=true
elif ! "$VENV_PYTHON" -c "import requests" >/dev/null 2>&1; then
    NEEDS_INSTALL=true
elif [ ! -x "${HOME}/.local/bin/doctor" ] && ! command -v doctor >/dev/null 2>&1; then
    NEEDS_INSTALL=true
fi

mkdir -p "${SCRIPT_DIR}/evidence"

if [ "$NEEDS_INSTALL" = true ]; then
    echo "[SETUP] Installing/repairing Machine 1 environment via install.sh..."
    bash "${SCRIPT_DIR}/install.sh"
else
    echo "[OK] Existing .venv, requests dependency, and doctor launcher detected (skipping reinstall)."
fi

exec "$VENV_PYTHON" "${SCRIPT_DIR}/readiness.py" --mode setup

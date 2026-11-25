#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "[INSTALL] Setting up MalBox Machine 2 Gateway in ${SCRIPT_DIR}..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required. Install python3 and python3-venv first."
    exit 1
fi

python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"

mkdir -p "${SCRIPT_DIR}/tmp"

echo ""
echo "[OK] Machine 2 Gateway setup completed."
echo "Start the gateway with:"
echo "  cd \"${SCRIPT_DIR}\""
echo "  source .venv/bin/activate"
echo "  python gateway.py"

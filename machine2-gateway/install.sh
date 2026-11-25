#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "[INSTALL] Setting up MalBox Machine 2 Gateway in ${SCRIPT_DIR}..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required. Install python3 and python3-venv first."
    exit 1
fi

if ! python3 -m venv "${VENV_DIR}"; then
    echo "[ERROR] Failed creating virtual environment. On Debian/Kali/REMnux, install: sudo apt install python3-venv"
    exit 1
fi
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
"${VENV_DIR}/bin/python" -c "import flask, requests"

mkdir -p "${SCRIPT_DIR}/tmp" "${SCRIPT_DIR}/retained_evidence"

echo ""
echo "[OK] Machine 2 Gateway setup completed."
echo "Start the gateway with:"
echo "  cd \"${SCRIPT_DIR}\""
echo "  source .venv/bin/activate"
echo "  python gateway.py"

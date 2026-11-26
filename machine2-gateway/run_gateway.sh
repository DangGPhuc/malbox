#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="${SCRIPT_DIR}/.venv/bin/python"
GATEWAY_PY="${SCRIPT_DIR}/gateway.py"
CONFIG_JSON="${SCRIPT_DIR}/config.json"

if [ ! -x "${VENV_PY}" ]; then
    echo "[ERROR] Virtual environment Python not found at ${VENV_PY}" >&2
    echo "[HINT] Run: cd \"${SCRIPT_DIR}\" && bash setup.sh" >&2
    exit 1
fi

if [ ! -f "${GATEWAY_PY}" ]; then
    echo "[ERROR] Missing gateway entrypoint: ${GATEWAY_PY}" >&2
    exit 1
fi

if [ ! -f "${CONFIG_JSON}" ]; then
    echo "[ERROR] Missing configuration file: ${CONFIG_JSON}" >&2
    exit 1
fi

if ! "${VENV_PY}" -c "import flask, requests" >/dev/null 2>&1; then
    echo "[ERROR] Required packages (Flask, requests) missing in ${SCRIPT_DIR}/.venv" >&2
    echo "[HINT] Run: cd \"${SCRIPT_DIR}\" && bash setup.sh" >&2
    exit 1
fi

exec "${VENV_PY}" "${GATEWAY_PY}" "$@"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

echo "[INSTALL] Setting up MalBox Machine 1 Client in ${SCRIPT_DIR}..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required. Install python3 and python3-venv first."
    exit 1
fi

if ! python3 -m venv "${VENV_DIR}"; then
    echo "[ERROR] Failed creating virtual environment. On Debian/Kali, install: sudo apt install python3-venv"
    exit 1
fi
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
"${VENV_DIR}/bin/python" -c "import requests"

chmod +x "${SCRIPT_DIR}/doctor.py"
mkdir -p "${SCRIPT_DIR}/evidence"

# Create a wrapper launcher so `doctor <file>` works from any directory.
USER_BIN="${HOME}/.local/bin"
mkdir -p "${USER_BIN}"
WRAPPER_PATH="${USER_BIN}/doctor"

cat > "${WRAPPER_PATH}" <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${SCRIPT_DIR}/doctor.py" "\$@"
EOF
chmod +x "${WRAPPER_PATH}"

if [ -w "/usr/local/bin" ]; then
    ln -sf "${WRAPPER_PATH}" /usr/local/bin/doctor
    echo "[OK] Installed global command: /usr/local/bin/doctor"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo ln -sf "${WRAPPER_PATH}" /usr/local/bin/doctor
    echo "[OK] Installed global command: /usr/local/bin/doctor"
else
    echo "[OK] Installed user command: ${WRAPPER_PATH}"
    echo "[NOTE] Ensure ${USER_BIN} is in your PATH, or run:"
    echo "       sudo ln -sf \"${WRAPPER_PATH}\" /usr/local/bin/doctor"
fi

echo ""
echo "[OK] Machine 1 Client setup completed."
echo "Usage:"
echo "  doctor /path/to/sample.exe"

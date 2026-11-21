from __future__ import annotations

import os
from pathlib import Path

# REMnux Gateway Configuration: no default fallback secrets allowed
GATEWAY_HOST: str = os.getenv("MALBOX_REMNUX_GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT: int = int(os.getenv("MALBOX_REMNUX_GATEWAY_PORT", "8008"))
GATEWAY_AUTH_TOKEN: str = os.getenv("MALBOX_REMNUX_GATEWAY_TOKEN", "").strip()

# Physical Kali Host Controller connection
HOST_CONTROLLER_URL: str = os.getenv("MALBOX_VBOX_CONTROLLER_URL", "http://192.168.56.1:8005").rstrip("/")
HOST_CONTROLLER_SECRET: str = os.getenv("MALBOX_VBOX_CONTROLLER_SECRET", "").strip()

# REMWin Windows Guest Agent connection
REMWIN_AGENT_URL: str = os.getenv("MALBOX_REMWIN_AGENT_URL", "http://10.77.0.10:8000").rstrip("/")
REMWIN_AGENT_TOKEN: str = os.getenv("MALBOX_AGENT_SECRET", os.getenv("MALBOX_REMWIN_AGENT_TOKEN", "")).strip()
MIN_SECRET_LENGTH: int = 16


def is_secret_valid(secret: str) -> bool:
    """Verifies that secret meets minimum 16-character length requirement."""
    return bool(secret and len(secret.strip()) >= MIN_SECRET_LENGTH)

# Target VM identifier & snapshot
TARGET_VM_IDENTIFIER: str = os.getenv("MALBOX_REMWIN_VM_UUID", "REMWin")
CLEAN_SNAPSHOT_NAME: str = os.getenv("MALBOX_REMWIN_CLEAN_SNAPSHOT", "clean_snapshot")

# Execution limits
EXECUTION_MAX_SECONDS: int = int(os.getenv("MALBOX_EXECUTION_MAX_SECONDS", "300"))
SANDBOX_INTERFACE: str = os.getenv("MALBOX_SANDBOX_INTERFACE", "eth1")

# Storage paths
STORAGE_ROOT: Path = Path(os.getenv("MALBOX_REMNUX_STORAGE", "./data/remnux_gateway"))
QUARANTINE_DIR: Path = STORAGE_ROOT / "quarantine"
EVIDENCE_DIR: Path = STORAGE_ROOT / "evidence"
JOBS_DB_PATH: Path = STORAGE_ROOT / "jobs_state.json"

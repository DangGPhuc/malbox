from __future__ import annotations

import os
from pathlib import Path

# REMnux Gateway Configuration
GATEWAY_HOST: str = os.getenv("MALBOX_REMNUX_GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT: int = int(os.getenv("MALBOX_REMNUX_GATEWAY_PORT", "8008"))
GATEWAY_AUTH_TOKEN: str = os.getenv("MALBOX_REMNUX_GATEWAY_TOKEN", "remnux-gateway-auth-token-xyz")

# Physical Kali Host Controller connection
HOST_CONTROLLER_URL: str = os.getenv("MALBOX_VBOX_CONTROLLER_URL", "http://192.168.56.1:8005").rstrip("/")
HOST_CONTROLLER_SECRET: str = os.getenv("MALBOX_VBOX_CONTROLLER_SECRET", "malbox-vbox-host-secret-token")

# REMWin Windows Guest Agent connection
REMWIN_AGENT_URL: str = os.getenv("MALBOX_REMWIN_AGENT_URL", "http://10.77.0.10:8000").rstrip("/")
REMWIN_AGENT_TOKEN: str = os.getenv("MALBOX_AGENT_SECRET", "remwin-guest-agent-token")

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

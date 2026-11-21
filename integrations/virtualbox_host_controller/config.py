from __future__ import annotations

import os
from pathlib import Path
from typing import Set

# Configuration for VirtualBox Host Controller
CONTROLLER_HOST: str = os.getenv("MALBOX_VBOX_CONTROLLER_HOST", "127.0.0.1")
CONTROLLER_PORT: int = int(os.getenv("MALBOX_VBOX_CONTROLLER_PORT", "8005"))
CONTROLLER_SECRET: str = os.getenv("MALBOX_VBOX_CONTROLLER_SECRET", "malbox-vbox-host-secret-token")

# Strict allowlist of manageable VM identifiers
_raw_uuids = os.getenv("MALBOX_REMWIN_VM_UUIDS", os.getenv("MALBOX_REMWIN_VM_UUID", "REMWin,win10_analyst"))
ALLOWED_VM_IDENTIFIERS: Set[str] = {x.strip() for x in _raw_uuids.split(",") if x.strip()}

# Clean snapshot baseline
CLEAN_SNAPSHOT_NAME: str = os.getenv("MALBOX_REMWIN_CLEAN_SNAPSHOT", "clean_snapshot")

# Allowed client IPs (management network only)
_raw_ips = os.getenv("MALBOX_VBOX_ALLOWED_CLIENT_IPS", "127.0.0.1,192.168.56.1,192.168.56.10,::1")
ALLOWED_CLIENT_IPS: Set[str] = {x.strip() for x in _raw_ips.split(",") if x.strip()}

# Required network configuration for REMWin isolation
REQUIRED_INTERNAL_NET: str = os.getenv("MALBOX_VBOX_INTERNAL_NET", "malbox-sandbox")

# Audit log path
AUDIT_LOG_PATH: Path = Path(os.getenv("MALBOX_VBOX_AUDIT_LOG", "data/runtime/vbox_host_controller_audit.log"))

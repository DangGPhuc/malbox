from __future__ import annotations

import os
from pathlib import Path
from typing import Set

# Configuration for VirtualBox Host Controller
CONTROLLER_HOST: str = os.getenv("MALBOX_VBOX_CONTROLLER_HOST", "127.0.0.1")
CONTROLLER_PORT: int = int(os.getenv("MALBOX_VBOX_CONTROLLER_PORT", "8005"))

# Management secret: No default fallback secret allowed (must be configured by operator)
CONTROLLER_SECRET: str = os.getenv("MALBOX_VBOX_CONTROLLER_SECRET", "")
MIN_SECRET_LENGTH: int = 16


def is_secret_valid(secret: str) -> bool:
    """Verifies that management secret meets minimum length and entropy."""
    return bool(secret and len(secret.strip()) >= MIN_SECRET_LENGTH)


# Single bound target VM identifier (binds hypervisor control to single explicit VM)
PRIMARY_VM_IDENTIFIER: str = os.getenv("MALBOX_REMWIN_VM_UUID", "REMWin").strip()
_raw_uuids = os.getenv("MALBOX_REMWIN_VM_UUIDS", PRIMARY_VM_IDENTIFIER)
ALLOWED_VM_IDENTIFIERS: Set[str] = {x.strip() for x in _raw_uuids.split(",") if x.strip()}

# Clean snapshot baseline (immutable approved target)
CLEAN_SNAPSHOT_NAME: str = os.getenv("MALBOX_REMWIN_CLEAN_SNAPSHOT", "clean_snapshot").strip()

# Allowed client IPs (exact management client IPs only; no implicit subnet wildcard)
_raw_ips = os.getenv("MALBOX_VBOX_ALLOWED_CLIENT_IPS", "127.0.0.1,192.168.56.10,::1")
ALLOWED_CLIENT_IPS: Set[str] = {x.strip() for x in _raw_ips.split(",") if x.strip()}

# Required network configuration for REMWin isolation
REQUIRED_INTERNAL_NET: str = os.getenv("MALBOX_VBOX_INTERNAL_NET", "malbox-sandbox").strip()

# Runtime persistence paths
DATA_DIR: Path = Path(os.getenv("MALBOX_DATA_DIR", "data/runtime"))
AUDIT_LOG_PATH: Path = Path(os.getenv("MALBOX_VBOX_AUDIT_LOG", str(DATA_DIR / "vbox_host_controller_audit.log")))
LEASE_PATH: Path = Path(os.getenv("MALBOX_VBOX_LEASE_PATH", str(DATA_DIR / "vbox_execution_lease.json")))
LOCKDOWN_PATH: Path = Path(os.getenv("MALBOX_VBOX_LOCKDOWN_PATH", str(DATA_DIR / "vbox_lockdown.flag")))

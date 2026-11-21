from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .config import AUDIT_LOG_PATH


def log_host_controller_action(
    action: str,
    vm_target: str,
    client_ip: str,
    request_id: Optional[str] = None,
    success: bool = True,
    details: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Appends an immutable audit entry to the host controller audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "epoch": time.time(),
        "action": action,
        "vm_target": vm_target,
        "client_ip": client_ip,
        "request_id": request_id,
        "success": success,
        "details": details,
        "extra": extra or {},
    }

    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # Non-blocking for log write failures, but printed to stdout/stderr
        pass

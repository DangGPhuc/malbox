# CAPE Sandbox Integration Guide — malbox-ai

This document details the configuration and operational requirements for connecting `malbox-ai` to a live CAPE Sandbox (v2) cluster.

---

## 1. Architecture Overview

`malbox-ai` communicates with CAPE Sandbox via its official REST API v2 (`apiv2/` endpoints).

```text
[ malbox-ai Backend ]
        │  (HTTP REST / Token Auth)
        ▼
[ CAPE Web Service /apiv2/ ]
        │  (Task Spooler & Monitor)
        ▼
[ KVM / QEMU Isolated Guest VM ] (Windows 10/11)
```

The adapter is implemented in `backend/app/services/sandbox/cape.py` (`CapeSandboxBackend`).

---

## 2. Prerequisites for Live Mode Activation

To transition from Replay Mode to Live Detonation Mode:

1. **Active CAPE Sandbox Installation:**
   - CAPE Sandbox 2.x installed on a dedicated Linux hypervisor host.
   - Dedicated isolated guest VM (e.g. Windows 10 x64) configured with CAPE agent (`agent.py`) and a clean baseline snapshot (e.g. `clean_snapshot`).
2. **Network Isolation:**
   - Host-only virtual bridge interface (`virbr0` or `cape-br0`).
   - Network routing configured through `INetSim` (simulated DNS/HTTP/SMTP) or an isolated Tor/VPN proxy. External LAN egress must be blocked with `iptables`.
3. **API Service:**
   - CAPE REST API running:
     ```bash
     cd /opt/CAPEv2
     poetry run python cuckoo.py api
     ```

---

## 3. Configuration in malbox-ai

In your `.env` or system environment variables:

```bash
# Enable live execution capabilities
MALBOX_LIVE_MODE_ENABLED=true
MALBOX_REQUIRE_EXPLICIT_APPROVAL=true

# Sandbox backend defaults
MALBOX_DEFAULT_SANDBOX_BACKEND=cape
MALBOX_CAPE_API_URL=http://192.168.122.1:8000
MALBOX_CAPE_API_TOKEN=your-cape-api-token-here
MALBOX_CAPE_TIMEOUT_SECONDS=180
MALBOX_CAPE_POLL_INTERVAL_SECONDS=5
```

---

## 4. Verification and Readiness Testing

You can verify your CAPE connection using the built-in health check:

```bash
python3 -c "
from app.services.sandbox.cape import CapeSandboxBackend
cape = CapeSandboxBackend()
print(cape.check_readiness())
"
```

If the CAPE cluster is offline, `check_readiness()` gracefully reports `ready: false` with missing prerequisites and error details without crashing the platform.

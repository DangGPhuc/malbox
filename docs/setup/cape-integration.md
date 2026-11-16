# CAPE Sandbox v2 Production Integration Guide

**Document Reference:** `docs/setup/cape-integration.md`  
**Applies to:** Malbox-AI v0.2+ & CAPE Sandbox v2.4+  
**Target Environment:** Isolated Kali Linux Host with VirtualBox Machinery

---

## 1. Architectural Overview

Malbox interacts with CAPE Sandbox through its REST API v2 (`/apiv2/`). The interaction lifecycle consists of:
1. **Health Verification:** Probing `/apiv2/cuckoo/status/` via Doctor CLI or live readiness check.
2. **Sample Submission:** Submitting quarantined PE binaries with strict option validation to `/apiv2/tasks/create/file/`.
3. **Lifecycle Polling:** Tracking task status from `pending` -> `running` -> `completed` (VM shutdown) -> `reported` (report compiled).
4. **Telemetry Ingestion:** Fetching `/apiv2/tasks/get/report/<task_id>/` with bounded retry and backoff, extracting processes, API calls, dropped files, registry modifications, and network connections.
5. **Quality Contract Evaluation:** Assessing whether telemetry is `COMPLETE`, `PARTIAL`, `INCOMPLETE`, or `UNVERIFIED`.

---

## 2. Server Configuration Templates

### 2.1 `cuckoo.conf` Critical Parameters

Ensure `conf/cuckoo.conf` within your CAPE installation root contains the following settings:

```ini
[cuckoo]
version_check = no
delete_original = off
delete_bin_copy = off

# Storage and disk management (Fix for ISSUE-09 / freespace issues)
# Lower freespace limit if running in a constrained virtualized lab
freespace = 10240

[resultserver]
# Resultserver IP binding:
# CRITICAL: Set to 0.0.0.0 or the exact host-only gateway IP (e.g. 192.168.56.1).
# Do not hardcode an unroutable external IP.
ip = 0.0.0.0
port = 2042
force_port = no
upload_max_size = 104857600

[processing]
# Ensure analysis summary and report generation are active
analysis_size_limit = 104857600
resolve_dns = yes
sort_pcap = yes
```

### 2.2 `virtualbox.conf` Template

```ini
[virtualbox]
# VirtualBox management mode
mode = headless
path = /usr/bin/vboxmanage

# Host-only network interface
interface = vboxnet0

# Registered Virtual Machines
machines = win10_analyst

[win10_analyst]
label = win10_analyst
platform = windows
ip = 192.168.56.101
snapshot = Snapshot_Clean
# Tags are optional. If set, Malbox will target them when requested.
tags = win10_x64,clean
```

---

## 3. Standardized Windows Guest Requirements

To prevent guest analyzer crashes and ensure telemetry fidelity:

1. **Python Runtime (Fix for ISSUE-10):**
   - **Requirement:** Python 3.10+ (64-bit or 32-bit matching guest architecture).
   - **Critical:** Older Python versions (<= 3.5) lack support for modern f-strings and typing syntax used in CAPE `analyzer.py`, leading to immediate guest analyzer crashes.
   - Install Python to `C:\Python310` and ensure it is registered in system `PATH`.

2. **Guest Agent Installation:**
   - Copy `agent/agent.py` from CAPE repository into `C:\agent\agent.py`.
   - Configure auto-start via Windows Registry Run key or Task Scheduler on logon.

3. **Security Countermeasures in Guest:**
   - Permanently disable Windows Defender Real-time Protection, Tamper Protection, and Cloud-delivered protection.
   - Disable Windows Firewall for Domain, Private, and Public profiles (`netsh advfirewall set allprofiles state off`).
   - Disable Windows Update and User Account Control (UAC: Never Notify).

4. **Static IP Configuration:**
   - IP: `192.168.56.101`
   - Subnet Mask: `255.255.255.0`
   - Default Gateway: `192.168.56.1`
   - Primary DNS: `192.168.56.1` (or INetSim IP if used)

---

## 4. Malbox Environment Configuration

In your Malbox `.env` file, configure the following:

```bash
# Enable Live Execution Gate (requires explicit operator token)
MALBOX_LIVE_MODE_ENABLED=true
MALBOX_DEFAULT_SANDBOX_BACKEND=cape
# Generate high-entropy operator token:
# openssl rand -hex 32
MALBOX_OPERATOR_TOKEN=your-random-high-entropy-token-min-32-chars

# CAPE API Endpoints (default port 8008 avoids collision with backend 8000)
MALBOX_CAPE_API_URL=http://127.0.0.1:8008
MALBOX_CAPE_API_TOKEN=your-cape-bearer-token-if-configured
MALBOX_CAPE_TIMEOUT_SECONDS=300
```

Verify readiness using the Doctor CLI:
```bash
./malbox doctor --check
```
If CAPE is online and responsive, the doctor output will confirm:
`[PASS] Optional: CAPE Sandbox: CAPE Sandbox READY at http://127.0.0.1:8008 (version: 2.4-CAPE).`

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

# Storage and disk management:
# Maintain at least 20GB of verified free capacity on the analysis storage volume.
# Check actual host storage: df -h /opt/CAPE
# Never arbitrarily lower freespace below 20480 without capacity validation.
freespace = 20480

[resultserver]
# Resultserver IP binding:
# CRITICAL: Bind ONLY to the host-only interface IP (e.g. 192.168.56.1).
# NEVER bind to 0.0.0.0 as this exposes the resultserver API and analysis uploads
# to all external host interfaces and local network segments.
ip = 192.168.56.1
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
   - Configure a least-privilege Windows Firewall rule on the Private profile allowing inbound traffic to the guest agent port (port 8000) strictly from the host-only interface (`192.168.56.1`), rather than disabling the firewall globally:
     `netsh advfirewall firewall add rule name="CAPE Agent" dir=in action=allow protocol=TCP localport=8000 remoteip=192.168.56.1 profile=private`
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

---

## 5. Mandatory Operator Confinement Attestation (`cape_isolation_attestation.json`)

### 5.1 Why Attestation is Mandatory
Configuring `route = drop` or `route = none` in `cuckoo.conf` or `.env` is **not sufficient proof of network isolation**. Misconfigurations, host routing table changes, or hypervisor bridge bypasses could permit guest VM outbound traffic to the local network or internet.

To enforce fail-closed isolation safety, Malbox implements an **Independent Operator Attestation Contract** (`verify_cape_confinement`):
- Dynamic detonation is **strictly blocked** unless an operator has independently verified network confinement and written an attestation.
- The attestation must specify the exact verified guest machine name (e.g. `win10_analyst`) and an exact permitted safe isolated route (`drop`, `none`, or `isolated`).
- **Wildcard (`*`) or missing machine and route values are strictly rejected.**
- The operator must explicitly certify all four mandatory manual assertions:
  1. `host_only_networking_verified`: Host-only virtual adapter (`vboxnet0`) configured with no physical bridging.
  2. `routing_isolation_verified`: Host kernel routing table has no NAT/forwarding enabled for the guest subnet (`sysctl net.ipv4.ip_forward` is `0` or iptables FORWARD drops guest packets).
  3. `firewall_rules_verified`: Host firewall rules enforce DROP for all guest subnet outbound traffic to external networks.
  4. `guest_snapshot_clean_verified`: Guest VM revert snapshot was captured in an uninfected, pristine state.
- The attestation file must have secure file permissions (e.g. `chmod 600` or `chmod 644`); world-writable or group-writable files are rejected as untrusted (`untrusted_attestation_file`).
- If the attestation is missing, expired, permissions are unsafe, or targets mismatch the requested submission machine/route, detonation immediately halts with status `FAILED` and fails closed.

### 5.2 Generating or Renewing Operator Attestation

Attestations are stored by default at:
`data/cape_isolation_attestation.json` (or path configured in `MALBOX_CAPE_ISOLATION_ATTESTATION_PATH`).

To generate or renew the attestation file using Python:

```bash
# Activate malbox environment and run attestation generator
python3 -c "
from app.services.sandbox.confinement import create_isolation_attestation
p = create_isolation_attestation(
    verified_machine='win10_analyst', # Exact target machine (wildcards rejected)
    verified_route='drop',            # Must be 'drop', 'none', or 'isolated'
    verifier='analyst@secops',
    validity_seconds=86400,           # 24-hour expiration
    operator_assertions={
        'host_only_networking_verified': True,
        'routing_isolation_verified': True,
        'firewall_rules_verified': True,
        'guest_snapshot_clean_verified': True,
    }
)
print(f'Confinement attestation active at {p}')
"
```

### 5.3 Three Operational Readiness States

1. **Mocked Unit/E2E Testing:** Uses synthetic responses and isolated test attestations targeting `win10_analyst` with `route=drop` in pytest fixtures (`create_isolation_attestation(verified_machine='win10_analyst', verified_route='drop')`).
2. **Benign Acceptance Verification:** Real benign PE binaries (e.g., standard Windows sysinternals or compilers) detonated on an attested isolated guest machine to verify the live integration lifecycle.
3. **Host Safety Failsafe:** Real malware execution remains strictly blocked pending explicit operator verification, operator token authentication, and signed attestation.


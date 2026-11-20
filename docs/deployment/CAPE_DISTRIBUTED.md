# Profile B: Distributed Sandbox Deployment Guide (Controller + Dedicated CAPE)

## 1. Architecture Overview

In **Profile B (Distributed Sandbox)**, Malbox is decoupled from the hypervisor host:
1. **Malbox Controller Node (Kali Linux or Debian)**:
   - Hosts the FastAPI backend, Vite UI, static triage engine (PE metadata, Ghidra), evidence correlation engine, and AI reporting.
   - Requires no virtualization extensions (`/dev/kvm` not required on this node).
2. **Dedicated CAPE Sandbox Node (Physical Bare-Metal Hypervisor)**:
   - Runs on a dedicated server (e.g. Ubuntu Server or Debian) equipped with KVM/VirtualBox.
   - Hosts Windows analysis VMs and manages network confinement, disk snapshots, and execution tracing.
   - Exposes the CAPE REST API (:8008) exclusively over an isolated management network.

```
+────────────────────────────────────────+       MANAGEMENT VLAN       +────────────────────────────────────────+
| MALBOX CONTROLLER NODE (Kali Linux)   |        (TLS / Token Auth)   | DEDICATED CAPE SERVER (Bare-Metal)     |
|                                        |                             |                                        |
|  [ Operator Browser ]                  |                             |  [ CAPE Web API ] (:8008)              |
|        │                               |                             |        │                               |
|        ▼                               |   HTTPS / Bearer Token      |        ▼                               |
|  [ Malbox Web UI ] (:5173)             | ──────────────────────────► |  [ CAPE Daemon ] (cuckoo.py)           |
|        │                               |       (Port 8008)           |        │                               |
|        ▼                               |                             |        ▼                               |
|  [ Malbox API Backend ] (:8000)        |                             |  [ KVM / VirtualBox Hypervisor ]       |
|    - Ghidra Headless (Static)          |                             |        │                               |
|    - Evidence Correlation Engine       |                             |        ▼ (Isolated host-only network)  |
|    - AI Intelligence Engine            |                             |  [ Windows 10 Guest VM ]               |
|                                        |                             |    (192.168.56.101, NO WAN ACCESS)     |
+────────────────────────────────────────+                             +────────────────────────────────────────+
```

---

## 2. Dedicated CAPE Node Configuration

On the dedicated CAPE server:

1. **Bind CAPE Web API to Dedicated Management IP**:
   In `/opt/cape/conf/cuckoo.conf` and `web/cuckoo_web/settings.py`:
   ```python
   # Bind to private management interface IP (e.g., 10.10.20.50)
   ALLOWED_HOSTS = ["127.0.0.1", "10.10.20.50", "malbox-controller.internal"]
   ```

   Launch server on management interface:
   ```bash
   poetry run python manage.py runserver 10.10.20.50:8008
   ```

2. **Generate API Bearer Token**:
   Generate an API token for the Malbox controller:
   ```bash
   poetry run python manage.py drf_create_token -u operator
   # Output: Generated token 4f9b2c8a1e3d5f7...
   ```

3. **Firewall Policy on CAPE Server**:
   Only permit port 8008 connections from the Malbox Controller's static IP:
   ```bash
   sudo iptables -A INPUT -p tcp -s 10.10.20.10 --dport 8008 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 8008 -j DROP
   ```

---

## 3. Malbox Controller Configuration

On the Kali Linux Malbox controller:

1. **Update `.env` configuration**:
   ```bash
   ./malbox setup --cape \
       --url http://10.10.20.50:8008 \
       --token 4f9b2c8a1e3d5f7b8c9d0e1f2a3b4c5d \
       --machine win10_remote_01 \
       --route host-only
   ```

2. **Verify Network Reachability & Token**:
   ```bash
   curl -H "Authorization: Token 4f9b2c8a1e3d5f7b8c9d0e1f2a3b4c5d" \
        http://10.10.20.50:8008/apiv2/cuckoo/status/
   ```
   *Expected response: HTTP 200 with JSON payload reporting available machines and tasks.*

3. **Operator Confinement Attestation**:
   Because guest VM isolation occurs on the remote hypervisor, the operator must verify the remote node's network topology and generate the attestation file on the controller:
   ```bash
   # Attestation created at data/cape_isolation_attestation.json
   ./malbox setup --cape --machine win10_remote_01 --route host-only
   ```

4. **Verify Controller Doctor Status**:
   ```bash
   ./malbox doctor --check
   ```
   *Verify: `[PASS] [READY] Optional: CAPE Sandbox: CAPE Sandbox READY at http://10.10.20.50:8008` and `[PASS] [VERIFIED] CAPE Confinement Attestation`.*

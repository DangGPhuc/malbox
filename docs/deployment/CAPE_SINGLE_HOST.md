# Profile A: Single-Host CAPE Sandbox Deployment Guide

## 1. Architecture Overview

In **Profile A (Single-Host Sandbox)**, all software layers run concurrently on the physical Kali Linux bare-metal machine:
1. **Malbox Platform**: FastAPI backend (:8000), Vite frontend (:5173), SQLite DB (`data/malbox.db`), and Ghidra Headless static analyzer.
2. **CAPE Sandbox Backend**: CAPE daemon (`cuckoo.py`), rooter service, and Django REST API (:8008).
3. **Hypervisor Subsystem**: KVM/QEMU or VirtualBox 7.x hosting an isolated Windows 10 64-bit guest VM.
4. **Isolated Virtual Network**: Host-only virtual bridge (`vboxnet0` or `virbr1`) strictly blocked from reaching the external LAN or WAN.

```
+-----------------------------------------------------------------------------------+
| PHYSICAL KALI LINUX HOST (Bare-Metal, VT-x/AMD-V)                                 |
|                                                                                   |
|  [ Web Browser / Operator ]                                                       |
|        │                                                                          |
|        ▼                                                                          |
|  [ Malbox Web UI ] (:5173) ──► [ Malbox API & Engine ] (:8000)                    |
|                                       │                                           |
|                                       ▼                                           |
|                            [ CAPE REST API ] (:8008)                              |
|                                       │                                           |
|                                       ▼                                           |
|                            [ CAPE Core Daemon ]                                   |
|                                       │                                           |
|          HOST-ONLY BRIDGE             ▼ (qemu / vboxmanage)                       |
|   ┌─────────────────────────── [ Hypervisor Engine ]                              |
|   │                                   │                                           |
|   │                                   ▼                                           |
|   │ 192.168.56.1/24       ┌───────────────────────┐                               |
|   └──────────────────────►│ Windows 10 Guest VM   │                               |
|       (NO INTERNET GATEWAY)│ (Analysis Sandbox)    │                               |
|       (ALL WAN DROPPED)   └───────────────────────┘                               |
+-----------------------------------------------------------------------------------+
```

---

## 2. CAPE Installation on Kali Linux

1. **Clone CAPE v2 Repository**:
   ```bash
   sudo mkdir -p /opt/cape
   sudo chown -R $USER:$USER /opt/cape
   git clone https://github.com/kevoreilly/CAPEv2.git /opt/cape
   cd /opt/cape
   ```

2. **Install Poetry and Dependencies**:
   ```bash
   pip install poetry
   poetry install
   ```

3. **Configure Database & Web Service**:
   ```bash
   cd /opt/cape/web
   poetry run python manage.py migrate
   poetry run python manage.py createsuperuser
   ```

4. **Start CAPE Web API**:
   ```bash
   poetry run python manage.py runserver 127.0.0.1:8008
   ```

---

## 3. Host-Only Network Configuration

In Profile A, the guest VM must be attached **strictly to a host-only network adapter**. Under VirtualBox:

```bash
# Create dedicated host-only adapter
VBoxManage hostonlyif create
# Configure host IP address (gateway for VM)
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Disable VirtualBox internal DHCP server to enforce static, deterministic addressing
VBoxManage dhcpserver remove --ifname vboxnet0 2>/dev/null || true
```

### Mandatory nftables / iptables Firewall Policy

Apply strict packet filtering rules on the Kali host to guarantee no traffic from `vboxnet0` escapes to the physical network interface (`eth0` / `wlan0`):

```bash
# Set default forward policy to DROP
sudo iptables -P FORWARD DROP

# Drop all traffic from the sandbox interface destined for the Internet or internal LAN
sudo iptables -A FORWARD -i vboxnet0 -o eth0 -j DROP
sudo iptables -A FORWARD -i vboxnet0 -o wlan0 -j DROP

# Allow bidirectional communication only between the host and guest on the isolated subnet
sudo iptables -A INPUT -i vboxnet0 -s 192.168.56.0/24 -d 192.168.56.1 -j ACCEPT
sudo iptables -A OUTPUT -o vboxnet0 -s 192.168.56.1 -d 192.168.56.0/24 -j ACCEPT

# Save firewall rules
sudo netfilter-persistent save || sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## 4. Virtual Machine Setup & Snapshot

1. **Create Virtual Machine**:
   - VM Name: `win10_malbox`
   - OS: Windows 10 64-bit Enterprise
   - RAM: 4096 MB – 8192 MB
   - Network Adapter 1: Attached to `vboxnet0` (Host-Only Adapter)
   - Network Adapter 2..4: Disabled

2. **Configure Static IP in Guest**:
   - IP: `192.168.56.101`
   - Netmask: `255.255.255.0`
   - Default Gateway: `NONE` (leave empty)
   - DNS Server: `192.168.56.1` (or local in-guest INetSim)

3. **Install CAPE Guest Agent**:
   - Copy `/opt/cape/agent/agent.py` to `C:\agent\agent.py` in the guest.
   - Configure agent auto-start on Windows boot via Scheduled Task or Registry Run key.
   - Test agent communication: from Kali host, verify `curl http://192.168.56.101:8000` responds.

4. **Take Clean Snapshot**:
   Power on the VM, wait for the agent to launch, and take a clean snapshot:
   ```bash
   VBoxManage snapshot win10_malbox take clean_snap --pause
   ```

---

## 5. CAPE Configuration Files

1. **`/opt/cape/conf/cuckoo.conf`**:
   ```ini
   [cuckoo]
   version_check = off
   delete_original = off
   delete_bin_copy = off
   machinery = virtualbox
   memory_dump = off

   [resultserver]
   ip = 192.168.56.1
   port = 2042
   force_port = on
   ```

2. **`/opt/cape/conf/virtualbox.conf`**:
   ```ini
   [virtualbox]
   mode = headless
   path = /usr/bin/VBoxManage
   machines = win10_malbox

   [win10_malbox]
   label = win10_malbox
   platform = windows
   ip = 192.168.56.101
   snapshot = clean_snap
   interface = vboxnet0
   ```

3. **`/opt/cape/conf/routing.conf`**:
   ```ini
   [routing]
   route = none
   internet = none
   auto_rt = no
   ```

---

## 6. Malbox Integration & Confinement Attestation

1. **Configure Malbox Settings**:
   Run the Malbox setup assistant:
   ```bash
   ./malbox setup --cape \
       --url http://127.0.0.1:8008 \
       --machine win10_malbox \
       --route host-only
   ```

2. **Verify Confinement Attestation**:
   The setup command creates `data/cape_isolation_attestation.json` with permissions `0600`.
   Verify platform readiness:
   ```bash
   ./malbox doctor --check
   ```
   *Expected output: `[PASS] [VERIFIED] CAPE Confinement Attestation: CAPE isolation verified for machine 'win10_malbox' on route 'host-only'`.*

# Manual Network Setup Guide

MalBox uses **two completely separate Internal Networks** so that Machine 1 (Client) and Machine 3 (Windows 11 Sandbox) can never reach each other directly, and Machine 3 has **zero Internet access** during analysis.

> **Important:** Perform `git clone` and dependency installation (`install.sh` / `install.ps1`) **while VMs still have temporary Internet/NAT access**, then switch NICs to Internal Networks and remove NAT/Bridged adapters before creating snapshots or submitting samples.

---

## 1. VirtualBox / VMware Adapter Layout

| VM | NIC 1 | NIC 2 |
| --- | --- | --- |
| **Machine 1 (Kali Client)** | Internal Network `malbox-net1` (`10.10.10.10/24`) | *(Removed)* |
| **Machine 2 (REMnux/Kali Gateway)** | Internal Network `malbox-net1` (`10.10.10.20/24`) | Internal Network `malbox-net2` (`10.10.20.20/24`) |
| **Machine 3 (Windows 11 Sandbox)** | Internal Network `malbox-net2` (`10.10.20.30/24`) | *(Removed)* |

- Do **not** set a default gateway or DNS server pointing to the Internet on Machine 3.
- Do **not** enable IP forwarding (`net.ipv4.ip_forward=0`) or NAT on Machine 2.

---

## 2. Assigning Static IPs

### Machine 1 (Kali Linux)
Identify your interface (`ip a`, e.g., `eth0`):
```bash
sudo nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses 10.10.10.10/24 ipv4.gateway "" ipv4.dns ""
sudo nmcli con up "Wired connection 1"
```
*(Or via `ip addr add 10.10.10.10/24 dev eth0 && sudo ip link set eth0 up`)*

### Machine 2 (REMnux / Kali Gateway)
Verify you have two NICs (`eth0` on `malbox-net1`, `eth1` on `malbox-net2`):
```bash
sudo ip addr flush dev eth0
sudo ip addr add 10.10.10.20/24 dev eth0
sudo ip link set eth0 up

sudo ip addr flush dev eth1
sudo ip addr add 10.10.20.20/24 dev eth1
sudo ip link set eth1 up

# Confirm IP forwarding is disabled:
sysctl net.ipv4.ip_forward
# Must return: net.ipv4.ip_forward = 0
```

### Machine 3 (Windows 11 Sandbox)
In **Administrator PowerShell** (replace `"Ethernet"` with your adapter name from `Get-NetAdapter`):
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.20.30 -PrefixLength 24
# Allow incoming HTTP port 8001 ONLY from Machine 2 on Internal Network 2:
New-NetFirewallRule -DisplayName "MalBox Sandbox HTTP" -Direction Inbound -LocalPort 8001 -Protocol TCP -RemoteAddress 10.10.20.20 -Action Allow
```

Also allow ICMP Echo (ping) temporarily if Windows Firewall blocks ping from Machine 2:
```powershell
New-NetFirewallRule -DisplayName "Allow ICMPv4 from Gateway" -Direction Inbound -Protocol ICMPv4 -RemoteAddress 10.10.20.20 -Action Allow
```

---

## 3. Manual Connectivity Verification (Ping & HTTP)

1. **Test Internal Network 1 (Machine 1 -> Machine 2):**
   ```bash
   # On Machine 1:
   ping -c 4 10.10.10.20
   ```
2. **Test Internal Network 2 (Machine 2 -> Machine 3):**
   ```bash
   # On Machine 2:
   ping -c 4 10.10.20.30
   ```
3. **Verify Isolation (Machine 1 MUST NOT reach Machine 3 directly, and Machine 3 MUST NOT reach Internet):**
   ```bash
   # On Machine 1 (expected to fail / Network unreachable):
   ping -c 2 10.10.20.30
   ```
   ```powershell
   # On Machine 3 (expected to fail):
   ping -n 2 8.8.8.8
   ```
4. **Verify HTTP Services:**
   - Start `python sandbox.py` on Machine 3 (`10.10.20.30:8001`).
   - Start `python gateway.py` on Machine 2 (`10.10.10.20:8000` / `10.10.20.20`).
   - From Machine 2: `curl http://10.10.20.30:8001/status` -> should return `{"state": "READY", ...}`.
   - From Machine 1: `curl http://10.10.10.20:8000/status` -> should show `"gateway": "ok"` and Sandbox `"state": "READY"`.

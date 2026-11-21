# Malbox — REMnux Gateway & REMWin VirtualBox Lab Installation Guide

## 1. Architectural Overview & Security Boundary

The `REMNUX_VIRTUALBOX_LAB` environment implements a deterministic, evidence-grounded malware analysis sandbox on a physical Kali Linux workstation. 

Oracle VirtualBox runs on physical Kali and hosts two peer virtual machines:
1. **REMnux VM (Gateway & Evidence Collector)**: Deterministic execution coordinator, traffic capture (`dumpcap`/`tcpdump`), simulated Internet sinkhole (INetSim / FakeNet-NG), and forensic packaging service.
2. **REMWin VM (Windows Execution Sandbox)**: Strictly isolated, zero-egress Windows 10/11 guest with an in-memory execution agent and automated clean-snapshot restoration.

```
+-----------------------------------------------------------------------------------------+
| PHYSICAL KALI LINUX HOST                                                                |
| IP: 192.168.56.1/24 (vboxnet0)                                                          |
| Services: Malbox Web & Backend, Static Analysis (Ghidra), Kali-Only AI Intelligence     |
| Daemon: VirtualBox Host Controller (:8005)                                              |
+-----------------------------------------------------------------------------------------+
                               |
                               | VirtualBox Host-Only Network: vboxnet0
                               | Subnet: 192.168.56.0/24 (DHCP Disabled)
                               |
+------------------------------v----------------------------------------------------------+
| VIRTUALBOX VM 1: REMNUX GATEWAY                                                         |
|                                                                                         |
| Adapter 1 (Management): Host-Only (vboxnet0) -> 192.168.56.10/24                         |
| Adapter 2 (Sandbox):    Internal Network (malbox-sandbox) -> 10.77.0.1/24                |
| Services: Gateway REST API (:8008), INetSim / DNS sinkhole, dumpcap                     |
|                                                                                         |
| Invariant: NO NAT, NO Bridged, FORWARD DROP, NO Public Internet Egress.                 |
+-----------------------------------------------------------------------------------------+
                               |
                               | VirtualBox Internal Network: malbox-sandbox
                               | Subnet: 10.77.0.0/24 (Strictly Isolated Layer 2)
                               |
+------------------------------v----------------------------------------------------------+
| VIRTUALBOX VM 2: REMWIN WINDOWS GUEST                                                   |
|                                                                                         |
| Adapter 1 (Sandbox):    Internal Network (malbox-sandbox) -> 10.77.0.10/24               |
| Gateway & DNS:          10.77.0.1 (REMnux Sinkhole)                                     |
| Daemon:                 REMWin Execution & Telemetry Agent (:8000)                      |
|                                                                                         |
| Invariant: SINGLE NIC ONLY. NO NAT, NO Bridged, NO Host-Only, NO Public Internet.       |
|            Shared Clipboard: DISABLED. Drag-and-Drop: DISABLED. Shared Folders: NONE.   |
+-----------------------------------------------------------------------------------------+
```

### Critical Non-Negotiable Rules
- **No AI Outside Kali**: REMnux and REMWin run strictly deterministic software. Zero LLM inference or AI models run inside either VM.
- **Fail-Closed Isolation**: REMWin has zero routes to the host network or public Internet.
- **Automated Rollback**: The host controller powers off and reverts REMWin to its clean snapshot after every task.

---

## 2. Step 1: Physical Kali Workstation Setup

### 2.1 Verify VirtualBox Installation
Ensure VirtualBox and the extension pack are installed:
```bash
VBoxManage --version
# Expected: 7.0+ or 7.2+
```

### 2.2 Configure the Host-Only Network (`vboxnet0`)
Create and configure the dedicated management network:
```bash
# Create the interface if it does not exist
VBoxManage hostonlyif create

# Assign static IP and netmask to Kali host
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Disable VirtualBox DHCP server on vboxnet0
VBoxManage dhcpserver remove --netname HostInterfaceNetworking-vboxnet0 2>/dev/null || true

# Verify interface is UP
ip addr show vboxnet0
```

### 2.3 Verify Host Kernel Routing
Ensure Kali does not forward traffic between interfaces:
```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

### 2.4 Deploy VirtualBox Host Controller Daemon
The Host Controller runs on Kali to provide safe, authenticated hypervisor control to the analysis pipeline without exposing raw command execution:

1. Test-run the controller manually:
   ```bash
   python3 -m integrations.virtualbox_host_controller.server
   ```
2. Or install as a systemd service:
   ```bash
   sudo tee /etc/systemd/system/malbox-vbox-controller.service << 'EOF'
   [Unit]
   Description=Malbox VirtualBox Host Controller Daemon
   After=network.target

   [Service]
   Type=simple
   User=kali
   WorkingDirectory=/home/kali/Documents/malbox
   Environment=MALBOX_VBOX_CONTROLLER_HOST=127.0.0.1
   Environment=MALBOX_VBOX_CONTROLLER_PORT=8005
   Environment=MALBOX_VBOX_CONTROLLER_SECRET=your-secure-secret-token-here
   ExecStart=/home/kali/Documents/malbox/.venv/bin/python3 -m integrations.virtualbox_host_controller.server
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   EOF

   sudo systemctl daemon-reload
   sudo systemctl enable --now malbox-vbox-controller.service
   ```

---

## 3. Step 2: REMnux Gateway Virtual Machine Setup

### 3.1 VirtualBox VM Network Configuration
Configure REMnux with two network interfaces:
```bash
# Adapter 1: Host-Only management
VBoxManage modifyvm "REMnux" --nic1 hostonly --hostonlyadapter1 "vboxnet0"

# Adapter 2: Isolated Internal sandbox
VBoxManage modifyvm "REMnux" --nic2 intnet --intnet2 "malbox-sandbox"

# Disable secondary adapters
VBoxManage modifyvm "REMnux" --nic3 none --nic4 none
```

### 3.2 REMnux Network Interfaces Configuration
Inside REMnux, edit `/etc/netplan/01-netcfg.yaml` (or `/etc/network/interfaces`):
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3: # Adapter 1 (Management)
      addresses:
        - 192.168.56.10/24
      routes: [] # No default gateway
    enp0s8: # Adapter 2 (Sandbox)
      addresses:
        - 10.77.0.1/24
```
Apply configuration:
```bash
sudo netplan apply
```

### 3.3 REMnux Isolation & Firewall Policy
Run the following inside REMnux to enforce non-routing and containment:
```bash
# 1. Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0

# 2. Flush existing rules
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F

# 3. Default DROP policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP

# 4. Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# 5. Allow management from Kali host only (192.168.56.1)
sudo iptables -A INPUT -i enp0s3 -s 192.168.56.1 -p tcp --dport 8008 -j ACCEPT
sudo iptables -A OUTPUT -o enp0s3 -d 192.168.56.1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# 6. Allow sandbox traffic from REMWin (10.77.0.10) to local sinkhole services
sudo iptables -A INPUT -i enp0s8 -s 10.77.0.10 -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i enp0s8 -s 10.77.0.10 -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i enp0s8 -s 10.77.0.10 -p tcp -m multiport --dports 80,443,8080 -j ACCEPT
sudo iptables -A OUTPUT -o enp0s8 -d 10.77.0.10 -j ACCEPT

# 7. Make persistent
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

### 3.4 Deploy REMnux Gateway Service
Copy the `integrations/remnux_gateway` package into REMnux (e.g. `/opt/malbox-gateway`) and run:
```bash
sudo tee /etc/systemd/system/malbox-gateway.service << 'EOF'
[Unit]
Description=Malbox REMnux Deterministic Gateway Service
After=network.target

[Service]
Type=simple
User=remnux
WorkingDirectory=/opt/malbox-gateway
Environment=MALBOX_GATEWAY_HOST=0.0.0.0
Environment=MALBOX_GATEWAY_PORT=8008
Environment=MALBOX_GATEWAY_AUTH_TOKEN=your-gateway-token-here
Environment=MALBOX_HOST_CONTROLLER_URL=http://192.168.56.1:8005
Environment=MALBOX_HOST_CONTROLLER_SECRET=your-secure-secret-token-here
Environment=MALBOX_REMWIN_AGENT_URL=http://10.77.0.10:8000
Environment=MALBOX_REMWIN_AGENT_TOKEN=remwin-guest-agent-token
ExecStart=/usr/bin/python3 -m uvicorn integrations.remnux_gateway.api.app:app --host 0.0.0.0 --port 8008
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now malbox-gateway.service
```

---

## 4. Step 3: REMWin Windows Guest Setup

### 4.1 VirtualBox Hardware & Isolation Hardening
Execute on the physical Kali host:
```bash
# 1. Connect NIC 1 exclusively to the internal sandbox network
VBoxManage modifyvm "REMWin" --nic1 intnet --intnet1 "malbox-sandbox"

# 2. Disable all secondary NICs
VBoxManage modifyvm "REMWin" --nic2 none --nic3 none --nic4 none

# 3. Disable shared clipboard and drag-and-drop
VBoxManage modifyvm "REMWin" --clipboard-mode disabled
VBoxManage modifyvm "REMWin" --drag-and-drop disabled

# 4. Remove all shared folders
for sf in $(VBoxManage showvminfo "REMWin" --machinereadable | grep -E '^SharedFolderName' | cut -d'=' -f2 | tr -d '"'); do
    VBoxManage sharedfolder remove "REMWin" --name "$sf"
done
```

### 4.2 Windows Guest IP Configuration
Inside REMWin, set static IPv4 properties on the Ethernet adapter:
- **IP Address:** `10.77.0.10`
- **Subnet Mask:** `255.255.255.0`
- **Default Gateway:** `10.77.0.1`
- **Preferred DNS Server:** `10.77.0.1`

### 4.3 Deploy REMWin Execution & Telemetry Agent
1. Copy `integrations/remwin_agent/agent.py` to `C:\malbox\agent.py` on REMWin.
2. Configure Windows to start the agent automatically on boot without requiring a login session:
   ```cmd
   schtasks /create /tn "MalboxAgent" /tr "python.exe C:\malbox\agent.py" /sc onstart /ru SYSTEM
   ```
3. Test that the agent starts and binds to port 8000:
   ```cmd
   python.exe C:\malbox\agent.py
   ```

### 4.4 Capture Golden Clean Baseline Snapshot
1. Power off REMWin cleanly:
   ```bash
   VBoxManage controlvm "REMWin" acpipowerbutton
   ```
2. Create the immutable clean snapshot:
   ```bash
   VBoxManage snapshot "REMWin" take "clean_snapshot" --description "Malbox verified baseline with agent auto-start"
   ```

---

## 5. Step 4: Verification Runbook & Acceptance

### 5.1 Run Automated Network Audit
Execute the Malbox CLI audit tool on Kali:
```bash
./malbox setup --audit-lab-network
```
Expected output:
- VirtualBox Version: Detected (7.x)
- Host-Only Adapter (`vboxnet0`): Configured (192.168.56.1/24)
- DHCP Server: Disabled
- IP Forwarding: Disabled (0)
- VM Status: `REMWin` present, `clean_snapshot` verified, network set to `intnet (malbox-sandbox)`

### 5.2 Configure Malbox Backend `.env`
Update `.env` on Kali to activate the REMnux Gateway:
```env
MALBOX_DEFAULT_SANDBOX_BACKEND=remnux_gateway
MALBOX_LIVE_MODE_ENABLED=true
MALBOX_OPERATOR_TOKEN=your-high-entropy-operator-token-32-chars-min
MALBOX_REMNUX_GATEWAY_URL=http://192.168.56.10:8008
MALBOX_REMNUX_GATEWAY_TOKEN=your-gateway-token-here
MALBOX_REMNUX_GUEST_VM_UUID=REMWin
MALBOX_VBOX_CONTROLLER_URL=http://127.0.0.1:8005
MALBOX_VBOX_CONTROLLER_SECRET=your-secure-secret-token-here
```

### 5.3 Health Check Verification
Verify health endpoints:
```bash
curl -s http://127.0.0.1:8000/api/v1/health | jq .
curl -s http://127.0.0.1:8000/api/v1/infrastructure/readiness | jq .
```
Expected: `overall_status` is `DETONATION_READY`, with all 7 verification tiers passing.

### 5.4 End-to-End Benign PE Analysis Verification
1. Open the Malbox Web UI at `http://127.0.0.1:5173`.
2. Navigate to **Analyze File**.
3. Upload a benign sample (e.g., `tests/fixtures/benign.exe` or `calc.exe`).
4. Enter the operator security token and check the explicit authorization box.
5. Click **Analyze File**.
6. Observe the execution stages:
   - `PREFLIGHT` -> Ghidra Headless decompilation and PE triage
   - `RUNNING` -> REMnux Gateway stages and launches binary on REMWin
   - `COLLECTING` -> Watchdog completes, PCAP & process logs collected
   - `GUEST_RESTORED` -> Host controller restores `clean_snapshot`
   - `REPORTING` -> Kali AI intelligence engine analyzes forensic evidence bundle
   - `COMPLETED` -> Unified Evidence-Grounded Threat Report rendered with zero hallucinations.

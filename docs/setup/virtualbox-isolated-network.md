# VirtualBox Isolated Host-Only Network Configuration

**Document Reference:** `docs/setup/virtualbox-isolated-network.md`  
**Applies to:** Host Linux / Kali setups hosting CAPE guest VMs  
**Target Goal:** Persistent host-only interface surviving system reboots (Fix for ISSUE-08)

---

## 1. The Ephemeral IP Problem (ISSUE-08)

When operators configure VirtualBox host-only interfaces using ad-hoc Linux networking commands:
```bash
sudo ip addr add 192.168.56.1/24 dev vboxnet0
sudo ip link set vboxnet0 up
```
The IP configuration is stored only in ephemeral kernel memory. Upon host system reboot, `vboxnet0` is re-initialized by VirtualBox without the IP assignment, causing CAPE's `resultserver` to fail with:
```
OSError: [Errno 99] Cannot assign requested address: ('192.168.56.1', 2042)
```

---

## 2. Persistent Configuration via `vboxmanage`

The officially supported and reboot-persistent method to configure VirtualBox host-only interfaces is via the `vboxmanage` command suite. VirtualBox stores this configuration in `~/.config/VirtualBox/VirtualBox.xml`.

### Step 1: Create or Verify Host-Only Interface

Check if `vboxnet0` exists:
```bash
vboxmanage list hostonlyifs
```

If `vboxnet0` does not exist, create it:
```bash
vboxmanage hostonlyif create
```

### Step 2: Configure Static IP and Netmask

Assign the persistent gateway IP and subnet mask:
```bash
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

### Step 3: Disable VirtualBox Internal DHCP (Recommended)

To avoid dynamic IP drift for analysis guests, ensure static IP addressing by disabling the VirtualBox DHCP server on `vboxnet0`:
```bash
vboxmanage dhcpserver remove --ifname vboxnet0 2>/dev/null || true
```

---

## 3. Host Firewall & Confinement Enforcement

To maintain strict malware containment and prevent live malware from routing to the host local network or the external Internet:

```bash
# Block all forwarding from the host-only interface
sudo iptables -I FORWARD -i vboxnet0 -j DROP
sudo iptables -I FORWARD -o vboxnet0 -j DROP

# Allow incoming telemetry to resultserver port 2042
sudo iptables -I INPUT -i vboxnet0 -p tcp --dport 2042 -j ACCEPT

# Allow DNS if hosting local INetSim / DNS sinkhole
sudo iptables -I INPUT -i vboxnet0 -p udp --dport 53 -j ACCEPT
```

---

## 4. Verification Check

After rebooting the host machine, verify persistent binding:
```bash
ip addr show vboxnet0
```
Expected output:
```
...
inet 192.168.56.1/24 brd 192.168.56.255 scope global vboxnet0
...
```

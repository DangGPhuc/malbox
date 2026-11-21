# Malbox Deployment Profile: REMNUX_VIRTUALBOX_LAB

## 1. Overview & Architectural Principle

The `REMNUX_VIRTUALBOX_LAB` deployment profile establishes a secure, dual-network sandbox topology managed by VirtualBox on a physical Kali Linux workstation. It decouples the analysis gateway and forensic collection (REMnux) from the untrusted execution environment (REMWin), ensuring that malware detonated inside Windows cannot reach the physical workstation, the local area network, or the public Internet.

---

## 2. Target Lab Topology

```
+-----------------------------------------------------------------------------+
| PHYSICAL KALI LINUX HOST                                                    |
| IP: 192.168.56.1/24 (vboxnet0)                                              |
| Services: Malbox Web/API (:8000), Host Controller (:8005), AI Inference     |
+-----------------------------------------------------------------------------+
                               |
                               | VirtualBox Host-Only Network: vboxnet0
                               | Subnet: 192.168.56.0/24 (DHCP Disabled)
                               |
+------------------------------v----------------------------------------------+
| VIRTUALBOX VM 1: REMnux Gateway                                             |
|                                                                             |
| NIC 1 (Management): Host-Only Adapter (vboxnet0)                            |
|                     IP: 192.168.56.10/24                                    |
|                     Gateway: None (or host 192.168.56.1 if controlled)      |
|                                                                             |
| NIC 2 (Sandbox):    Internal Network: `malbox-sandbox`                      |
|                     IP: 10.77.0.1/24                                        |
|                     Services: Gateway API (:8008), INetSim / DNS sinkhole   |
|                                                                             |
| Invariant: NO NAT adapter, NO Bridged adapter, NO IP forwarding to host.    |
+-----------------------------------------------------------------------------+
                               |
                               | VirtualBox Internal Network: `malbox-sandbox`
                               | Strictly isolated, guest-to-guest L2 broadcast domain
                               |
+------------------------------v----------------------------------------------+
| VIRTUALBOX VM 2: REMWin Windows Guest                                       |
|                                                                             |
| NIC 1 (Sandbox):    Internal Network: `malbox-sandbox`                      |
|                     IP: 10.77.0.10/24                                       |
|                     Gateway: 10.77.0.1 (REMnux sinkhole/gateway)            |
|                     DNS: 10.77.0.1                                          |
|                                                                             |
| Invariant: SINGLE NIC ONLY. NO NAT, NO Bridged, NO Host-Only, NO Internet.  |
|            VirtualBox Guest Additions: Shared folders DISABLED,             |
|            Shared clipboard DISABLED, Drag-and-drop DISABLED.               |
+-----------------------------------------------------------------------------+
```

---

## 3. Network Configuration Parameters & Defaults

All IP addresses and network identifiers are configurable via `.env`:

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| `MALBOX_VBOX_HOSTONLY_IF` | `vboxnet0` | Physical Kali host-only network adapter name |
| `MALBOX_KALI_MGMT_IP` | `192.168.56.1` | Physical Kali IP on the host-only interface |
| `MALBOX_REMNUX_MGMT_IP` | `192.168.56.10` | REMnux IP on the host-only management network |
| `MALBOX_REMNUX_MGMT_PORT` | `8008` | REMnux Gateway REST API port |
| `MALBOX_VBOX_INTERNAL_NET` | `malbox-sandbox` | VirtualBox Internal Network name connecting REMnux & REMWin |
| `MALBOX_REMNUX_SANDBOX_IP` | `10.77.0.1` | REMnux IP on the internal sandbox network |
| `MALBOX_REMWIN_SANDBOX_IP` | `10.77.0.10` | REMWin Windows guest IP on the internal network |
| `MALBOX_REMWIN_AGENT_PORT` | `8000` | REMWin Guest Execution Agent HTTP port |
| `MALBOX_VBOX_CONTROLLER_PORT` | `8005` | Kali VirtualBox Host Controller port |
| `MALBOX_EXECUTION_MAX_SECONDS`| `300` | Maximum execution budget per sample |

---

## 4. VirtualBox Isolation & Anti-Tamper Configuration

To prevent guest-to-host or guest-to-guest escapes via hypervisor features:

```bash
# 1. Ensure Shared Clipboard is disabled on REMWin
VBoxManage modifyvm "REMWin" --clipboard-mode disabled

# 2. Ensure Drag and Drop is disabled on REMWin
VBoxManage modifyvm "REMWin" --drag-and-drop disabled

# 3. Remove all shared folders from REMWin
for sf in $(VBoxManage showvminfo "REMWin" --machinereadable | grep -E '^SharedFolderName' | cut -d'=' -f2 | tr -d '"'); do
    VBoxManage sharedfolder remove "REMWin" --name "$sf"
done

# 4. Verify REMWin NIC 1 is strictly Internal Network 'malbox-sandbox'
VBoxManage modifyvm "REMWin" --nic1 intnet --intnet1 "malbox-sandbox"

# 5. Disable all secondary NICs on REMWin
VBoxManage modifyvm "REMWin" --nic2 none --nic3 none --nic4 none
```

---

## 5. Non-Routing / Safe Sinkhole Invariant

REMnux must **never** act as an unrestricted router or NAT gateway:
1. `sysctl -w net.ipv4.ip_forward=0` must be enforced on REMnux unless an explicitly isolated transparent proxy (such as PolarProxy or INetSim) is bound strictly to `10.77.0.1` and sinks all external traffic.
2. `iptables -P FORWARD DROP` is mandatory on REMnux to prevent traffic from `10.77.0.0/24` forwarding to `192.168.56.0/24`.
3. Kali host packet forwarding (`net.ipv4.ip_forward`) must be `0` or drop forward traffic on `vboxnet0`.

---

## 6. Read-Only Network Audit vs Explicit Setup Actions

* **Audit Command (Read-Only):**
  ```bash
  ./malbox setup --audit-lab-network
  ```
  Inspects host interfaces, VirtualBox VM NIC attachments, routing tables, and firewall rules without mutating any configuration.

* **Setup Action (Operator-Approved):**
  ```bash
  ./malbox setup --configure-lab-network
  ```
  Creates `vboxnet0`, configures IP addressing, and prints exact commands for REMnux and REMWin guest configuration.

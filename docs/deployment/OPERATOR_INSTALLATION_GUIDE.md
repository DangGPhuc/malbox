# Malbox-AI Operator Installation & Provisioning Guide

This guide describes the complete, operator-controlled procedure for provisioning, configuring, and verifying the **Malbox-AI** suspicious-file analysis platform.

Whether deploying on physical Kali Linux bare-metal, a distributed controller architecture, or a resource-constrained laboratory VM, this guide details every automated CLI stage, required virtualization configuration, guest image provisioning, network isolation boundary, and end-to-end acceptance test.

---

## 1. Hardware Architecture & Deployment Profiles

Malbox provides built-in hardware discovery and automated profile assessment via:

```bash
./malbox setup --plan
```

The system interrogates the CPU architecture, hardware virtualization flags (Intel VT-x `vmx` / AMD-V `svm`), access to `/dev/kvm`, RAM capacity, disk headroom, and hypervisor toolchains, recommending one of three operational profiles:

### Profile A: Single-Host Physical Kali (All-in-One)
* **Target Audience**: Dedicated bare-metal security workstations and standalone hardware analysis rigs.
* **Requirements**:
  - CPU: x86_64 with VT-x or AMD-V virtualization extensions.
  - KVM: Accessible `/dev/kvm` (read/write permissions for operator).
  - RAM: Minimum 8 GB (16 GB+ strongly recommended).
  - Disk: Minimum 50 GB free NVMe/SSD space.
* **Architecture**: Malbox Web/API, Ghidra Headless, Local AI inference (Ollama), and the virtualized Windows 10 guest run on the same physical host.
* **Important Warning**: Running upstream CAPEv2 directly on Kali Rolling can encounter package conflicts due to rolling kernel updates and Python 3.12+ removals of legacy libraries. Profile B is strongly recommended for production environments.

### Profile B: Distributed Architecture (Upstream Recommended)
* **Target Audience**: Enterprise SOCs, malware analysis teams, production lab infrastructure.
* **Architecture**:
  - **Operator Node (Kali Linux or Linux Workstation)**: Hosts Malbox UI, FastAPI backend, Ghidra Headless engine, and local AI inference.
  - **CAPE Controller Node (Dedicated Ubuntu 22.04 LTS Server)**: Hosts upstream CAPEv2 daemon, QEMU/KVM hypervisor, host-only bridge, and virtualized Windows 10 guests.
* **Advantages**: Strictly isolates dynamic detonation and kernel hypervisors from the analyst's workstation; avoids rolling release breakages.

### Profile C: Resource-Constrained VM (Static & Triage Only)
* **Target Audience**: Cloud development environments, nested VMs lacking VT-x, or laptops with < 8 GB RAM.
* **Capabilities**: Enables full PE triage, static unpacking, Ghidra decompilation, YARA rule scanning, and AI correlation. Dynamic CAPE detonation is safely marked `DISABLED`.

---

## 2. Automated Setup & Provisioning Workflow

The `./malbox setup` CLI provides an end-to-end, operator-controlled pipeline. Every command supports `--dry-run` to preview actions without making filesystem or state modifications.

### Step 1: System Assessment & Planning

```bash
# Analyze hardware, check virtualization, and view deployment recommendation
./malbox setup --plan
```

### Step 2: Core Platform Installation

```bash
# Create runtime directories (0700 permissions), generate cryptographic secrets,
# initialize the SQLite database schema, and build the frontend
./malbox setup --install-core
```
*Creates `data/quarantine`, `data/artifacts`, `data/runtime`, generates a 48-character operator token in `.env`, and initializes `data/malbox.db`.*

### Step 3: Ghidra Headless Engine Setup

```bash
# Detect OpenJDK 21+, verify analyzeHeadless, probe bubblewrap/cgroups containment,
# and run an automated static import smoke test
./malbox setup --install-ghidra
```
If Ghidra is missing, the tool prompts with the exact apt installation command:
```bash
sudo apt update && sudo apt install -y ghidra default-jdk bubblewrap
```

### Step 4: Local AI Inference Setup

```bash
# Query hardware RAM and recommend/pull an optimal Ollama model
./malbox setup --install-ai
```
* **RAM < 8 GB**: Recommended `qwen2.5:1.5b` (~1.0 GB download).
* **RAM 8–16 GB**: Recommended `qwen2.5:7b` (~4.7 GB download).
* **RAM > 16 GB**: Recommended `qwen2.5:14b` (~9.0 GB download).

### Step 5: CAPE Sandbox Controller Provisioning

```bash
# For Profile B (Distributed):
./malbox setup --provision-cape --profile B --target-api-url http://192.168.1.50:8008 --target-machine win10_analyst

# For Profile A (Single-Host Local):
./malbox setup --provision-cape --profile A
```
Automated deployment scripts and systemd unit templates for Ubuntu 22.04 LTS are located in:
- `scripts/provisioning/cape/install_cape_ubuntu2204.sh`
- `scripts/provisioning/cape/systemd/*.service`

### Step 6: Windows Guest VM Provisioning

```bash
# Generate libvirt XML definition, autounattend.xml template, and agent installation scripts
./malbox setup --provision-guest --hypervisor kvm --vm-name win10_analyst --iso /var/iso/Win10_22H2_English_x64.iso
```

### Step 7: Isolation Verification & Evidence Collection

```bash
# Inspect network bridges, verify non-forwarding rules, and collect auditable evidence
./malbox setup --verify
```
Generates `data/confinement_evidence.json` detailing host NIC count, bridge default routes, and iptables/nftables forwarding status.

### Step 8: Harmless Benign Acceptance Smoke Test

```bash
# Execute safe end-to-end verification using a minimal synthetic benign PE (xor eax, eax; ret)
./malbox setup --benign-e2e
```
Verifies the complete 8-stage pipeline:
1. Benign PE Generation (1024-byte zero-risk binary)
2. Static PE Header Triage
3. Ghidra Headless Disassembly
4. YARA Threat Rule Matching
5. AI Synthesis & Epistemic Standards
6. CAPE API Connectivity & Routing
7. Confinement Assertion Validation
8. Unified Analysis Report Generation

---

## 3. Windows Guest Provisioning & Snapshot Clean State

To ensure malware cannot fingerprint the analysis environment or persist across detonations, the guest must be cleanly configured:

### Automated Unattended Setup
Use the template at `scripts/provisioning/templates/autounattend.xml` with your official Windows 10 ISO:
1. Disables Windows Defender, SmartScreen, and Windows Update.
2. Disables UAC (User Account Control).
3. Configures auto-logon for the analyst account.
4. Sets static IP: `192.168.100.10/24`, Gateway: `none`.

### Agent Installation
Place `scripts/provisioning/templates/agent.py` in the guest:
```cmd
mkdir C:\cape
copy agent.py C:\cape\agent.py
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CAPEAgent" /t REG_SZ /d "C:\Python310\pythonw.exe C:\cape\agent.py" /f
```

### Clean Snapshot Creation
Once the guest has booted and the agent is responding on `http://192.168.100.10:8000`:
```bash
# For KVM:
sudo virsh snapshot-create-as --domain win10_analyst --name clean_snapshot --description "Clean baseline state with agent active"

# For VirtualBox:
VBoxManage snapshot win10_analyst take "clean_snapshot" --description "Clean baseline state with agent active"
```

---

## 4. Confinement Verification & Operator Attestation

Malbox enforces strict, non-bypassable runtime confinement gates. Live dynamic detonation is **refused** unless the operator explicitly verifies and attests to the physical isolation boundaries:

1. **Host-Only Network Interface**: Analysis VM interface is bound exclusively to an internal host-only bridge (`virbr-malbox` or `vboxnet0`).
2. **Default Route Nullification**: The guest has no default gateway routing to the Internet or local LAN (`default_route: none` or `drop`).
3. **Firewall Forwarding Prohibition**: Host packet forwarding (`/proc/sys/net/ipv4/ip_forward`) is set to 0, or `iptables -P FORWARD DROP` is enforced.
4. **Snapshot Integrity**: The analysis machine is reverted to `clean_snapshot` prior to every task.

To sign the operator attestation:
```bash
./malbox setup --verify
```
Review the gathered evidence, then accept the four core invariants to generate `data/cape_operator_attestation.json`.

---

## 5. Web-Based Infrastructure Readiness Dashboard

Operators can monitor real-time infrastructure readiness directly from the web interface:

1. Start Malbox:
   ```bash
   ./malbox start
   ```
2. Navigate to: `http://127.0.0.1:8000/#infrastructure`
3. The dashboard displays:
   - **Overall Platform Status**: `READY`, `DEGRADED`, or `BLOCKED`.
   - **7 Core Readiness Tiers**: Application, Static Analysis, AI Provider, CAPE API, Guest VM, Confinement, Detonation Ready.
   - **8 Subsystem Diagnostic Cards**: CPU/KVM, Host Memory, Ghidra Headless, Local AI, CAPE Controller, Guest VM, Network Isolation, File Storage.
   - **One-Click Remediation**: Copyable CLI commands for any degraded or unconfigured subsystem.

---

## 6. Security Disclaimer & Epistemic Boundaries

* Live analysis executes untrusted code inside isolated virtual environments.
* Never run live detonation on a workstation connected directly to sensitive production networks.
* Always review the output of `./malbox setup --verify` before enabling live analysis.

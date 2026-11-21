# ADR-008: Deterministic REMnux Gateway and REMWin Automated Sandbox Architecture

**Status:** APPROVED  
**Date:** 2026-11-21  
**Author:** Lead Security Platform Architect & Platform Engineering Team  
**Supercedes:** None (Extends Live-First Analysis Model with VirtualBox Peer-VM Gateway)

---

## 1. Context & Architectural Challenge

Malbox is an evidence-grounded suspicious file analysis platform. The platform operates on a physical Kali Linux workstation with Oracle VirtualBox managing two peer virtual machines:
1. **REMnux VM**: Linux-based reverse-engineering and network containment appliance.
2. **REMWin VM**: Windows 10/11 guest serving as the isolated, zero-egress execution sandbox.

### Mandatory Compatibility Findings
1. **Peer-VM Topology in VirtualBox**: REMnux and REMWin are peer guests hosted by the physical Kali VirtualBox hypervisor. Neither VM runs inside the other.
2. **Hypervisor Privilege Boundary**: A guest operating system inside VirtualBox (REMnux) does not possess hypervisor privileges over its peer VM (REMWin). It cannot execute `VBoxManage snapshot restore` or `VBoxManage controlvm` without hypervisor control delegated from the physical host.
3. **CAPE Compatibility Limitations**: Running CAPEv2 directly inside REMnux to control a peer VM is unsupported out of the box because CAPE's VirtualBox machinery expects local hypervisor execution or complex remote VBoxWebSrv bindings that compromise host isolation.
4. **Epistemic & Deterministic Integrity**: Analysis and evidence collection must be deterministic, auditable, and immutable. REMnux and REMWin must have **ZERO AI AGENTS, ZERO LLM INFERENCE, and ZERO AI-DRIVEN EXECUTION DECISIONS**. All AI analysis and report generation must execute exclusively on the physical Kali workstation after the evidence archive has been downloaded, validated, and cryptographically verified.

---

## 2. Decision: Three-Tier Peer-VM Gateway Architecture

To resolve hypervisor control while maintaining strict network confinement and forensic integrity, Malbox implements a three-tier architecture:

```
+-----------------------------------------------------------------------------------------+
| PHYSICAL KALI WORKSTATION                                                               |
|                                                                                         |
|  [Malbox Web & Backend]           [Kali-Only AI Engine & Report Generator]              |
|          |                                            ^                                 |
|          | (1. Submit Sample)                         | (9. Import Evidence Bundle)     |
|          v                                            |                                 |
|  [RemnuxGatewayBackend]                               |                                 |
|          |                                            |                                 |
|          | (REST API over TLS)                        |                                 |
|          v                                            |                                 |
|  +----------------------------------------------------+------------------------------+  |
|  | Host-Only Management Network (e.g. 192.168.56.0/24)                               |  |
|  | Kali: 192.168.56.1  <---->  REMnux: 192.168.56.10                                 |  |
|  +----------------------------------------------------+------------------------------+  |
|          |                                            ^                                 |
|          | (2. Snapshot/Lifecycle Request)            | (8. Package Evidence)           |
|          v                                            |                                 |
|  [VirtualBox Host Controller]                         |                                 |
|  (Restricted local daemon, exact VM UUID allowlist)   |                                 |
+----------|--------------------------------------------|---------------------------------+
           | (VBoxManage snapshot / poweroff)           |
           v                                            |
+------------------------------------+   +------------------------------------------------+
| VIRTUALBOX PEER VM 1: REMNUX       |   | VIRTUALBOX PEER VM 2: REMWIN                   |
| (Gateway & Evidence Collector)     |   | (Execution Guest)                              |
|                                    |   |                                                |
|  [Deterministic Gateway Service]   |   |  [Minimal Deterministic Guest Agent]           |
|  [Constrained MCP Interface]       |   |  - Verifies sample SHA-256                     |
|  [Evidence Collectors: PCAP/Logs]  |   |  - Launches process in sandbox workspace       |
|  - NO AI / NO LLM INFERENCE        |   |  - Monitored up to 300s monotonic deadline     |
|          |                         |   |  - Collects Sysmon / Event Logs / Telemetry    |
|          |                         |   |  - NO AI / NO LLM INFERENCE                    |
|          +------------+            |   |          ^                                     |
|                       |            |   |          |                                     |
|  +--------------------v------------+---+----------|----------------------------------+  |
|  | VirtualBox Internal Network (`malbox-sandbox`, e.g. 10.77.0.0/24)                 |  |
|  | REMnux: 10.77.0.1  <------------------------->  REMWin: 10.77.0.10                |  |
|  | (STRICTLY ISOLATED: NO NAT, NO BRIDGED, NO DEFAULT ROUTE, NO INTERNET EGRESS)     |  |
|  +-----------------------------------------------------------------------------------+  |
+------------------------------------+   +------------------------------------------------+
```

### Core Invariants

1. **Physical Host Controller (`integrations/virtualbox_host_controller/`)**:
   - Runs locally on the Kali host, binding exclusively to `127.0.0.1` and `192.168.56.1`.
   - Never exposes an unrestricted shell or raw `VBoxManage` parameters.
   - Enforces an exact allowlist for the managed REMWin VM UUID and clean snapshot name.
   - Requires mutual authentication via HMAC-SHA256 tokens with timestamped replay protection.
   - Responsibilities: restore clean snapshot before execution, start VM, verify VM running state, power off VM after execution, restore clean snapshot, verify final state.

2. **REMnux Sandbox Gateway (`integrations/remnux_gateway/`)**:
   - Runs inside the REMnux VM as an authenticated REST service and constrained MCP interface.
   - Dual-homed: NIC 1 on Host-Only (`192.168.56.10`), NIC 2 on Internal Network `malbox-sandbox` (`10.77.0.1`).
   - Receives sample from Kali Malbox Backend via `POST /v1/jobs`.
   - Requests REMWin VM snapshot preparation from the Kali Host Controller.
   - Stages sample to the REMWin Guest Agent over the isolated internal network.
   - Monitors execution against a strict monotonic deadline (default maximum 300 seconds).
   - Collects evidence (PCAP, Sysmon/EVTX logs, process telemetry, registry/file changes).
   - Requests VM power-off and snapshot restoration via the Kali Host Controller upon completion, timeout, or cancellation.
   - Packages immutable evidence bundle with manifest and cryptographic hashes for download by Kali.

3. **REMWin Execution Agent (`integrations/remwin_agent/`)**:
   - Runs inside the Windows guest VM on Internal Network `malbox-sandbox` (`10.77.0.10`).
   - Zero Internet or physical LAN access (no NAT or bridged adapters).
   - Receives staged sample job, validates SHA-256, executes the sample in a restricted workspace.
   - Records execution acknowledgment, start timestamp, PID, child processes, and exit status.
   - Exports telemetry prior to termination.
   - **Failsafe**: If malware crashes or tampers with the guest agent, the Kali Host Controller independently enforces the 300-second deadline and forcefully powers off and rolls back the VM snapshot.

4. **Kali-Resident AI Engine & Telemetry Normalization**:
   - The Kali backend downloads the verified evidence bundle via `GET /v1/jobs/{job_id}/evidence`.
   - Normalizes raw telemetry into `AnalysisEvent` records.
   - Executes deterministic detection rules and static/dynamic correlation.
   - Only after evidence is imported and verified does the Kali AI provider generate the threat assessment.

5. **CAPE Preservation**:
   - The existing `CapeSandboxBackend` is retained in full as an optional backend selection.
   - `RemnuxGatewayBackend` implements the same `SandboxBackend` interface (`check_readiness`, `submit_sample`, `get_task_status`, `collect_results`, `cancel_task`, `generate_artifacts`).

---

## 3. Deployment Profile: `REMNUX_VIRTUALBOX_LAB`

| Component | Network Interface 1 | Network Interface 2 | Gateway / Routing | Hypervisor Role |
| :--- | :--- | :--- | :--- | :--- |
| **Physical Kali** | Physical LAN / Internet | Host-Only (`192.168.56.1/24`) | Host default gateway | Hypervisor Host |
| **REMnux VM** | Host-Only (`192.168.56.10/24`) | Internal (`malbox-sandbox`, `10.77.0.1/24`) | No default gateway or isolated | Gateway & Collector |
| **REMWin VM** | Internal (`malbox-sandbox`, `10.77.0.10/24`) | None | None (`0.0.0.0/0` blocked) | Target Sandbox |

---

## 4. Consequences & Security Guarantees

* **Zero Guest-to-Host Escape via Hypervisor Commands**: REMnux cannot execute arbitrary hypervisor commands; it can only invoke specific, allowlisted lifecycle transitions against a pre-authorized VM UUID.
* **Deterministic Execution & Zero AI Hallucination in Sandbox**: No LLM makes execution choices or influences evidence capture inside REMnux or REMWin.
* **Guaranteed Guest Cleanliness**: The physical host controller enforces snapshot restoration to `clean_snapshot` before and after every single job. If snapshot restoration fails, future analyses are immediately blocked.
* **Dual-Network Defense-in-Depth**: REMWin has no route to the host management network (`192.168.56.0/24`) or the physical LAN/Internet.

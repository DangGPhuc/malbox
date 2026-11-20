# Windows Guest VM Preparation & Hardening Guide

## 1. Supported Guest Environments

- **Primary Target**: Windows 10 64-bit Enterprise / Pro (Build 21H2 / 22H2).
- **Secondary Target**: Windows 11 64-bit Enterprise (Virtual TPM disabled).
- **Architecture**: x86_64.
- **Base Image Footprint**: 40 GB – 60 GB dynamically expanding virtual disk (`.qcow2` or `.vdi`).

---

## 2. Guest OS Installation Steps

> [!CAUTION]
> The security relaxations below (disabling Windows Defender, UAC, and Firewall) must **ONLY** be executed inside an isolated guest VM dedicated to malware detonation. Never apply these changes to a production system or host operating system.

1. **Install Clean Windows OS**:
   - Create a dedicated local administrator user account with a strong password (e.g., `analyst` or custom lab account; avoid reusable passwords).
   - Set Computer Name: `WIN-ANALYST-01`.
   - Install Guest Additions / VirtIO drivers.

2. **Guest VM Analysis Tuning (Scoped Observation vs Containment)**:
   > [!IMPORTANT]
   > Host-side kernel routing (`sysctl net.ipv4.ip_forward = 0`) and host-only firewalling are the non-negotiable containment boundaries. Guest settings do NOT provide isolation from the host.
   > Avoid blanket security-disabling defaults. Configure scoped exemptions to observe malware behavior without unnecessarily crippling system logging:
   - **Antivirus Interference vs Observation Trade-off**:
     In raw behavioral observation environments, real-time Defender can quarantine malware payloads before behavioral hooks trigger. If uninhibited execution observation is required:
     ```powershell
     # Disable real-time interception in dedicated detonation VM
     Set-MpPreference -DisableRealtimeMonitoring $true
     Set-MpPreference -DisableIOAVProtection $true
     ```
     *Note*: Maintain a secondary analysis profile with Defender enabled to evaluate evasion techniques against standard Windows security controls.
   - **Scoped Firewall Configuration (Avoid Blanket Disabling)**:
     Rather than disabling the Windows Firewall entirely, allow the CAPE agent inbound on port 8000:
     ```powershell
     New-NetFirewallRule -DisplayName "CAPE Guest Agent" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
     ```
     If full outbound behavioral network analysis is required and the host-side firewall enforces drop policies, guest outbound filtering may be relaxed per-profile.
   - **User Account Control (UAC) & SmartScreen**:
     ```powershell
     # Disable elevation prompt modal popups that block headless execution
     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
     Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
     ```
   - **Disable Sleep & Background Updates**:
     ```powershell
     Stop-Service wuauserv; Set-Service wuauserv -StartupType Disabled
     powercfg /h off
     powercfg /change standby-timeout-ac 0
     ```

---

## 3. Install Analysis Tooling & Runtimes

Install realistic target software to provide realistic attack surfaces for trojans and stealers:
- **Python 3.10+ (64-bit)**: Install to `C:\Python310` (Check "Add Python to PATH").
- **Visual C++ Redistributable 2015-2022**: Essential for PE execution.
- **.NET Framework 3.5 & 4.8**: Enable via Windows Features.
- **Realistic User Decoy Data**:
  - Chrome / Firefox browser profile with history.
  - Decoy `.docx`, `.pdf`, and `.txt` files in `C:\Users\$env:USERNAME\Desktop` and `Documents`.
  - Fake registry keys and credential placeholders.

---

## 4. CAPE Guest Agent Deployment

1. **Deploy Agent Script**:
   Create directory `C:\agent` and copy `agent.py` from `/opt/cape/agent/agent.py`:
   ```powershell
   New-Item -ItemType Directory -Path "C:\agent" -Force
   # Place agent.py inside C:\agent\agent.py
   ```

2. **Configure Auto-Start via Scheduled Task**:
   Create a scheduled task that executes with highest privileges at user logon:
   ```powershell
   $Action = New-ScheduledTaskAction -Execute "C:\Python310\python.exe" -Argument "C:\agent\agent.py"
   $Trigger = New-ScheduledTaskTrigger -AtLogOn
   $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
   Register-ScheduledTask -TaskName "CapeAgent" -Action $Action -Trigger $Trigger -Principal $Principal
   ```

3. **Verify Agent Listener**:
   Run `python C:\agent\agent.py` manually. Verify listener on `0.0.0.0:8000`:
   ```powershell
   Get-NetTCPConnection -LocalPort 8000
   ```

---

## 5. Network Configuration & Snapshot Creation

1. **Set Static Host-Only IP**:
   - IP Address: `192.168.56.101`
   - Subnet Mask: `255.255.255.0`
   - Default Gateway: **BLANK (Do NOT configure a gateway)**
   - DNS Server: `192.168.56.1`

2. **Verify Confinement Invariant from Guest**:
   From an Administrator Command Prompt in Windows:
   ```cmd
   ping 192.168.56.1
   :: Should SUCCEED (Host resultserver reachable)

   ping 8.8.8.8
   :: Must FAIL immediately (Destination host unreachable / Transmit failed)

   nslookup google.com
   :: Must FAIL or resolve to local sinkhole IP (192.168.56.1)
   ```

3. **Take Authoritative Clean Snapshot**:
   Once the agent is running and verified:
   ```bash
   # From Kali host terminal:
   VBoxManage snapshot win10_malbox take clean_snap --pause
   ```
   *The guest is now ready for autonomous, reproducible detonation.*

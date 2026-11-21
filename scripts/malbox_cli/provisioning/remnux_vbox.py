from __future__ import annotations

import json
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from integrations.virtualbox_host_controller.vbox import (
    check_virtualbox_installed,
    get_vm_machinereadable,
    validate_vm_network_isolation,
)


def audit_lab_network(
    root_dir: Path,
    remwin_name: str = "REMWin",
    remnux_name: str = "REMnux",
    hostonly_if: str = "vboxnet0",
    internal_net: str = "malbox-sandbox",
) -> Dict[str, Any]:
    """
    Read-only audit of the REMNUX_VIRTUALBOX_LAB network and VM topology.
    Does NOT mutate any host or VM configuration.
    """
    checks: List[Dict[str, Any]] = []
    violations: List[str] = []
    remediations: List[str] = []

    # 1. VirtualBox Installation Check
    vbox_ok, vbox_ver = check_virtualbox_installed()
    checks.append({
        "check": "virtualbox_installed",
        "status": "PASS" if vbox_ok else "FAIL",
        "version": vbox_ver if vbox_ok else None,
        "details": f"VirtualBox version: {vbox_ver}" if vbox_ok else vbox_ver,
    })
    if not vbox_ok:
        violations.append("VirtualBox is not installed or VBoxManage is not accessible in PATH.")
        remediations.append("sudo apt update && sudo apt install -y virtualbox")

    # 2. Host-Only Interface Check
    vbox_bin = shutil.which("VBoxManage") or shutil.which("vboxmanage")
    hostonly_found = False
    hostonly_ip = None
    dhcp_disabled = True

    if vbox_bin:
        try:
            res_ho = subprocess.run([vbox_bin, "list", "hostonlyifs"], capture_output=True, text=True, timeout=5)
            if res_ho.returncode == 0:
                current_if = None
                for line in res_ho.stdout.splitlines():
                    if line.startswith("Name:"):
                        current_if = line.split(":", 1)[1].strip()
                    if current_if == hostonly_if:
                        hostonly_found = True
                        if line.startswith("IPAddress:"):
                            hostonly_ip = line.split(":", 1)[1].strip()
                        if line.startswith("DHCPEnabled:") and "true" in line.lower():
                            dhcp_disabled = False
        except Exception:
            pass

    checks.append({
        "check": "hostonly_interface",
        "status": "PASS" if hostonly_found else "WARN",
        "interface": hostonly_if,
        "ip": hostonly_ip,
        "dhcp_disabled": dhcp_disabled,
        "details": f"Found {hostonly_if} (IP: {hostonly_ip}, DHCP disabled: {dhcp_disabled})" if hostonly_found else f"Host-only interface {hostonly_if} not yet created",
    })
    if not hostonly_found:
        remediations.append(f"VBoxManage hostonlyif create && VBoxManage hostonlyif ipconfig {hostonly_if} --ip 192.168.56.1 --netmask 255.255.255.0")
    elif not dhcp_disabled:
        violations.append(f"DHCP is enabled on management network {hostonly_if}. Static IP assignment required.")
        remediations.append(f"VBoxManage dhcpserver remove --ifname {hostonly_if}")

    # 3. Host Forwarding Check (/proc/sys/net/ipv4/ip_forward)
    forwarding_enabled = False
    ip_fwd_path = Path("/proc/sys/net/ipv4/ip_forward")
    if ip_fwd_path.is_file():
        try:
            val = ip_fwd_path.read_text().strip()
            forwarding_enabled = (val == "1")
        except Exception:
            pass

    checks.append({
        "check": "host_ip_forwarding",
        "status": "WARN" if forwarding_enabled else "PASS",
        "ip_forwarding": forwarding_enabled,
        "details": "Host packet forwarding is disabled (net.ipv4.ip_forward=0)" if not forwarding_enabled else "Host packet forwarding is ENABLED (net.ipv4.ip_forward=1); verify iptables DROP on vboxnet0",
    })

    # 4. REMWin VM Inspection
    remwin_info = get_vm_machinereadable(remwin_name) if vbox_bin else {}
    if remwin_info:
        iso_ok, iso_errs = validate_vm_network_isolation(remwin_name, internal_net)
        checks.append({
            "check": "remwin_isolation",
            "status": "PASS" if iso_ok else "FAIL",
            "vm_name": remwin_name,
            "isolation_verified": iso_ok,
            "details": f"REMWin strictly isolated to '{internal_net}'" if iso_ok else f"Isolation violations: {'; '.join(iso_errs)}",
        })
        if not iso_ok:
            violations.extend([f"REMWin: {e}" for e in iso_errs])
            remediations.append(f"VBoxManage modifyvm \"{remwin_name}\" --nic1 intnet --intnet1 {internal_net} --nic2 none --clipboard-mode disabled --drag-and-drop disabled")
    else:
        checks.append({
            "check": "remwin_vm_exists",
            "status": "WARN",
            "vm_name": remwin_name,
            "details": f"VM '{remwin_name}' not found in VirtualBox. Ensure VM is imported.",
        })
        remediations.append(f"Import or create '{remwin_name}' VM in VirtualBox")

    # 5. REMnux VM Inspection
    remnux_info = get_vm_machinereadable(remnux_name) if vbox_bin else {}
    if remnux_info:
        nic1 = remnux_info.get("nic1", "").lower()
        ho1 = remnux_info.get("hostonlyadapter1", "")
        nic2 = remnux_info.get("nic2", "").lower()
        int2 = remnux_info.get("intnet2", "")

        nux_ok = (nic1 == "hostonly" and ho1 == hostonly_if and nic2 == "intnet" and int2 == internal_net)
        nux_errs = []
        if nic1 != "hostonly" or ho1 != hostonly_if:
            nux_errs.append(f"NIC 1 should be hostonly '{hostonly_if}', found '{nic1}' ('{ho1}')")
        if nic2 != "intnet" or int2 != internal_net:
            nux_errs.append(f"NIC 2 should be intnet '{internal_net}', found '{nic2}' ('{int2}')")

        checks.append({
            "check": "remnux_dual_network",
            "status": "PASS" if nux_ok else "FAIL",
            "vm_name": remnux_name,
            "details": f"REMnux configured with dual NIC (Management: {hostonly_if}, Sandbox: {internal_net})" if nux_ok else f"REMnux network issues: {'; '.join(nux_errs)}",
        })
        if not nux_ok:
            violations.extend([f"REMnux: {e}" for e in nux_errs])
            remediations.append(f"VBoxManage modifyvm \"{remnux_name}\" --nic1 hostonly --hostonlyadapter1 {hostonly_if} --nic2 intnet --intnet2 {internal_net} --nic3 none")
    else:
        checks.append({
            "check": "remnux_vm_exists",
            "status": "WARN",
            "vm_name": remnux_name,
            "details": f"VM '{remnux_name}' not found in VirtualBox.",
        })
        remediations.append(f"Import or create '{remnux_name}' VM in VirtualBox")

    # 6. Physical Kali Host Controller Daemon Probe
    hc_url = "http://127.0.0.1:8005/health"
    hc_ok = False
    hc_details = None
    try:
        req = urllib.request.Request(hc_url)
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            if resp.status == 200:
                hc_ok = True
                hc_data = json.loads(resp.read().decode("utf-8"))
                hc_details = f"Host Controller active (Allowed VMs: {', '.join(hc_data.get('allowed_vms', []))})"
    except Exception as e:
        hc_details = f"Host Controller not responding on 127.0.0.1:8005 ({str(e)})"

    checks.append({
        "check": "host_controller_service",
        "status": "PASS" if hc_ok else "WARN",
        "url": hc_url,
        "details": hc_details,
    })
    if not hc_ok:
        remediations.append("python3 -m uvicorn integrations.virtualbox_host_controller.server:app --host 127.0.0.1 --port 8005")

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else ("WARN" if any(c["status"] == "WARN" for c in checks) else "PASS")
    return {
        "overall_status": overall,
        "profile": "REMNUX_VIRTUALBOX_LAB",
        "checks": checks,
        "violations": violations,
        "remediations": remediations,
    }


def generate_lab_setup_commands(
    remwin_name: str = "REMWin",
    remnux_name: str = "REMnux",
    hostonly_if: str = "vboxnet0",
    internal_net: str = "malbox-sandbox",
) -> Dict[str, Any]:
    """Generates structured, copyable configuration commands for the operator."""
    return {
        "profile": "REMNUX_VIRTUALBOX_LAB",
        "steps": [
            {
                "step": "1. Host-Only Management Network Creation",
                "command": (
                    f"VBoxManage hostonlyif create\n"
                    f"VBoxManage hostonlyif ipconfig {hostonly_if} --ip 192.168.56.1 --netmask 255.255.255.0\n"
                    f"VBoxManage dhcpserver remove --ifname {hostonly_if} 2>/dev/null || true"
                ),
            },
            {
                "step": "2. REMnux VM Dual-Network Attachment",
                "command": (
                    f"VBoxManage modifyvm \"{remnux_name}\" --nic1 hostonly --hostonlyadapter1 {hostonly_if}\n"
                    f"VBoxManage modifyvm \"{remnux_name}\" --nic2 intnet --intnet2 {internal_net}\n"
                    f"VBoxManage modifyvm \"{remnux_name}\" --nic3 none --nic4 none"
                ),
            },
            {
                "step": "3. REMWin VM Strict Isolation & Anti-Tamper Configuration",
                "command": (
                    f"VBoxManage modifyvm \"{remwin_name}\" --nic1 intnet --intnet1 {internal_net}\n"
                    f"VBoxManage modifyvm \"{remwin_name}\" --nic2 none --nic3 none --nic4 none\n"
                    f"VBoxManage modifyvm \"{remwin_name}\" --clipboard-mode disabled\n"
                    f"VBoxManage modifyvm \"{remwin_name}\" --drag-and-drop disabled"
                ),
            },
            {
                "step": "4. REMWin Baseline Clean Snapshot",
                "command": f"VBoxManage snapshot \"{remwin_name}\" take \"clean_snapshot\" --description \"Clean baseline with agent active\"",
            },
            {
                "step": "5. Kali Host Controller Startup",
                "command": "python3 -m uvicorn integrations.virtualbox_host_controller.server:app --host 127.0.0.1 --port 8005",
            },
        ],
    }

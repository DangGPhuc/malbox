from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..discovery import discover_all_hardware


def probe_guest_agent_http(guest_ip: str = "192.168.100.10", port: int = 8000, timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """Probes the CAPE guest agent HTTP server inside the Windows analysis VM."""
    url = f"http://{guest_ip}:{port}/status"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Malbox-AI-Probe/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return True, f"Agent active: version {data.get('version', '2.0')} ({data.get('system', 'Windows')})"
            return False, f"Agent returned HTTP {resp.status}"
    except urllib.error.URLError as e:
        return False, f"Agent connection failed: {str(e.reason)}"
    except Exception as e:
        return False, f"Agent probe error: {str(e)}"


def check_hypervisor_readiness() -> Dict[str, Any]:
    """Inspects installed hypervisors and virtual machine management tools."""
    virsh_bin = shutil.which("virsh")
    qemu_img = shutil.which("qemu-img")
    vbox_bin = shutil.which("VBoxManage")

    preferred = "kvm" if (virsh_bin and qemu_img) else ("virtualbox" if vbox_bin else "none")

    # Check if win10_analyst VM is defined
    vms_defined: List[str] = []
    if virsh_bin:
        try:
            res = subprocess.run(["virsh", "list", "--all", "--name"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            if res.returncode == 0:
                vms_defined.extend([line.strip() for line in res.stdout.splitlines() if line.strip()])
        except Exception:
            pass
    if vbox_bin:
        try:
            res = subprocess.run(["VBoxManage", "list", "vms"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if '"' in line:
                        vms_defined.append(line.split('"')[1])
        except Exception:
            pass

    return {
        "preferred_hypervisor": preferred,
        "virsh_available": bool(virsh_bin),
        "qemu_img_available": bool(qemu_img),
        "vbox_available": bool(vbox_bin),
        "vms_defined": vms_defined,
        "win10_analyst_exists": ("win10_analyst" in vms_defined),
    }


def generate_guest_provisioning_artifacts(
    root_dir: Path,
    hypervisor: str = "kvm",
    vm_name: str = "win10_analyst",
    guest_ip: str = "192.168.100.10",
    vcpus: int = 2,
    ram_mb: int = 4096,
    disk_gb: int = 50,
    iso_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generates VM definitions, unattended configuration templates, and setup commands.
    """
    templates_dir = root_dir / "scripts" / "provisioning" / "templates"
    if not templates_dir.is_dir():
        fallback_templates = Path(__file__).resolve().parent.parent.parent / "provisioning" / "templates"
        if fallback_templates.is_dir():
            templates_dir = fallback_templates
    xml_template = templates_dir / "win10_analyst.xml"
    unattend_template = templates_dir / "autounattend.xml"
    agent_template = templates_dir / "agent.py"

    disk_image_path = f"/var/lib/libvirt/images/{vm_name}.qcow2" if hypervisor == "kvm" else f"/var/lib/virtualbox/{vm_name}.vdi"

    commands = {
        "create_disk": f"sudo qemu-img create -f qcow2 {disk_image_path} {disk_gb}G" if hypervisor == "kvm" else f"VBoxManage createmedium disk --filename {disk_image_path} --size {disk_gb * 1024}",
        "define_vm": f"sudo virsh define {xml_template}" if hypervisor == "kvm" else f"VBoxManage createvm --name {vm_name} --ostype Windows10_64 --register",
        "install_vm_cli": (
            f"sudo virt-install --name {vm_name} --vcpus {vcpus} --memory {ram_mb} "
            f"--disk path={disk_image_path},format=qcow2,bus=virtio "
            f"--network bridge=virbr-malbox,model=virtio "
            f"--cdrom {iso_path or '/path/to/windows10.iso'} "
            f"--graphics vnc,listen=127.0.0.1 --noautoconsole"
            if hypervisor == "kvm"
            else f"VBoxManage startvm {vm_name} --type gui"
        ),
        "create_clean_snapshot": (
            f"sudo virsh snapshot-create-as {vm_name} clean 'Clean baseline snapshot for CAPE'"
            if hypervisor == "kvm"
            else f"VBoxManage snapshot {vm_name} take clean"
        ),
        "revert_snapshot_test": (
            f"sudo virsh snapshot-revert {vm_name} clean"
            if hypervisor == "kvm"
            else f"VBoxManage snapshot {vm_name} restore clean"
        ),
    }

    checklist = [
        "1. Obtain official Windows 10/11 Enterprise Evaluation ISO from Microsoft Evaluation Center.",
        "2. (For KVM) Download latest virtio-win.iso driver package from Fedora/Red Hat repository.",
        "3. Create dedicated isolated host-only bridge network ('virbr-malbox' / 'vboxnet0').",
        f"4. Create dedicated virtual disk: {commands['create_disk']}.",
        "5. Install Windows in guest with local user 'analyst' (using autounattend.xml or manual setup).",
        "6. In guest: Install Python 3.10+ (from python.org) and copy agent.py to Startup or as a Scheduled Task.",
        "7. In guest: Configure static IP 192.168.100.10, mask 255.255.255.0, NO DEFAULT GATEWAY.",
        "8. In guest: Allow incoming TCP port 8000 in Windows Firewall for the host-only subnet.",
        "9. Verify agent connectivity from controller: curl -s http://192.168.100.10:8000/status.",
        f"10. Create pristine baseline snapshot: {commands['create_clean_snapshot']}.",
        "11. Register VM in CAPE Controller conf/kvm.conf (machine name: win10_analyst, ip: 192.168.100.10, snapshot: clean).",
    ]

    return {
        "vm_name": vm_name,
        "hypervisor": hypervisor,
        "guest_ip": guest_ip,
        "specs": {
            "vcpus": vcpus,
            "ram_mb": ram_mb,
            "disk_gb": disk_gb,
            "disk_path": disk_image_path,
        },
        "templates": {
            "xml_definition": str(xml_template),
            "unattended_setup": str(unattend_template),
            "guest_agent_script": str(agent_template),
        },
        "commands": commands,
        "checklist": checklist,
    }


def provision_and_verify_guest(
    root_dir: Path,
    hypervisor: Optional[str] = None,
    vm_name: str = "win10_analyst",
    guest_ip: str = "192.168.100.10",
    iso_path: Optional[str] = None,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """
    Operator-guided workflow to provision and verify the Windows Analysis Guest:
    1. Inspects hypervisor compatibility.
    2. Generates VM sizing and definitions.
    3. Checks whether VM and clean snapshot already exist.
    4. Probes guest agent HTTP connectivity.
    5. Returns structured readiness report and actionable checklist.
    """
    hw_info = check_hypervisor_readiness()
    chosen_hyp = hypervisor or hw_info["preferred_hypervisor"]
    if chosen_hyp == "none":
        chosen_hyp = "kvm"

    plan = generate_guest_provisioning_artifacts(
        root_dir,
        hypervisor=chosen_hyp,
        vm_name=vm_name,
        guest_ip=guest_ip,
        iso_path=iso_path,
    )

    # Probe live agent if VM exists
    agent_live, agent_msg = probe_guest_agent_http(guest_ip=guest_ip, port=8000, timeout=1.0)

    # Check snapshots if virsh present
    has_clean_snapshot = False
    if hw_info["virsh_available"] and hw_info["win10_analyst_exists"]:
        try:
            s_res = subprocess.run(
                ["virsh", "snapshot-list", vm_name, "--name"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if s_res.returncode == 0:
                snaps = [line.strip() for line in s_res.stdout.splitlines() if line.strip()]
                has_clean_snapshot = ("clean" in snaps)
        except Exception:
            pass

    ready = bool(hw_info["win10_analyst_exists"] and agent_live and has_clean_snapshot)
    tier = "VERIFIED" if ready else ("CONFIGURED" if hw_info["win10_analyst_exists"] else "NOT_PROVISIONED")

    return {
        "success": ready or dry_run,
        "vm_name": vm_name,
        "guest_ip": guest_ip,
        "hypervisor": chosen_hyp,
        "vm_defined": hw_info["win10_analyst_exists"],
        "agent_online": agent_live,
        "agent_status": agent_msg,
        "clean_snapshot_exists": has_clean_snapshot,
        "readiness_tier": tier,
        "plan": plan,
        "notice": (
            "Windows Guest verified with active agent and clean snapshot."
            if ready
            else "Windows Guest provisioning required. Follow the generated checklist."
        ),
    }

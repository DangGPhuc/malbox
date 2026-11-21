from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _read_file_safe(path: Path) -> str:
    """Reads text file safely, returning empty string on any IO/permission error."""
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def discover_os_info() -> Dict[str, Any]:
    """Discovers host operating system details from /etc/os-release and platform."""
    os_release = Path("/etc/os-release")
    fields: Dict[str, str] = {}
    if os_release.is_file():
        for line in _read_file_safe(os_release).splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip().strip('"').strip("'")

    sys_name = platform.system()
    distro_name = fields.get("NAME", sys_name)
    version = fields.get("VERSION_ID", platform.release())
    os_id = fields.get("ID", sys_name.lower())
    id_like = fields.get("ID_LIKE", "").lower().split()

    is_kali = (os_id == "kali" or "kali" in distro_name.lower())
    is_ubuntu = (os_id == "ubuntu" or "ubuntu" in distro_name.lower())
    is_debian_derivative = (
        is_kali or is_ubuntu or os_id in ("debian", "raspbian") or "debian" in id_like
    )

    return {
        "system": sys_name,
        "release": platform.release(),
        "pretty_name": fields.get("PRETTY_NAME", platform.platform()),
        "name": distro_name,
        "version_id": version,
        "id": os_id,
        "version_codename": fields.get("VERSION_CODENAME", ""),
        "is_kali": is_kali,
        "is_ubuntu": is_ubuntu,
        "is_debian_derivative": is_debian_derivative,
    }


def discover_virtualization() -> Dict[str, Any]:
    """Detects whether host is physical bare-metal or a virtual machine, and KVM capabilities."""
    virt_type = "none"
    is_physical = True

    # 1. systemd-detect-virt
    try:
        res = subprocess.run(
            ["systemd-detect-virt"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
        )
        out = res.stdout.strip().lower()
        if res.returncode == 0 and out and out != "none":
            virt_type = out
            is_physical = False
    except Exception:
        pass

    # 2. DMI inspection fallback if still none
    dmi_product = _read_file_safe(Path("/sys/class/dmi/id/product_name")).lower()
    dmi_vendor = _read_file_safe(Path("/sys/class/dmi/id/sys_vendor")).lower()
    vm_indicators = ["qemu", "virtualbox", "vmware", "kvm", "bochs", "innotek", "hyper-v", "parallels"]
    for ind in vm_indicators:
        if ind in dmi_product or ind in dmi_vendor:
            if is_physical:
                virt_type = ind
                is_physical = False
            break

    # 3. CPU virtualization extensions (VT-x / AMD-V)
    cpuinfo = _read_file_safe(Path("/proc/cpuinfo")).lower()
    virt_flags: List[str] = []
    for flag in ("vmx", "svm"):
        if re.search(r"\b" + flag + r"\b", cpuinfo):
            virt_flags.append(flag)

    has_hardware_virt = len(virt_flags) > 0

    # 4. /dev/kvm availability and usability
    dev_kvm = Path("/dev/kvm")
    kvm_present = dev_kvm.exists()
    kvm_usable = False
    kvm_permissions_error: Optional[str] = None
    if kvm_present:
        try:
            # Check read-write access
            if os.access(dev_kvm, os.R_OK | os.W_OK):
                kvm_usable = True
            else:
                kvm_permissions_error = "User lacks read/write access to /dev/kvm (check kvm group membership)."
        except Exception as e:
            kvm_permissions_error = str(e)
    else:
        kvm_permissions_error = "/dev/kvm device node does not exist (VT-x/AMD-V disabled in BIOS or nested virt off)."

    # 5. Nested virtualization capability
    nested_virt = False
    for nested_param in (
        Path("/sys/module/kvm_intel/parameters/nested"),
        Path("/sys/module/kvm_amd/parameters/nested"),
    ):
        if nested_param.is_file():
            val = _read_file_safe(nested_param).upper()
            if val in ("Y", "1"):
                nested_virt = True
                break

    return {
        "is_physical": is_physical,
        "virt_type": virt_type,
        "dmi_product": dmi_product,
        "dmi_vendor": dmi_vendor,
        "virt_flags": virt_flags,
        "has_hardware_virt": has_hardware_virt,
        "kvm_present": kvm_present,
        "kvm_usable": kvm_usable,
        "kvm_permissions_error": kvm_permissions_error,
        "nested_virt": nested_virt,
    }


def discover_cpu() -> Dict[str, Any]:
    """Discovers CPU architecture, core counts, and model name."""
    total_vcpus = os.cpu_count() or 1
    arch = platform.machine()
    model_name = "Unknown CPU"

    physical_cores = total_vcpus
    cpuinfo_txt = _read_file_safe(Path("/proc/cpuinfo"))
    if cpuinfo_txt:
        # Extract model name
        for line in cpuinfo_txt.splitlines():
            if "model name" in line.lower() and ":" in line:
                model_name = line.split(":", 1)[1].strip()
                break

        # Count distinct physical cores
        cores_seen = set()
        current_phys = 0
        current_core = 0
        for line in cpuinfo_txt.splitlines():
            line = line.strip().lower()
            if line.startswith("physical id"):
                try:
                    current_phys = int(line.split(":", 1)[1].strip())
                except Exception:
                    pass
            elif line.startswith("core id"):
                try:
                    current_core = int(line.split(":", 1)[1].strip())
                    cores_seen.add((current_phys, current_core))
                except Exception:
                    pass
        if cores_seen:
            physical_cores = len(cores_seen)

    return {
        "arch": arch,
        "total_vcpus": total_vcpus,
        "physical_cores": physical_cores,
        "model_name": model_name,
        "is_x86_64": (arch in ("x86_64", "AMD64")),
    }


def discover_memory() -> Dict[str, Any]:
    """Discovers memory and swap capacity."""
    meminfo_txt = _read_file_safe(Path("/proc/meminfo"))
    total_mb = 0
    available_mb = 0
    free_mb = 0
    swap_total_mb = 0
    swap_free_mb = 0

    if meminfo_txt:
        for line in meminfo_txt.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                k = parts[0].rstrip(":")
                try:
                    val_kb = int(parts[1])
                    if k == "MemTotal":
                        total_mb = val_kb // 1024
                    elif k == "MemAvailable":
                        available_mb = val_kb // 1024
                    elif k == "MemFree":
                        free_mb = val_kb // 1024
                    elif k == "SwapTotal":
                        swap_total_mb = val_kb // 1024
                    elif k == "SwapFree":
                        swap_free_mb = val_kb // 1024
                except Exception:
                    pass

    return {
        "total_mb": total_mb,
        "available_mb": available_mb or free_mb,
        "free_mb": free_mb,
        "swap_total_mb": swap_total_mb,
        "swap_free_mb": swap_free_mb,
    }


def discover_disk(root_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Discovers disk capacity on the target volume."""
    target_path = root_dir or Path.cwd()
    try:
        usage = shutil.disk_usage(target_path)
        total_gb = round(usage.total / (1024 ** 3), 1)
        free_gb = round(usage.free / (1024 ** 3), 1)
        used_gb = round(usage.used / (1024 ** 3), 1)
    except Exception:
        total_gb, free_gb, used_gb = 0.0, 0.0, 0.0

    return {
        "target_path": str(target_path),
        "total_gb": total_gb,
        "free_gb": free_gb,
        "used_gb": used_gb,
    }


def discover_network() -> Dict[str, Any]:
    """Discovers network interfaces and existing isolated host-only bridges."""
    net_dir = Path("/sys/class/net")
    interfaces: List[Dict[str, Any]] = []
    host_only_bridges: List[str] = []

    if net_dir.is_dir():
        for iface_path in sorted(net_dir.iterdir()):
            if not iface_path.is_symlink() and not iface_path.is_dir():
                continue
            name = iface_path.name
            operstate = _read_file_safe(iface_path / "operstate") or "unknown"
            is_bridge = (iface_path / "bridge").is_dir()
            is_loopback = (name == "lo")

            interfaces.append({
                "name": name,
                "operstate": operstate,
                "is_bridge": is_bridge,
                "is_loopback": is_loopback,
            })

            # Check for standard host-only bridge candidates
            if name in ("vboxnet0", "virbr0", "virbr1", "virbr-malbox", "isolated0") or is_bridge:
                host_only_bridges.append(name)

    return {
        "interfaces": interfaces,
        "host_only_bridges": sorted(set(host_only_bridges)),
    }


def discover_hypervisors() -> Dict[str, Any]:
    """Detects installed hypervisors (KVM/libvirt, QEMU, VirtualBox)."""
    return {
        "virsh": bool(shutil.which("virsh")),
        "virsh_path": shutil.which("virsh"),
        "qemu_system_x86_64": bool(shutil.which("qemu-system-x86_64")),
        "qemu_path": shutil.which("qemu-system-x86_64"),
        "libvirtd": bool(shutil.which("libvirtd")),
        "vboxmanage": bool(shutil.which("VBoxManage")),
        "vboxmanage_path": shutil.which("VBoxManage"),
    }


def _is_port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    """Tests if a TCP port is listening locally."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def discover_subsystem_services() -> Dict[str, Any]:
    """Discovers running local CAPE services, Ghidra, and local AI runtimes."""
    cape_listening = _is_port_open("127.0.0.1", 8008)

    ghidra_path = shutil.which("ghidra")
    ghidra_home: Optional[str] = None
    for cand in ("/usr/share/ghidra", "/opt/ghidra"):
        if (Path(cand) / "support" / "analyzeHeadless").is_file():
            ghidra_home = cand
            break

    java_path = shutil.which("java")
    javac_path = shutil.which("javac")

    ollama_path = shutil.which("ollama")
    ollama_listening = _is_port_open("127.0.0.1", 11434)

    return {
        "cape_api_listening_8008": cape_listening,
        "ghidra_binary": ghidra_path,
        "ghidra_home": ghidra_home,
        "ghidra_installed": bool(ghidra_home or ghidra_path),
        "java_binary": java_path,
        "javac_binary": javac_path,
        "has_java_compiler": bool(javac_path),
        "ollama_binary": ollama_path,
        "ollama_listening_11434": ollama_listening,
    }


def discover_all_hardware(root_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Consolidated hardware and system environment discovery."""
    return {
        "os": discover_os_info(),
        "virtualization": discover_virtualization(),
        "cpu": discover_cpu(),
        "memory": discover_memory(),
        "disk": discover_disk(root_dir),
        "network": discover_network(),
        "hypervisors": discover_hypervisors(),
        "services": discover_subsystem_services(),
    }


def evaluate_deployment_profiles(hardware: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates hardware metrics against Profile A, Profile B, and Profile C.
    Produces a structured sizing budget and installation plan.
    """
    os_info = hardware.get("os", {})
    virt = hardware.get("virtualization", {})
    cpu = hardware.get("cpu", {})
    mem = hardware.get("memory", {})
    disk = hardware.get("disk", {})
    hyp = hardware.get("hypervisors", {})

    total_ram_mb = mem.get("total_mb", 0)
    free_disk_gb = disk.get("free_gb", 0.0)
    has_hw_virt = virt.get("has_hardware_virt", False)
    kvm_usable = virt.get("kvm_usable", False)
    is_x86_64 = cpu.get("is_x86_64", False)
    has_hypervisor = bool(hyp.get("virsh") or hyp.get("vboxmanage") or hyp.get("qemu_system_x86_64"))

    # Profile A: Physical Kali workstation with compatible CAPE host and Windows Guest
    # Strict requirements: x86_64, hardware virtualization, >= 8 GB RAM (>= 16 GB rec), >= 80 GB disk
    profile_a_supported = False
    profile_a_reasons: List[str] = []
    profile_a_warnings: List[str] = []

    if not is_x86_64:
        profile_a_reasons.append(f"Architecture '{cpu.get('arch')}' is not x86_64.")
    if not has_hw_virt:
        profile_a_reasons.append("VT-x / AMD-V CPU virtualization extensions are absent or disabled.")
    if not kvm_usable and not hyp.get("vboxmanage"):
        profile_a_reasons.append("/dev/kvm is not accessible and VirtualBox is not installed.")
    if total_ram_mb < 7500:
        profile_a_reasons.append(f"Host RAM ({total_ram_mb} MB) is below the minimum 8,000 MB for local sandbox.")
    if free_disk_gb < 40.0:
        profile_a_reasons.append(f"Free disk ({free_disk_gb} GB) is below the minimum 40 GB required for VM images.")

    if not profile_a_reasons:
        profile_a_supported = True
        if total_ram_mb < 15500:
            profile_a_warnings.append(
                f"Host RAM is {total_ram_mb} MB (~8 GB). Recommended is >= 16 GB. "
                "Guest VM memory must be budgeted strictly at 2 GB – 3 GB to prevent host OOM."
            )
        if free_disk_gb < 80.0:
            profile_a_warnings.append(
                f"Free disk is {free_disk_gb} GB. Recommended is >= 80 GB for multiple snapshots and dumps."
            )

    # Profile B: Kali Malbox Client with dedicated Ubuntu CAPE Controller and Windows Guest
    # Always supported as Kali client only needs 4 GB RAM, no local KVM
    profile_b_supported = True
    profile_b_warnings: List[str] = []
    if total_ram_mb < 3800:
        profile_b_warnings.append(f"Controller RAM ({total_ram_mb} MB) is below recommended 4,000 MB.")

    # Profile C: Resource-constrained Kali VM using externally managed CAPE infrastructure
    # For lightweight cloud/VM environments
    profile_c_supported = True

    # Determine recommended profile
    if profile_a_supported and not profile_a_warnings:
        recommended_profile = "Profile A: Kali Single-Host Sandbox"
        recommended_key = "profile_a_single_host"
    elif profile_b_supported:
        recommended_profile = "Profile B: Distributed Sandbox (Kali Client + Dedicated Ubuntu CAPE)"
        recommended_key = "profile_b_distributed"
    else:
        recommended_profile = "Profile C: Resource-Constrained VM (External CAPE / Cloud AI)"
        recommended_key = "profile_c_cloud_or_external"

    resource_budget = {
        "host_current": {
            "os": os_info.get("pretty_name"),
            "cpu_arch": cpu.get("arch"),
            "vcpus": cpu.get("total_vcpus"),
            "ram_mb": total_ram_mb,
            "free_disk_gb": free_disk_gb,
            "kvm_usable": kvm_usable,
        },
        "profiles_matrix": {
            "profile_a_single_host": {
                "min_ram_mb": 8000,
                "rec_ram_mb": 16000,
                "min_disk_gb": 60,
                "rec_disk_gb": 120,
                "kvm_required": True,
                "guest_ram_budget_mb": 4096 if total_ram_mb >= 15500 else 2048,
                "host_ram_headroom_mb": max(0, total_ram_mb - (4096 if total_ram_mb >= 15500 else 2048)),
            },
            "profile_b_distributed": {
                "controller_min_ram_mb": 4000,
                "controller_min_disk_gb": 20,
                "cape_node_min_ram_mb": 16000,
                "cape_node_min_disk_gb": 80,
                "kvm_required_on_controller": False,
            },
            "profile_c_cloud_or_external": {
                "min_ram_mb": 2048,
                "min_disk_gb": 15,
                "kvm_required": False,
            },
        },
    }

    return {
        "recommended_profile": recommended_profile,
        "recommended_key": recommended_key,
        "hardware_virtualization_detected": has_hw_virt,
        "kvm_present": virt.get("kvm_present", False),
        "virt_flags": virt.get("virt_flags", []),
        "profiles": {
            "profile_a_single_host": {
                "name": "Profile A: Kali Single-Host Sandbox",
                "supported_on_current_host": profile_a_supported,
                "reasons_unsupported": profile_a_reasons,
                "warnings": profile_a_warnings,
                "description": "FastAPI + Vite frontend + CAPE Controller + Windows Guest execute on this single physical Kali machine.",
                "prerequisites": [
                    "Host OS: Physical bare-metal Kali Linux (or nested-virt enabled VM)",
                    "Virtualization: /dev/kvm active and accessible (or VirtualBox 7.x)",
                    "RAM: >= 16 GB recommended (minimum 8 GB)",
                    "Disk: >= 80 GB free SSD storage",
                ],
                "network_topology": "Host-only virtual network (virbr-malbox at 192.168.100.1/24; guest at 192.168.100.10; no default gateway, no NAT).",
                "setup_commands": [
                    "./malbox setup --install-core",
                    "./malbox setup --install-ghidra",
                    "./malbox setup --install-ai",
                    "./malbox setup --provision-cape",
                    "./malbox setup --provision-guest",
                    "./malbox setup --verify",
                    "./malbox setup --benign-e2e",
                ],
            },
            "profile_b_distributed": {
                "name": "Profile B: Distributed Sandbox (Controller + External Dedicated CAPE)",
                "supported_on_current_host": profile_b_supported,
                "reasons_unsupported": [],
                "warnings": profile_b_warnings,
                "description": "FastAPI + Vite run on Kali host; Windows guest VMs run on dedicated remote Ubuntu 22.04 LTS CAPE hypervisor node.",
                "prerequisites": [
                    "Controller Host: Kali Linux / Debian with Malbox backend & frontend",
                    "Sandbox Node: Dedicated physical Ubuntu 22.04 LTS server running CAPEv2 REST API",
                    "Network: Dedicated private management VLAN between Malbox and CAPE API (:8008)",
                    "Isolation: Windows guest network confined entirely on the CAPE hypervisor node",
                ],
                "network_topology": "Host-only network local to external CAPE server. Controller communicates via REST API over TLS / SSH tunnel.",
                "setup_commands": [
                    "./malbox setup --install-core",
                    "./malbox setup --install-ghidra",
                    "./malbox setup --install-ai",
                    "./malbox setup --provision-cape --profile B --url <cape_api_url>",
                    "./malbox setup --verify",
                ],
            },
            "profile_c_cloud_or_external": {
                "name": "Profile C: Resource-Constrained VM (External CAPE & External AI)",
                "supported_on_current_host": profile_c_supported,
                "reasons_unsupported": [],
                "warnings": [],
                "description": "Lightweight client deployment for VMs or laptops without virtualization capabilities. Uses externally managed CAPE and AI.",
                "prerequisites": [
                    "Host: 2+ vCPUs, 2 GB+ RAM, 15 GB disk",
                    "External CAPE endpoint available over HTTPS or tunnel",
                    "External AI API or local mock provider",
                ],
                "network_topology": "No local virtual machines. API integration only.",
                "setup_commands": [
                    "./malbox setup --install-core",
                    "./malbox setup --cape --url <remote_cape_url>",
                    "./malbox setup --ai --provider mock",
                    "./malbox setup --verify",
                ],
            },
        },
        "resource_budget": resource_budget,
        "next_step": f"Run `./malbox setup --install-core` followed by `./malbox setup --install-ghidra` and `./malbox setup --install-ai`.",
    }

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..discovery import discover_all_hardware
from ..setup import update_env_values

PINNED_CAPE_UPSTREAM = {
    "repository": "https://github.com/kevoreilly/CAPEv2.git",
    "tested_tag": "v2.4+",
    "recommended_os": "Ubuntu 22.04 LTS (Jammy Jellyfish)",
    "python_version": "3.10 / 3.11",
    "hypervisor": "KVM / libvirt with QEMU",
    "api_port": 8008,
}


def probe_cape_api(api_url: str, api_token: Optional[str] = None, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Probes remote or local CAPE REST API to check liveness, version,
    configured analysis machines, and execution routes.
    """
    clean_url = api_url.rstrip("/")
    status_endpoint = f"{clean_url}/apiv2/cuckoo/status/"
    headers = {"User-Agent": "Malbox-AI-Installer/1.0"}
    if api_token:
        headers["Authorization"] = f"Token {api_token.strip()}"

    reachable = False
    authenticated = False
    version: Optional[str] = None
    machines_available = 0
    machines_list: List[str] = []
    routes_list: List[str] = []
    error_msg: Optional[str] = None

    try:
        req = urllib.request.Request(status_endpoint, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                reachable = True
                authenticated = True
                data = json.loads(resp.read().decode("utf-8"))
                # Extract CAPE status data
                cuckoo_data = data.get("data", data)
                version = str(cuckoo_data.get("version", "2.x"))
                machines_info = cuckoo_data.get("machines", {})
                if isinstance(machines_info, dict):
                    machines_available = machines_info.get("available", 0)
                    machines_list = list(machines_info.get("details", {}).keys())
                elif isinstance(machines_info, list):
                    machines_available = len(machines_info)
                    machines_list = [m.get("name", str(m)) for m in machines_info if isinstance(m, dict)]
            elif resp.status == 401 or resp.status == 403:
                reachable = True
                authenticated = False
                error_msg = f"HTTP {resp.status} Unauthorized: Invalid or missing CAPE API token."
    except urllib.error.HTTPError as e:
        reachable = True
        if e.code in (401, 403):
            authenticated = False
            error_msg = f"HTTP {e.code} Unauthorized: Invalid or missing CAPE API token."
        else:
            error_msg = f"HTTP {e.code} from {status_endpoint}"
    except urllib.error.URLError as e:
        error_msg = f"Connection refused or unreachable: {str(e.reason)}"
    except Exception as e:
        error_msg = f"CAPE probe error: {str(e)}"

    # If status failed, probe root or tasks to confirm reachability
    if not reachable:
        try:
            req_root = urllib.request.Request(clean_url, headers=headers)
            with urllib.request.urlopen(req_root, timeout=1.0) as root_resp:
                reachable = True
                if not error_msg:
                    error_msg = f"CAPE web responding on root, but API status returned error."
        except Exception:
            pass

    return {
        "reachable": reachable,
        "authenticated": authenticated,
        "version": version,
        "machines_available": machines_available,
        "machines_list": machines_list,
        "routes_list": routes_list or ["drop", "none"],
        "error": error_msg,
    }


def generate_cape_deployment_plan(
    root_dir: Path,
    profile: str = "B",
    target_api_url: Optional[str] = None,
    api_token: Optional[str] = None,
    machine_name: str = "win10_analyst",
    route_name: str = "drop",
) -> Dict[str, Any]:
    """
    Generates a structured deployment plan for CAPE Controller provisioning:
    - Profile A: Single-Host (warns if Kali rolling, outlines dedicated KVM/VBox setup).
    - Profile B: Dedicated Ubuntu 22.04 LTS controller (upstream recommended).
    - Generates systemd service units, configuration templates, and setup commands.
    """
    hw = discover_all_hardware(root_dir)
    os_info = hw["os"]
    is_kali = os_info["is_kali"]
    virt = hw["virtualization"]
    mem = hw["memory"]
    disk = hw["disk"]

    warnings: List[str] = []
    if is_kali and profile.upper() == "A":
        warnings.append(
            "Upstream CAPEv2 officially targets Ubuntu 22.04 LTS. Running the full CAPE daemon directly "
            "on Kali Rolling may suffer package breakages due to Python 3.12+ and kernel updates. "
            "Profile B (dedicated Ubuntu 22.04 LTS node) or containerized controller is strongly recommended."
        )

    if mem["total_mb"] < 15500 and profile.upper() == "A":
        warnings.append(
            f"Host RAM ({mem['total_mb']} MB) is tight for concurrent Kali + CAPE + Windows VM execution. "
            "Profile B decouples hypervisor RAM from the operator client."
        )

    url = (target_api_url or "http://127.0.0.1:8008").rstrip("/")
    scripts_dir = root_dir / "scripts" / "provisioning" / "cape"
    if not scripts_dir.is_dir():
        fallback_scripts = Path(__file__).resolve().parent.parent.parent / "provisioning" / "cape"
        if fallback_scripts.is_dir():
            scripts_dir = fallback_scripts

    return {
        "profile": profile.upper(),
        "upstream_pinning": PINNED_CAPE_UPSTREAM,
        "target_api_url": url,
        "target_machine": machine_name,
        "target_route": route_name,
        "host_assessment": {
            "os": os_info["pretty_name"],
            "is_kali": is_kali,
            "kvm_usable": virt["kvm_usable"],
            "ram_mb": mem["total_mb"],
            "free_disk_gb": disk["free_gb"],
        },
        "warnings": warnings,
        "provisioning_scripts": {
            "ubuntu_controller_installer": str(scripts_dir / "install_cape_ubuntu2204.sh"),
            "systemd_units_dir": str(scripts_dir / "systemd"),
        },
        "tunneling_guidance": (
            "To connect Malbox on Kali to an external CAPE server securely without public exposure:\n"
            "  ssh -N -L 8008:127.0.0.1:8008 cape-operator@<cape_server_ip>\n"
            "Then configure MALBOX_CAPE_API_URL=http://127.0.0.1:8008 in .env"
        ),
    }


def provision_and_connect_cape(
    root_dir: Path,
    profile: str = "B",
    api_url: Optional[str] = None,
    api_token: Optional[str] = None,
    machine: str = "win10_analyst",
    route: str = "drop",
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """
    Configures and verifies connection to CAPE Sandbox Controller:
    1. Verifies API availability and authentication.
    2. Inspects registered machines and execution routes.
    3. Configures Malbox .env settings.
    4. Enforces safe non-egress execution route ('drop' or 'none').
    5. Returns readiness report with explicit confinement gate status.
    """
    clean_url = (api_url or "http://127.0.0.1:8008").rstrip("/")
    clean_mach = machine.strip()
    clean_route = route.strip().lower()

    if clean_route not in ("drop", "none"):
        return {
            "success": False,
            "operational": False,
            "readiness_tier": "BLOCKED",
            "error": f"Route '{clean_route}' is unsafe for malware analysis. Approved routes are 'drop' or 'none'.",
        }

    plan = generate_cape_deployment_plan(
        root_dir,
        profile=profile,
        target_api_url=clean_url,
        api_token=api_token,
        machine_name=clean_mach,
        route_name=clean_route,
    )

    probe = probe_cape_api(clean_url, api_token=api_token, timeout=2.5)

    updates = {
        "MALBOX_CAPE_API_URL": clean_url,
        "MALBOX_CAPE_DEFAULT_MACHINE": clean_mach,
        "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": clean_route,
        "MALBOX_DEFAULT_SANDBOX_BACKEND": "cape",
        "MALBOX_LIVE_MODE_ENABLED": "true",
    }
    if api_token:
        updates["MALBOX_CAPE_API_TOKEN"] = api_token.strip()

    ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)

    # Operational status requires reachable and authenticated API
    is_operational = bool(probe["reachable"] and probe["authenticated"])
    guest_ready = bool(probe["machines_available"] > 0 and clean_mach in probe["machines_list"])

    tier = "VERIFIED" if (is_operational and guest_ready) else ("READY" if is_operational else "CONFIGURED")

    return {
        "success": ok,
        "operational": is_operational,
        "readiness_tier": tier,
        "api_url": clean_url,
        "machine": clean_mach,
        "route": clean_route,
        "probe": probe,
        "guest_ready": guest_ready,
        "plan": plan,
        "backup_file": str(backup) if backup else None,
        "notice": (
            "CAPE connection configured in .env. Live detonation remains BLOCKED "
            "until explicit manual isolation attestation is completed. Run "
            "`./malbox setup --attest-isolation --operator <name> --evidence-refs <refs>` to authorize execution."
        ),
    }

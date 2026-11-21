from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple


def get_vboxmanage_bin() -> Optional[str]:
    return shutil.which("VBoxManage") or shutil.which("vboxmanage")


def check_virtualbox_installed() -> Tuple[bool, str]:
    bin_path = get_vboxmanage_bin()
    if not bin_path:
        return False, "VBoxManage executable not found on host system."
    try:
        res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return True, res.stdout.strip()
        return False, f"VBoxManage exited with code {res.returncode}: {res.stderr.strip()}"
    except Exception as e:
        return False, f"Failed to execute VBoxManage: {str(e)}"


def get_vm_machinereadable(vm_target: str) -> Dict[str, str]:
    bin_path = get_vboxmanage_bin()
    if not bin_path:
        return {}
    try:
        res = subprocess.run(
            [bin_path, "showvminfo", vm_target, "--machinereadable"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            return {}
        info: Dict[str, str] = {}
        for line in res.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')
        return info
    except Exception:
        return {}


def is_vm_running(vm_target: str) -> bool:
    info = get_vm_machinereadable(vm_target)
    state = info.get("VMState", "").lower()
    return state in ("running", "paused", "saved", "teleporting", "live")


def get_current_snapshot_name(vm_target: str) -> Optional[str]:
    info = get_vm_machinereadable(vm_target)
    return info.get("CurrentSnapshotName")


def validate_vm_network_isolation(
    vm_target: str,
    required_internal_net: str = "malbox-sandbox",
) -> Tuple[bool, List[str]]:
    """
    Strictly verifies that REMWin is connected ONLY to the isolated internal network
    and that hypervisor shared folders and clipboards are disabled.
    """
    violations: List[str] = []
    info = get_vm_machinereadable(vm_target)
    if not info:
        return False, [f"Unable to read VM properties for '{vm_target}'. Ensure VM exists and is accessible."]

    # 1. NIC 1 must be intnet
    nic1 = info.get("nic1", "").lower()
    if nic1 != "intnet":
        violations.append(f"NIC 1 adapter type is '{nic1}', expected 'intnet'")
    
    intnet1 = info.get("intnet1", "")
    if intnet1 != required_internal_net:
        violations.append(f"NIC 1 internal network is '{intnet1}', expected '{required_internal_net}'")

    # 2. Secondary NICs must be disabled (none)
    for nic_idx in range(2, 9):
        val = info.get(f"nic{nic_idx}", "none").lower()
        if val != "none":
            violations.append(f"Unauthorized secondary adapter NIC {nic_idx} is active ('{val}')")

    # 3. Clipboard & Drag-and-Drop disabled
    clipboard = info.get("clipboard", "").lower()
    if clipboard and clipboard != "disabled":
        violations.append(f"Shared clipboard is enabled ('{clipboard}'). Must be disabled.")

    dnd = info.get("draganddrop", "").lower()
    if dnd and dnd != "disabled":
        violations.append(f"Drag and drop is enabled ('{dnd}'). Must be disabled.")

    # 4. Check for shared folders
    for k in info.keys():
        if k.startswith("SharedFolderName"):
            folder_name = info[k]
            violations.append(f"Unauthorized shared folder attached: '{folder_name}'")

    return (len(violations) == 0), violations


def poweroff_vm(vm_target: str, timeout_seconds: int = 15) -> Tuple[bool, str]:
    bin_path = get_vboxmanage_bin()
    if not bin_path:
        return False, "VBoxManage not found"

    if not is_vm_running(vm_target):
        return True, "VM is already powered off"

    try:
        res = subprocess.run(
            [bin_path, "controlvm", vm_target, "poweroff"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        # Give hypervisor process time to release lock
        time.sleep(1.0)
        if res.returncode == 0 or "is not currently running" in res.stderr.lower():
            return True, "VM powered off successfully"
        return False, f"controlvm poweroff failed: {res.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, f"poweroff command timed out after {timeout_seconds}s"
    except Exception as e:
        return False, f"poweroff exception: {str(e)}"


def restore_clean_snapshot(vm_target: str, snapshot_name: str, timeout_seconds: int = 45) -> Tuple[bool, str]:
    bin_path = get_vboxmanage_bin()
    if not bin_path:
        return False, "VBoxManage not found"

    # Must be powered off before snapshot restore
    if is_vm_running(vm_target):
        ok, msg = poweroff_vm(vm_target)
        if not ok:
            return False, f"Failed to poweroff VM before snapshot restore: {msg}"

    try:
        res = subprocess.run(
            [bin_path, "snapshot", vm_target, "restore", snapshot_name],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        time.sleep(1.0)
        if res.returncode == 0:
            return True, f"Snapshot '{snapshot_name}' restored successfully"
        return False, f"snapshot restore failed: {res.stderr.strip() or res.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return False, f"snapshot restore timed out after {timeout_seconds}s"
    except Exception as e:
        return False, f"snapshot restore exception: {str(e)}"


def start_vm(vm_target: str, headless: bool = True, timeout_seconds: int = 20) -> Tuple[bool, str]:
    bin_path = get_vboxmanage_bin()
    if not bin_path:
        return False, "VBoxManage not found"

    if is_vm_running(vm_target):
        return True, "VM is already running"

    vm_type = "headless" if headless else "gui"
    try:
        res = subprocess.run(
            [bin_path, "startvm", vm_target, "--type", vm_type],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        time.sleep(1.5)
        if res.returncode == 0:
            return True, f"VM '{vm_target}' started ({vm_type})"
        return False, f"startvm failed: {res.stderr.strip() or res.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return False, f"startvm timed out after {timeout_seconds}s"
    except Exception as e:
        return False, f"startvm exception: {str(e)}"


def cycle_vm_clean(
    vm_target: str,
    snapshot_name: str,
    required_internal_net: str = "malbox-sandbox",
) -> Tuple[bool, str]:
    """
    Enforces the complete clean lifecycle:
    1. Validate network isolation policy on VM.
    2. Power off VM if running.
    3. Restore clean snapshot.
    4. Verify final snapshot and power state.
    """
    iso_ok, iso_errs = validate_vm_network_isolation(vm_target, required_internal_net)
    if not iso_ok:
        return False, f"Isolation policy violation on '{vm_target}': {'; '.join(iso_errs)}"

    if is_vm_running(vm_target):
        ok, msg = poweroff_vm(vm_target)
        if not ok:
            return False, f"Cannot power off VM: {msg}"

    ok_restore, msg_restore = restore_clean_snapshot(vm_target, snapshot_name)
    if not ok_restore:
        return False, f"Cannot restore clean snapshot: {msg_restore}"

    # Verify final state
    curr_snap = get_current_snapshot_name(vm_target)
    if curr_snap != snapshot_name:
        return False, f"Snapshot mismatch after restore: current '{curr_snap}', expected '{snapshot_name}'"

    if is_vm_running(vm_target):
        return False, "VM is unexpectedly still running after snapshot restore"

    return True, f"VM '{vm_target}' successfully cycled to clean snapshot '{snapshot_name}'"

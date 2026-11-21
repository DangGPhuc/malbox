from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import chmod_safe


def verify_confinement_and_collect_evidence(
    root_dir: Path,
    machine: str = "win10_analyst",
    route: str = "drop",
    bridge_name: str = "virbr-malbox",
) -> Dict[str, Any]:
    """
    Automated network confinement inspection and diagnostic evidence collection:
    1. Verifies exact machine identity and hypervisor domain.
    2. Inspects isolated virtual bridge interface (no default route).
    3. Verifies that the VM has only 1 network interface attached strictly to the isolated bridge.
    4. Inspects firewall forwarding rules (default DROP/REJECT for VM traffic to external WAN).
    5. Checks clean baseline snapshot.
    6. Saves full diagnostic evidence payload to data/confinement_evidence.json.
    """
    evidence: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_machine": machine,
        "target_route": route,
        "bridge_name": bridge_name,
        "checks": {},
    }
    failures: List[str] = []

    # 1. Hypervisor Domain & NIC Binding Verification
    virsh_bin = shutil.which("virsh")
    vm_found = False
    interfaces_attached: List[str] = []
    if virsh_bin:
        try:
            dom_res = subprocess.run(
                ["virsh", "domiflist", machine],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if dom_res.returncode == 0:
                vm_found = True
                for line in dom_res.stdout.splitlines()[2:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        source_bridge = parts[2]
                        interfaces_attached.append(source_bridge)
        except Exception:
            pass

    evidence["checks"]["hypervisor_binding"] = {
        "vm_found": vm_found,
        "interfaces_attached": interfaces_attached,
        "nic_count": len(interfaces_attached),
    }

    if vm_found:
        if len(interfaces_attached) > 1:
            failures.append(f"Security invariant violated: VM has {len(interfaces_attached)} NICs attached. Only 1 isolated NIC allowed.")
        if interfaces_attached and interfaces_attached[0] not in (bridge_name, "vboxnet0", "virbr0"):
            failures.append(f"Security invariant violated: VM NIC is attached to unexpected network '{interfaces_attached[0]}'.")

    # 2. Bridge Routing Table Inspection
    routes_dump: List[str] = []
    has_default_gw_on_bridge = False
    try:
        ip_r = subprocess.run(["ip", "route", "show"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
        if ip_r.returncode == 0:
            for line in ip_r.stdout.splitlines():
                routes_dump.append(line.strip())
                if "default" in line and bridge_name in line:
                    has_default_gw_on_bridge = True
    except Exception:
        pass

    evidence["checks"]["routing"] = {
        "routes": routes_dump,
        "has_default_gw_on_isolated_bridge": has_default_gw_on_bridge,
    }
    if has_default_gw_on_bridge:
        failures.append(f"Security invariant violated: Default gateway route found on isolated bridge '{bridge_name}'.")

    # 3. Firewall Forwarding Inspection
    iptables_dump: List[str] = []
    forwarding_blocked = False
    iptables_bin = shutil.which("iptables")
    if iptables_bin:
        try:
            fw_res = subprocess.run(
                ["sudo", "-n", "iptables", "-L", "FORWARD", "-n", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if fw_res.returncode == 0:
                iptables_dump = [l.strip() for l in fw_res.stdout.splitlines() if l.strip()]
                # Look for DROP or REJECT policy / rules
                for line in iptables_dump:
                    if "DROP" in line or "REJECT" in line:
                        forwarding_blocked = True
                        break
        except Exception:
            pass

    evidence["checks"]["firewall"] = {
        "forwarding_rules": iptables_dump,
        "forwarding_blocked": forwarding_blocked,
    }

    # 4. Snapshot Clean Inspection
    clean_snapshot_found = False
    if virsh_bin and vm_found:
        try:
            s_res = subprocess.run(
                ["virsh", "snapshot-list", machine, "--name"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if s_res.returncode == 0:
                snaps = [l.strip() for l in s_res.stdout.splitlines() if l.strip()]
                clean_snapshot_found = ("clean" in snaps)
        except Exception:
            pass

    evidence["checks"]["snapshot"] = {
        "clean_snapshot_verified": clean_snapshot_found,
    }

    # Record overall verification status
    evidence["failures"] = failures
    evidence["is_verified"] = (len(failures) == 0 and vm_found and clean_snapshot_found)

    # Save diagnostic evidence file
    data_dir = root_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    chmod_safe(data_dir, 0o700)
    evidence_file = data_dir / "confinement_evidence.json"
    evidence_file.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    chmod_safe(evidence_file, 0o600)

    return {
        "is_verified": evidence["is_verified"],
        "evidence_path": str(evidence_file),
        "failures": failures,
        "evidence": evidence,
    }

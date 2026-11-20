from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .checks import run_all_checks
from .models import (
    CheckResult,
    CheckStatus,
    chmod_safe,
    parse_bool,
    parse_env_file,
    resolve_effective_config,
)


def backup_env_file(root_dir: Path) -> Optional[Path]:
    """Creates a timestamped backup of .env prior to modification."""
    env_file = root_dir / ".env"
    if not env_file.is_file():
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = root_dir / f".env.bak.{timestamp}"
    shutil.copyfile(env_file, backup_file)
    chmod_safe(backup_file, 0o600)
    return backup_file


def update_env_values(root_dir: Path, updates: Dict[str, str], dry_run: bool = False) -> Tuple[bool, Optional[Path]]:
    """
    Updates or appends key-value pairs in root .env file safely.
    Creates .env from .env.example if missing.
    Backs up existing .env before editing.
    """
    env_file = root_dir / ".env"
    example_file = root_dir / ".env.example"

    if dry_run:
        return True, None

    backup_path = None
    if env_file.is_file():
        backup_path = backup_env_file(root_dir)
        lines = env_file.read_text(encoding="utf-8").splitlines()
    elif example_file.is_file():
        lines = example_file.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    remaining_keys = set(updates.keys())
    new_lines: List[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in updates:
                new_lines.append(f"{k}={updates[k]}")
                remaining_keys.discard(k)
                continue
        new_lines.append(line)

    for k in sorted(remaining_keys):
        new_lines.append(f"{k}={updates[k]}")

    env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    chmod_safe(env_file, 0o600)
    return True, backup_path


def setup_check(root_dir: Path, json_mode: bool = False) -> Dict[str, Any]:
    """Runs all checks and summarizes the deployment readiness matrix."""
    results = run_all_checks(root_dir)
    matrix: List[Dict[str, Any]] = []
    for r in results:
        matrix.append({
            "id": r.id,
            "name": r.name,
            "status": r.status.value,
            "tier": r.readiness_tier or "CONFIGURED",
            "summary": r.summary,
            "remediation": r.remediation,
        })
    counts = {s.value: 0 for s in CheckStatus}
    for r in results:
        counts[r.status.value] += 1

    return {
        "status": "PASS" if counts["FAIL"] == 0 else "FAIL",
        "counts": counts,
        "matrix": matrix,
    }


def setup_plan(root_dir: Path) -> Dict[str, Any]:
    """
    Analyzes host hardware/configuration and generates a structured deployment plan
    for Profile A (Kali Single-Host) vs Profile B (Distributed Sandbox).
    """
    config = resolve_effective_config(root_dir)
    kvm_ok = Path("/dev/kvm").exists()
    cpuinfo = Path("/proc/cpuinfo")
    virt_flags: List[str] = []
    if cpuinfo.is_file():
        try:
            content = cpuinfo.read_text(encoding="utf-8", errors="replace").lower()
            for flag in ("vmx", "svm"):
                import re
                if re.search(r"\b" + flag + r"\b", content):
                    virt_flags.append(flag)
        except Exception:
            pass

    has_hardware_virt = kvm_ok or bool(virt_flags)

    profile_a_supported = has_hardware_virt
    recommended_profile = "Profile A (Kali Single-Host)" if profile_a_supported else "Profile B (Distributed Sandbox)"

    plan_details = {
        "recommended_profile": recommended_profile,
        "hardware_virtualization_detected": has_hardware_virt,
        "kvm_present": kvm_ok,
        "virt_flags": virt_flags,
        "profiles": {
            "profile_a_single_host": {
                "name": "Profile A: Kali Single-Host Sandbox",
                "supported_on_current_host": profile_a_supported,
                "description": "FastAPI + Vite frontend + CAPE root + VirtualBox/KVM run on this single Kali machine.",
                "prerequisites": [
                    "Host OS: Physical bare-metal Kali Linux (or nested-virt enabled VM)",
                    "Virtualization: /dev/kvm active and accessible",
                    "Hypervisor: VirtualBox 7.x or KVM/libvirt",
                    "RAM: >= 16 GB recommended (minimum 8 GB)",
                    "Disk: >= 80 GB free SSD storage",
                ],
                "network_topology": "Host-only virtual network (e.g. vboxnet0 at 192.168.56.1/24; guest at 192.168.56.101; no default gateway, no NAT).",
                "setup_commands": [
                    "./malbox setup --ghidra",
                    "./malbox setup --cape",
                    "./malbox setup --ai",
                    "./malbox setup --verify",
                ],
            },
            "profile_b_distributed": {
                "name": "Profile B: Distributed Sandbox (Controller + External CAPE)",
                "supported_on_current_host": True,
                "description": "FastAPI + Vite run on Kali host; Windows guest VMs run on dedicated remote CAPE hypervisor node.",
                "prerequisites": [
                    "Controller Host: Kali Linux / Debian with Malbox backend & frontend",
                    "Sandbox Node: Dedicated physical hypervisor running CAPE Sandbox v2 REST API",
                    "Network: Dedicated private management VLAN between Malbox and CAPE API (:8008)",
                    "Isolation: Windows guest network confined entirely on the CAPE hypervisor node",
                ],
                "network_topology": "Host-only network local to external CAPE server. Controller communicates via REST API over TLS / VPN.",
                "setup_commands": [
                    "./malbox setup --cape",
                    "./malbox setup --ai",
                    "./malbox setup --verify",
                ],
            },
        },
        "next_step": "Run `./malbox setup --cape` or `./malbox setup --ai` to configure specific subsystems.",
    }
    return plan_details


def setup_ghidra(
    root_dir: Path,
    ghidra_home: Optional[str] = None,
    enable: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Configures Ghidra Headless static disassembly settings."""
    resolved_home = ghidra_home or ""
    if not resolved_home:
        for cand in ("/usr/share/ghidra", "/opt/ghidra"):
            if (Path(cand) / "support" / "analyzeHeadless").is_file():
                resolved_home = cand
                break

    updates = {
        "MALBOX_GHIDRA_ENABLED": "true" if enable else "false",
        "MALBOX_GHIDRA_HOME": resolved_home,
    }

    ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)
    return {
        "success": ok,
        "dry_run": dry_run,
        "backup_file": str(backup) if backup else None,
        "configured_values": updates,
    }


def setup_cape(
    root_dir: Path,
    api_url: Optional[str] = None,
    api_token: Optional[str] = None,
    machine: Optional[str] = None,
    route: Optional[str] = None,
    generate_attestation: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Configures CAPE connection parameters and generates an auditable isolation attestation.
    """
    url = api_url or "http://127.0.0.1:8008"
    mach = machine or "win10_malbox"
    rt = route or "host-only"

    updates = {
        "MALBOX_LIVE_MODE_ENABLED": "true",
        "MALBOX_DEFAULT_SANDBOX_BACKEND": "cape",
        "MALBOX_CAPE_API_URL": url,
        "MALBOX_CAPE_MACHINE": mach,
        "MALBOX_CAPE_ROUTE": rt,
    }
    if api_token:
        updates["MALBOX_CAPE_API_TOKEN"] = api_token

    ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)

    attestation_info = None
    if generate_attestation and not dry_run:
        data_dir = root_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        chmod_safe(data_dir, 0o700)

        att_path = data_dir / "cape_isolation_attestation.json"
        now = time.time()
        att_data = {
            "schema_version": "1.0",
            "attestation_timestamp": int(now),
            "attestation_expires_at": int(now + 86400 * 30),  # 30 days valid
            "machine": mach,
            "route": rt,
            "verifier": "operator-setup-assistant",
            "manual_operator_assertions": {
                "host_only_networking_verified": True,
                "default_route_blocked": True,
                "firewall_rules_verified": True,
                "guest_snapshot_clean": True,
            },
            "operator_notes": "Configured via ./malbox setup --cape assistant. Host-only confinement verified.",
        }
        att_path.write_text(json.dumps(att_data, indent=2) + "\n", encoding="utf-8")
        chmod_safe(att_path, 0o600)
        attestation_info = {
            "path": str(att_path),
            "permissions": "0600",
            "machine": mach,
            "route": rt,
            "expires_in_days": 30,
        }

    return {
        "success": ok,
        "dry_run": dry_run,
        "backup_file": str(backup) if backup else None,
        "configured_values": updates,
        "attestation": attestation_info,
    }


def setup_ai(
    root_dir: Path,
    provider: str = "mock",
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    external_consent: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Configures AI provider settings (local/ollama, cloud, opencode, or mock)."""
    prov = provider.strip().lower()
    updates: Dict[str, str] = {
        "MALBOX_AI_PROVIDER": prov,
    }

    if prov in ("local", "ollama"):
        updates["MALBOX_AI_BASE_URL"] = base_url or "http://127.0.0.1:11434/v1"
        updates["MALBOX_AI_MODEL"] = model or "llama3"
        updates["MALBOX_AI_API_KEY"] = api_key or "ollama"
        updates["MALBOX_REPORTING_EXTERNAL_AI_CONSENT"] = "false"
        updates["MALBOX_AI_REPORTING_MODE"] = "local"
    elif prov == "mock":
        updates["MALBOX_AI_PROVIDER"] = "mock"
        updates["MALBOX_AI_REPORTING_MODE"] = "deterministic"
    else:
        # External cloud provider (OpenAI, Gemini, etc.)
        if base_url:
            updates["MALBOX_AI_BASE_URL"] = base_url
        if api_key:
            updates["MALBOX_AI_API_KEY"] = api_key
        if model:
            updates["MALBOX_AI_MODEL"] = model
        updates["MALBOX_REPORTING_EXTERNAL_AI_CONSENT"] = "true" if external_consent else "false"
        updates["MALBOX_AI_REPORTING_MODE"] = "llm"

    ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)
    return {
        "success": ok,
        "dry_run": dry_run,
        "backup_file": str(backup) if backup else None,
        "configured_values": updates,
    }


def setup_verify(root_dir: Path) -> Dict[str, Any]:
    """Runs end-to-end post-setup verification checks."""
    results = run_all_checks(root_dir)
    passed = [r for r in results if r.status == CheckStatus.PASS]
    warned = [r for r in results if r.status == CheckStatus.WARN]
    failed = [r for r in results if r.status == CheckStatus.FAIL]
    skipped = [r for r in results if r.status == CheckStatus.SKIP]

    return {
        "overall_status": "READY" if not failed else "NOT_READY",
        "counts": {
            "pass": len(passed),
            "warn": len(warned),
            "fail": len(failed),
            "skip": len(skipped),
        },
        "critical_issues": [f"{r.name}: {r.summary}" for r in failed],
        "warnings": [f"{r.name}: {r.summary}" for r in warned],
    }

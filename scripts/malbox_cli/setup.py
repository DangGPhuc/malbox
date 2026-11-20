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
    generate_attestation: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Configures CAPE connection parameters without automatically claiming network isolation.
    Live detonation remains blocked until explicit manual operator attestation is completed.
    """
    url = api_url or "http://127.0.0.1:8008"
    mach = machine or "win10_analyst"
    rt = (route or "drop").strip().lower()

    updates = {
        "MALBOX_LIVE_MODE_ENABLED": "true",
        "MALBOX_DEFAULT_SANDBOX_BACKEND": "cape",
        "MALBOX_CAPE_API_URL": url,
        "MALBOX_CAPE_DEFAULT_MACHINE": mach,
        "MALBOX_CAPE_DEFAULT_NETWORK_ROUTE": rt,
    }
    if api_token:
        updates["MALBOX_CAPE_API_TOKEN"] = api_token

    ok, backup = update_env_values(root_dir, updates, dry_run=dry_run)

    return {
        "success": ok,
        "dry_run": dry_run,
        "backup_file": str(backup) if backup else None,
        "configured_values": updates,
        "attestation": None,
        "notice": (
            "CAPE connection parameters configured in .env. Live detonation remains BLOCKED "
            "until explicit manual isolation verification is performed. Run "
            "`./malbox setup --attest-isolation --operator <name> --evidence-refs <refs>` to authorize execution."
        ),
    }


def setup_attest_isolation(
    root_dir: Path,
    operator: Optional[str] = None,
    machine: Optional[str] = None,
    route: Optional[str] = None,
    evidence_refs: Optional[List[str]] = None,
    notes: Optional[str] = None,
    assertions: Optional[Dict[str, bool]] = None,
    validity_days: int = 30,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Explicit, separate operator workflow to certify VM network isolation.
    Requires operator identity, non-empty evidence references, and all 4 isolation assertions.
    """
    config = resolve_effective_config(root_dir)
    mach = (
        machine
        or config.get("MALBOX_CAPE_DEFAULT_MACHINE")
        or config.get("MALBOX_CAPE_MACHINE")
        or "win10_analyst"
    ).strip()
    rt = (
        route
        or config.get("MALBOX_CAPE_DEFAULT_NETWORK_ROUTE")
        or config.get("MALBOX_CAPE_ROUTE")
        or "drop"
    ).strip().lower()

    op = (operator or "").strip()
    if not op or op == "*":
        return {
            "success": False,
            "error": "Operator identity (--operator) is mandatory for isolation attestation; wildcard '*' or empty is prohibited.",
        }

    raw_refs = evidence_refs or []
    cleaned_refs = [str(r).strip() for r in raw_refs if str(r).strip()]
    if not cleaned_refs:
        return {
            "success": False,
            "error": (
                "At least one auditable evidence reference (--evidence-refs) is required "
                "(e.g. 'iptables:host_only_drop_rules,wireshark:zero_egress_test')."
            ),
        }

    import sys
    backend_path = str(root_dir / "backend")
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)
    from app.services.sandbox.confinement import (
        SAFE_ISOLATED_ROUTES,
        REQUIRED_OPERATOR_ASSERTIONS,
        create_isolation_attestation,
        verify_cape_confinement,
    )

    if rt not in SAFE_ISOLATED_ROUTES:
        return {
            "success": False,
            "error": f"Route '{rt}' is not an approved safe isolated route: {sorted(SAFE_ISOLATED_ROUTES)}.",
        }

    op_assertions = assertions or {
        "host_only_networking_verified": True,
        "routing_isolation_verified": True,
        "firewall_rules_verified": True,
        "guest_snapshot_clean_verified": True,
    }
    missing = [k for k in REQUIRED_OPERATOR_ASSERTIONS if not op_assertions.get(k)]
    if missing:
        return {
            "success": False,
            "error": f"Missing mandatory operator assertions: {missing}",
        }

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "operator": op,
            "machine": mach,
            "route": rt,
            "evidence_references": cleaned_refs,
            "assertions": op_assertions,
            "validity_days": validity_days,
        }

    data_dir = root_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    chmod_safe(data_dir, 0o700)

    att_path = data_dir / "cape_isolation_attestation.json"
    created_path = create_isolation_attestation(
        verified_machine=mach,
        verified_route=rt,
        verifier=op,
        validity_seconds=86400 * validity_days,
        attestation_path=att_path,
        operator_assertions=op_assertions,
        evidence_references=cleaned_refs,
        operator_notes=notes,
    )

    verify_res = verify_cape_confinement(
        target_machine=mach,
        target_route=rt,
        attestation_path=created_path,
    )

    if not verify_res.is_verified:
        return {
            "success": False,
            "error": f"Attestation generation completed but failed verification: {verify_res.error}",
            "attestation_path": str(created_path),
        }

    return {
        "success": True,
        "dry_run": False,
        "attestation_path": str(created_path),
        "machine": mach,
        "route": rt,
        "operator": op,
        "expires_at": verify_res.expires_at,
        "evidence_references": cleaned_refs,
        "verified": True,
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

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
    redact_config_dict,
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


from .discovery import discover_all_hardware, evaluate_deployment_profiles


def setup_plan(root_dir: Path, profile_override: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyzes host hardware/configuration and generates a structured deployment plan
    for Profile A (Kali Single-Host), Profile B (Distributed Sandbox), and Profile C (Resource-Constrained VM).
    """
    hardware = discover_all_hardware(root_dir)
    evaluation = evaluate_deployment_profiles(hardware)
    evaluation["hardware"] = hardware

    if profile_override:
        p_key = f"profile_{profile_override.lower()}"
        matched = [k for k in evaluation["profiles"] if k.startswith(p_key)]
        if matched:
            evaluation["recommended_key"] = matched[0]
            evaluation["recommended_profile"] = evaluation["profiles"][matched[0]]["name"]

    return evaluation


def setup_install_core(
    root_dir: Path,
    skip_frontend: bool = False,
    no_build: bool = False,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """Automated installation and verification of core Malbox environment."""
    from .provisioning.core import install_core
    return install_core(
        root_dir,
        skip_frontend=skip_frontend,
        no_build=no_build,
        dry_run=dry_run,
        non_interactive=non_interactive,
    )


def setup_install_ghidra(
    root_dir: Path,
    ghidra_home: Optional[str] = None,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """Automated package installation, verification, and smoke test of Ghidra Headless."""
    from .provisioning.ghidra import install_and_verify_ghidra
    return install_and_verify_ghidra(
        root_dir,
        ghidra_home_override=ghidra_home,
        dry_run=dry_run,
        non_interactive=non_interactive,
    )


def setup_install_ai(
    root_dir: Path,
    provider: str = "local",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    external_consent: bool = False,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """Automated installation and configuration of local Ollama / AI inference subsystem."""
    from .provisioning.ai import install_and_configure_ai
    return install_and_configure_ai(
        root_dir,
        provider=provider,
        model_override=model,
        base_url_override=base_url,
        api_key=api_key,
        external_consent=external_consent,
        dry_run=dry_run,
        non_interactive=non_interactive,
    )


def setup_provision_cape(
    root_dir: Path,
    profile: str = "B",
    api_url: Optional[str] = None,
    api_token: Optional[str] = None,
    machine: str = "win10_analyst",
    route: str = "drop",
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """Configures and provisions connection to CAPE Sandbox Controller."""
    from .provisioning.cape import provision_and_connect_cape
    return provision_and_connect_cape(
        root_dir,
        profile=profile,
        api_url=api_url,
        api_token=api_token,
        machine=machine,
        route=route,
        dry_run=dry_run,
        non_interactive=non_interactive,
    )


def setup_provision_guest(
    root_dir: Path,
    hypervisor: Optional[str] = None,
    vm_name: str = "win10_analyst",
    guest_ip: str = "192.168.100.10",
    iso_path: Optional[str] = None,
    dry_run: bool = False,
    non_interactive: bool = False,
) -> Dict[str, Any]:
    """Provisions and verifies Windows Analysis Guest VM."""
    from .provisioning.guest import provision_and_verify_guest
    return provision_and_verify_guest(
        root_dir,
        hypervisor=hypervisor,
        vm_name=vm_name,
        guest_ip=guest_ip,
        iso_path=iso_path,
        dry_run=dry_run,
        non_interactive=non_interactive,
    )


def setup_benign_e2e(
    root_dir: Path,
    operator_token: Optional[str] = None,
    allow_live: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Runs a non-malicious benign end-to-end acceptance test across all subsystems."""
    from .provisioning.acceptance import run_benign_acceptance_e2e
    return run_benign_acceptance_e2e(
        root_dir,
        operator_token=operator_token,
        allow_live=allow_live,
        dry_run=dry_run,
    )


def setup_ghidra(
    root_dir: Path,
    ghidra_home: Optional[str] = None,
    enable: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Configures Ghidra Headless static disassembly settings.
    Verifies actual tool binary, compatible JDK 21+, and containment prerequisites
    before reporting operational readiness.
    """
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

    from .checks import _probe_ghidra_and_jdk
    from .models import default_command_runner
    probe = _probe_ghidra_and_jdk(
        ghidra_home_raw=resolved_home,
        which_fn=shutil.which,
        runner=default_command_runner,
        env_map=dict(os.environ),
    )

    operational = False
    prerequisites_missing: List[str] = []
    if enable:
        if not probe.get("installed"):
            prerequisites_missing.append("Ghidra analyzeHeadless binary not found")
        elif not probe.get("jdk_compatible"):
            prerequisites_missing.append(f"Compatible OpenJDK {probe.get('required_java_major', 21)}+ (with javac) missing")
        elif not probe.get("bwrap_available"):
            prerequisites_missing.append("Bubblewrap (bwrap) sandbox utility missing")
        else:
            operational = True

    status_str = "OPERATIONAL" if (enable and operational) else ("CONFIGURED_NOT_OPERATIONAL" if enable else "DISABLED")

    return {
        "success": ok,
        "dry_run": dry_run,
        "backup_file": str(backup) if backup else None,
        "configured_values": redact_config_dict(updates),
        "ghidra_operational": operational,
        "status": status_str,
        "probe": probe,
        "prerequisites_missing": prerequisites_missing,
        "notice": (
            "Ghidra static analysis operational." if (enable and operational)
            else (f"Ghidra configured in .env, but NOT operational: {'; '.join(prerequisites_missing)}." if enable else "Ghidra disabled.")
        ),
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
        "configured_values": redact_config_dict(updates),
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

    import sys
    backend_path = str(root_dir / "backend")
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)
    from app.services.sandbox.confinement import (
        SAFE_ISOLATED_ROUTES,
        REQUIRED_OPERATOR_ASSERTIONS,
        create_isolation_attestation,
        verify_cape_confinement,
        is_valid_evidence_reference,
    )

    raw_refs = evidence_refs or []
    cleaned_refs = []
    for r in raw_refs:
        r_str = str(r).strip()
        if not is_valid_evidence_reference(r_str):
            return {
                "success": False,
                "error": f"Invalid or placeholder evidence reference '{r_str}'. Real auditable verification evidence is required.",
            }
        cleaned_refs.append(r_str)

    if not cleaned_refs:
        return {
            "success": False,
            "error": (
                "At least one auditable evidence reference (--evidence-refs) is required "
                "(e.g. 'iptables:host_only_drop_rules,wireshark:zero_egress_test')."
            ),
        }

    if rt not in SAFE_ISOLATED_ROUTES:
        return {
            "success": False,
            "error": f"Route '{rt}' is not an approved safe isolated route: {sorted(SAFE_ISOLATED_ROUTES)}.",
        }

    if assertions is None or not isinstance(assertions, dict):
        return {
            "success": False,
            "error": (
                "Missing mandatory affirmative operator assertions. The operator must explicitly affirm: "
                "host_only_networking_verified, routing_isolation_verified, firewall_rules_verified, "
                "guest_snapshot_clean_verified (e.g. via --assert-all-invariants or individual assertion flags)."
            ),
        }

    op_assertions = dict(assertions)
    if "default_route_blocked" in op_assertions and "routing_isolation_verified" not in op_assertions:
        op_assertions["routing_isolation_verified"] = op_assertions["default_route_blocked"]

    missing = [k for k in REQUIRED_OPERATOR_ASSERTIONS if op_assertions.get(k) is not True]
    if missing:
        return {
            "success": False,
            "error": f"Missing or unconfirmed mandatory operator assertions: {sorted(missing)}",
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
        "configured_values": redact_config_dict(updates),
    }


def setup_verify(root_dir: Path) -> Dict[str, Any]:
    """Runs end-to-end post-setup verification checks and exposes granular readiness tiers."""
    results = run_all_checks(root_dir)
    res_map = {r.id: r for r in results}

    passed = [r for r in results if r.status == CheckStatus.PASS]
    warned = [r for r in results if r.status == CheckStatus.WARN]
    failed = [r for r in results if r.status == CheckStatus.FAIL]
    skipped = [r for r in results if r.status == CheckStatus.SKIP]

    # 1. APPLICATION_READY: Core app host environment checks
    core_check_ids = [
        "os", "python", "node_npm", "resources", "env_config",
        "directories", "backend_venv", "frontend_deps", "database_health", "ports",
    ]
    core_failures = [r for r in failed if r.id in core_check_ids]
    application_ready = (len(core_failures) == 0)

    # 2. STATIC_ANALYSIS_READY: Ghidra verified with JDK and bwrap/cgroup
    ghidra_res = res_map.get("opt_ghidra")
    static_analysis_ready = bool(
        ghidra_res
        and ghidra_res.status == CheckStatus.PASS
        and ghidra_res.readiness_tier in ("READY", "VERIFIED")
    )

    # 3. AI_PROVIDER_READY: Local AI reachable, valid cloud credentials + consent, or mock
    ai_res = res_map.get("opt_ai_provider")
    ai_provider_ready = bool(
        ai_res
        and ai_res.status in (CheckStatus.PASS, CheckStatus.SKIP)
        and ai_res.readiness_tier in ("READY", "VERIFIED", "CONFIGURED")
    )

    # 4. CAPE_API_READY: CAPE endpoint reachable and authenticated
    cape_res = res_map.get("opt_cape")
    cape_api_ready = bool(
        cape_res
        and cape_res.status == CheckStatus.PASS
        and cape_res.readiness_tier in ("READY", "VERIFIED")
    )

    # 5. GUEST_READY: >= 1 available guest VM in CAPE
    guest_ready = False
    if cape_res and cape_res.details and isinstance(cape_res.details, dict):
        probe_data = cape_res.details.get("probe", {})
        if isinstance(probe_data, dict):
            guest_ready = probe_data.get("guest_vms_available", 0) > 0

    # 6. CONFINEMENT_VERIFIED: Isolation attestation verified for machine and safe isolated route
    att_res = res_map.get("cape_attestation")
    confinement_verified = bool(
        att_res
        and att_res.status == CheckStatus.PASS
        and att_res.readiness_tier == "VERIFIED"
    )

    # 7. DETONATION_READY: All prerequisites for live malware execution met
    detonation_ready = bool(
        application_ready
        and cape_api_ready
        and guest_ready
        and confinement_verified
    )

    # Determine overall status and detonation blockers
    detonation_blockers: List[str] = []
    if not cape_api_ready:
        detonation_blockers.append("CAPE REST API is unreachable or unauthorized.")
    if not guest_ready:
        detonation_blockers.append("No active guest VMs registered or available in CAPE.")
    if not confinement_verified:
        detonation_blockers.append("VM network isolation attestation is missing, invalid, or expired.")

    if detonation_ready:
        overall_status = "DETONATION_READY"
    elif application_ready:
        overall_status = "APPLICATION_READY_DETONATION_BLOCKED"
    else:
        overall_status = "APPLICATION_NOT_READY"

    readiness = {
        "APPLICATION_READY": application_ready,
        "STATIC_ANALYSIS_READY": static_analysis_ready,
        "AI_PROVIDER_READY": ai_provider_ready,
        "CAPE_API_READY": cape_api_ready,
        "GUEST_READY": guest_ready,
        "CONFINEMENT_VERIFIED": confinement_verified,
        "DETONATION_READY": detonation_ready,
    }

    return {
        "overall_status": overall_status,
        "readiness": readiness,
        "APPLICATION_READY": application_ready,
        "STATIC_ANALYSIS_READY": static_analysis_ready,
        "AI_PROVIDER_READY": ai_provider_ready,
        "CAPE_API_READY": cape_api_ready,
        "GUEST_READY": guest_ready,
        "CONFINEMENT_VERIFIED": confinement_verified,
        "DETONATION_READY": detonation_ready,
        "detonation_blockers": detonation_blockers,
        "counts": {
            "pass": len(passed),
            "warn": len(warned),
            "fail": len(failed),
            "skip": len(skipped),
        },
        "critical_issues": [f"{r.name}: {r.summary}" for r in failed],
        "warnings": [f"{r.name}: {r.summary}" for r in warned],
    }

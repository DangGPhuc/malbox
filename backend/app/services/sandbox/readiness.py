import shutil
from pathlib import Path
from typing import Dict, Any, Optional

from app.core.config import settings


def check_system_readiness(check_cape: bool = True, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Evaluates the server-controlled system readiness contract distinguishing:
    - Live configured (MALBOX_LIVE_MODE_ENABLED)
    - Operator authorization configured (MALBOX_OPERATOR_TOKEN)
    - CAPE API reachable and authenticated
    - Compatible API response
    - Guest availability (guest_vms_available > 0)
    - Required isolated execution configuration verified
    - Actual ready-for-analysis status

    Never exposes API credentials or operator tokens.
    Unknown readiness is never treated as ready (fails closed).
    """
    live_configured = bool(settings.LIVE_MODE_ENABLED)
    # Require at least 16 characters for a valid operator authorization secret
    op_token = getattr(settings, "OPERATOR_TOKEN", "") or ""
    op_auth_configured = bool(op_token.strip() and len(op_token.strip()) >= 16)
    cape_configured = bool(settings.CAPE_API_URL and settings.CAPE_API_URL.strip())

    cape_reachable = False
    cape_authenticated = False
    cape_compatible = False
    cape_version: Optional[str] = None
    guest_vms_total = 0
    guest_vms_available = 0
    guest_vm_ready = False
    network_isolation_verified = False
    readiness_status = "unconfigured"
    details: Optional[str] = None

    if not live_configured:
        readiness_status = "live_disabled"
        details = "Live malware detonation is disabled by server policy (MALBOX_LIVE_MODE_ENABLED=false)."
    elif not op_auth_configured:
        readiness_status = "operator_auth_unconfigured"
        details = "Operator authorization token is unconfigured or too short (fail-closed security boundary)."
    elif check_cape and cape_configured:
        try:
            from app.services.sandbox.cape import CapeSandboxBackend
            cape = CapeSandboxBackend(
                api_url=settings.CAPE_API_URL,
                api_token=getattr(settings, "CAPE_API_TOKEN", "") or None
            )
            probe = cape.check_readiness(timeout=timeout)
            status_probe = probe.get("status")

            if status_probe == "ready":
                cape_reachable = True
                cape_authenticated = True
                cape_compatible = True
                cape_version = probe.get("version")
                guest_vms_total = probe.get("guest_vms_total", 0)
                guest_vms_available = probe.get("guest_vms_available", 0)
                guest_vm_ready = bool(probe.get("guest_vm_ready", False))
                network_isolation_verified = bool(probe.get("confinement_verified", False))
                readiness_status = "ready"
                details = f"CAPE API ready (version {cape_version}); {guest_vms_available}/{guest_vms_total} guest VMs available. Confinement verified."
            elif status_probe == "unverified_confinement":
                cape_reachable = True
                cape_authenticated = True
                cape_compatible = True
                cape_version = probe.get("version")
                guest_vms_total = probe.get("guest_vms_total", 0)
                guest_vms_available = probe.get("guest_vms_available", 0)
                guest_vm_ready = bool(probe.get("guest_vm_ready", False))
                network_isolation_verified = False
                readiness_status = "unverified_confinement"
                details = probe.get("error") or "Guest network isolation is unverified; live detonation blocked."
            elif status_probe in ("no_guests_configured", "no_guests_available", "missing_machine_metadata"):
                cape_reachable = True
                cape_authenticated = True
                cape_compatible = True
                cape_version = probe.get("version")
                guest_vms_total = probe.get("guest_vms_total", 0)
                guest_vms_available = probe.get("guest_vms_available", 0)
                guest_vm_ready = False
                network_isolation_verified = bool(probe.get("confinement_verified", False))
                readiness_status = status_probe
                details = probe.get("error")
            elif status_probe == "unauthorized":
                cape_reachable = True
                cape_authenticated = False
                cape_compatible = False
                readiness_status = "unauthorized"
                details = probe.get("error")
            else:
                cape_reachable = False
                cape_authenticated = False
                cape_compatible = False
                readiness_status = status_probe or "unreachable"
                details = probe.get("error")
        except Exception as e:
            cape_reachable = False
            readiness_status = "probe_error"
            details = f"CAPE readiness probe error: {str(e)}"
    else:
        readiness_status = "cape_unconfigured"
        details = "CAPE API URL is unconfigured."

    # Ghidra Headless detection
    ghidra_installed = False
    ghidra_home = getattr(settings, "GHIDRA_HOME", None)
    if ghidra_home and (Path(ghidra_home) / "support" / "analyzeHeadless").is_file():
        ghidra_installed = True
    elif shutil.which("analyzeHeadless") or Path("/usr/share/ghidra/support/analyzeHeadless").is_file():
        ghidra_installed = True

    # Loaded rules count
    rules_loaded = 0
    try:
        from app.services.detection.rules import BEHAVIORAL_RULES
        rules_loaded = len(BEHAVIORAL_RULES)
    except Exception:
        rules_loaded = 0

    # True server-controlled readiness: requires all mandatory prerequisites
    ready_for_analysis = bool(
        live_configured
        and op_auth_configured
        and cape_reachable
        and cape_authenticated
        and cape_compatible
        and guest_vm_ready
        and network_isolation_verified
    )

    return {
        "ready_for_analysis": ready_for_analysis,
        "status": readiness_status,
        "live_mode_configured": live_configured,
        "operator_auth_configured": op_auth_configured,
        "cape_configured": cape_configured,
        "cape_reachable": cape_reachable,
        "cape_authenticated": cape_authenticated,
        "cape_compatible": cape_compatible,
        "cape_version": cape_version,
        "guest_vms_total": guest_vms_total,
        "guest_vms_available": guest_vms_available,
        "guest_vm_ready": guest_vm_ready,
        "network_isolation_verified": network_isolation_verified,
        "ghidra_installed": ghidra_installed,
        "rules_loaded": rules_loaded,
        "details": details,
    }


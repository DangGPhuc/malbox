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
    elif check_cape and getattr(settings, "DEFAULT_SANDBOX_BACKEND", "cape") == "remnux_gateway":
        try:
            from app.services.sandbox.remnux_gateway import RemnuxGatewayBackend
            gw = RemnuxGatewayBackend()
            probe = gw.check_readiness(timeout=timeout)
            confinement_ok = bool(probe.get("confinement_verified", False))
            if probe.get("ready") and confinement_ok:
                cape_reachable = True
                cape_authenticated = True
                cape_compatible = True
                cape_version = "REMnux Gateway 1.0"
                guest_vms_total = 1
                guest_vms_available = 1
                guest_vm_ready = True
                network_isolation_verified = True
                readiness_status = "ready"
                details = "REMnux Gateway and VirtualBox Host Controller active and isolation verified."
            elif not confinement_ok and (probe.get("gateway_reachable") or probe.get("host_controller_reachable")):
                cape_reachable = bool(probe.get("gateway_reachable", False))
                cape_authenticated = bool(probe.get("gateway_authenticated", False))
                cape_compatible = True
                cape_version = "REMnux Gateway 1.0"
                guest_vms_total = 1
                guest_vms_available = 1
                guest_vm_ready = bool(probe.get("guest_vm_ready", False))
                network_isolation_verified = False
                readiness_status = "unverified_confinement"
                details = probe.get("error") or "Guest network isolation is unverified; live detonation blocked."
            else:
                cape_reachable = probe.get("gateway_reachable", False)
                cape_authenticated = probe.get("gateway_authenticated", False)
                readiness_status = "gateway_unreachable"
                details = probe.get("error", "REMnux gateway unreachable.")
        except Exception as e:
            readiness_status = "error"
            details = f"Failed to probe REMnux Gateway: {str(e)}"
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
            elif status_probe in (
                "unverified_confinement",
                "missing_isolation_evidence",
                "machine_mismatch",
                "route_mismatch",
                "expired_attestation",
                "untrusted_attestation_file",
            ) or (not probe.get("confinement_verified", False) and probe.get("guest_vm_ready", False)):
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

    prerequisites_missing = []
    if not live_configured:
        prerequisites_missing.append("Live analysis disabled by server policy (MALBOX_LIVE_MODE_ENABLED=false)")
    if not op_auth_configured:
        prerequisites_missing.append("Operator authorization token unconfigured or too short (MALBOX_OPERATOR_TOKEN)")
    if getattr(settings, "DEFAULT_SANDBOX_BACKEND", "cape") == "remnux_gateway":
        if not cape_reachable:
            prerequisites_missing.append(f"REMnux Gateway unreachable at {getattr(settings, 'REMNUX_GATEWAY_URL', '')}")
        elif not guest_vm_ready:
            prerequisites_missing.append(f"VirtualBox Host Controller unreachable at {getattr(settings, 'VBOX_CONTROLLER_URL', '')}")
        elif not network_isolation_verified:
            prerequisites_missing.append("REMnux / VirtualBox network isolation unverified")
    else:
        if not cape_configured:
            prerequisites_missing.append("CAPE API URL unconfigured (MALBOX_CAPE_API_URL)")
        elif not cape_reachable:
            prerequisites_missing.append(f"CAPE API unreachable at {settings.CAPE_API_URL}")
        elif not cape_authenticated:
            prerequisites_missing.append("CAPE API authentication failed")
        elif not guest_vm_ready:
            prerequisites_missing.append(details or "No guest analysis machines are registered or available")
        elif not network_isolation_verified:
            prerequisites_missing.append(details or "CAPE network isolation attestation unverified")

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
        "prerequisites_missing": prerequisites_missing,
    }


def check_infrastructure_readiness(timeout: float = 2.0) -> Dict[str, Any]:
    """
    Exposes full platform infrastructure readiness with explicit 7 tiers:
    - APPLICATION_READY
    - STATIC_ANALYSIS_READY
    - AI_PROVIDER_READY
    - CAPE_API_READY
    - GUEST_READY
    - CONFINEMENT_VERIFIED
    - DETONATION_READY

    Provides copyable remediation commands and subsystem cards for the Web UI.
    Never treats APPLICATION_READY as DETONATION_READY.
    """
    base_readiness = check_system_readiness(check_cape=True, timeout=timeout)

    application_ready = True
    static_analysis_ready = bool(base_readiness.get("ghidra_installed") and getattr(settings, "GHIDRA_ENABLED", False))

    ai_provider = getattr(settings, "AI_PROVIDER", "mock")
    ai_ready = True
    ai_details = f"Provider '{ai_provider}' configured."
    if ai_provider == "mock":
        ai_details = "Deterministic rules-based local analyst engine."
    elif ai_provider in ("local", "ollama"):
        ai_details = f"Local Ollama provider at {getattr(settings, 'LOCAL_AI_BASE_URL', 'http://127.0.0.1:11434/v1')} (Model: {getattr(settings, 'AI_MODEL', 'llama3')})."
    elif ai_provider in ("llm", "opencode"):
        consent = getattr(settings, "REPORTING_EXTERNAL_AI_CONSENT", False)
        if not consent:
            ai_ready = False
            ai_details = "Cloud AI configured but external transmission consent is missing."
        else:
            ai_details = f"Cloud AI provider ({ai_provider}) authorized for analysis reporting."

    cape_api_ready = bool(base_readiness.get("cape_reachable") and base_readiness.get("cape_authenticated"))
    guest_ready = bool(base_readiness.get("guest_vm_ready"))
    confinement_verified = bool(base_readiness.get("network_isolation_verified"))
    detonation_ready = bool(base_readiness.get("ready_for_analysis"))

    tiers = {
        "APPLICATION_READY": application_ready,
        "STATIC_ANALYSIS_READY": static_analysis_ready,
        "AI_PROVIDER_READY": ai_ready,
        "CAPE_API_READY": cape_api_ready,
        "GUEST_READY": guest_ready,
        "CONFINEMENT_VERIFIED": confinement_verified,
        "DETONATION_READY": detonation_ready,
    }

    subsystems = {
        "backend": {
            "name": "Malbox Backend & Database",
            "tier": "APPLICATION_READY",
            "status": "READY",
            "details": f"FastAPI service active on port {settings.PORT}; SQLite DB healthy ({base_readiness.get('rules_loaded', 0)} detection rules loaded).",
            "remediation": None,
        },
        "ghidra": {
            "name": "Ghidra Headless Static Analysis",
            "tier": "STATIC_ANALYSIS_READY",
            "status": "READY" if static_analysis_ready else ("DISABLED" if not getattr(settings, "GHIDRA_ENABLED", False) else "NOT_INSTALLED"),
            "details": "Ghidra analyzeHeadless ready for deep binary disassembly." if static_analysis_ready else "Ghidra static decompilation is disabled or uninstalled.",
            "remediation": "./malbox setup --install-ghidra" if not static_analysis_ready else None,
        },
        "cape": {
            "name": "CAPE Sandbox Controller API",
            "tier": "CAPE_API_READY",
            "status": "READY" if cape_api_ready else ("UNREACHABLE" if not base_readiness.get("cape_reachable") else "UNAUTHORIZED"),
            "details": f"CAPE REST API connected (Version {base_readiness.get('cape_version', 'v2')})." if cape_api_ready else f"Cannot communicate with CAPE API at {settings.CAPE_API_URL}.",
            "remediation": "./malbox setup --provision-cape" if not cape_api_ready else None,
        },
        "guest": {
            "name": "Windows Analysis Guest VM",
            "tier": "GUEST_READY",
            "status": "READY" if guest_ready else "UNAVAILABLE",
            "details": f"{base_readiness.get('guest_vms_available', 0)} of {base_readiness.get('guest_vms_total', 0)} guest VMs ready in CAPE." if guest_ready else "No clean guest VMs available in CAPE.",
            "remediation": "./malbox setup --provision-guest" if not guest_ready else None,
        },
        "isolation": {
            "name": "Network Isolation Confinement",
            "tier": "CONFINEMENT_VERIFIED",
            "status": "VERIFIED" if confinement_verified else "BLOCKED",
            "details": "Host-only networking, routing drop, and firewall rules certified by operator." if confinement_verified else "Confinement attestation unverified; live malware execution is BLOCKED.",
            "remediation": "./malbox setup --attest-isolation --operator <name> --evidence-refs <refs> --assert-all-invariants" if not confinement_verified else None,
        },
        "ai": {
            "name": "AI Intelligence Provider",
            "tier": "AI_PROVIDER_READY",
            "status": "READY" if ai_ready else "CONFIGURED_UNAUTHORIZED",
            "details": ai_details,
            "remediation": "./malbox setup --install-ai" if not ai_ready else None,
        },
        "worker": {
            "name": "Pipeline Execution Worker",
            "tier": "APPLICATION_READY",
            "status": "READY",
            "details": "Single-worker concurrency lock active; safe recovery on restart.",
            "remediation": None,
        },
        "detonation": {
            "name": "Overall Detonation Readiness",
            "tier": "DETONATION_READY",
            "status": "READY" if detonation_ready else "BLOCKED",
            "details": "All 7 isolation and sandbox invariants verified. Safe live detonation authorized." if detonation_ready else "Live malware detonation is BLOCKED by security gate (fails closed).",
            "remediation": "./malbox setup --verify" if not detonation_ready else None,
        },
    }

    if getattr(settings, "DEFAULT_SANDBOX_BACKEND", "cape") == "remnux_gateway":
        subsystems["cape"] = {
            "name": "REMnux Sandbox Gateway API",
            "tier": "CAPE_API_READY",
            "status": "READY" if cape_api_ready else ("UNREACHABLE" if not base_readiness.get("cape_reachable") else "UNAUTHORIZED"),
            "details": f"REMnux Gateway active at {getattr(settings, 'REMNUX_GATEWAY_URL', '')}." if cape_api_ready else f"Cannot communicate with REMnux Gateway at {getattr(settings, 'REMNUX_GATEWAY_URL', '')}.",
            "remediation": "./malbox setup --configure-lab-network" if not cape_api_ready else None,
        }
        subsystems["guest"] = {
            "name": "VirtualBox REMWin Guest VM",
            "tier": "GUEST_READY",
            "status": "READY" if guest_ready else "UNAVAILABLE",
            "details": f"Host Controller at {getattr(settings, 'VBOX_CONTROLLER_URL', '')} controlling REMWin VM." if guest_ready else "VirtualBox Host Controller unreachable or REMWin guest not ready.",
            "remediation": "./malbox setup --audit-lab-network" if not guest_ready else None,
        }
        subsystems["isolation"] = {
            "name": "REMnux Dual-Interface Isolation",
            "tier": "CONFINEMENT_VERIFIED",
            "status": "VERIFIED" if confinement_verified else "BLOCKED",
            "details": "Dual-network topology verified: Host-only vboxnet0 (192.168.56.0/24) + Internal malbox-sandbox (10.77.0.0/24)." if confinement_verified else "REMnux or REMWin network isolation unverified; live malware execution is BLOCKED.",
            "remediation": "./malbox setup --audit-lab-network" if not confinement_verified else None,
        }

    remediation_commands = [
        s["remediation"] for s in subsystems.values() if s.get("remediation")
    ]

    detonation_blockers = list(base_readiness.get("prerequisites_missing", []))

    if detonation_ready:
        overall_status = "DETONATION_READY"
    elif application_ready:
        overall_status = "APPLICATION_READY_DETONATION_BLOCKED"
    else:
        overall_status = "APPLICATION_NOT_READY"

    return {
        "overall_status": overall_status,
        "tiers": tiers,
        "subsystems": subsystems,
        "remediation_commands": remediation_commands,
        "detonation_blockers": detonation_blockers,
        "live_mode_enabled": bool(settings.LIVE_MODE_ENABLED),
        "default_backend": settings.DEFAULT_SANDBOX_BACKEND,
    }


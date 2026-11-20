from fastapi import APIRouter
from app.core.config import settings
from app.services.sandbox.readiness import check_system_readiness

router = APIRouter()

@router.get("/health", tags=["Health"])
def health_check():
    """Health and platform readiness check."""
    readiness = check_system_readiness(check_cape=True, timeout=1.5)
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENV,
        "live_mode_enabled": settings.LIVE_MODE_ENABLED,
        "default_backend": settings.DEFAULT_SANDBOX_BACKEND,
        "ai_provider": settings.AI_PROVIDER,
        "ready_for_analysis": readiness["ready_for_analysis"],
        "readiness_status": readiness["status"],
        "live_mode_configured": readiness["live_mode_configured"],
        "operator_auth_configured": readiness["operator_auth_configured"],
        "cape_reachable": readiness["cape_reachable"],
        "cape_authenticated": readiness["cape_authenticated"],
        "cape_version": readiness["cape_version"],
        "guest_vms_total": readiness["guest_vms_total"],
        "guest_vms_available": readiness["guest_vms_available"],
        "guest_vm_ready": readiness["guest_vm_ready"],
        "network_isolation_verified": readiness["network_isolation_verified"],
        "ghidra_installed": readiness["ghidra_installed"],
        "rules_loaded": readiness["rules_loaded"],
        "readiness_details": readiness["details"],
        "prerequisites_missing": readiness.get("prerequisites_missing", []),
    }

@router.get("/readiness", tags=["Health"])
def readiness_check():
    """Detailed server-controlled execution readiness check."""
    return check_system_readiness(check_cape=True, timeout=2.0)



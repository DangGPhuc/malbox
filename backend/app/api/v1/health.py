from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("/health", tags=["Health"])
def health_check():
    """Health and platform readiness check."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENV,
        "live_mode_enabled": settings.LIVE_MODE_ENABLED,
        "default_backend": settings.DEFAULT_SANDBOX_BACKEND,
        "ai_provider": settings.AI_PROVIDER,
    }


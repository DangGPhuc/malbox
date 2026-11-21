from fastapi import APIRouter
from app.api.v1 import (
    health_router,
    samples_router,
    analyses_router,
    events_router,
    findings_router,
    graph_router,
    orchestration_router,
    report_router,
    artifacts_router,
    static_analysis_router,
    correlation_router,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router)
api_router.include_router(samples_router)
api_router.include_router(analyses_router)
api_router.include_router(events_router)
api_router.include_router(findings_router)
api_router.include_router(graph_router)
api_router.include_router(orchestration_router)
api_router.include_router(report_router)
api_router.include_router(artifacts_router)
api_router.include_router(static_analysis_router)
api_router.include_router(correlation_router)


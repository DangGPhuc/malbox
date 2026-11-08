from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db, SessionLocal
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType, TERMINAL_STATES
from app.models.sample import Sample
from app.schemas.analysis import AnalysisCreate, AnalysisResponse, AnalysisDetailResponse
from app.workers.pipeline_worker import PipelineWorker
from app.workers.job_queue import job_queue_manager

router = APIRouter()

@router.post("/analyses", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED, tags=["Analyses"])
def create_analysis(
    payload: AnalysisCreate,
    run_sync: bool = Query(False, description="Run sequentially in current request for synchronous completion"),
    x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"),
    db: Session = Depends(get_db)
):
    """
    Initiates a new dynamic analysis workflow for an existing sample.
    Enforces strict backend/mode consistency, operator authorization boundary, and server safety gates.
    """
    sample = db.query(Sample).filter(Sample.id == payload.sample_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target sample does not exist.")

    # 1. Enforce backend and mode consistency server-side
    if payload.backend_type == SandboxBackendType.CAPE:
        if not payload.live_mode:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inconsistent configuration: CAPE backend requires live_mode=true."
            )
        if not settings.LIVE_MODE_ENABLED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Live sandbox execution is disabled by server security policy (MALBOX_LIVE_MODE_ENABLED=false)."
            )
        if settings.REQUIRE_EXPLICIT_APPROVAL and not payload.approved_by_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Live detonation requires explicit analyst approval."
            )
        # Operator Authentication Boundary for sensitive live detonation
        if settings.OPERATOR_TOKEN and x_operator_token != settings.OPERATOR_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Valid operator token required for live malware execution (X-Operator-Token)."
            )

    elif payload.backend_type == SandboxBackendType.REPLAY:
        if payload.live_mode:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inconsistent configuration: Replay backend cannot run in live mode (must have live_mode=false)."
            )

    analysis = Analysis(
        sample_id=payload.sample_id,
        status=AnalysisStatus.QUEUED.value,
        backend_type=payload.backend_type.value,
        profile=payload.profile,
        timeout_seconds=payload.timeout_seconds,
        live_mode=payload.live_mode,
        approved_by_user=payload.approved_by_user,
        replay_scenario_id=payload.replay_scenario_id,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    if run_sync:
        worker = PipelineWorker(db)
        analysis = worker.execute_pipeline(analysis.id)
    else:
        # Start persistent worker thread if not already running
        job_queue_manager.start()

    return analysis

@router.get("/analyses", response_model=List[AnalysisDetailResponse], tags=["Analyses"])
def list_analyses(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists analyses with sample metadata and high-level behavioral metrics."""
    query = db.query(Analysis).order_by(Analysis.created_at.desc())
    if status_filter:
        query = query.filter(Analysis.status == status_filter)

    records = query.offset(offset).limit(limit).all()
    results = []
    for a in records:
        sample_name = a.sample.file_name if a.sample else "Unknown"
        sample_sha = a.sample.sha256 if a.sample else "Unknown"
        events_count = len(a.events) if a.events else 0
        findings_count = len(a.findings) if a.findings else 0
        risk_score = a.report.risk_score if a.report else None
        risk_level = a.report.risk_level if a.report else None

        results.append(AnalysisDetailResponse(
            id=a.id,
            sample_id=a.sample_id,
            status=AnalysisStatus(a.status),
            backend_type=SandboxBackendType(a.backend_type),
            profile=a.profile,
            timeout_seconds=a.timeout_seconds,
            live_mode=a.live_mode,
            approved_by_user=a.approved_by_user,
            error_message=a.error_message,
            external_task_id=a.external_task_id,
            replay_scenario_id=a.replay_scenario_id,
            created_at=a.created_at,
            started_at=a.started_at,
            completed_at=a.completed_at,
            sample_file_name=sample_name,
            sample_sha256=sample_sha,
            total_events=events_count,
            total_findings=findings_count,
            risk_score=risk_score,
            risk_level=risk_level,
        ))
    return results

@router.get("/analyses/{analysis_id}", response_model=AnalysisDetailResponse, tags=["Analyses"])
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full status and lifecycle details for an analysis."""
    a = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    sample_name = a.sample.file_name if a.sample else "Unknown"
    sample_sha = a.sample.sha256 if a.sample else "Unknown"
    events_count = len(a.events) if a.events else 0
    findings_count = len(a.findings) if a.findings else 0
    risk_score = a.report.risk_score if a.report else None
    risk_level = a.report.risk_level if a.report else None

    return AnalysisDetailResponse(
        id=a.id,
        sample_id=a.sample_id,
        status=AnalysisStatus(a.status),
        backend_type=SandboxBackendType(a.backend_type),
        profile=a.profile,
        timeout_seconds=a.timeout_seconds,
        live_mode=a.live_mode,
        approved_by_user=a.approved_by_user,
        error_message=a.error_message,
        external_task_id=a.external_task_id,
        replay_scenario_id=a.replay_scenario_id,
        created_at=a.created_at,
        started_at=a.started_at,
        completed_at=a.completed_at,
        sample_file_name=sample_name,
        sample_sha256=sample_sha,
        total_events=events_count,
        total_findings=findings_count,
        risk_score=risk_score,
        risk_level=risk_level,
    )

@router.post("/analyses/{analysis_id}/cancel", response_model=AnalysisResponse, tags=["Analyses"])
def cancel_analysis(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Cancels a pending or running analysis using the JobQueueManager."""
    a = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    success = job_queue_manager.request_cancellation(analysis_id, db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel task in terminal state: {a.status}."
        )

    db.refresh(a)
    return a

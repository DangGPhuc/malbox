from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.analysis import Analysis, AnalysisStatus
from app.models.sample import Sample
from app.schemas.analysis import AnalysisCreate, AnalysisResponse, AnalysisDetailResponse

router = APIRouter()

@router.post("/analyses", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED, tags=["Analyses"])
def create_analysis(
    payload: AnalysisCreate,
    db: Session = Depends(get_db)
):
    """
    Initiates a new dynamic analysis workflow for an existing sample.
    Validates execution mode, safety gates, and sets initial state machine status.
    """
    sample = db.query(Sample).filter(Sample.id == payload.sample_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target sample does not exist.")

    # Safety Gate for Live Mode
    if payload.live_mode:
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

    analysis = Analysis(
        sample_id=payload.sample_id,
        status=AnalysisStatus.PREFLIGHT.value,
        backend_type=payload.backend_type,
        profile=payload.profile,
        timeout_seconds=payload.timeout_seconds,
        live_mode=payload.live_mode,
        approved_by_user=payload.approved_by_user,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
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
            backend_type=a.backend_type,
            profile=a.profile,
            timeout_seconds=a.timeout_seconds,
            live_mode=a.live_mode,
            approved_by_user=a.approved_by_user,
            error_message=a.error_message,
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
        backend_type=a.backend_type,
        profile=a.profile,
        timeout_seconds=a.timeout_seconds,
        live_mode=a.live_mode,
        approved_by_user=a.approved_by_user,
        error_message=a.error_message,
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
    """Cancels a pending or running analysis."""
    a = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")
    
    if a.status in [AnalysisStatus.COMPLETED.value, AnalysisStatus.FAILED.value, AnalysisStatus.CANCELLED.value]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel task in {a.status} state.")
    
    a.status = AnalysisStatus.CANCELLED.value
    a.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(a)
    return a

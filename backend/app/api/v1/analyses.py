import hmac
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db, SessionLocal
from app.models.analysis import Analysis, AnalysisStatus, SandboxBackendType, TERMINAL_STATES
from app.models.sample import Sample
from app.schemas.analysis import AnalysisCreate, AnalysisResponse, AnalysisDetailResponse
from app.services.sandbox.replay import REGISTERED_REPLAY_SCENARIOS
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
        # Operator Authentication Boundary for sensitive live detonation (fails closed if unconfigured)
        if not settings.OPERATOR_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Live detonation is blocked: Server operator security token is unconfigured (fail closed)."
            )
        if not x_operator_token or not hmac.compare_digest(x_operator_token, settings.OPERATOR_TOKEN):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Valid operator token required for live malware execution (X-Operator-Token)."
            )

    elif payload.backend_type == SandboxBackendType.REPLAY:
        if not getattr(settings, "ALLOW_SYNTHETIC_REPLAY", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Replay mode is deprecated and disabled in production. Live CAPE analysis is the default."
            )
        if payload.live_mode:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inconsistent configuration: Replay backend cannot run in live mode (must have live_mode=false)."
            )
        # Validate scenario ID if provided
        if payload.replay_scenario_id:
            if ".." in payload.replay_scenario_id or "/" in payload.replay_scenario_id or "\\" in payload.replay_scenario_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid replay scenario identifier: path traversal characters detected."
                )
            if payload.replay_scenario_id not in REGISTERED_REPLAY_SCENARIOS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unknown replay scenario identifier: '{payload.replay_scenario_id}'. Registered scenarios: {sorted(list(REGISTERED_REPLAY_SCENARIOS))}"
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
        # Enforce concurrency=1 even for synchronous requests
        analysis = job_queue_manager.execute_sync(analysis.id, db)
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
    x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"),
    db: Session = Depends(get_db)
):
    """Cancels a pending or running analysis using the JobQueueManager."""
    a = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    # Protect sensitive live analysis cancellation operations
    if a.live_mode:
        if not settings.OPERATOR_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Live cancellation blocked: Server operator security token is unconfigured (fail closed)."
            )
        if not x_operator_token or not hmac.compare_digest(x_operator_token, settings.OPERATOR_TOKEN):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Valid operator token required to cancel live malware analysis (X-Operator-Token)."
            )

    success = job_queue_manager.request_cancellation(analysis_id, db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel task in terminal state: {a.status}."
        )

    db.refresh(a)
    return a

@router.post("/analyses/{analysis_id}/retry", response_model=AnalysisResponse, tags=["Analyses"])
def retry_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
    run_sync: bool = Query(False),
    x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"),
):
    """
    Allows safe operator retry of failed or cancelled analysis tasks.
    Enforces operator security token for live mode and concurrency limits.
    """
    a = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    if a.status not in [AnalysisStatus.FAILED.value, AnalysisStatus.CANCELLED.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot retry analysis in status '{a.status}'. Only FAILED or CANCELLED analyses can be retried."
        )

    # Protect live analysis retry operations
    if a.live_mode:
        if not settings.OPERATOR_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Live retry blocked: Server operator security token is unconfigured (fail closed)."
            )
        if not x_operator_token or not hmac.compare_digest(x_operator_token, settings.OPERATOR_TOKEN):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Valid operator token required to retry live malware analysis (X-Operator-Token)."
            )

        # Recheck Live Mode & confinement readiness
        if a.backend_type == SandboxBackendType.CAPE.value:
            from app.services.sandbox.confinement import verify_cape_confinement
            target_machine = getattr(settings, "CAPE_DEFAULT_MACHINE", "win10_analyst")
            target_route = getattr(settings, "CAPE_DEFAULT_NETWORK_ROUTE", "drop")
            conf_res = verify_cape_confinement(target_machine=target_machine, target_route=target_route)
            if not conf_res.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_412_PRECONDITION_FAILED,
                    detail=f"Live retry blocked by confinement policy: {conf_res.error or conf_res.status}"
                )

            # Reconcile previous CAPE task before retrying
            if a.external_task_id:
                from app.services.sandbox.cape import cape_adapter
                try:
                    task_status = cape_adapter.get_task_status(a.external_task_id)
                    cape_status = str(task_status.get("cape_status", "")).lower()

                    # Prevent duplicate remote detonation if task is still running or pending
                    if cape_status in ("running", "processing", "pending", "distributed"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=f"Cannot retry analysis: remote CAPE task {a.external_task_id} is still active (status: {cape_status}). Reconcile or cancel remote task before retrying."
                        )

                    # For cancelled tasks, confirm remote cancellation/cleanup before retrying
                    if a.status == AnalysisStatus.CANCELLED.value:
                        if cape_status not in ("completed", "reported", "failed", "not_found", "deleted"):
                            cape_adapter.cancel_task(a.external_task_id)
                            recheck = cape_adapter.get_task_status(a.external_task_id)
                            recheck_status = str(recheck.get("cape_status", "")).lower()
                            if recheck_status in ("running", "processing", "pending"):
                                raise HTTPException(
                                    status_code=status.HTTP_409_CONFLICT,
                                    detail=f"Cannot retry cancelled analysis: remote CAPE task {a.external_task_id} cleanup could not be confirmed."
                                )
                except HTTPException:
                    raise
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Failed to reconcile previous remote CAPE task {a.external_task_id}: {str(e)}. Retry blocked to prevent duplicate remote execution."
                    )

    # Record retry event for provenance and preserve historical evidence
    from app.models.event import AnalysisEvent
    retry_event = AnalysisEvent(
        analysis_id=a.id,
        category="artifact",
        action="operator_retry",
        attributes={
            "previous_status": a.status,
            "previous_external_task_id": a.external_task_id,
            "live_mode": a.live_mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        source_tool="operator",
        confidence=1.0,
    )
    db.add(retry_event)

    # Reset analysis status to QUEUED, clear external_task_id for fresh execution, and clear transient error state
    a.external_task_id = None
    a.status = AnalysisStatus.QUEUED.value
    a.error_message = None
    a.started_at = None
    a.completed_at = None
    db.commit()
    db.refresh(a)

    if run_sync:
        a = job_queue_manager.execute_sync(a.id, db)
    else:
        job_queue_manager.start()

    return a

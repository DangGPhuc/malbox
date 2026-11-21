from __future__ import annotations

import hmac
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai.opencode_sandbox import check_os_sandbox_support
from app.core.config import settings
from app.core.database import get_db
from app.models.analysis import Analysis
from app.models.sample import Sample
from app.models.static_analysis import StaticAnalysisRecord
from app.schemas.static_analysis import StaticAnalysisResult
from app.services.static_analysis.containment import check_cgroup_memory_support, check_vm_memory_headroom
from app.services.static_analysis.selector import build_static_result_response
from app.services.static_analysis.version_check import validate_ghidra_runtime
from app.services.static_analysis.worker import (
    StaticAnalysisBusyError,
    StaticAnalysisSubmissionError,
    static_worker_manager,
)

router = APIRouter()


class StaticAnalysisJobAcceptedResponse(BaseModel):
    job_id: str
    sample_id: str
    analysis_id: Optional[str] = None
    status: str
    message: str


def _verify_static_operator_token(x_reporting_token: Optional[str]) -> None:
    if not settings.REPORTING_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Static analysis trigger is disabled: server authorization token (MALBOX_REPORTING_AUTH_TOKEN) is unconfigured.",
        )
    if not x_reporting_token or not hmac.compare_digest(
        x_reporting_token, settings.REPORTING_AUTH_TOKEN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: valid X-Reporting-Token required for static analysis execution.",
        )


@router.get(
    "/analyses/{analysis_id}/static-analysis",
    response_model=StaticAnalysisResult,
    tags=["Static Analysis"],
)
def get_analysis_static_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves stored static analysis results without triggering Ghidra execution."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    sample = db.query(Sample).filter(Sample.id == analysis.sample_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent sample not found.")

    return build_static_result_response(
        db=db,
        sample=sample,
        requested_analysis_id=analysis_id,
    )


@router.post(
    "/analyses/{analysis_id}/static-analysis",
    response_model=StaticAnalysisJobAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Static Analysis"],
)
def trigger_analysis_static_analysis(
    analysis_id: str,
    x_reporting_token: Optional[str] = Header(None, alias="X-Reporting-Token"),
    db: Session = Depends(get_db),
):
    """
    Explicitly queues an optional, single-concurrency Ghidra Headless static analysis job
    for an existing analysis sample. Never runs decompilation synchronously inside the request.
    """
    _verify_static_operator_token(x_reporting_token)

    if not settings.GHIDRA_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ghidra static analysis is disabled by configuration (MALBOX_GHIDRA_ENABLED=false).",
        )

    runtime = validate_ghidra_runtime(configured_home=settings.GHIDRA_HOME)
    if not runtime.ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Ghidra Headless runtime unavailable: {runtime.error}",
        )

    mem_ok, _avail_mb, mem_msg = check_vm_memory_headroom(settings.GHIDRA_MIN_AVAILABLE_MEMORY_MB)
    if not mem_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=mem_msg,
        )

    sb_ok, _bwrap, sb_reason = check_os_sandbox_support("bwrap")
    if not sb_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Required Bubblewrap OS isolation unavailable for Ghidra: {sb_reason}",
        )

    if settings.GHIDRA_REQUIRE_CGROUP_MEMORY_LIMIT:
        cg = check_cgroup_memory_support()
        if not cg.supported:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Required Linux cgroup process-tree memory limit unavailable: {cg.reason}",
            )

    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    sample = db.query(Sample).filter(Sample.id == analysis.sample_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target sample not found.")

    try:
        rec = static_worker_manager.submit_job(db=db, sample=sample, analysis_id=analysis.id)
    except StaticAnalysisBusyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except StaticAnalysisSubmissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return StaticAnalysisJobAcceptedResponse(
        job_id=rec.id,
        sample_id=sample.id,
        analysis_id=analysis.id,
        status=rec.status,
        message="Bounded Ghidra Headless static analysis job queued (single-worker queue).",
    )


@router.get(
    "/samples/{sample_id}/static-analysis",
    response_model=StaticAnalysisResult,
    tags=["Static Analysis"],
)
def get_sample_static_analysis(
    sample_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves the latest static analysis result for a quarantined sample without running Ghidra."""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found.")

    return build_static_result_response(
        db=db,
        sample=sample,
        requested_analysis_id=None,
    )


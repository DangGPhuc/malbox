from __future__ import annotations

import hmac
from typing import Optional
from fastapi import APIRouter, Body, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.analysis import Analysis
from app.services.evidence_correlation.schemas import CorrelationResult
from app.services.evidence_correlation.service import EvidenceCorrelationService

router = APIRouter()


class CorrelationTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force: bool = False


def _verify_correlation_operator_token(x_reporting_token: Optional[str]) -> None:
    if not settings.REPORTING_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Evidence correlation trigger is disabled: server authorization token "
                "(MALBOX_REPORTING_AUTH_TOKEN) is unconfigured."
            ),
        )
    if not x_reporting_token or not hmac.compare_digest(
        x_reporting_token, settings.REPORTING_AUTH_TOKEN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: valid X-Reporting-Token required for evidence correlation.",
        )


@router.get(
    "/analyses/{analysis_id}/correlation",
    response_model=CorrelationResult,
    tags=["Evidence Correlation"],
)
def get_analysis_correlation(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieves stored static/dynamic evidence correlation without running Ghidra, CAPE, or OpenCode.
    Never modifies database state or deterministic risk scores.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    return EvidenceCorrelationService(db).get_correlation_readonly(analysis_id)


@router.post(
    "/analyses/{analysis_id}/correlation",
    response_model=CorrelationResult,
    tags=["Evidence Correlation"],
)
def trigger_analysis_correlation(
    analysis_id: str,
    payload: Optional[CorrelationTriggerRequest] = Body(default=None),
    x_reporting_token: Optional[str] = Header(None, alias="X-Reporting-Token"),
    db: Session = Depends(get_db),
):
    """
    Explicitly runs bounded deterministic static/dynamic correlation against existing persisted
    evidence and stores the versioned result. Never spawns Ghidra, CAPE, or external AI.
    """
    _verify_correlation_operator_token(x_reporting_token)

    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    force_recompute = bool(payload.force) if payload is not None else False
    return EvidenceCorrelationService(db).compute_and_persist(
        analysis_id=analysis_id,
        force=force_recompute,
        triggered_automatically=False,
    )


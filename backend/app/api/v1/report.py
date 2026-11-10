from copy import deepcopy
from typing import Literal, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai.llm_client import get_reporting_llm_provider
from app.ai.mock_provider import MockLLMProvider
from app.core.database import get_db
from app.models.analysis import Analysis
from app.models.report import AnalysisReport
from app.schemas.report import ReportResponse, RiskAssessment
from app.services.intelligence.bundle_builder import EvidenceBundleBuilder

router = APIRouter()


class IntelligenceEnrichRequest(BaseModel):
    mode: Literal["auto", "llm", "deterministic"] = "auto"

@router.get("/analyses/{analysis_id}/report", response_model=ReportResponse, tags=["Reporting"])
def get_analysis_report(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves the complete structured intelligence report."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    report_record = db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
    if not report_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report has not been generated yet.")

    return ReportResponse(
        id=report_record.id,
        analysis_id=report_record.analysis_id,
        executive_summary=report_record.executive_summary,
        risk_score=report_record.risk_score,
        risk_level=report_record.risk_level,
        backend_type=analysis.backend_type,
        is_replay=(analysis.backend_type == "replay"),
        replay_scenario_id=analysis.replay_scenario_id,
        full_report=report_record.full_report_json,
        created_at=report_record.created_at,
    )

@router.get("/analyses/{analysis_id}/report/html", response_class=HTMLResponse, tags=["Reporting"])
def get_analysis_report_html(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Renders and exports a standalone HTML executive and forensic report."""
    from app.services.reporting.export_html import generate_html_report
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    report_record = db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
    if not report_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report has not been generated yet.")

    html_content = generate_html_report(report_record.full_report_json)
    return HTMLResponse(content=html_content)


@router.post("/analyses/{analysis_id}/report/intelligence", response_model=ReportResponse, tags=["Reporting"])
def generate_report_intelligence(
    analysis_id: str,
    payload: Optional[IntelligenceEnrichRequest] = Body(default=None),
    db: Session = Depends(get_db),
):
    """
    Explicit opt-in endpoint to regenerate or enrich Phase 2A evidence-grounded
    AI intelligence on an existing analysis report without re-running the sandbox.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    report_record = db.query(AnalysisReport).filter(AnalysisReport.analysis_id == analysis_id).first()
    if not report_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report has not been generated yet.")

    updated_json = deepcopy(report_record.full_report_json or {})
    raw_risk = updated_json.get("risk_assessment") or {
        "score": report_record.risk_score,
        "level": report_record.risk_level,
    }
    risk_assessment = RiskAssessment.model_validate(raw_risk)
    env_meta = updated_json.get("analysis_environment") or {}

    bundle = EvidenceBundleBuilder(db).build(
        analysis_id=analysis_id,
        risk_assessment=risk_assessment,
        env_metadata=env_meta if isinstance(env_meta, dict) else {},
    )

    requested_mode = payload.mode if payload else "auto"
    if requested_mode == "deterministic":
        provider = MockLLMProvider()
    else:
        provider = get_reporting_llm_provider(force_external=True)

    intelligence_report = provider.generate_intelligence_report(bundle)
    updated_json["intelligence_report"] = intelligence_report.model_dump()
    updated_json["executive_summary"] = intelligence_report.executive_assessment

    report_record.executive_summary = intelligence_report.executive_assessment
    report_record.full_report_json = updated_json
    db.commit()
    db.refresh(report_record)

    return ReportResponse(
        id=report_record.id,
        analysis_id=report_record.analysis_id,
        executive_summary=report_record.executive_summary,
        risk_score=report_record.risk_score,
        risk_level=report_record.risk_level,
        backend_type=analysis.backend_type,
        is_replay=(analysis.backend_type == "replay"),
        replay_scenario_id=analysis.replay_scenario_id,
        full_report=report_record.full_report_json,
        created_at=report_record.created_at,
    )


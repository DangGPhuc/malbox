from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis import Analysis
from app.models.report import AnalysisReport
from app.schemas.report import ReportResponse

router = APIRouter()

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

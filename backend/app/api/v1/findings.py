from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis import Analysis
from app.models.finding import BehavioralFinding
from app.schemas.finding import FindingResponse, ProcessTreeResponse

router = APIRouter()

@router.get("/analyses/{analysis_id}/findings", response_model=List[FindingResponse], tags=["Detection & Findings"])
def get_analysis_findings(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves detected behavioral findings and MITRE ATT&CK technique mappings."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    findings = (
        db.query(BehavioralFinding)
        .filter(BehavioralFinding.analysis_id == analysis_id)
        .order_by(BehavioralFinding.created_at.asc())
        .all()
    )
    return findings

@router.get("/analyses/{analysis_id}/process-tree", response_model=ProcessTreeResponse, tags=["Detection & Findings"])
def get_analysis_process_tree(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves reconstructed process hierarchy for execution lineage analysis."""
    from app.services.correlation.process_tree import build_process_tree
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    tree = build_process_tree(analysis_id, db)
    return tree


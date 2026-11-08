from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis import Analysis
from app.models.audit import OrchestrationRecord
from app.schemas.orchestration import OrchestrationRecordResponse

router = APIRouter()

@router.get("/analyses/{analysis_id}/orchestration", response_model=List[OrchestrationRecordResponse], tags=["AI Orchestration"])
def get_orchestration_history(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full AI orchestration decision audit trail and policy validation logs."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    records = (
        db.query(OrchestrationRecord)
        .filter(OrchestrationRecord.analysis_id == analysis_id)
        .order_by(OrchestrationRecord.created_at.asc())
        .all()
    )
    return records


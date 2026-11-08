from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis import Analysis
from app.models.event import AnalysisEvent
from app.schemas.event import EventResponse, PaginatedEvents

router = APIRouter()

@router.get("/analyses/{analysis_id}/events", response_model=PaginatedEvents, tags=["Telemetry & Events"])
def get_analysis_events(
    analysis_id: str,
    category: Optional[str] = Query(None, description="Filter by event category"),
    action: Optional[str] = Query(None, description="Filter by event action"),
    process_id: Optional[int] = Query(None, description="Filter by process ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves normalized telemetry events for an analysis task with filtering and pagination."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    query = db.query(AnalysisEvent).filter(AnalysisEvent.analysis_id == analysis_id)
    if category:
        query = query.filter(AnalysisEvent.category == category)
    if action:
        query = query.filter(AnalysisEvent.action == action)
    if process_id:
        query = query.filter(AnalysisEvent.process_id == process_id)

    total = query.count()
    items = (
        query.order_by(AnalysisEvent.timestamp.asc().nulls_last(), AnalysisEvent.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedEvents(
        total=total,
        page=page,
        page_size=page_size,
        items=items
    )

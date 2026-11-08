from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.analysis import Analysis
from app.schemas.graph import BehaviorGraphResponse

router = APIRouter()

@router.get("/analyses/{analysis_id}/graph", response_model=BehaviorGraphResponse, tags=["Behavior Graph"])
def get_analysis_behavior_graph(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves Cytoscape-compatible interactive behavior graph."""
    from app.services.graph.builder import build_behavior_graph
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    graph = build_behavior_graph(analysis_id, db)
    return graph


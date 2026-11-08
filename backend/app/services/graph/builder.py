from sqlalchemy.orm import Session
from app.schemas.graph import BehaviorGraphResponse

def build_behavior_graph(analysis_id: str, db: Session) -> BehaviorGraphResponse:
    """Builds Cytoscape-compatible behavior graph from events and correlations."""
    # Will be fully populated in Phase 2
    return BehaviorGraphResponse(analysis_id=analysis_id, nodes=[], edges=[], total_nodes=0, total_edges=0)

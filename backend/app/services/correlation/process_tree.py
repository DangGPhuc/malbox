from sqlalchemy.orm import Session
from app.schemas.finding import ProcessTreeResponse, ProcessTreeNode

def build_process_tree(analysis_id: str, db: Session) -> ProcessTreeResponse:
    """Builds a hierarchical process execution tree from correlated events."""
    # Will be fully populated in Phase 2
    return ProcessTreeResponse(analysis_id=analysis_id, root_nodes=[], total_processes=0)

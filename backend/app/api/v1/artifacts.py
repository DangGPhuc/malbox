from typing import List, Dict, Any
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.analysis import Analysis

router = APIRouter()

@router.get("/analyses/{analysis_id}/artifacts", response_model=List[Dict[str, Any]], tags=["Artifacts"])
def list_analysis_artifacts(
    analysis_id: str,
    db: Session = Depends(get_db)
):
    """Lists safe forensic artifacts (e.g. PCAP, screenshots, dropped files) collected during execution."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    artifacts_dir = settings.ARTIFACTS_DIR / analysis_id
    if not artifacts_dir.exists():
        return []

    results = []
    for p in artifacts_dir.glob("*"):
        if p.is_file():
            results.append({
                "file_name": p.name,
                "file_size": p.stat().st_size,
                "artifact_type": p.suffix.lstrip(".").lower() or "binary",
                "relative_path": f"/api/v1/analyses/{analysis_id}/artifacts/{p.name}",
            })
    return results

@router.get("/analyses/{analysis_id}/artifacts/{artifact_name}", tags=["Artifacts"])
def download_artifact(
    analysis_id: str,
    artifact_name: str,
    db: Session = Depends(get_db)
):
    """Safely retrieves a specific forensic artifact without executing it."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis task not found.")

    # Sanitize artifact_name against directory traversal
    safe_name = Path(artifact_name).name
    artifact_path = settings.ARTIFACTS_DIR / analysis_id / safe_name

    if not artifact_path.exists() or not artifact_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file not found.")

    return FileResponse(
        path=artifact_path,
        filename=safe_name,
        media_type="application/octet-stream"
    )


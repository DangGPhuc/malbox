from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.sample import Sample
from app.schemas.sample import SampleResponse
from app.services.submission.service import SubmissionService

router = APIRouter()

@router.post("/samples", response_model=SampleResponse, status_code=status.HTTP_201_CREATED, tags=["Samples"])
async def upload_sample(
    file: UploadFile = File(..., description="Windows PE executable to analyze"),
    db: Session = Depends(get_db)
):
    """
    Submits a suspicious binary for isolation, metadata inspection, and static PE triage.
    Enforces quarantine storage and deduplication. Does NOT execute binary on host.
    """
    contents = await file.read()
    service = SubmissionService(db)
    sample = service.submit_sample(file_bytes=contents, original_filename=file.filename or "unknown.bin")
    return sample

@router.get("/samples", response_model=List[SampleResponse], tags=["Samples"])
def list_samples(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists submitted samples in reverse chronological order."""
    samples = db.query(Sample).order_by(Sample.created_at.desc()).offset(offset).limit(limit).all()
    return samples

@router.get("/samples/{sample_id}", response_model=SampleResponse, tags=["Samples"])
def get_sample(
    sample_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves metadata and static PE analysis for a specific sample."""
    service = SubmissionService(db)
    sample = service.get_sample_by_id(sample_id)
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found.")
    return sample

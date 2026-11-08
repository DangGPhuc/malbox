import os
from pathlib import Path
from typing import Tuple, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.security import sanitize_filename, compute_hashes_and_size
from app.models.sample import Sample
from app.services.submission.pe_parser import parse_pe_metadata

class SubmissionService:
    def __init__(self, db: Session):
        self.db = db

    def submit_sample(self, file_bytes: bytes, original_filename: str) -> Sample:
        """
        Accepts, inspects, quarantines, and deduplicates a suspicious executable.
        Never executes the uploaded binary.
        """
        if not file_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty file uploaded."
            )

        file_size = len(file_bytes)
        if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed upload size ({settings.MAX_UPLOAD_SIZE_BYTES} bytes)."
            )

        sha256, sha1, md5, _ = compute_hashes_and_size(file_bytes)
        safe_name = sanitize_filename(original_filename)

        # Check for existing sample deduplication
        existing = self.db.query(Sample).filter(Sample.sha256 == sha256).first()
        if existing:
            return existing

        # Ensure quarantine directory exists
        settings.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        quarantine_file_path = settings.QUARANTINE_DIR / f"{sha256}.bin"

        # Safely write to quarantine with non-executable permissions
        try:
            with open(quarantine_file_path, "wb") as f:
                f.write(file_bytes)
            # Make quarantined file read-only, non-executable (0400)
            os.chmod(quarantine_file_path, 0o400)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to isolate sample in secure quarantine: {str(e)}"
            )

        # Static PE triage without host execution
        pe_meta = parse_pe_metadata(file_bytes)
        is_pe = pe_meta.get("is_valid_pe", False)

        sample = Sample(
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            file_name=safe_name,
            file_size=file_size,
            mime_type="application/vnd.microsoft.portable-executable" if is_pe else "application/octet-stream",
            is_pe=is_pe,
            pe_metadata=pe_meta,
            quarantine_path=str(quarantine_file_path),
        )

        self.db.add(sample)
        self.db.commit()
        self.db.refresh(sample)
        return sample

    def get_sample_by_id(self, sample_id: str) -> Optional[Sample]:
        return self.db.query(Sample).filter(Sample.id == sample_id).first()

    def get_sample_by_hash(self, sha256: str) -> Optional[Sample]:
        return self.db.query(Sample).filter(Sample.sha256 == sha256).first()

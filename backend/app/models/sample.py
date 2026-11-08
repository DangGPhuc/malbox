import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base

class Sample(Base):
    __tablename__ = "samples"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    sha1 = Column(String(40), index=True, nullable=False)
    md5 = Column(String(32), index=True, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), default="application/octet-stream")
    is_pe = Column(Boolean, default=False)
    pe_metadata = Column(JSON, nullable=True)
    quarantine_path = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    analyses = relationship("Analysis", back_populates="sample", cascade="all, delete-orphan")

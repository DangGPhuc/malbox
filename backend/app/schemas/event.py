from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

class EventCreate(BaseModel):
    category: str = Field(..., description="Category: process, file, registry, network, dns, http, api, persistence, artifact")
    action: str = Field(..., description="Specific action: spawn, write, delete, reg_write, connect, resolve, etc.")
    timestamp: Optional[datetime] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    target_path: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source_tool: str = "sandbox"
    confidence: float = 1.0

class EventResponse(EventCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    created_at: datetime

class PaginatedEvents(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[EventResponse]

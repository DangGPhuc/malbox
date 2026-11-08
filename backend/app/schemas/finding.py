from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    analysis_id: str
    rule_id: str
    title: str
    description: str
    severity: str  # Informational, Low, Medium, High, Critical
    confidence: float
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    supporting_event_ids: List[str] = Field(default_factory=list)
    created_at: datetime

class ProcessTreeNode(BaseModel):
    pid: int
    name: str
    ppid: Optional[int] = None
    command_line: Optional[str] = None
    spawn_time: Optional[str] = None
    terminate_time: Optional[str] = None
    suspicious: bool = False
    children: List["ProcessTreeNode"] = Field(default_factory=list)
    events_count: int = 0
    event_ids: List[str] = Field(default_factory=list)

class ProcessTreeResponse(BaseModel):
    analysis_id: str
    root_nodes: List[ProcessTreeNode] = Field(default_factory=list)
    total_processes: int = 0

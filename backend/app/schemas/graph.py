from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class GraphNodeData(BaseModel):
    id: str
    label: str
    type: str  # Sample, Process, File, RegistryKey, Domain, IPAddress, NetworkConnection, BehavioralFinding, Artifact
    details: Dict[str, Any] = Field(default_factory=dict)
    suspicious: bool = False
    severity: Optional[str] = None
    pid: Optional[int] = None

class GraphNode(BaseModel):
    data: GraphNodeData

class GraphEdgeData(BaseModel):
    id: str
    source: str
    target: str
    label: str  # EXECUTED_AS, SPAWNED, CREATED, MODIFIED, DELETED, ACCESSED, CONNECTED_TO, RESOLVED_TO, DROPPED, OBSERVED_IN, SUPPORTS_FINDING
    event_ids: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    data: GraphEdgeData

class BehaviorGraphResponse(BaseModel):
    analysis_id: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0


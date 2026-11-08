from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

class SectionInfo(BaseModel):
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    entropy: float
    characteristics: List[str] = Field(default_factory=list)

class ImportFunction(BaseModel):
    dll: str
    functions: List[str] = Field(default_factory=list)

class PEMetadata(BaseModel):
    is_valid_pe: bool
    machine_type: str = "Unknown"
    subsystem: str = "Unknown"
    compile_time: Optional[str] = None
    entry_point: Optional[str] = None
    image_base: Optional[str] = None
    number_of_sections: int = 0
    sections: List[SectionInfo] = Field(default_factory=list)
    imports: List[ImportFunction] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    overall_entropy: float = 0.0
    is_packed_heuristic: bool = False
    warning: Optional[str] = None

class SampleBase(BaseModel):
    file_name: str
    file_size: int
    mime_type: str = "application/octet-stream"

class SampleResponse(SampleBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sha256: str
    sha1: str
    md5: str
    is_pe: bool
    pe_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime

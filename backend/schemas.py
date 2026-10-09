from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List
from datetime import datetime

class AnalyzeRequest(BaseModel):
    """Request payload for /analyze endpoint."""
    input: str = Field(..., description="A URL, IP address or domain to be analyzed")

    @field_validator("input")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Input cannot be empty")
        return v

class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    input: str
    input_type: str
    risk_score: float
    risk_level: str
    findings: str
    timestamp: datetime
    url: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    evidence_id: str
    threat_intelligence_sources: List[str] = Field(default_factory=list)
    threat_intelligence_summary: str = ""

class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: str
    input_value: str
    input_type: str
    url: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    risk_score: float
    risk_level: str
    findings: Optional[str] = None
    threat_intelligence_sources: Optional[str] = None
    threat_intelligence_summary: Optional[str] = None
    timestamp: datetime

class ReportRequest(BaseModel):
    """Data needed to generate an incident report (future implementation)."""
    title: str = Field(..., description="Report title")
    description: Optional[str] = Field(None, description="Brief description of the incident")
    evidence_ids: List[str] = Field(..., description="List of evidence IDs to include in the report")


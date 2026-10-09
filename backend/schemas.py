from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List, Any, Dict
from datetime import datetime

class AnalyzeRequest(BaseModel):
    """Request payload for /analyze endpoint."""
    input: str = Field(..., description="A URL, IP address or domain to be analyzed")
    case_id: Optional[str] = Field(None, description="Optional Investigation Case ID to associate evidence with")

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
    sha256_hash: Optional[str] = None
    case_id: Optional[str] = None
    heuristic_breakdown: Optional[List[Dict[str, Any]]] = None
    threat_intel_breakdown: Optional[List[Dict[str, Any]]] = None

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
    sha256_hash: Optional[str] = None
    timestamp: datetime
    cases: Optional[List[str]] = Field(default_factory=list)

class EvidenceVerifyResponse(BaseModel):
    evidence_id: str
    status: str  # VERIFIED, INTEGRITY_MISMATCH, UNHASHED_LEGACY
    matches: bool
    stored_hash: Optional[str] = None
    calculated_hash: str
    protected_fields: List[str]
    message: str
    disclaimer: str

class CaseCreate(BaseModel):
    title: str = Field(..., description="Investigation Case title")
    description: Optional[str] = Field(None, description="Detailed case description or scope")

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Case title cannot be empty")
        return v.strip()

class CaseEvidenceAdd(BaseModel):
    evidence_id: str = Field(..., description="Evidence ID to link to the case")
    notes: Optional[str] = Field(None, description="Optional investigative notes regarding this evidence in this case")

class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: str
    title: str
    description: Optional[str] = None
    status: str
    created_at: datetime
    evidence_count: int = 0

class TimelineEvent(BaseModel):
    event_type: str
    timestamp: Optional[str] = None
    title: str
    details: str
    evidence_id: Optional[str] = None

class CaseDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: str
    title: str
    description: Optional[str] = None
    status: str
    created_at: datetime
    evidence_records: List[EvidenceResponse] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)

class ReportRequest(BaseModel):
    """Data needed to generate an incident report."""
    title: str = Field(default="Cyber Incident Evidence Report", description="Report title")
    description: Optional[str] = Field(None, description="Brief description of the incident / investigator notes")
    evidence_ids: Optional[List[str]] = Field(default_factory=list, description="List of evidence IDs to include")
    case_id: Optional[str] = Field(None, description="Optional Investigation Case ID to generate report for")

class IndicatorMatch(BaseModel):
    indicator_type: str
    matched_value: str
    is_private_or_shared: bool = False
    details: Optional[str] = None

class CorrelationRelationship(BaseModel):
    relationship_id: str
    source_evidence_id: str
    target_evidence_id: str
    source_input: str
    target_input: str
    source_risk_level: Optional[str] = None
    target_risk_level: Optional[str] = None
    relationship_type: str
    confidence_level: str
    rule_applied: Optional[str] = None
    matched_indicators: List[IndicatorMatch] = Field(default_factory=list)
    time_delta_seconds: Optional[float] = None
    time_delta_human: Optional[str] = None
    simple_explanation: Optional[str] = None
    investigator_action: Optional[str] = None
    explanation: str
    forensic_caveat: str

class CorrelationSummary(BaseModel):
    total_records_analyzed: int
    total_correlations_found: int
    relationship_type_counts: dict[str, int] = Field(default_factory=dict)
    correlations: List[CorrelationRelationship] = Field(default_factory=list)

class CorrelateRequest(BaseModel):
    evidence_ids: Optional[List[str]] = Field(None, description="Optional list of specific evidence IDs to correlate")
    case_id: Optional[str] = Field(None, description="Optional Investigation Case ID to correlate evidence within")

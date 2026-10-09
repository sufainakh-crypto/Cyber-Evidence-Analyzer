from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
try:
    from .database import Base
except ImportError:
    from database import Base

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String, unique=True, index=True, nullable=False)
    input_value = Column(String, nullable=False)
    input_type = Column(String, nullable=False)  # url, ip, domain
    url = Column(String, nullable=True)
    domain = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)  # LOW, MEDIUM, HIGH
    findings = Column(Text, nullable=True)
    threat_intelligence_sources = Column(Text, nullable=True)
    threat_intelligence_summary = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=True)
    heuristic_details = Column(Text, nullable=True)
    threat_intel_details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    @property
    def input(self) -> str:
        return self.input_value

class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="OPEN")  # OPEN, IN_REVIEW, CLOSED
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, index=True, nullable=False)
    evidence_id = Column(String, index=True, nullable=False)
    notes = Column(Text, nullable=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now())

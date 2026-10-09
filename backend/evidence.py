import re
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
try:
    from . import models, integrity
except ImportError:
    import models, integrity

def generate_evidence_id(db: Session) -> str:
    """Generate unique, sequential evidence ID formatted like EV-001, EV-002, EV-003."""
    records = db.query(models.Evidence.evidence_id).all()
    max_num = 0
    pattern = re.compile(r"^EV-(\d+)$")

    for (eid,) in records:
        if eid:
            match = pattern.match(eid)
            if match:
                num = int(match.group(1))
                if num > max_num:
                    max_num = num

    if max_num == 0:
        # Fallback to max DB primary key if present
        max_id_val = db.query(func.max(models.Evidence.id)).scalar()
        if max_id_val:
            max_num = max_id_val

    return f"EV-{max_num + 1:03d}"

def create_evidence(db: Session, analysis_data: dict) -> models.Evidence:
    """Save an analysis result dict to SQLite database as an Evidence record."""
    evidence_id = analysis_data.get("evidence_id") or generate_evidence_id(db)

    # Compute hash if missing
    stored_hash = analysis_data.get("sha256_hash")
    if not stored_hash:
        stored_hash = integrity.compute_evidence_hash({
            "evidence_id": evidence_id,
            "input_value": analysis_data["input"],
            "input_type": analysis_data["input_type"],
            "risk_score": analysis_data["risk_score"],
            "risk_level": analysis_data["risk_level"],
            "timestamp": analysis_data["timestamp"],
        })

    ev = models.Evidence(
        evidence_id=evidence_id,
        input_value=analysis_data["input"],
        input_type=analysis_data["input_type"],
        url=analysis_data.get("url"),
        domain=analysis_data.get("domain"),
        ip_address=analysis_data.get("ip_address"),
        risk_score=analysis_data["risk_score"],
        risk_level=analysis_data["risk_level"],
        findings=analysis_data.get("findings"),
        threat_intelligence_sources=analysis_data.get("threat_intelligence_sources"),
        threat_intelligence_summary=analysis_data.get("threat_intelligence_summary"),
        sha256_hash=stored_hash,
        timestamp=analysis_data["timestamp"],
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev

def get_all_evidence(db: Session) -> List[models.Evidence]:
    """Retrieve all evidence records ordered by creation ID descending."""
    return db.query(models.Evidence).order_by(models.Evidence.id.asc()).all()

def get_evidence_by_id(db: Session, evidence_id: str) -> Optional[models.Evidence]:
    """Retrieve a single evidence record by evidence_id."""
    return db.query(models.Evidence).filter(models.Evidence.evidence_id == evidence_id).first()

def delete_evidence_by_id(db: Session, evidence_id: str) -> bool:
    """Delete an evidence record by evidence_id. Returns True if deleted, False if not found."""
    ev = get_evidence_by_id(db, evidence_id)
    if not ev:
        return False
    db.delete(ev)
    db.commit()
    return True


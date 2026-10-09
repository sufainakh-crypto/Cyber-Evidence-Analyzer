import os
import re
import json
from typing import Optional, List
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
try:
    from .database import SessionLocal, engine, Base, init_db
    from datetime import datetime, timezone
    from . import models, schemas, analyzer, correlation, integrity, report
except ImportError:
    from database import SessionLocal, engine, Base, init_db
    from datetime import datetime, timezone
    import models, schemas, analyzer, correlation, integrity, report

load_dotenv()

# Initialize database tables and columns safely
init_db()

app = FastAPI(
    title="Cyber Evidence Analyzer API",
    description="Backend API for cyber evidence analysis with Threat Intelligence, Case Management, and Cryptographic Integrity.",
    version="0.3.0"
)

# Enable CORS for all origins so React frontend can connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency to get a DB session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_case_id(db: Session) -> str:
    """Generate sequential unique Case ID (e.g. CASE-001, CASE-002)."""
    existing = db.query(models.Case.case_id).all()
    max_num = 0
    pattern = re.compile(r"^CASE-(\d+)$")
    for (cid,) in existing:
        if cid:
            match = pattern.match(cid)
            if match:
                num = int(match.group(1))
                if num > max_num:
                    max_num = num

    if max_num == 0:
        count = db.query(models.Case).count()
        max_num = count

    return f"CASE-{max_num + 1:03d}"


@app.get("/")
def root():
    """Health check and API overview endpoint."""
    return {
        "status": "online",
        "service": "Cyber Evidence Analyzer API",
        "version": "0.3.0",
        "docs_url": "/docs"
    }


# ==========================================
# FEATURE: Threat Analysis & Ingestion
# ==========================================

@app.post("/analyze", response_model=schemas.AnalyzeResponse)
def analyze(request: schemas.AnalyzeRequest, db: Session = Depends(get_db)):
    """Accept a URL, IP address or domain, perform analysis with Threat Intelligence, and store as evidence."""
    # Check if case_id was provided and valid
    if request.case_id:
        c = db.query(models.Case).filter(models.Case.case_id == request.case_id).first()
        if not c:
            raise HTTPException(status_code=404, detail=f"Case '{request.case_id}' does not exist.")

    # Perform analysis
    try:
        result = analyzer.analyze_input(request.input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sources_str = ", ".join(result.get("threat_intelligence_sources", []))
    heuristic_json = json.dumps(result.get("heuristic_breakdown", []))
    threat_intel_json = json.dumps(result.get("threat_intel_breakdown", []))

    ev = models.Evidence(
        evidence_id=result["evidence_id"],
        input_value=result["input"],
        input_type=result["input_type"],
        url=result.get("url"),
        domain=result.get("domain"),
        ip_address=result.get("ip_address"),
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        findings=result["findings"],
        threat_intelligence_sources=sources_str,
        threat_intelligence_summary=result.get("threat_intelligence_summary"),
        sha256_hash=result.get("sha256_hash"),
        heuristic_details=heuristic_json,
        threat_intel_details=threat_intel_json,
        timestamp=result["timestamp"],
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)

    # If linked to a case, record association
    if request.case_id:
        link = models.CaseEvidence(
            case_id=request.case_id,
            evidence_id=result["evidence_id"],
            notes=f"Analyzed directly during investigation of {request.case_id}.",
        )
        db.add(link)
        db.commit()
        result["case_id"] = request.case_id

    return schemas.AnalyzeResponse(**result)


# ==========================================
# FEATURE: Evidence Management & Integrity
# ==========================================

@app.get("/evidence", response_model=List[schemas.EvidenceResponse])
def get_all_evidence(db: Session = Depends(get_db)):
    """Return all saved evidence records, with any associated Case IDs."""
    records = db.query(models.Evidence).all()

    # Pre-fetch case mappings
    links = db.query(models.CaseEvidence).all()
    ev_case_map = {}
    for l in links:
        ev_case_map.setdefault(l.evidence_id, []).append(l.case_id)

    results = []
    for rec in records:
        data = schemas.EvidenceResponse.model_validate(rec)
        data.cases = ev_case_map.get(rec.evidence_id, [])
        results.append(data)

    return results


@app.get("/evidence/{evidence_id}", response_model=schemas.EvidenceResponse)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Return a single evidence record by its evidence_id."""
    ev = db.query(models.Evidence).filter(models.Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    links = db.query(models.CaseEvidence).filter(models.CaseEvidence.evidence_id == evidence_id).all()
    data = schemas.EvidenceResponse.model_validate(ev)
    data.cases = [l.case_id for l in links]
    return data


@app.get("/evidence/{evidence_id}/verify", response_model=schemas.EvidenceVerifyResponse)
def verify_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Cryptographically verify the integrity of an evidence record using SHA-256."""
    ev = db.query(models.Evidence).filter(models.Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    rec_data = {
        "evidence_id": ev.evidence_id,
        "input_value": ev.input_value,
        "input_type": ev.input_type,
        "risk_score": ev.risk_score,
        "risk_level": ev.risk_level,
        "timestamp": ev.timestamp,
    }

    result = integrity.verify_evidence_hash(ev.sha256_hash, rec_data)
    return schemas.EvidenceVerifyResponse(
        evidence_id=ev.evidence_id,
        status=result["status"],
        matches=result["matches"],
        stored_hash=result["stored_hash"],
        calculated_hash=result["calculated_hash"],
        protected_fields=result["protected_fields"],
        message=result["message"],
        disclaimer=result["disclaimer"],
    )


@app.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Delete a specific evidence record and unlink from cases."""
    ev = db.query(models.Evidence).filter(models.Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # Clean up any case links
    db.query(models.CaseEvidence).filter(models.CaseEvidence.evidence_id == evidence_id).delete()
    db.delete(ev)
    db.commit()
    return {"detail": f"Evidence {evidence_id} deleted"}


# ==========================================
# FEATURE 1: Case-Based Evidence Management
# ==========================================

@app.get("/cases", response_model=List[schemas.CaseResponse])
def get_cases(db: Session = Depends(get_db)):
    """Return all investigation cases with linked evidence count."""
    cases = db.query(models.Case).order_by(models.Case.created_at.desc()).all()
    results = []
    for c in cases:
        count = db.query(models.CaseEvidence).filter(models.CaseEvidence.case_id == c.case_id).count()
        item = schemas.CaseResponse.model_validate(c)
        item.evidence_count = count
        results.append(item)
    return results


@app.post("/cases", response_model=schemas.CaseResponse)
def create_case(case_in: schemas.CaseCreate, db: Session = Depends(get_db)):
    """Create a new investigation case with unique Case ID."""
    case_id = generate_case_id(db)
    new_case = models.Case(
        case_id=case_id,
        title=case_in.title,
        description=case_in.description,
        status="OPEN",
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    res = schemas.CaseResponse.model_validate(new_case)
    res.evidence_count = 0
    return res


@app.get("/cases/{case_id}", response_model=schemas.CaseDetailResponse)
def get_case_detail(case_id: str, db: Session = Depends(get_db)):
    """Retrieve an investigation case, all linked evidence items, and chronological timeline."""
    c = db.query(models.Case).filter(models.Case.case_id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    links = db.query(models.CaseEvidence).filter(models.CaseEvidence.case_id == case_id).all()
    ev_ids = [l.evidence_id for l in links]

    evidence_records = []
    if ev_ids:
        evidence_records = db.query(models.Evidence).filter(models.Evidence.evidence_id.in_(ev_ids)).all()

    # Build chronological timeline
    timeline = []
    if c.created_at:
        timeline.append(schemas.TimelineEvent(
            event_type="CASE_CREATED",
            timestamp=c.created_at.isoformat(),
            title=f"Case Opened: {c.title}",
            details=f"Investigation case {c.case_id} registered.",
            evidence_id=None,
        ))

    for ev in evidence_records:
        timeline.append(schemas.TimelineEvent(
            event_type="EVIDENCE_RECORDED",
            timestamp=ev.timestamp.isoformat() if ev.timestamp else None,
            title=f"Evidence Logged: {ev.input_value}",
            details=f"{ev.input_type.upper()} | Risk: {ev.risk_level} ({ev.risk_score}/100)",
            evidence_id=ev.evidence_id,
        ))

    # Sort timeline chronologically
    timeline.sort(key=lambda t: t.timestamp or "")

    ev_responses = [schemas.EvidenceResponse.model_validate(rec) for rec in evidence_records]

    return schemas.CaseDetailResponse(
        id=c.id,
        case_id=c.case_id,
        title=c.title,
        description=c.description,
        status=c.status,
        created_at=c.created_at,
        evidence_records=ev_responses,
        timeline=timeline,
    )


@app.post("/cases/{case_id}/evidence")
def add_evidence_to_case(case_id: str, payload: schemas.CaseEvidenceAdd, db: Session = Depends(get_db)):
    """Associate an existing evidence record with an investigation case."""
    c = db.query(models.Case).filter(models.Case.case_id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    ev = db.query(models.Evidence).filter(models.Evidence.evidence_id == payload.evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence '{payload.evidence_id}' not found")

    # Check if already linked
    existing_link = (
        db.query(models.CaseEvidence)
        .filter(models.CaseEvidence.case_id == case_id, models.CaseEvidence.evidence_id == payload.evidence_id)
        .first()
    )
    if existing_link:
        return {"message": f"Evidence '{payload.evidence_id}' is already linked to case '{case_id}'."}

    link = models.CaseEvidence(
        case_id=case_id,
        evidence_id=payload.evidence_id,
        notes=payload.notes,
    )
    db.add(link)
    db.commit()
    return {"message": f"Evidence '{payload.evidence_id}' successfully associated with case '{case_id}'."}


@app.delete("/cases/{case_id}/evidence/{evidence_id}")
def remove_evidence_from_case(case_id: str, evidence_id: str, db: Session = Depends(get_db)):
    """Unlink an evidence record from a case without deleting the standalone evidence."""
    link = (
        db.query(models.CaseEvidence)
        .filter(models.CaseEvidence.case_id == case_id, models.CaseEvidence.evidence_id == evidence_id)
        .first()
    )
    if not link:
        raise HTTPException(status_code=404, detail=f"Evidence association not found for case '{case_id}'.")

    db.delete(link)
    db.commit()
    return {"message": f"Evidence '{evidence_id}' unlinked from case '{case_id}'."}


@app.delete("/cases/{case_id}")
def delete_case(case_id: str, db: Session = Depends(get_db)):
    """Delete an investigation case and its associations, preserving standalone evidence records."""
    c = db.query(models.Case).filter(models.Case.case_id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    db.query(models.CaseEvidence).filter(models.CaseEvidence.case_id == case_id).delete()
    db.delete(c)
    db.commit()
    return {"detail": f"Case '{case_id}' deleted successfully."}


# ==========================================
# FEATURE: Correlation Analysis
# ==========================================

@app.get("/correlate", response_model=schemas.CorrelationSummary)
def correlate_evidence(
    evidence_id: Optional[str] = None,
    case_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Correlate stored evidence records across indicators, optionally scoped to an evidence ID or Case ID."""
    links = db.query(models.CaseEvidence).all()
    ev_case_map = {}
    for l in links:
        ev_case_map.setdefault(l.evidence_id, []).append(l.case_id)

    query = db.query(models.Evidence)
    if case_id:
        target_ev_ids = [l.evidence_id for l in links if l.case_id == case_id]
        query = query.filter(models.Evidence.evidence_id.in_(target_ev_ids))

    records = query.all()
    for r in records:
        setattr(r, "cases", ev_case_map.get(r.evidence_id, []))

    results = correlation.correlate_records(records, target_evidence_id=evidence_id)
    return schemas.CorrelationSummary(**results)


@app.post("/correlate", response_model=schemas.CorrelationSummary)
def correlate_selected_evidence(
    request: schemas.CorrelateRequest,
    db: Session = Depends(get_db)
):
    """Correlate specific evidence IDs, a case's evidence, or all records."""
    links = db.query(models.CaseEvidence).all()
    ev_case_map = {}
    for l in links:
        ev_case_map.setdefault(l.evidence_id, []).append(l.case_id)

    query = db.query(models.Evidence)
    if request.case_id:
        case_ev_ids = [l.evidence_id for l in links if l.case_id == request.case_id]
        query = query.filter(models.Evidence.evidence_id.in_(case_ev_ids))
    elif request.evidence_ids:
        query = query.filter(models.Evidence.evidence_id.in_(request.evidence_ids))

    records = query.all()
    for r in records:
        setattr(r, "cases", ev_case_map.get(r.evidence_id, []))

    results = correlation.correlate_records(records)
    return schemas.CorrelationSummary(**results)


# ==========================================
# FEATURE 4: Incident Report Generation
# ==========================================

@app.post("/reports")
def create_report(report_req: schemas.ReportRequest, db: Session = Depends(get_db)):
    """Generate a detailed forensic incident report for an Evidence ID or Investigation Case ID.
    
    Populated with real database records, integrity status, timeline, and forensic limitations.
    """
    try:
        report_data = report.generate_incident_report(
            db=db,
            title=report_req.title,
            description=report_req.description,
            evidence_ids=report_req.evidence_ids,
            case_id=report_req.case_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal report generation error: {str(e)}")

    return {"message": "Incident report generated successfully", "data": report_data}

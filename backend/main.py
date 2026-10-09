import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from database import SessionLocal, engine, Base, init_db
import models, schemas, analyzer

load_dotenv()

# Initialize database tables and columns
init_db()

app = FastAPI(
    title="Cyber Evidence Analyzer API",
    description="Backend API for cyber evidence analysis (URLs, IPs, Domains) with Threat Intelligence integration.",
    version="0.2.0"
)

# Enable CORS for all origins so React frontend can connect later
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

@app.get("/")
def root():
    """Health check and API overview endpoint."""
    return {
        "status": "online",
        "service": "Cyber Evidence Analyzer API",
        "version": "0.2.0",
        "docs_url": "/docs"
    }

@app.post("/analyze", response_model=schemas.AnalyzeResponse)
def analyze(request: schemas.AnalyzeRequest, db: SessionLocal = Depends(get_db)):
    """Accept a URL, IP address or domain, perform analysis with Threat Intelligence, and store as evidence."""
    # Perform analysis
    try:
        result = analyzer.analyze_input(request.input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Save to database
    sources_str = ", ".join(result.get("threat_intelligence_sources", []))
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
        timestamp=result["timestamp"],
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return schemas.AnalyzeResponse(**result)

@app.get("/evidence", response_model=list[schemas.EvidenceResponse])
def get_all_evidence(db: SessionLocal = Depends(get_db)):
    """Return all saved evidence records."""
    records = db.query(models.Evidence).all()
    return [schemas.EvidenceResponse.model_validate(rec) for rec in records]

@app.get("/evidence/{evidence_id}", response_model=schemas.EvidenceResponse)
def get_evidence(evidence_id: str, db: SessionLocal = Depends(get_db)):
    """Return a single evidence record by its evidence_id."""
    ev = db.query(models.Evidence).filter(models.Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return schemas.EvidenceResponse.model_validate(ev)

@app.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, db: SessionLocal = Depends(get_db)):
    """Delete a specific evidence record."""
    ev = db.query(models.Evidence).filter(models.Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.delete(ev)
    db.commit()
    return {"detail": f"Evidence {evidence_id} deleted"}

@app.post("/reports")
def create_report(report: schemas.ReportRequest):
    """Placeholder endpoint for report generation (PDF generation to be added later)."""
    return {"message": "Report generation not implemented yet", "data": report.model_dump()}

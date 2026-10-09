"""Incident Report generation engine for Cyber Evidence Analyzer.

Constructs comprehensive, forensic-grade incident reports from actual database
records for individual evidence items or multi-artifact investigation cases.
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
try:
    from . import models, correlation, integrity
except ImportError:
    import models, correlation, integrity


FORENSIC_LIMITATIONS = [
    (
        "Preliminary Assessment Disclaimer",
        "Risk scores and classifications are automated, preliminary triage assessments based on "
        "heuristic static rules and external threat intelligence feeds. They do not constitute a "
        "guarantee of malware detection, absence of compromise, or professional forensic sign-off."
    ),
    (
        "Transport Encryption (HTTPS) Caveat",
        "The presence of HTTPS indicates encrypted transport between client and server, but does NOT "
        "indicate that a website is benign or safe. Phishing and malware distribution routinely utilize "
        "valid TLS/SSL certificates."
    ),
    (
        "Threat Intelligence Coverage Limitations",
        "Absence of threat intelligence flags or unconfigured external feeds (VirusTotal, AbuseIPDB, "
        "urlscan.io) does NOT imply that an indicator is safe. Zero detections frequently occur with "
        "newly minted infrastructure, targeted attacks, or unindexed resources."
    ),
    (
        "Evidence Integrity Verification Scope",
        "The SHA-256 cryptographic verification certifies that protected database fields have not "
        "been altered since initial recording. It does not certify the truthfulness of external "
        "information or guarantee admissibility in any specific legal jurisdiction."
    ),
]


def _build_evidence_dict(ev: models.Evidence) -> Dict[str, Any]:
    """Transform an Evidence SQLAlchemy model into a serialized dictionary with integrity verification."""
    rec = {
        "evidence_id": ev.evidence_id,
        "input_value": ev.input_value,
        "input_type": ev.input_type,
        "url": ev.url,
        "domain": ev.domain,
        "ip_address": ev.ip_address,
        "risk_score": ev.risk_score,
        "risk_level": ev.risk_level,
        "findings": ev.findings,
        "threat_intelligence_sources": ev.threat_intelligence_sources or "",
        "threat_intelligence_summary": ev.threat_intelligence_summary or "",
        "sha256_hash": ev.sha256_hash,
        "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
    }

    # Perform on-the-fly integrity verification against stored hash
    verification = integrity.verify_evidence_hash(ev.sha256_hash, rec)
    rec["integrity_verification"] = verification

    # Parse heuristic and threat intel details if present
    try:
        rec["heuristic_details"] = json.loads(ev.heuristic_details) if ev.heuristic_details else None
    except Exception:
        rec["heuristic_details"] = ev.heuristic_details

    try:
        rec["threat_intel_details"] = json.loads(ev.threat_intel_details) if ev.threat_intel_details else None
    except Exception:
        rec["threat_intel_details"] = ev.threat_intel_details

    return rec


def generate_incident_report(
    db: Session,
    title: str,
    description: Optional[str] = None,
    evidence_ids: Optional[List[str]] = None,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a formal forensic incident report from real database records.
    
    Raises ValueError if neither valid evidence_ids nor case_id yields records.
    """
    case_obj: Optional[models.Case] = None
    case_info = None
    all_evidence_ids: List[str] = list(evidence_ids or [])

    if case_id:
        case_obj = db.query(models.Case).filter(models.Case.case_id == case_id).first()
        if not case_obj:
            raise ValueError(f"Investigation Case '{case_id}' was not found in the database.")
        
        case_info = {
            "case_id": case_obj.case_id,
            "title": case_obj.title,
            "description": case_obj.description,
            "status": case_obj.status,
            "created_at": case_obj.created_at.isoformat() if case_obj.created_at else None,
        }

        # Retrieve linked evidence IDs for the case
        links = db.query(models.CaseEvidence).filter(models.CaseEvidence.case_id == case_id).all()
        for link in links:
            if link.evidence_id not in all_evidence_ids:
                all_evidence_ids.append(link.evidence_id)

    if not all_evidence_ids:
        if case_id:
            raise ValueError(f"Case '{case_id}' does not currently have any linked evidence records.")
        raise ValueError("No Evidence IDs or Case ID provided for report generation.")

    # Retrieve all evidence records from DB
    evidence_models = (
        db.query(models.Evidence)
        .filter(models.Evidence.evidence_id.in_(all_evidence_ids))
        .all()
    )

    if not evidence_models:
        raise ValueError("None of the specified Evidence IDs exist in the database.")

    # Sort evidence records by creation timestamp
    evidence_models.sort(key=lambda e: e.timestamp or datetime.min)
    evidence_dicts = [_build_evidence_dict(ev) for ev in evidence_models]

    # Compute risk summary statistics
    total_count = len(evidence_dicts)
    low_count = sum(1 for e in evidence_dicts if e["risk_level"] == "LOW")
    med_count = sum(1 for e in evidence_dicts if e["risk_level"] == "MEDIUM")
    high_count = sum(1 for e in evidence_dicts if e["risk_level"] == "HIGH")
    avg_score = round(sum(e["risk_score"] for e in evidence_dicts) / total_count, 1)

    overall_level = "LOW"
    if high_count > 0 or avg_score >= 70.0:
        overall_level = "HIGH"
    elif med_count > 0 or avg_score >= 35.0:
        overall_level = "MEDIUM"

    # Cross-evidence correlation
    corr_summary = correlation.correlate_records(evidence_dicts)

    # Build investigation timeline
    timeline_events = []
    if case_obj and case_obj.created_at:
        timeline_events.append({
            "event_type": "CASE_CREATED",
            "timestamp": case_obj.created_at.isoformat(),
            "title": f"Case Initiated: {case_obj.title}",
            "details": f"Investigation case {case_obj.case_id} registered.",
            "evidence_id": None,
        })

    for ev in evidence_models:
        timeline_events.append({
            "event_type": "EVIDENCE_RECORDED",
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "title": f"Artifact Analyzed: {ev.input_value}",
            "details": f"Type: {ev.input_type.upper()} | Risk: {ev.risk_level} ({ev.risk_score}/100)",
            "evidence_id": ev.evidence_id,
        })

    # Sort timeline chronologically
    timeline_events.sort(key=lambda t: t["timestamp"] or "")

    # Compile threat intelligence source breakdown status across evidence
    active_sources_seen = set()
    for ev in evidence_dicts:
        srcs = [s.strip() for s in (ev.get("threat_intelligence_sources") or "").split(",") if s.strip()]
        active_sources_seen.update(srcs)

    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"

    report_data = {
        "report_id": report_id,
        "title": title.strip() or "Cyber Forensic Incident Report",
        "description": description.strip() if description else "",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": case_info,
        "summary": {
            "total_artifacts": total_count,
            "overall_risk_level": overall_level,
            "average_risk_score": avg_score,
            "low_count": low_count,
            "medium_count": med_count,
            "high_count": high_count,
            "active_threat_sources": list(active_sources_seen),
        },
        "evidence_records": evidence_dicts,
        "timeline": timeline_events,
        "correlations": corr_summary.get("correlations", []),
        "limitations": [
            {"title": title_txt, "content": content_txt}
            for title_txt, content_txt in FORENSIC_LIMITATIONS
        ],
    }

    return report_data

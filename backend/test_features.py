"""Comprehensive Unit and Integration Tests for Cyber Evidence Analyzer Features.

Tests cover:
1. Feature 1: Case-based digital evidence management
2. Feature 2: Explainable risk assessment & transparent heuristics
3. Feature 3: SHA-256 Evidence integrity verification (canonical hash, tampering detection, legacy handling)
4. Feature 4: Incident report generation from real records
"""
import unittest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
import models
import integrity
import analyzer
import report
import threat_intelligence


class TestFeatureImplementations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use an in-memory SQLite database for isolated test execution
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        cls.TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.TestingSessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    # -------------------------------------------------------------------------
    # FEATURE 3: EVIDENCE INTEGRITY TESTS
    # -------------------------------------------------------------------------

    def test_canonical_hash_consistency(self):
        """Test that canonical serialization produces identical hash regardless of dict key order."""
        t0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
        record1 = {
            "evidence_id": "EV-TEST-1",
            "input_value": "https://malicious-test.xyz",
            "input_type": "url",
            "risk_score": 75.0,
            "risk_level": "HIGH",
            "timestamp": t0,
        }
        record2 = {
            "timestamp": t0,
            "risk_level": "HIGH",
            "risk_score": 75.0,
            "input_type": "url",
            "input_value": "https://malicious-test.xyz",
            "evidence_id": "EV-TEST-1",
        }
        hash1 = integrity.compute_evidence_hash(record1)
        hash2 = integrity.compute_evidence_hash(record2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_integrity_verification_verified(self):
        """Test that an unmodified record returns VERIFIED."""
        t0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
        record = {
            "evidence_id": "EV-VERIFY-1",
            "input_value": "192.168.1.50",
            "input_type": "ip",
            "risk_score": 35.0,
            "risk_level": "MEDIUM",
            "timestamp": t0,
        }
        stored_hash = integrity.compute_evidence_hash(record)
        res = integrity.verify_evidence_hash(stored_hash, record)
        self.assertEqual(res["status"], "VERIFIED")
        self.assertTrue(res["matches"])
        self.assertIn("verified", res["message"].lower())

    def test_integrity_verification_mismatch_on_tampering(self):
        """Test that tampering with protected fields triggers INTEGRITY_MISMATCH."""
        t0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
        original_record = {
            "evidence_id": "EV-TAMPER-1",
            "input_value": "evil.xyz",
            "input_type": "domain",
            "risk_score": 85.0,
            "risk_level": "HIGH",
            "timestamp": t0,
        }
        stored_hash = integrity.compute_evidence_hash(original_record)

        # Alter the risk score
        tampered_record = dict(original_record)
        tampered_record["risk_score"] = 20.0  # Falsified risk score
        tampered_record["risk_level"] = "LOW"

        res = integrity.verify_evidence_hash(stored_hash, tampered_record)
        self.assertEqual(res["status"], "INTEGRITY_MISMATCH")
        self.assertFalse(res["matches"])
        self.assertIn("MISMATCH", res["message"])

    def test_integrity_verification_legacy_unhashed(self):
        """Test handling of older records that do not possess a stored hash."""
        record = {
            "evidence_id": "EV-LEGACY-1",
            "input_value": "old-artifact.org",
            "input_type": "domain",
            "risk_score": 50.0,
            "risk_level": "MEDIUM",
            "timestamp": datetime.now(timezone.utc),
        }
        res = integrity.verify_evidence_hash(None, record)
        self.assertEqual(res["status"], "UNHASHED_LEGACY")
        self.assertFalse(res["matches"])
        self.assertIn("Legacy", res["message"])

    # -------------------------------------------------------------------------
    # FEATURE 2: EXPLAINABLE RISK ASSESSMENT TESTS
    # -------------------------------------------------------------------------

    def test_https_does_not_imply_safety(self):
        """Test that HTTPS presence is explained as transport encryption only without reducing danger."""
        res = analyzer.analyze_input("https://secure-login-update.top/auth")
        findings = res["findings"]
        self.assertIn("HTTPS", findings)
        self.assertIn("does NOT guarantee website safety", findings)

        # Confirm structured heuristic breakdown has the transport note
        rules = [r["rule"] for r in res["heuristic_breakdown"]]
        self.assertIn("HTTPS Transport Layer", rules)

    def test_explainable_heuristic_breakdown(self):
        """Test that heuristic scoring provides explicit rule breakdown and documented methodology."""
        res = analyzer.analyze_input("http://192.168.1.1@phish-bank.xyz:8080/account")
        self.assertIsInstance(res["heuristic_breakdown"], list)
        self.assertGreater(len(res["heuristic_breakdown"]), 2)
        rules = {r["rule"] for r in res["heuristic_breakdown"]}
        self.assertIn("High-Risk Top Level Domain", rules)
        self.assertIn("Userinfo Spoofing Symbol", rules)
        self.assertIn("Scoring Method:", res["scoring_methodology"])

    def test_threat_intel_missing_keys_explicit_status(self):
        """Test that unconfigured threat intelligence sources are marked as not configured without claiming safety."""
        ti_res = threat_intelligence.fetch_threat_intelligence("example.com", "domain")
        self.assertIn("sources_detail", ti_res)
        sources_map = {s["source"]: s for s in ti_res["sources_detail"]}
        self.assertIn("VirusTotal", sources_map)
        self.assertIn("forensic_notice", ti_res)
        self.assertIn("NOT treated as evidence of safety", ti_res["forensic_notice"])

    # -------------------------------------------------------------------------
    # FEATURE 1: CASE-BASED EVIDENCE MANAGEMENT TESTS
    # -------------------------------------------------------------------------

    def test_case_creation_and_evidence_linking(self):
        """Test creating a case, associating multiple evidence items, and fetching chronological timeline."""
        # Create Case
        case_obj = models.Case(
            case_id="CASE-001",
            title="Operation Test Shield",
            description="Investigating suspicious credential harvesting cluster.",
            status="OPEN",
            created_at=datetime(2026, 10, 9, 8, 0, 0, tzinfo=timezone.utc),
        )
        self.db.add(case_obj)

        # Create 2 Evidence items
        ev1 = models.Evidence(
            evidence_id="EV-CASE-A",
            input_value="https://phish-site.xyz/login",
            input_type="url",
            risk_score=75.0,
            risk_level="HIGH",
            findings="Suspicious domain and sensitive keywords.",
            timestamp=datetime(2026, 10, 9, 8, 30, 0, tzinfo=timezone.utc),
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        ev2 = models.Evidence(
            evidence_id="EV-CASE-B",
            input_value="198.51.100.22",
            input_type="ip",
            risk_score=60.0,
            risk_level="MEDIUM",
            findings="Public IP hosting suspicious endpoint.",
            timestamp=datetime(2026, 10, 9, 9, 15, 0, tzinfo=timezone.utc),
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.db.add_all([ev1, ev2])

        # Link evidence to case
        link1 = models.CaseEvidence(case_id="CASE-001", evidence_id="EV-CASE-A", notes="Primary landing page")
        link2 = models.CaseEvidence(case_id="CASE-001", evidence_id="EV-CASE-B", notes="Resolved infrastructure")
        self.db.add_all([link1, link2])
        self.db.commit()

        # Query links
        links = self.db.query(models.CaseEvidence).filter(models.CaseEvidence.case_id == "CASE-001").all()
        self.assertEqual(len(links), 2)
        linked_eids = {l.evidence_id for l in links}
        self.assertEqual(linked_eids, {"EV-CASE-A", "EV-CASE-B"})

    # -------------------------------------------------------------------------
    # FEATURE 4: INCIDENT REPORT GENERATION TESTS
    # -------------------------------------------------------------------------

    def test_generate_incident_report_for_case(self):
        """Test generating an incident report populated from real database records for a case."""
        case_obj = models.Case(
            case_id="CASE-RPT-99",
            title="Credential Harvest Campaign",
            description="Campaign targeting authentication portals.",
            status="OPEN",
            created_at=datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc),
        )
        ev = models.Evidence(
            evidence_id="EV-RPT-1",
            input_value="https://portal-verify.top",
            input_type="url",
            risk_score=80.0,
            risk_level="HIGH",
            findings="High risk TLD and sensitive keyword.",
            timestamp=datetime(2026, 10, 9, 10, 15, 0, tzinfo=timezone.utc),
            sha256_hash=integrity.compute_evidence_hash({
                "evidence_id": "EV-RPT-1",
                "input_value": "https://portal-verify.top",
                "input_type": "url",
                "risk_score": 80.0,
                "risk_level": "HIGH",
                "timestamp": datetime(2026, 10, 9, 10, 15, 0, tzinfo=timezone.utc),
            }),
        )
        self.db.add(case_obj)
        self.db.add(ev)
        self.db.add(models.CaseEvidence(case_id="CASE-RPT-99", evidence_id="EV-RPT-1"))
        self.db.commit()

        # Generate report
        rpt = report.generate_incident_report(
            db=self.db,
            title="Forensic Audit Report",
            description="Confidential investigator findings.",
            case_id="CASE-RPT-99",
        )

        self.assertIsNotNone(rpt["report_id"])
        self.assertEqual(rpt["title"], "Forensic Audit Report")
        self.assertEqual(rpt["case"]["case_id"], "CASE-RPT-99")
        self.assertEqual(len(rpt["evidence_records"]), 1)
        self.assertEqual(rpt["evidence_records"][0]["integrity_verification"]["status"], "VERIFIED")
        self.assertGreater(len(rpt["timeline"]), 0)
        self.assertGreater(len(rpt["limitations"]), 0)

    def test_generate_incident_report_missing_records_error(self):
        """Test that report generation raises ValueError when given non-existent IDs."""
        with self.assertRaises(ValueError):
            report.generate_incident_report(
                db=self.db,
                title="Invalid Report",
                evidence_ids=["NON-EXISTENT-ID"],
            )


class TestEndpointWorkflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        cls.TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.TestingSessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_complete_investigation_lifecycle(self):
        """End-to-end test of the entire workflow:
        1. Open an Investigation Case
        2. Analyze an artifact directly into the case
        3. Verify cryptographic SHA-256 evidence integrity
        4. Link a second standalone evidence item to the case
        5. Verify chronological timeline ordering
        6. Generate a full Incident Report from real DB records
        7. Unlink evidence and delete case while preserving evidence
        """
        import main
        import schemas

        # Step 1: Open an Investigation Case
        case_res = main.create_case(
            schemas.CaseCreate(
                title="Operation BlackSun Spearphish",
                description="Targeted credential harvesting against executive team."
            ),
            db=self.db,
        )
        case_id = case_res.case_id
        self.assertTrue(case_id.startswith("CASE-"))
        self.assertEqual(case_res.evidence_count, 0)

        # Step 2: Analyze an artifact directly associated with the case
        analyze_req = schemas.AnalyzeRequest(
            input="https://secure-portal-update.xyz/login",
            case_id=case_id,
        )
        analyzed = main.analyze(analyze_req, db=self.db)
        ev_id_1 = analyzed.evidence_id
        self.assertEqual(analyzed.case_id, case_id)
        self.assertIsNotNone(analyzed.sha256_hash)
        self.assertGreater(len(analyzed.heuristic_breakdown), 0)

        # Step 3: Verify cryptographic SHA-256 evidence integrity
        verify_res = main.verify_evidence(ev_id_1, db=self.db)
        self.assertEqual(verify_res.status, "VERIFIED")
        self.assertTrue(verify_res.matches)
        self.assertEqual(verify_res.stored_hash, analyzed.sha256_hash)

        # Step 4: Analyze a standalone artifact and link it into the case
        standalone_req = schemas.AnalyzeRequest(input="198.51.100.44")
        analyzed_2 = main.analyze(standalone_req, db=self.db)
        ev_id_2 = analyzed_2.evidence_id

        # Link into the case
        link_res = main.add_evidence_to_case(
            case_id,
            schemas.CaseEvidenceAdd(evidence_id=ev_id_2, notes="C2 IP resolution"),
            db=self.db,
        )
        self.assertIn("successfully associated", link_res["message"])

        # Step 5: Check Case details & chronological timeline
        case_detail = main.get_case_detail(case_id, db=self.db)
        self.assertEqual(len(case_detail.evidence_records), 2)
        self.assertGreaterEqual(len(case_detail.timeline), 3)  # CASE_CREATED + 2 EVIDENCE_RECORDED
        # Verify timeline is sorted chronologically
        timestamps = [t.timestamp for t in case_detail.timeline if t.timestamp]
        self.assertEqual(timestamps, sorted(timestamps))

        # Step 6: Generate real Incident Report
        rpt_res = main.create_report(
            schemas.ReportRequest(
                title="Executive Incident Briefing",
                description="Formal preliminary report.",
                case_id=case_id,
            ),
            db=self.db,
        )
        self.assertIn("message", rpt_res)
        rpt_data = rpt_res["data"]
        self.assertEqual(rpt_data["title"], "Executive Incident Briefing")
        self.assertEqual(rpt_data["case"]["case_id"], case_id)
        self.assertEqual(len(rpt_data["evidence_records"]), 2)
        # All evidence in report has verified integrity
        for ev in rpt_data["evidence_records"]:
            self.assertEqual(ev["integrity_verification"]["status"], "VERIFIED")
        self.assertGreater(len(rpt_data["limitations"]), 0)

        # Step 7: Unlink evidence and delete case, ensuring standalone evidence remains
        unlink_res = main.remove_evidence_from_case(case_id, ev_id_2, db=self.db)
        self.assertIn("unlinked", unlink_res["message"])

        del_res = main.delete_case(case_id, db=self.db)
        self.assertIn("deleted successfully", del_res["detail"])

        # Standalone evidence records still exist in database
        all_ev = main.get_all_evidence(db=self.db)
        ev_ids_remaining = {e.evidence_id for e in all_ev}
        self.assertIn(ev_id_1, ev_ids_remaining)
        self.assertIn(ev_id_2, ev_ids_remaining)


if __name__ == "__main__":
    unittest.main()


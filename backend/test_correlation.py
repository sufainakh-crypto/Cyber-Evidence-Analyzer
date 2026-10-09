"""Unit tests for the Cyber Evidence Analyzer Cross-Evidence Correlation Engine."""
import unittest
from datetime import datetime, timezone, timedelta
from correlation import (
    un_defang,
    normalize_url,
    normalize_domain,
    extract_apex_domain,
    normalize_ip,
    normalize_hash,
    extract_cves,
    extract_indicators_from_evidence,
    correlate_records,
)


class TestCorrelationEngine(unittest.TestCase):
    def test_un_defang(self):
        self.assertEqual(un_defang("hxxps://malicious[.]example[.]com/login"), "https://malicious.example.com/login")
        self.assertEqual(un_defang("hxxp://192[.]168[.]1[.]100[:]8080"), "http://192.168.1.100:8080")
        self.assertEqual(un_defang("evil(.)xyz"), "evil.xyz")
        self.assertIsNone(un_defang(""))
        self.assertIsNone(un_defang(None))

    def test_normalize_url(self):
        # Defanging, fragment stripping, port cleaning, query param sorting
        url1 = "hxxps://example.com:443/login/?b=2&a=1#token"
        url2 = "https://example.com/login?a=1&b=2"
        self.assertEqual(normalize_url(url1), normalize_url(url2))

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("Sub.EXAMPLE.COM."), "sub.example.com")
        self.assertEqual(normalize_domain("hxxps://c2[.]phish[.]top:443/test"), "c2.phish.top")

    def test_extract_apex_domain(self):
        self.assertEqual(extract_apex_domain("api.sub.example.co.uk"), "example.co.uk")
        self.assertEqual(extract_apex_domain("portal.c2.example.com"), "example.com")
        self.assertEqual(extract_apex_domain("gov.in"), "gov.in")

    def test_normalize_ip(self):
        # IPv4 with port
        res_v4 = normalize_ip("192.168.1.1:8080")
        self.assertIsNotNone(res_v4)
        self.assertEqual(res_v4[0], "192.168.1.1")
        self.assertTrue(res_v4[1])  # RFC 1918 private

        # Public IPv4
        res_pub = normalize_ip("93.184.216.34")
        self.assertIsNotNone(res_pub)
        self.assertEqual(res_pub[0], "93.184.216.34")
        self.assertFalse(res_pub[1])

        # Bracketed IPv6
        res_v6 = normalize_ip("[2001:db8::1]:443")
        self.assertIsNotNone(res_v6)
        self.assertEqual(res_v6[0], "2001:db8::1")

        # Invalid IP
        self.assertIsNone(normalize_ip("999.999.999.999"))

    def test_normalize_hash(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(normalize_hash(sha256.upper()), sha256)
        self.assertIsNone(normalize_hash("not_a_hash"))

    def test_extract_cves(self):
        findings = "Potential exploit targeting CVE-2023-38606 and CVE-2024-21413 in binary."
        cves = extract_cves(findings)
        self.assertEqual(cves, ["CVE-2023-38606", "CVE-2024-21413"])

    def test_correlate_exact_hash_match(self):
        records = [
            {
                "evidence_id": "ev-001",
                "input_value": "payload1.bin",
                "input_type": "sha256",
                "sha256_hash": "a" * 64,
                "risk_score": 85.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-002",
                "input_value": "payload2.bin",
                "input_type": "sha256",
                "sha256_hash": "a" * 64,
                "risk_score": 90.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "EXACT_MATCH")
        self.assertEqual(rel["confidence_level"], "HIGH")
        self.assertEqual(rel["matched_indicators"][0]["indicator_type"], "sha256")

    def test_correlate_multi_indicator_no_derivative_inflation(self):
        # Two records with identical URL should NOT inflate to MULTI_INDICATOR
        # because the domain is derivative of the URL.
        records = [
            {
                "evidence_id": "ev-url-1",
                "input_value": "https://evil.com/path",
                "input_type": "url",
                "url": "https://evil.com/path",
                "domain": "evil.com",
                "risk_score": 75.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-url-2",
                "input_value": "https://evil.com/path",
                "input_type": "url",
                "url": "https://evil.com/path",
                "domain": "evil.com",
                "risk_score": 80.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "EXACT_MATCH")
        self.assertEqual(rel["matched_indicators"][0]["indicator_type"], "url")

    def test_correlate_true_multi_indicator(self):
        # Two records sharing Domain AND IP address (true multi-indicator convergence)
        records = [
            {
                "evidence_id": "ev-a",
                "input_value": "https://threat-actor.org/c2",
                "input_type": "url",
                "domain": "threat-actor.org",
                "ip_address": "198.51.100.55",
                "risk_score": 85.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-b",
                "input_value": "threat-actor.org",
                "input_type": "domain",
                "domain": "threat-actor.org",
                "ip_address": "198.51.100.55",
                "risk_score": 90.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "MULTI_INDICATOR")
        self.assertEqual(rel["confidence_level"], "HIGH")
        ind_types = {m["indicator_type"] for m in rel["matched_indicators"]}
        self.assertTrue("domain" in ind_types and "ip" in ind_types)

    def test_correlate_shared_private_ip_caveat(self):
        # Two records sharing RFC 1918 address must NOT be classified as high confidence exact match
        records = [
            {
                "evidence_id": "ev-priv-1",
                "input_value": "192.168.1.1",
                "input_type": "ip",
                "ip_address": "192.168.1.1",
                "risk_score": 25.0,
                "risk_level": "LOW",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-priv-2",
                "input_value": "192.168.1.1",
                "input_type": "ip",
                "ip_address": "192.168.1.1",
                "risk_score": 25.0,
                "risk_level": "LOW",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "UNCONFIRMED_HYPOTHESIS")
        self.assertEqual(rel["confidence_level"], "LOW")
        self.assertIn("RFC 1918", rel["forensic_caveat"])

    def test_correlate_unconfirmed_apex_domain_hypothesis(self):
        records = [
            {
                "evidence_id": "ev-sub1",
                "input_value": "phish.target-corp.com",
                "input_type": "domain",
                "domain": "phish.target-corp.com",
                "risk_score": 60.0,
                "risk_level": "MEDIUM",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-sub2",
                "input_value": "c2.target-corp.com",
                "input_type": "domain",
                "domain": "c2.target-corp.com",
                "risk_score": 65.0,
                "risk_level": "MEDIUM",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "UNCONFIRMED_HYPOTHESIS")
        self.assertEqual(rel["confidence_level"], "LOW")
        self.assertEqual(rel["matched_indicators"][0]["indicator_type"], "apex_domain_cluster")
        self.assertIn("Shared apex domain", rel["forensic_caveat"])

    def test_correlate_temporal_relationship(self):
        t0 = datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(hours=2)
        records = [
            {
                "evidence_id": "ev-temp1",
                "input_value": "attack-server-alpha.net",
                "input_type": "domain",
                "domain": "attack-server-alpha.net",
                "risk_score": 85.0,
                "risk_level": "HIGH",
                "timestamp": t0,
            },
            {
                "evidence_id": "ev-temp2",
                "input_value": "ransom-drop-bravo.org",
                "input_type": "domain",
                "domain": "ransom-drop-bravo.org",
                "risk_score": 90.0,
                "risk_level": "HIGH",
                "timestamp": t1,
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "TEMPORAL_RELATIONSHIP")
        self.assertEqual(rel["confidence_level"], "INFORMATIONAL")
        self.assertIn("Temporal co-occurrence", rel["explanation"])
        self.assertIn("does NOT establish common origin", rel["forensic_caveat"])

    def test_correlate_shared_cve(self):
        records = [
            {
                "evidence_id": "ev-cve-1",
                "input_value": "https://host1.io",
                "input_type": "url",
                "findings": "Active exploit detected matching CVE-2024-38812 in headers.",
                "risk_score": 75.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-cve-2",
                "input_value": "https://host2.io",
                "input_type": "url",
                "findings": "Remote code execution vector identified CVE-2024-38812 payload.",
                "risk_score": 80.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["matched_indicators"][0]["indicator_type"], "cve_exploitation")
        self.assertEqual(rel["matched_indicators"][0]["matched_value"], "CVE-2024-38812")

    def test_malformed_and_incomplete_indicators_safe_handling(self):
        records = [
            None,
            {},
            {"evidence_id": ""},
            {"evidence_id": "ev-empty", "input_value": "   ", "input_type": "unknown"},
            {"evidence_id": "ev-valid", "input_value": "example.com", "input_type": "domain", "domain": "example.com"},
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_records_analyzed"], 1)
        self.assertEqual(result["total_correlations_found"], 0)
    def test_no_self_links_or_duplicates(self):
        now = datetime.now(timezone.utc)
        records = [
            {
                "evidence_id": f"ev-{i}",
                "input_value": f"item-{i}.com",
                "input_type": "domain",
                "domain": "shared.example.com",
                "risk_score": 40.0,
                "risk_level": "MEDIUM",
                "timestamp": now,
            }
            for i in range(3)
        ]
        result = correlate_records(records)
        # For 3 records sharing an indicator, number of pairs should be exactly 3: (0,1), (0,2), (1,2)
        self.assertEqual(result["total_correlations_found"], 3)
        for rel in result["correlations"]:
            self.assertNotEqual(rel["source_evidence_id"], rel["target_evidence_id"])


    def test_correlate_shared_user_account(self):
        records = [
            {
                "evidence_id": "ev-user-1",
                "input_value": "https://portal.internal/login?user=admin_analyst",
                "input_type": "url",
                "findings": "Observed activity for user:admin_analyst",
                "risk_score": 60.0,
                "risk_level": "MEDIUM",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-user-2",
                "input_value": "user:admin_analyst session token",
                "input_type": "domain",
                "findings": "Suspicious login attempt by user:admin_analyst",
                "risk_score": 65.0,
                "risk_level": "MEDIUM",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertGreaterEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["matched_indicators"][0]["indicator_type"], "user_identifier")
        self.assertEqual(rel["rule_applied"], "SHARED_USER_ACCOUNT")
        self.assertEqual(rel["confidence_level"], "MEDIUM")

    def test_correlate_shared_device_affinity(self):
        records = [
            {
                "evidence_id": "ev-dev-1",
                "input_value": "C:\\Windows\\Temp\\trojan.exe",
                "input_type": "domain",
                "findings": "Payload execution on host:WORKSTATION-FIN-09",
                "risk_score": 75.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-dev-2",
                "input_value": "PowerShell command execution",
                "input_type": "domain",
                "findings": "Encoded execution on host:WORKSTATION-FIN-09",
                "risk_score": 80.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertGreaterEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        dev_indicators = [m for m in rel["matched_indicators"] if m["indicator_type"] == "device_identifier"]
        self.assertGreaterEqual(len(dev_indicators), 1)
        self.assertEqual(dev_indicators[0]["matched_value"], "WORKSTATION-FIN-09")

    def test_correlate_shared_case_event_record(self):
        records = [
            {
                "evidence_id": "ev-case-1",
                "input_value": "https://c2-beacon.top/sync",
                "input_type": "url",
                "cases": ["CASE-042"],
                "risk_score": 70.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-case-2",
                "input_value": "198.51.100.99",
                "input_type": "ip",
                "cases": ["CASE-042"],
                "risk_score": 60.0,
                "risk_level": "MEDIUM",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertGreaterEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        case_indicators = [m for m in rel["matched_indicators"] if m["indicator_type"] == "related_case_record"]
        self.assertEqual(len(case_indicators), 1)
        self.assertEqual(case_indicators[0]["matched_value"], "CASE-042")

    def test_correlate_hash_extracted_from_findings(self):
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        records = [
            {
                "evidence_id": "ev-hash-1",
                "input_value": "ransomware_sample_a.bin",
                "input_type": "domain",
                "findings": f"Observed sample with SHA256 {test_hash} in sandbox.",
                "risk_score": 85.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "evidence_id": "ev-hash-2",
                "input_value": "ransomware_sample_b.bin",
                "input_type": "domain",
                "sha256_hash": test_hash,
                "risk_score": 85.0,
                "risk_level": "HIGH",
                "timestamp": datetime.now(timezone.utc),
            },
        ]
        result = correlate_records(records)
        self.assertEqual(result["total_correlations_found"], 1)
        rel = result["correlations"][0]
        self.assertEqual(rel["relationship_type"], "EXACT_MATCH")
        self.assertEqual(rel["confidence_level"], "HIGH")
        self.assertEqual(rel["matched_indicators"][0]["indicator_type"], "sha256")
        self.assertEqual(rel["matched_indicators"][0]["matched_value"], test_hash)


if __name__ == "__main__":
    unittest.main()

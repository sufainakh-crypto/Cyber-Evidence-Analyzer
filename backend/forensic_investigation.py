"""Forensic Investigation Intelligence Engine for Cyber Evidence Analyzer.

Implements:
1. Feature 1: Missing Evidence Detective (Evidence Gap Analysis Engine)
2. Feature 2: Evidence Contradiction Detector (Inconsistency, Clock Skew & Discrepancy Engine)
3. Feature 3: Next Investigation Steps (Evidence-Based Actionable Guidance)
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import ipaddress


# =============================================================================
# JARGON BUSTER / FORENSIC DEFINITIONS FOR INVESTIGATORS AND STUDENTS
# =============================================================================

FORENSIC_GLOSSARY = {
    "SHA-256": {
        "term": "SHA-256 (Cryptographic Hash)",
        "simple": "A unique digital fingerprint for data. If even a single letter changes, the fingerprint changes completely.",
        "technical": "Secure Hash Algorithm generating a fixed 256-bit cryptographic digest used for tamper detection and data integrity validation."
    },
    "Clock Skew": {
        "term": "Clock Skew / NTP Drift",
        "simple": "A small difference in time between two computers' clocks, often because one system clock is slightly fast or slow.",
        "technical": "Temporal delta between independent hardware timers or NTP synchronization drift, commonly accounting for discrepancies up to several minutes."
    },
    "RFC 1918": {
        "term": "RFC 1918 (Private IP Address)",
        "simple": "An internal company network address (like 192.168.x.x or 10.x.x.x) that cannot be directly reached from the public internet.",
        "technical": "Non-globally-routable IPv4 address ranges reserved for private enterprise intranets and local subnet routing."
    },
    "Passive DNS": {
        "term": "Passive DNS (pDNS)",
        "simple": "A historical log of which IP addresses a website domain has pointed to in the past.",
        "technical": "Historical sensor database storing past domain-to-IP resolution mappings independent of live authoritative zone files."
    },
    "Evidence Gap": {
        "term": "Evidence Gap (Unverified Fact)",
        "simple": "A missing piece of the puzzle that we do not have logs for yet. Missing evidence is NOT proof of guilt.",
        "technical": "Uncorroborated premise in an investigative hypothesis arising from absence of specific forensic logging channels or telemetry."
    },
    "Heuristic Triage": {
        "term": "Heuristic Triage",
        "simple": "A practical set of rules used to quickly spot suspicious signs (like weird spelling or unusual domain endings).",
        "technical": "Rule-based static indicator inspection evaluating structural anomalies, known abuse patterns, and entropy."
    }
}


# =============================================================================
# FEATURE 1: MISSING EVIDENCE DETECTIVE (GAP ANALYSIS ENGINE)
# =============================================================================

def analyze_evidence_gaps(evidence_records: List[Dict[str, Any]], case_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Identify what is supported by existing records vs. what remains unverified or missing.
    
    Adheres strictly to the principle that missing evidence is NEVER proof of wrongdoing.
    """
    gaps: List[Dict[str, Any]] = []
    if not evidence_records:
        return gaps

    has_url = any(e.get("input_type") == "url" for e in evidence_records)
    has_ip = any(e.get("input_type") == "ip" for e in evidence_records)
    has_domain = any(e.get("input_type") == "domain" for e in evidence_records)

    # 1. Payload / File Transfer Verification Gap
    if has_url:
        url_records = [e for e in evidence_records if e.get("input_type") == "url"]
        gaps.append({
            "gap_id": f"GAP-PAYLOAD-{uuid.uuid4().hex[:6]}",
            "category": "Payload & Content Verification",
            "title": "File Download & Payload Delivery Unconfirmed",
            "supported_by_evidence": (
                f"We have identified {len(url_records)} URL indicator(s) "
                f"({', '.join(e.get('input_value', '')[:28] for e in url_records[:2])}). "
                "The presence of a URL demonstrates a network pointer exists."
            ),
            "unverified_aspect": (
                "The available records do NOT confirm whether any file or malicious payload "
                "was actually transferred, downloaded, or executed on a client machine."
            ),
            "unavailable_sources": [
                "Full Packet Capture (PCAP) / NetFlow Records",
                "Web Proxy Ingress Logs / HTTP Response Body Cache",
                "Endpoint File Download History / Zone.Identifier Telemetry"
            ],
            "why_it_matters": (
                "Without payload confirmation, an investigator cannot determine whether an end-user "
                "was successfully compromised or merely encountered a dead link, 404 response, or network block."
            ),
            "suggested_collection": (
                "Inspect proxy access logs for HTTP 200 responses with byte sizes > 0, "
                "or review endpoint browser download history ($MFT and web browser SQLite databases)."
            ),
            "neutrality_reminder": "Never assume a file was downloaded simply because a suspicious URL was identified.",
            "simple_explanation": (
                "We know this web address exists, but we do not know if anyone actually downloaded a file from it. "
                "To confirm, you would need to check computer download history or network proxy records."
            )
        })

    # 2. Host Resolution & DNS Infrastructure Gap
    if has_domain and not has_ip:
        domain_records = [e for e in evidence_records if e.get("input_type") == "domain"]
        gaps.append({
            "gap_id": f"GAP-DNS-{uuid.uuid4().hex[:6]}",
            "category": "Infrastructure Resolution",
            "title": "Hosting IP & Server Infrastructure Uncorrelated",
            "supported_by_evidence": (
                f"Domain indicator(s) recorded: {', '.join(e.get('input_value', '') for e in domain_records[:3])}."
            ),
            "unverified_aspect": (
                "Current records lack corresponding resolving IP addresses and hosting infrastructure data."
            ),
            "unavailable_sources": [
                "Passive DNS (pDNS) Historical Resolution Logs",
                "Authoritative DNS Query Logs (BIND / Windows DNS Server)",
                "Autonomous System (ASN) and Hosting Provider Records"
            ],
            "why_it_matters": (
                "Threat actors frequently change the IP addresses behind malicious domains (fast-flux). "
                "Knowing the hosting provider and IP is critical to identify shared command-and-control servers."
            ),
            "suggested_collection": (
                "Query passive DNS history (e.g. VirusTotal pDNS, SecurityTrails) or internal DNS cache "
                "to see which IP address resolved at the exact time of the incident."
            ),
            "neutrality_reminder": "Domain registration alone does not prove the host was active during the incident timeframe.",
            "simple_explanation": (
                "We have the website name, but we don't know which physical server or computer was hosting it. "
                "Checking historical DNS logs will show where this domain pointed at the time of the event."
            )
        })

    # 3. Endpoint Execution & Process Lineage Gap
    high_risk_records = [e for e in evidence_records if e.get("risk_level") == "HIGH"]
    if high_risk_records:
        gaps.append({
            "gap_id": f"GAP-EXEC-{uuid.uuid4().hex[:6]}",
            "category": "Host Execution Telemetry",
            "title": "Endpoint Process Execution & Impact Unknown",
            "supported_by_evidence": (
                f"{len(high_risk_records)} high-risk artifact(s) identified in evidence repository."
            ),
            "unverified_aspect": (
                "We have no endpoint telemetry confirming whether any malicious script, binary, "
                "or child process spawned on victim machines."
            ),
            "unavailable_sources": [
                "Endpoint Detection & Response (EDR) Telemetry",
                "Sysmon Event ID 1 (Process Creation) / Windows Security Event 4688",
                "Windows Prefetch (.pf), Amcache.hve, and Shimcache Records"
            ],
            "why_it_matters": (
                "Distinguishing between an attempted attack and a successful execution determines "
                "whether incident response should focus on containment or basic reconnaissance."
            ),
            "suggested_collection": (
                "Collect forensic triage packages (KAPE/Velociraptor) from suspected endpoints "
                "to inspect process lineage and Amcache execution artifacts."
            ),
            "neutrality_reminder": "Identifying a high-risk URL or IP in perimeter telemetry does not prove internal systems executed malware.",
            "simple_explanation": (
                "We found a suspicious web address or IP, but we do not know if any computer actually ran harmful software. "
                "You would need computer activity logs (like Windows process logs) to see if a program started."
            )
        })

    # 4. User Interaction & Authentication Scope Gap
    url_with_keywords = [
        e for e in evidence_records
        if any(kw in (e.get("input_value") or "").lower() for kw in ["login", "verify", "auth", "account", "banking", "signin"])
    ]
    if url_with_keywords:
        gaps.append({
            "gap_id": f"GAP-CREDS-{uuid.uuid4().hex[:6]}",
            "category": "Credential & User Interaction",
            "title": "Credential Submission & Victim Interaction Unverified",
            "supported_by_evidence": (
                "Indicator URL matches credential-harvesting phishing profile keywords."
            ),
            "unverified_aspect": (
                "Unknown whether any legitimate employee entered usernames, passwords, or MFA tokens."
            ),
            "unavailable_sources": [
                "Identity Provider Logs (Entra ID / Okta Sign-in Logs)",
                "Browser Autofill & Form Submission Artifacts",
                "Email Gateway Delivery Status (Was email opened? Link clicked?)"
            ],
            "why_it_matters": (
                "If credentials were submitted, accounts must be immediately revoked and sessions killed. "
                "If the page was never submitted, account compromise risk is significantly lower."
            ),
            "suggested_collection": (
                "Review Azure/Okta Sign-In logs for unusual user logins or conditional access failures "
                "around the time of indicator observation."
            ),
            "neutrality_reminder": "Visiting a phishing page does not automatically mean the user typed in their password.",
            "simple_explanation": (
                "The web page looks like a fake login page, but we don't know if anyone typed their password into it. "
                "Checking company login logs will show if an account was used right after."
            )
        })

    # 5. Internal Network Attribution Gap for RFC 1918 IPs
    private_ips = []
    for e in evidence_records:
        if e.get("input_type") == "ip":
            try:
                ip_obj = ipaddress.ip_address(e.get("input_value", "").strip())
                if ip_obj.is_private:
                    private_ips.append(str(ip_obj))
            except ValueError:
                pass

    if private_ips:
        gaps.append({
            "gap_id": f"GAP-PRIVATEIP-{uuid.uuid4().hex[:6]}",
            "category": "Internal Host Attribution",
            "title": "Internal Host Device & Lease Ownership Unmapped",
            "supported_by_evidence": (
                f"Evidence contains private network address(es): {', '.join(private_ips)}."
            ),
            "unverified_aspect": (
                "Private IP addresses (RFC 1918) are dynamically assigned. Current records do not identify "
                "the specific physical device, MAC address, or hostname holding the lease at the exact time."
            ),
            "unavailable_sources": [
                "DHCP Server Lease History",
                "Internal Active Directory DNS Dynamic Updates",
                "Switch ARP / MAC address correlation tables"
            ],
            "why_it_matters": (
                "Private IPs are reused across computers. Without DHCP lease records, an investigator cannot "
                "attribute internal traffic to a specific employee laptop or server."
            ),
            "suggested_collection": (
                "Obtain DHCP server audit logs matching the exact timestamp and IP address to identify MAC and Hostname."
            ),
            "neutrality_reminder": "A private IP address cannot be traced to an internet user without internal network logs.",
            "simple_explanation": (
                "This IP address belongs to an internal office network. Because office computers share and swap IP addresses, "
                "you need office network lease logs to know which specific computer had this address at that moment."
            )
        })

    return gaps


# =============================================================================
# FEATURE 2: EVIDENCE CONTRADICTION DETECTOR
# =============================================================================

def detect_evidence_contradictions(evidence_records: List[Dict[str, Any]], case_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Detect potential inconsistencies between timestamps, metadata, protocols, and indicators.
    
    Accounts for NTP skew, timezones, proxy caching, and protocol differences without
    prematurely declaring malicious fabrication.
    """
    contradictions: List[Dict[str, Any]] = []
    if len(evidence_records) < 2:
        return contradictions

    # Helper: parse timestamp safely
    def _parse_ts(e):
        ts = e.get("timestamp")
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                # Replace Z and handle ISO
                s = ts.replace("Z", "+00:00")
                return datetime.fromisoformat(s)
            except Exception:
                return None
        return None

    # Check 1: Temporal Inversion & Micro-Drift (Clock Skew vs Sequence Anomaly)
    sorted_by_time = []
    for e in evidence_records:
        parsed_t = _parse_ts(e)
        if parsed_t:
            sorted_by_time.append((parsed_t, e))
    sorted_by_time.sort(key=lambda x: x[0])

    for i in range(len(sorted_by_time) - 1):
        t1, e1 = sorted_by_time[i]
        t2, e2 = sorted_by_time[i + 1]

        # Check if URL in e2 references host/domain in e1, or related infrastructure
        val1 = e1.get("input_value", "").lower()
        val2 = e2.get("input_value", "").lower()

        time_delta = (t2 - t1).total_seconds()

        # Potential Clock Skew / Out-of-Sequence Logging
        # If two events are recorded within 1-120 seconds of each other on what appear to be separate logs
        if 0 < time_delta <= 120 and (e1.get("input_type") != e2.get("input_type")):
            contradictions.append({
                "contradiction_id": f"CONTRA-TIME-{uuid.uuid4().hex[:6]}",
                "type": "CLOCK_DRIFT_OR_TIMEZONE_VARIANCE",
                "severity": "LOW",
                "is_genuine_contradiction": False,
                "involved_records": [
                    {"evidence_id": e1.get("evidence_id"), "input": e1.get("input_value"), "time": t1.isoformat()},
                    {"evidence_id": e2.get("evidence_id"), "input": e2.get("input_value"), "time": t2.isoformat()},
                ],
                "exact_difference": (
                    f"Time difference between records is only {int(time_delta)} second(s). "
                    f"Record '{e1.get('evidence_id', '')[:8]}' was ingested at {t1.strftime('%H:%M:%S UTC')}, "
                    f"while record '{e2.get('evidence_id', '')[:8]}' was ingested at {t2.strftime('%H:%M:%S UTC')}."
                ),
                "plausible_technical_explanations": [
                    "Logging latency: SIEM or log shipper batch flush interval caused near-simultaneous timestamping.",
                    "Clock skew: Systems without active Network Time Protocol (NTP) synchronization commonly drift by 1-5 minutes.",
                    "Local time zone offset misunderstanding (e.g., UTC vs local daylight saving time)."
                ],
                "investigator_verification_steps": (
                    "Inspect the origin system's NTP synchronization status (e.g. `w32tm /query /status` on Windows). "
                    "Cross-reference firewall packet timestamps against host event log timestamps."
                ),
                "simple_explanation": (
                    f"These two events occurred within {int(time_delta)} seconds of each other. "
                    "In forensic investigations, slight differences in seconds are very common due to computer clocks being slightly off or logs taking a few moments to save."
                )
            })

    # Check 2: Transport Protocol Mismatch (HTTP vs HTTPS for identical domain/path)
    url_records = [e for e in evidence_records if e.get("input_type") == "url"]
    for i in range(len(url_records)):
        for j in range(i + 1, len(url_records)):
            u1 = url_records[i].get("input_value", "")
            u2 = url_records[j].get("input_value", "")

            # Strip scheme to see if host/path match
            clean1 = u1.replace("https://", "").replace("http://", "").rstrip("/")
            clean2 = u2.replace("https://", "").replace("http://", "").rstrip("/")

            if clean1 and clean1 == clean2 and (u1.startswith("http://") != u2.startswith("http://")):
                contradictions.append({
                    "contradiction_id": f"CONTRA-PROTO-{uuid.uuid4().hex[:6]}",
                    "type": "TRANSPORT_PROTOCOL_DISCREPANCY",
                    "severity": "MEDIUM",
                    "is_genuine_contradiction": True,
                    "involved_records": [
                        {"evidence_id": url_records[i].get("evidence_id"), "input": u1, "level": url_records[i].get("risk_level")},
                        {"evidence_id": url_records[j].get("evidence_id"), "input": u2, "level": url_records[j].get("risk_level")},
                    ],
                    "exact_difference": (
                        f"Identical target path accessed under contrasting security schemes: "
                        f"one uses unencrypted HTTP ({u1}), while the other uses encrypted HTTPS ({u2})."
                    ),
                    "plausible_technical_explanations": [
                        "SSL Strip attack: A man-in-the-middle network proxy stripped HTTPS down to HTTP for eavesdropping.",
                        "Web server redirection: Server initially accepted HTTP requests on port 80 and redirected with HTTP 301/302 to HTTPS on port 443.",
                        "Phishing staging: Threat actor registered SSL certificate after initial unencrypted testing."
                    ],
                    "investigator_verification_steps": (
                        "Inspect proxy response codes: verify if an HTTP 301 Moved Permanently redirect was returned, "
                        "or if network captures show plaintext credential transmission on port 80."
                    ),
                    "simple_explanation": (
                        "One record shows this address was visited with a secure padlock (HTTPS), but another shows an insecure connection (HTTP). "
                        "This often happens when a website automatically forwards visitors from the old web address to the secure one."
                    )
                })

    # Check 3: Assessment Classification Divergence (Same host evaluated with divergent risk levels)
    # E.g. one record rated LOW and another rated HIGH
    for i in range(len(evidence_records)):
        for j in range(i + 1, len(evidence_records)):
            e1 = evidence_records[i]
            e2 = evidence_records[j]

            # If both point to the same host/domain
            h1 = (e1.get("domain") or e1.get("input_value") or "").lower()
            h2 = (e2.get("domain") or e2.get("input_value") or "").lower()

            if h1 and h1 == h2 and e1.get("risk_level") != e2.get("risk_level"):
                # If one is LOW and one is HIGH
                levels = {e1.get("risk_level"), e2.get("risk_level")}
                if "LOW" in levels and "HIGH" in levels:
                    contradictions.append({
                        "contradiction_id": f"CONTRA-RISK-{uuid.uuid4().hex[:6]}",
                        "type": "CLASSIFICATION_DIVERGENCE",
                        "severity": "MEDIUM",
                        "is_genuine_contradiction": True,
                        "involved_records": [
                            {"evidence_id": e1.get("evidence_id"), "input": e1.get("input_value"), "risk": f"{e1.get('risk_level')} ({e1.get('risk_score')})"},
                            {"evidence_id": e2.get("evidence_id"), "input": e2.get("input_value"), "risk": f"{e2.get('risk_level')} ({e2.get('risk_score')})"},
                        ],
                        "exact_difference": (
                            f"Host '{h1}' is associated with conflicting risk scores: "
                            f"{e1.get('evidence_id', '')[:8]} assessed as {e1.get('risk_level')} ({e1.get('risk_score')}/100), "
                            f"while {e2.get('evidence_id', '')[:8]} assessed as {e2.get('risk_level')} ({e2.get('risk_score')}/100)."
                        ),
                        "plausible_technical_explanations": [
                            "Contextual indicator difference: Standalone apex domain may appear neutral, while specific URI path contains phishing payload parameters.",
                            "Threat intelligence update: External blacklist vendor updated threat intelligence feed between ingestion timestamps.",
                            "Legitimate service abuse: A benign file-sharing or cloud service (e.g. OneDrive, Google Drive) was weaponized with a specific malicious URI path."
                        ],
                        "investigator_verification_steps": (
                            "Inspect specific subpaths, query parameters, and vendor threat intelligence timestamps. "
                            "Examine whether legitimate infrastructure was abused for phishing delivery."
                        ),
                        "simple_explanation": (
                            "One test rated this website as safe, but another rated it as high risk. "
                            "This usually happens when attackers hide a malicious file on a normally safe website (like a cloud drive or shared folder)."
                        )
                    })

    return contradictions


# =============================================================================
# FEATURE 3: NEXT INVESTIGATION STEPS (RECOMMENDATION ENGINE)
# =============================================================================

def generate_next_investigation_steps(
    evidence_records: List[Dict[str, Any]],
    gaps: Optional[List[Dict[str, Any]]] = None,
    contradictions: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Generate practical, prioritized, evidence-based recommendations for what an investigator should examine next."""
    steps: List[Dict[str, Any]] = []

    if not evidence_records:
        steps.append({
            "step_id": "STEP-INGEST-01",
            "title": "Ingest Target Cyber Artifacts",
            "priority": "ESSENTIAL",
            "priority_justification": "No evidence records exist in this investigation workspace.",
            "what_to_check": "Import suspected URL, IP address, or domain into the analyzer.",
            "why_useful": "Establishes baseline forensic indicators and cryptographic chain of custody.",
            "triggering_finding": "Empty evidence repository.",
            "tools_needed": "Cyber Evidence Analyzer Ingestion Engine",
            "simple_explanation": "Add the first website, link, or IP address you want to investigate."
        })
        return steps

    # Check 1: Cryptographic Integrity Verification
    unverified_count = sum(1 for e in evidence_records if not e.get("sha256_hash"))
    if unverified_count > 0:
        steps.append({
            "step_id": "STEP-INTEG-01",
            "title": "Validate Cryptographic Hash Signatures",
            "priority": "ESSENTIAL",
            "priority_justification": "Evidence integrity is mandatory to prove records were not altered during analysis.",
            "what_to_check": f"Perform SHA-256 integrity check on {unverified_count} legacy record(s).",
            "why_useful": "Guarantees digital forensic chain of custody and proves data has not been modified in storage.",
            "triggering_finding": f"{unverified_count} record(s) lack recorded SHA-256 hash signatures.",
            "tools_needed": "Cyber Evidence Analyzer Integrity Verifier",
            "simple_explanation": "Check that the digital fingerprints of your evidence items are valid so you can prove nobody changed them."
        })

    # Check 2: High-Risk URL / Phishing Next Steps
    high_risk_urls = [e for e in evidence_records if e.get("input_type") == "url" and e.get("risk_level") == "HIGH"]
    if high_risk_urls:
        target_sample = high_risk_urls[0].get("input_value", "")
        steps.append({
            "step_id": "STEP-PROXY-01",
            "title": "Correlate Web Proxy Ingress & Egress Logs",
            "priority": "ESSENTIAL",
            "priority_justification": "High-risk URL identified; critical to determine if perimeter firewall or proxy blocked user access.",
            "what_to_check": f"Query proxy logs (Squid / Zscaler / Palo Alto) for outbound HTTP GET/POST requests matching: {target_sample[:35]}...",
            "why_useful": "Reveals whether any internal client IP actually communicated with the malicious URL and received an HTTP 200 OK response.",
            "triggering_finding": f"High-risk URL detected with risk score of {high_risk_urls[0].get('risk_score')}/100.",
            "tools_needed": "SIEM (Splunk, Elastic) or Web Proxy Server Access Logs",
            "simple_explanation": "Search your company network logs to see if anyone clicked on this dangerous link and if the website loaded."
        })

        steps.append({
            "step_id": "STEP-SANDBOX-02",
            "title": "Submit URL to Controlled Malware Sandbox",
            "priority": "OPTIONAL",
            "priority_justification": "Useful for dynamic detonation, but should be handled carefully to avoid alerting threat actors to investigation.",
            "what_to_check": "Detonate URL in isolated virtual environment (urlscan.io, ANY.RUN, Cuckoo Sandbox).",
            "why_useful": "Captures live screenshots, DOM document tree, and redirects without exposing investigator workstation.",
            "triggering_finding": "High-risk URL identified with credential-harvesting patterns.",
            "tools_needed": "ANY.RUN, urlscan.io, Hybrid Analysis, or local isolated VM",
            "simple_explanation": "Open the link inside a safe, isolated test computer to take pictures of what the fake website looks like."
        })

    # Check 3: Private RFC 1918 Address Next Steps
    private_ips = [
        e for e in evidence_records
        if e.get("input_type") == "ip" and e.get("findings") and "RFC 1918" in e.get("findings")
    ]
    if private_ips:
        steps.append({
            "step_id": "STEP-DHCP-01",
            "title": "Query DHCP Leases & Internal Endpoint Hostnames",
            "priority": "ESSENTIAL",
            "priority_justification": "Private IP addresses are non-routable; host identity cannot be confirmed without internal lease correlation.",
            "what_to_check": f"Extract DHCP lease log around the timestamp for internal IP: {private_ips[0].get('input_value')}.",
            "why_useful": "Maps ephemeral internal IP address to MAC address, machine NetBIOS hostname, and logged-in Active Directory user.",
            "triggering_finding": f"Private IP address ({private_ips[0].get('input_value')}) identified in evidence repository.",
            "tools_needed": "Windows DHCP Server Logs / Active Directory Domain Services / Network Switch ARP Tables",
            "simple_explanation": "Find out which physical laptop or desktop in your office had this internal IP address at that exact time."
        })

    # Check 4: Domain Passive DNS & Certificate History
    domains = [e for e in evidence_records if e.get("input_type") == "domain"]
    if domains:
        steps.append({
            "step_id": "STEP-PDNS-01",
            "title": "Examine Passive DNS & Certificate Transparency Logs",
            "priority": "OPTIONAL",
            "priority_justification": "Valuable for uncovering adversary infrastructure clusters, but not required if domain is already neutralized.",
            "what_to_check": f"Query crt.sh and SecurityTrails for domain: {domains[0].get('input_value')}.",
            "why_useful": "Identifies subdomains created by the threat actor and past IP addresses used in the campaign.",
            "triggering_finding": f"Domain indicator recorded: {domains[0].get('input_value')}.",
            "tools_needed": "crt.sh (Certificate Transparency), SecurityTrails, VirusTotal Passive DNS",
            "simple_explanation": "Look at historical records to see what other web addresses this hacker may have created in the past."
        })

    # Check 5: Resolve Contradictions if any exist
    if contradictions:
        steps.append({
            "step_id": "STEP-TIMELINE-CALIB",
            "title": "Calibrate Time Zones & Reference Source NTP Servers",
            "priority": "ESSENTIAL",
            "priority_justification": "Evidence discrepancies detected across event timestamps.",
            "what_to_check": "Verify origin log time zone headers (UTC vs Local Standard Time) and NTP synchronization records.",
            "why_useful": "Resolves potential clock drift and confirms whether apparent contradictions are real or logging artifacts.",
            "triggering_finding": f"{len(contradictions)} potential evidence inconsistency/contradiction(s) identified.",
            "tools_needed": "Forensic Timeline Tool (Plaso/log2timeline) or Event Viewer Time Zone Config",
            "simple_explanation": "Double-check the clocks on all logging servers to ensure time zone differences aren't causing confusion."
        })

    # Check 6: Generate Formal Incident Report
    steps.append({
        "step_id": "STEP-REPORT-FINAL",
        "title": "Compile Formal Forensic Incident Report",
        "priority": "OPTIONAL",
        "priority_justification": "Synthesizes all validated findings, gaps, and next steps into an official investigation deliverable.",
        "what_to_check": "Navigate to Incident Reports tab to build printable PDF documentation.",
        "why_useful": "Produces auditable legal and forensic documentation with cryptographic signatures and disclaimers.",
        "triggering_finding": "Ready for case reporting phase.",
        "tools_needed": "Cyber Evidence Analyzer Incident Report Generator",
        "simple_explanation": "Turn your findings, evidence gaps, and next steps into an official printed or PDF investigation report."
    })

    return steps


# =============================================================================
# WORKFLOW STEP EVALUATOR (GUIDED 8-STEP WORKFLOW TRACKER)
# =============================================================================

def evaluate_guided_workflow_progress(
    case_info: Optional[Dict[str, Any]],
    evidence_records: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    next_steps: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Determine the status of each of the 8 guided investigation steps.
    
    Status values: 'COMPLETED', 'ATTENTION_REQUIRED', 'PENDING'
    """
    ev_count = len(evidence_records)
    has_unverified_hash = any(not e.get("sha256_hash") for e in evidence_records) if ev_count > 0 else False
    has_contradictions = len(contradictions) > 0

    steps = [
        {
            "step_number": 1,
            "title": "Select or Create Investigation Case",
            "status": "COMPLETED" if case_info else "ATTENTION_REQUIRED",
            "status_label": "Case Active" if case_info else "Select / Create Case",
            "description": f"Active Case: {case_info.get('case_id')} ({case_info.get('title')})" if case_info else "No case selected. Open a case to track evidence together.",
            "icon": "📁"
        },
        {
            "step_number": 2,
            "title": "Import Supported Evidence Artifacts",
            "status": "COMPLETED" if ev_count > 0 else "ATTENTION_REQUIRED",
            "status_label": f"{ev_count} Ingested" if ev_count > 0 else "Needs Artifacts",
            "description": f"{ev_count} evidence record(s) logged in workspace." if ev_count > 0 else "Input URLs, IPs, or domains on the Analyze page to ingest.",
            "icon": "📥"
        },
        {
            "step_number": 3,
            "title": "Validate Imported Evidence (SHA-256)",
            "status": "COMPLETED" if (ev_count > 0 and not has_unverified_hash) else ("ATTENTION_REQUIRED" if ev_count > 0 else "PENDING"),
            "status_label": "Integrity Signed" if (ev_count > 0 and not has_unverified_hash) else "Unsigned Records",
            "description": "All records possess canonical SHA-256 cryptographic signatures." if (ev_count > 0 and not has_unverified_hash) else "Verify cryptographic integrity to guarantee audit compliance.",
            "icon": "🛡️"
        },
        {
            "step_number": 4,
            "title": "Analyze Available Evidence",
            "status": "COMPLETED" if ev_count > 0 else "PENDING",
            "status_label": "Analyzed" if ev_count > 0 else "Pending",
            "description": "Static heuristics and threat intelligence feeds evaluated." if ev_count > 0 else "Heuristic rules will execute upon artifact ingestion.",
            "icon": "🔍"
        },
        {
            "step_number": 5,
            "title": "Review Correlated Events & Findings",
            "status": "COMPLETED" if ev_count > 1 else ("ATTENTION_REQUIRED" if ev_count == 1 else "PENDING"),
            "status_label": "Correlated" if ev_count > 1 else "Needs More Records",
            "description": f"{ev_count} records evaluated for technical indicator overlap." if ev_count > 1 else "Add at least 2 records to discover cross-evidence indicator convergence.",
            "icon": "🔗"
        },
        {
            "step_number": 6,
            "title": "Identify Missing Evidence & Contradictions",
            "status": "ATTENTION_REQUIRED" if (len(gaps) > 0 or has_contradictions) else ("COMPLETED" if ev_count > 0 else "PENDING"),
            "status_label": f"{len(gaps)} Gaps | {len(contradictions)} Inconsistencies" if (len(gaps) > 0 or has_contradictions) else "Clean",
            "description": f"Identified {len(gaps)} evidence gap(s) and {len(contradictions)} potential inconsistency flag(s)." if (len(gaps) > 0 or has_contradictions) else "No severe evidence gaps or contradictions flagged.",
            "icon": "🕵️"
        },
        {
            "step_number": 7,
            "title": "Review Recommended Next Steps",
            "status": "ATTENTION_REQUIRED" if any(s.get("priority") == "ESSENTIAL" for s in next_steps) else "COMPLETED",
            "status_label": f"{sum(1 for s in next_steps if s.get('priority') == 'ESSENTIAL')} Essential Steps",
            "description": f"{len(next_steps)} evidence-based recommendation(s) generated.",
            "icon": "🧭"
        },
        {
            "step_number": 8,
            "title": "Generate Investigation Report",
            "status": "COMPLETED" if ev_count > 0 else "PENDING",
            "status_label": "Ready to Generate" if ev_count > 0 else "Pending",
            "description": "Formal, printable incident report available in the Reports section.",
            "icon": "📄"
        }
    ]

    return steps

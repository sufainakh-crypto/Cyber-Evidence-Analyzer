import re
import uuid
import ipaddress
import json
from urllib.parse import urlparse
from datetime import datetime, timezone
try:
    from . import threat_intelligence, integrity
except ImportError:
    import threat_intelligence, integrity

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".info", ".biz", ".live", ".cc", ".zip", ".gq", ".tk", ".cf", ".ml"}
SUSPICIOUS_KEYWORDS = {"login", "admin", "wp-admin", "verify", "secure", "account", "update", "banking", "signin", "auth", "password"}

SCORING_METHODOLOGY_DOC = (
    "Scoring Method: Base score (20.0) + Heuristic rule adjustments (0-60 pts) + "
    "External Threat Intelligence adjustments (VT: +15/mal, +5/susp; AbuseIPDB: +0.5*abuseScore; urlscan: +20/mal). "
    "Score clamped between 0.0 and 100.0. "
    "Classifications: LOW (0-34.9), MEDIUM (35.0-69.9), HIGH (70.0-100.0)."
)


def _detect_input_type(value: str) -> str:
    """Detect whether input is 'url', 'ip', or 'domain'.
    Raises ValueError if input does not match any valid type.
    """
    val = value.strip()
    if not val:
        raise ValueError("Input cannot be empty.")

    # Check IP address first
    try:
        ipaddress.ip_address(val)
        return "ip"
    except ValueError:
        pass

    # Check URL format
    if val.startswith("http://") or val.startswith("https://"):
        parsed = urlparse(val)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return "url"

    # Check Domain format
    if DOMAIN_REGEX.match(val):
        return "domain"

    # Secondary URL check without scheme prefix if user passed full URL path
    if "/" in val:
        parsed = urlparse("http://" + val)
        if parsed.netloc and DOMAIN_REGEX.match(parsed.netloc):
            return "url"

    raise ValueError("Invalid input. Must be a valid URL, IP address, or domain.")


def _basic_risk_score(input_type: str, value: str) -> Tuple[float, List[str], List[Dict[str, Any]]]:
    """Calculate an explainable rule-based heuristic risk score and return structured findings.
    
    Returns:
        (clamped_score, findings_strings, heuristic_rules_breakdown)
    """
    score = 20.0
    findings = [f"Detected valid {input_type.upper()} input format."]
    breakdown: List[Dict[str, Any]] = [
        {
            "rule": "Baseline Ingestion Score",
            "delta": 20.0,
            "category": "baseline",
            "detail": f"Initial baseline assigned for valid {input_type.upper()} artifact.",
        }
    ]

    val_lower = value.lower()

    if input_type == "url":
        parsed = urlparse(value if value.startswith("http") else "http://" + value)
        hostname = parsed.hostname or ""

        if parsed.scheme == "http":
            score += 15.0
            findings.append("Uses unencrypted HTTP protocol (vulnerable to interception and data tampering).")
            breakdown.append({
                "rule": "Unencrypted Transport (HTTP)",
                "delta": 15.0,
                "category": "transport",
                "detail": "Traffic transmitted in cleartext without SSL/TLS encryption.",
            })
        elif parsed.scheme == "https":
            findings.append(
                "Uses HTTPS protocol (provides transport layer encryption only; "
                "does NOT guarantee website safety or benign intent)."
            )
            breakdown.append({
                "rule": "HTTPS Transport Layer",
                "delta": 0.0,
                "category": "transport",
                "detail": "Encrypted transport present. Notice: cybercriminals routinely utilize valid SSL certificates.",
            })

        # Check for IP address as hostname
        try:
            ipaddress.ip_address(hostname)
            score += 20.0
            findings.append("URL hostname is a raw IP address rather than a domain name.")
            breakdown.append({
                "rule": "Direct IP Hostname",
                "delta": 20.0,
                "category": "hostname",
                "detail": "Hostname bypasses DNS resolution using direct IP addressing (common evasion tactic).",
            })
        except ValueError:
            pass

        # Check suspicious keywords in path or query
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in val_lower]
        if matched_keywords:
            score += 15.0
            findings.append(f"Contains security-sensitive keyword(s): {', '.join(matched_keywords)}.")
            breakdown.append({
                "rule": "Sensitive Target Keywords",
                "delta": 15.0,
                "category": "content",
                "detail": f"Path contains targeted credential/authentication terms: {', '.join(matched_keywords)}.",
            })

        # Check for userinfo spoofing symbol '@'
        if "@" in value:
            score += 25.0
            findings.append("Contains '@' character in URL (potential userinfo authentication spoofing).")
            breakdown.append({
                "rule": "Userinfo Spoofing Symbol",
                "delta": 25.0,
                "category": "obfuscation",
                "detail": "RFC URL userinfo delimiter '@' detected, frequently abused in phishing to disguise real host.",
            })

        if len(value) > 75:
            score += 10.0
            findings.append("URL length is unusually long (>75 characters).")
            breakdown.append({
                "rule": "Anomalous URL Length",
                "delta": 10.0,
                "category": "structure",
                "detail": f"URL length is {len(value)} chars, exceeding common navigation thresholds.",
            })

        # Check hostname TLD and hyphens if hostname exists
        if hostname:
            host_lower = hostname.lower()
            for tld in SUSPICIOUS_TLDS:
                if host_lower.endswith(tld):
                    score += 20.0
                    findings.append(f"URL hostname uses high-risk TLD ({tld}).")
                    breakdown.append({
                        "rule": "High-Risk Top Level Domain",
                        "delta": 20.0,
                        "category": "reputation",
                        "detail": f"Hostname '{hostname}' uses TLD '{tld}' with documented high abuse density.",
                    })
                    break

            if host_lower.count("-") >= 2:
                score += 15.0
                findings.append("URL hostname contains multiple hyphens (common tactic in phishing domains).")
                breakdown.append({
                    "rule": "Multiple Hyphens",
                    "delta": 15.0,
                    "category": "typosquatting",
                    "detail": f"Hostname '{hostname}' contains {host_lower.count('-')} hyphens.",
                })

    elif input_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(value.strip())
            if ip_obj.is_private:
                score += 15.0
                findings.append("IP address belongs to a private network range (RFC 1918 / internal network).")
                breakdown.append({
                    "rule": "RFC 1918 Private Address",
                    "delta": 15.0,
                    "category": "network",
                    "detail": "Internal / non-routable address space. Cannot be queried against public internet blocklists.",
                })
            elif ip_obj.is_loopback:
                score += 10.0
                findings.append("IP address is a local loopback address (127.0.0.1 / ::1).")
                breakdown.append({
                    "rule": "Loopback Host",
                    "delta": 10.0,
                    "category": "network",
                    "detail": "Resolves strictly to local machine loopback interface.",
                })
            else:
                findings.append("IP address is a public internet address.")
                breakdown.append({
                    "rule": "Public Routable IP",
                    "delta": 0.0,
                    "category": "network",
                    "detail": "Publicly routable IP address subject to global threat intelligence inspection.",
                })
        except ValueError:
            pass

    elif input_type == "domain":
        # Check TLD
        tld_matched = False
        for tld in SUSPICIOUS_TLDS:
            if val_lower.endswith(tld):
                score += 20.0
                findings.append(f"Domain uses high-risk TLD ({tld}).")
                breakdown.append({
                    "rule": "High-Risk Top Level Domain",
                    "delta": 20.0,
                    "category": "reputation",
                    "detail": f"Top-level domain '{tld}' has documented high abuse/phishing density.",
                })
                tld_matched = True
                break

        # Check hyphens count
        if val_lower.count("-") >= 2:
            score += 15.0
            findings.append("Domain contains multiple hyphens (common tactic in phishing domains).")
            breakdown.append({
                "rule": "Multiple Hyphens",
                "delta": 15.0,
                "category": "typosquatting",
                "detail": f"Domain contains {val_lower.count('-')} hyphens, a standard typosquatting pattern.",
            })

        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in val_lower]
        if matched_keywords:
            score += 15.0
            findings.append(f"Domain contains sensitive keyword(s): {', '.join(matched_keywords)}.")
            breakdown.append({
                "rule": "Keyword Impersonation",
                "delta": 15.0,
                "category": "impersonation",
                "detail": f"Targeting sensitive brand/service keywords: {', '.join(matched_keywords)}.",
            })

        if len(val_lower) > 30:
            score += 10.0
            findings.append("Domain name is unusually long (>30 characters).")
            breakdown.append({
                "rule": "Anomalous Domain Length",
                "delta": 10.0,
                "category": "structure",
                "detail": f"Domain character count is {len(val_lower)}, exceeding standard naming profiles.",
            })

    findings.append("Disclaimer: Analysis provides heuristic and threat intelligence insights; it does not guarantee malware detection.")

    clamped_score = min(max(score, 0.0), 100.0)
    return clamped_score, findings, breakdown


def _risk_level(score: float) -> str:
    """Return risk level: LOW, MEDIUM, or HIGH."""
    if score < 35.0:
        return "LOW"
    if score < 70.0:
        return "MEDIUM"
    return "HIGH"


def analyze_input(value: str) -> Dict[str, Any]:
    """Perform analysis on URL, IP, or domain input and return formatted dictionary."""
    clean_val = value.strip()
    input_type = _detect_input_type(clean_val)
    basic_score, findings_list, heuristic_breakdown = _basic_risk_score(input_type, clean_val)

    # Query Threat Intelligence APIs safely
    intel = threat_intelligence.fetch_threat_intelligence(clean_val, input_type)

    # Calculate combined score
    final_score = min(max(basic_score + intel["score_delta"], 0.0), 100.0)
    level = _risk_level(final_score)

    evidence_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc)

    # Prepare canonical record dict to compute SHA-256 evidence integrity hash
    record_for_hash = {
        "evidence_id": evidence_id,
        "input_value": clean_val,
        "input_type": input_type,
        "risk_score": round(final_score, 1),
        "risk_level": level,
        "timestamp": ts,
    }
    canonical_hash = integrity.compute_evidence_hash(record_for_hash)

    result: Dict[str, Any] = {
        "evidence_id": evidence_id,
        "input": clean_val,
        "input_type": input_type,
        "risk_score": round(final_score, 1),
        "risk_level": level,
        "findings": " ".join(findings_list),
        "threat_intelligence_sources": intel["sources"],
        "threat_intelligence_summary": intel["summary"],
        "sha256_hash": canonical_hash,
        "timestamp": ts,
        "url": None,
        "domain": None,
        "ip_address": None,
        "heuristic_breakdown": heuristic_breakdown,
        "threat_intel_breakdown": intel.get("sources_detail", []),
        "scoring_methodology": SCORING_METHODOLOGY_DOC,
    }

    if input_type == "url":
        result["url"] = clean_val
        try:
            parsed = urlparse(clean_val if clean_val.startswith("http") else "http://" + clean_val)
            result["domain"] = parsed.hostname
        except Exception:
            result["domain"] = None
    elif input_type == "ip":
        result["ip_address"] = clean_val
    elif input_type == "domain":
        result["domain"] = clean_val

    return result

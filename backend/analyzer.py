import re
import uuid
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any
import threat_intelligence

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".info", ".biz", ".live", ".cc", ".zip", ".gq", ".tk", ".cf", ".ml"}
SUSPICIOUS_KEYWORDS = {"login", "admin", "wp-admin", "verify", "secure", "account", "update", "banking", "signin", "auth", "password"}

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

def _basic_risk_score(input_type: str, value: str) -> tuple[float, list[str]]:
    """Calculate a safe rule-based risk score (0-100) and return identified findings list."""
    score = 20.0
    findings = [f"Detected valid {input_type.upper()} input format."]

    val_lower = value.lower()

    if input_type == "url":
        parsed = urlparse(value if value.startswith("http") else "http://" + value)
        hostname = parsed.hostname or ""

        if parsed.scheme == "http":
            score += 15.0
            findings.append("Uses HTTP protocol instead of HTTPS (unencrypted transfer).")
        elif parsed.scheme == "https":
            findings.append("Uses HTTPS protocol (encrypted transport).")

        # Check for IP address as hostname
        try:
            ipaddress.ip_address(hostname)
            score += 20.0
            findings.append("URL hostname is a raw IP address rather than a domain name.")
        except ValueError:
            pass

        # Check suspicious keywords in path or query
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in val_lower]
        if matched_keywords:
            score += 15.0
            findings.append(f"Contains security-sensitive keyword(s): {', '.join(matched_keywords)}.")

        # Check for userinfo spoofing symbol '@'
        if "@" in value:
            score += 25.0
            findings.append("Contains '@' character in URL (potential userinfo authentication spoofing).")

        if len(value) > 75:
            score += 10.0
            findings.append("URL length is unusually long (>75 characters).")

    elif input_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(value.strip())
            if ip_obj.is_private:
                score += 15.0
                findings.append("IP address belongs to a private network range (RFC 1918 / internal network).")
            elif ip_obj.is_loopback:
                score += 10.0
                findings.append("IP address is a local loopback address (127.0.0.1 / ::1).")
            else:
                findings.append("IP address is a public internet address.")
        except ValueError:
            pass

    elif input_type == "domain":
        # Check TLD
        for tld in SUSPICIOUS_TLDS:
            if val_lower.endswith(tld):
                score += 20.0
                findings.append(f"Domain uses high-risk TLD ({tld}).")
                break

        # Check hyphens count
        if val_lower.count("-") >= 2:
            score += 15.0
            findings.append("Domain contains multiple hyphens (common tactic in phishing domains).")

        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in val_lower]
        if matched_keywords:
            score += 15.0
            findings.append(f"Domain contains sensitive keyword(s): {', '.join(matched_keywords)}.")

        if len(val_lower) > 30:
            score += 10.0
            findings.append("Domain name is unusually long (>30 characters).")

    # Add disclaimer
    findings.append("Disclaimer: Analysis provides heuristic and threat intelligence insights; it does not guarantee malware detection.")

    clamped_score = min(max(score, 0.0), 100.0)
    return clamped_score, findings

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
    basic_score, findings_list = _basic_risk_score(input_type, clean_val)

    # Query Threat Intelligence APIs safely
    intel = threat_intelligence.fetch_threat_intelligence(clean_val, input_type)

    # Calculate combined score
    final_score = min(max(basic_score + intel["score_delta"], 0.0), 100.0)
    level = _risk_level(final_score)

    result = {
        "evidence_id": str(uuid.uuid4()),
        "input": clean_val,
        "input_type": input_type,
        "risk_score": round(final_score, 1),
        "risk_level": level,
        "findings": " ".join(findings_list),
        "threat_intelligence_sources": intel["sources"],
        "threat_intelligence_summary": intel["summary"],
        "timestamp": datetime.now(timezone.utc),
        "url": None,
        "domain": None,
        "ip_address": None,
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


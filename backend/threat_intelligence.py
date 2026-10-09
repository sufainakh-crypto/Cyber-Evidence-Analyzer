import os
import base64
import requests
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()

# Timeout limit in seconds to prevent blocking API calls
REQUEST_TIMEOUT = 4.0


def query_virustotal(input_value: str, input_type: str) -> Optional[Dict[str, Any]]:
    """Query VirusTotal API v3 for domain, IP, or URL intelligence."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"status": "key_missing", "source": "VirusTotal"}

    headers = {"x-apikey": api_key}
    try:
        if input_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{input_value}"
        elif input_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{input_value}"
        elif input_type == "url":
            # VT v3 requires URL identifier to be URL-safe base64 string without trailing '='
            url_id = base64.urlsafe_b64encode(input_value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return None

        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values()) if stats else 0

            return {
                "status": "success",
                "source": "VirusTotal",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total_vendors": total,
            }
        elif response.status_code in (401, 403):
            return {"status": "error", "source": "VirusTotal", "message": "Invalid API key"}
        elif response.status_code == 404:
            return {
                "status": "success",
                "source": "VirusTotal",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_vendors": 0,
                "note": "No previous record found on VirusTotal",
            }
        elif response.status_code == 429:
            return {"status": "error", "source": "VirusTotal", "message": "Rate limit exceeded"}
        else:
            return {"status": "error", "source": "VirusTotal", "message": f"HTTP {response.status_code}"}
    except requests.RequestException:
        return {
            "status": "error",
            "source": "VirusTotal",
            "message": "Threat intelligence source unavailable",
        }


def query_abuseipdb(input_value: str, input_type: str) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB v2 API for IP address threat intelligence."""
    if input_type != "ip":
        return None

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {"status": "key_missing", "source": "AbuseIPDB"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": input_value, "maxAgeInDays": 90}

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            isp = data.get("isp", "Unknown")
            country = data.get("countryCode", "Unknown")

            return {
                "status": "success",
                "source": "AbuseIPDB",
                "abuse_score": score,
                "total_reports": reports,
                "isp": isp,
                "country": country,
            }
        elif response.status_code in (401, 403):
            return {"status": "error", "source": "AbuseIPDB", "message": "Invalid API key"}
        elif response.status_code == 429:
            return {"status": "error", "source": "AbuseIPDB", "message": "Rate limit exceeded"}
        else:
            return {"status": "error", "source": "AbuseIPDB", "message": f"HTTP {response.status_code}"}
    except requests.RequestException:
        return {
            "status": "error",
            "source": "AbuseIPDB",
            "message": "Threat intelligence source unavailable",
        }


def query_urlscan(input_value: str, input_type: str) -> Optional[Dict[str, Any]]:
    """Query urlscan.io search API for URL, domain, or IP scan history."""
    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key:
        return {"status": "key_missing", "source": "urlscan.io"}

    headers = {"API-Key": api_key}
    try:
        if input_type == "domain":
            query_str = f"domain:{input_value}"
        elif input_type == "ip":
            query_str = f"ip:{input_value}"
        elif input_type == "url":
            query_str = f'url:"{input_value}"'
        else:
            return None

        url = f"https://urlscan.io/api/v1/search/?q={query_str}"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            total = data.get("total", 0)
            malicious_count = 0
            for item in results[:5]:
                verdicts = item.get("verdicts", {}).get("overall", {})
                if verdicts.get("malicious"):
                    malicious_count += 1

            return {
                "status": "success",
                "source": "urlscan.io",
                "total_scans": total,
                "malicious_scans": malicious_count,
            }
        elif response.status_code in (401, 403):
            return {"status": "error", "source": "urlscan.io", "message": "Invalid API key"}
        elif response.status_code == 429:
            return {"status": "error", "source": "urlscan.io", "message": "Rate limit exceeded"}
        else:
            return {"status": "error", "source": "urlscan.io", "message": f"HTTP {response.status_code}"}
    except requests.RequestException:
        return {
            "status": "error",
            "source": "urlscan.io",
            "message": "Threat intelligence source unavailable",
        }


def fetch_threat_intelligence(input_value: str, input_type: str) -> Dict[str, Any]:
    """Safely fetch and aggregate threat intelligence from all available APIs.
    
    Provides structured status for each provider: CONFIGURED, KEY_MISSING, UNAVAILABLE, or NOT_APPLICABLE.
    Explicitly enforces that missing threat intelligence does not imply safety.
    """
    raw_results = []

    # VirusTotal
    vt_res = query_virustotal(input_value, input_type)
    if vt_res:
        raw_results.append(vt_res)

    # AbuseIPDB (only for IP)
    abuse_res = query_abuseipdb(input_value, input_type)
    if abuse_res:
        raw_results.append(abuse_res)
    else:
        raw_results.append({
            "source": "AbuseIPDB",
            "status": "not_applicable",
            "message": "AbuseIPDB only inspects IP addresses."
        })

    # urlscan.io
    urlscan_res = query_urlscan(input_value, input_type)
    if urlscan_res:
        raw_results.append(urlscan_res)

    active_sources: List[str] = []
    summary_parts: List[str] = []
    sources_detail: List[Dict[str, Any]] = []
    score_delta: float = 0.0

    for res in raw_results:
        src = res["source"]
        st = res["status"]

        detail_item = {
            "source": src,
            "status": st,
            "configured": st != "key_missing",
            "data_received": st == "success",
            "score_delta": 0.0,
            "explanation": "",
        }

        if st == "success":
            active_sources.append(src)
            if src == "VirusTotal":
                mal = res.get("malicious", 0)
                susp = res.get("suspicious", 0)
                tot = res.get("total_vendors", 0)
                vt_delta = (mal * 15.0) + (susp * 5.0)
                score_delta += vt_delta
                detail_item["score_delta"] = vt_delta
                detail_item["detections"] = {"malicious": mal, "suspicious": susp, "harmless": res.get("harmless", 0), "total": tot}
                if mal > 0 or susp > 0:
                    exp = f"Detected {mal} malicious and {susp} suspicious security vendor flags out of {tot} engines."
                    summary_parts.append(f"VirusTotal: {exp}")
                    detail_item["explanation"] = exp
                else:
                    exp = f"Clean across {tot} security vendor engines (0 detections). Note: recent or targeted threats may not yet be indexed."
                    summary_parts.append(f"VirusTotal: Clean ({tot} engines).")
                    detail_item["explanation"] = exp

            elif src == "AbuseIPDB":
                score = res.get("abuse_score", 0)
                reports = res.get("total_reports", 0)
                isp = res.get("isp", "Unknown")
                country = res.get("country", "Unknown")
                abuse_delta = score * 0.5
                score_delta += abuse_delta
                detail_item["score_delta"] = abuse_delta
                detail_item["detections"] = {"abuse_score": score, "total_reports": reports, "isp": isp, "country": country}
                if score > 0:
                    exp = f"Abuse confidence score of {score}% with {reports} community report(s). ISP: {isp} ({country})."
                    summary_parts.append(f"AbuseIPDB: {exp}")
                    detail_item["explanation"] = exp
                else:
                    exp = f"0% abuse confidence score ({reports} reports). ISP: {isp} ({country})."
                    summary_parts.append(f"AbuseIPDB: 0% abuse score.")
                    detail_item["explanation"] = exp

            elif src == "urlscan.io":
                total = res.get("total_scans", 0)
                mal = res.get("malicious_scans", 0)
                urlscan_delta = mal * 20.0
                score_delta += urlscan_delta
                detail_item["score_delta"] = urlscan_delta
                detail_item["detections"] = {"total_scans": total, "malicious_scans": mal}
                if mal > 0:
                    exp = f"{mal} out of {total} recent scans flagged as malicious."
                    summary_parts.append(f"urlscan.io: {exp}")
                    detail_item["explanation"] = exp
                else:
                    exp = f"0 malicious scans found across {total} historical submissions."
                    summary_parts.append(f"urlscan.io: Clean ({total} historical scans).")
                    detail_item["explanation"] = exp

        elif st == "key_missing":
            detail_item["explanation"] = "API key not configured in backend environment (.env). External intelligence query skipped."
            summary_parts.append(f"{src}: Not Configured (API key missing).")
        elif st == "not_applicable":
            detail_item["explanation"] = res.get("message", "Not applicable for this input type.")
        elif st == "error":
            msg = res.get("message", "Threat intelligence source unavailable")
            detail_item["explanation"] = f"Service returned error or timed out: {msg}. Source unavailable."
            summary_parts.append(f"{src}: Unavailable ({msg}).")

        sources_detail.append(detail_item)

    summary_text = " ".join(summary_parts) if summary_parts else "No threat intelligence queries were executed."

    return {
        "sources": active_sources,
        "summary": summary_text,
        "score_delta": score_delta,
        "sources_detail": sources_detail,
        "forensic_notice": (
            "Unconfigured, missing, or unavailable threat intelligence feeds are NOT treated as evidence of safety. "
            "Zero detections do not prove benign status."
        ),
    }

